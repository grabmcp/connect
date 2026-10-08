#!/usr/bin/env python3
"""GA4 bridge launcher — the only thing we add around Google's unchanged server.

It does three jobs, and each is a Stage 1 validation item:

  V3  credential handoff. Google's server reads Application Default Credentials from a FILE
      PATH only (measured in Stage 0), so a secret must exist on disk for the moment the
      server needs it. The launcher writes it 0600 inside a 0700 directory it owns, hands the
      path over by environment variable, and removes it on exit, on SIGTERM, and — because a
      SIGKILL leaves no chance to clean up — at the NEXT start, before the server is spawned.

  V6  truthful errors. Google's server reports a credential failure as `isError: false` with
      the error buried in the text payload, and ships no tool annotations (both measured in
      Stage 0, and neither fixable upstream without forking). The launcher proxies MCP stdio
      and repairs both: error-shaped results become protocol errors, and `tools/list` gains
      `title` and `readOnlyHint` on every tool.

  status. An `initialize` and each SUCCESSFUL report call are recorded as events. Since 0.3.0
      EVERY tool call is also recorded as a `call` event carrying the tool, its full ARGUMENTS
      (property, dates, metrics, dimensions: metadata, no business data) and a SHA-256 of the
      result delivered to the client -- never the result itself (Reviewer ruling G6, 19:11), so
      an answer can later be checked against the exact call and result it came from. A FAILED
      call records no report event.

  0.3.0 configuration (rulings G2-G5, 19:11). The OAuth client arrives as the PATH of Google's
  installed-app client JSON (`GA4_OAUTH_CLIENT_JSON`, set from the extension's user_config),
  read in place and never copied; the keychain is the dedicated one named by absolute path
  (`GA4_BRIDGE_KEYCHAIN`), and a LOCKED keychain is reported as locked, never as "not set up".

  0.5.0 (Owner ruling 2026-10-05 08:48-08:55, Reviewer conditions C1-C8). A call that fails for
  want of a credential (no credential, `invalid_grant`, or Google's 401 "Request had invalid
  authentication credentials") makes the launcher RE-READ the keychain. If the credential has
  CHANGED it rewrites this instance's credential file, restarts Google's server under the same
  stdio session (replaying `initialize` under a private id) and retries the call ONCE -- so the
  user need not restart Claude after connecting. No credential, or an UNCHANGED credential that
  is still refused (revoked), gives message A; a changed credential whose restart or retry failed,
  or a keychain read still pending, gives message B. Every other text is kept verbatim (C5).
  `security` is NEVER killed: a read that does not return is left running and reported (C1-C3).
  GOOGLE_APPLICATION_CREDENTIALS is ALWAYS set to this instance's own file, so google-auth can
  never fall through to a gcloud user credential on the machine. Each instance has its own
  credential file, and the call record is written under a lock with a unique temporary file,
  because the host runs two instances at once (LCH-3).

It never modifies Google's code. The vendored package in server/ is byte-identical to the
PyPI release, and that is asserted by the build.
"""
import ctypes
import ctypes.util
import fcntl
import glob
import hashlib
import hmac
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PRIVATE = os.environ.get("GA4_BRIDGE_PRIVATE") or os.path.join(HERE, ".private")
# 0.5.0 (LCH-3, Q2): ONE CREDENTIAL FILE PER INSTANCE. The host runs two instances at once, and a
# restart in one must not rewrite the file the other's server may load. The 0.4.x shared name is
# still swept, so a leftover from an older version cannot persist.
ADC_PATH = os.path.join(PRIVATE, "adc-%d.json" % os.getpid())
LEGACY_ADC = os.path.join(PRIVATE, "adc.json")
# 0.7.0 (N-5): the call record and the helper's state live OUTSIDE the extension folder, which an
# update replaces: one per-user directory (0700), overridable by GA4_BRIDGE_STATE_DIR (tests, the QA
# build). The credential files (adc-<pid>.json) and the helper log stay in .private. The 0.6.x
# files in .private are copied once at start (migrate_state -> migrate_file) and left in place. A run that names its
# own private directory (GA4_BRIDGE_PRIVATE: the test suites; the product never sets it) keeps its
# state there unless GA4_BRIDGE_STATE_DIR is also given, so no test touches the user's directory.
STATE_DIR = (os.environ.get("GA4_BRIDGE_STATE_DIR")
             or (PRIVATE if os.environ.get("GA4_BRIDGE_PRIVATE") else None)
             or os.path.expanduser("~/Library/Application Support/GrabMCP/ga4-bridge"))
STATUS_PATH = os.environ.get("GA4_BRIDGE_STATUS") or os.path.join(STATE_DIR, "status.json")
HELPER_STATE_PATH = os.path.join(STATE_DIR, "helper-state.json")
# Code review 03 r2 (candidate iv): the helper's "pending verified" marker. helper_env gives the
# helper GA4_HELPER_STATE = HELPER_STATE_PATH, and the helper writes the marker beside it.
PENDING_MARKER = os.path.join(os.path.dirname(HELPER_STATE_PATH), "pending-verified")
# E-1: the helper's "legacy pending ok" flag, in the same directory (see the helper).
LEGACY_FLAG = os.path.join(os.path.dirname(HELPER_STATE_PATH), "legacy-pending-ok")
LEGACY_PRIVATE = os.path.join(HERE, ".private")
STALE_MARKER = "ga4-bridge-adc"
# The ONLY binary we run against a keychain, by absolute path. Tests run a scratch copy of this
# file with this one line changed to a fake; the product never reads it from the environment.
SECURITY_BIN = "/usr/bin/security"
SEC_BOUND = 10.0          # s a caller waits for `security`; the process is NEVER killed (C1-C3)
# 0.7.0 (C-5, Owner ruling 2026-10-06 21:37): how long a question waits on a read of the LOCKED
# login keychain, while macOS's own unlock prompt may be up. Past it the read is "pending" (MSG_B).
LOGIN_UNLOCK_BOUND = 60.0
RESTART_BOUND = 60.0      # s for a restarted server to answer the replayed `initialize`
DRAIN_BOUND = 15.0        # s an old server keeps answering its in-flight calls after a restart
REPLAY_PREFIX = "grabmcp-launcher-replay-"

# The two Owner-approved texts, verbatim. MSG_B as ruled 2026-10-05 08:54; MSG_A as approved in the
# GA4 brief p.12 (R13, instruction RVW-INSTRUCTION-20261007-P step 3): three paragraphs separated by
# a blank line, U+2019 apostrophes (the Reviewer's 21:18 ASCII ruling is withdrawn).
MSG_A = ("The connection to Google Analytics was disconnected.\n\n"
         "Reconnect your Google account on the grabmcp website, then ask your question here "
         "again. You don’t need to reinstall the extension or restart Claude Desktop.\n\n"
         "If it still doesn’t work, send a problem report to support@grabmcp.com.")
MSG_B = ("The connection to Google failed. Please restart Claude Desktop. If it still doesn't "
         "work, send a problem report to support@grabmcp.com.")

# Tool annotations. Google ships none; these are ours. Every tool the vendored server exposes
# (the 9 listed in manifest.json) is a read: it has no mutating operation, so readOnlyHint is true
# for all of them.
TITLES = {
    "get_account_summaries": "List GA4 accounts and properties",
    "list_google_ads_links": "List Google Ads links",
    "get_property_details": "Get GA4 property details",
    "list_property_annotations": "List property annotations",
    "get_custom_dimensions_and_metrics": "List custom dimensions and metrics",
    "run_report": "Run a GA4 report",
    "run_realtime_report": "Run a GA4 realtime report",
    "run_funnel_report": "Run a GA4 funnel report",
    "run_conversions_report": "Run a GA4 conversions report",
}
REPORT_TOOLS = {"run_report", "run_realtime_report", "run_funnel_report",
                "run_conversions_report"}

# 0.6.0 (KPI-6, Reviewer ruling D2 2026-10-05 11:00): the properties this build may read. Fixed at
# BUILD time -- the Owner's build command (O7) writes this one line; nothing at run time widens it.
ALLOWED_PROPERTIES = frozenset({"449629553"})
# Re-review N1: FAIL CLOSED on tool names. Only the tools named here go upstream without a
# property check; EVERY other tool -- including one Google's server adds later -- must carry an
# allowed property id. (0.6.0 rr1 listed the property tools instead and missed two of them,
# `list_google_ads_links` and `get_custom_dimensions_and_metrics`.)
UNCHECKED_TOOLS = frozenset({"get_account_summaries"})
PROPERTY_KEYS = ("property_id", "propertyId")

# The keychain ACCOUNT the refresh token lives under. SHARED with the S2L helper, which writes
# it (ruling G3): 0.2.x read "ga4-bridge-test" while the helper wrote "ga4-refresh-token", so the
# launcher could never have found the token the helper stored. One name, asserted by a test that
# the launcher reads what the helper wrote.
REFRESH_ACCOUNT = "ga4-refresh-token"
# 0.6.0 P1 custody (Reviewer ruling D1, 11:00): with no keychain configured the credential lives in
# the user's LOGIN keychain -- unlocked whenever the user is logged in, so no manual unlock step.
LOGIN_KEYCHAIN = os.path.expanduser("~/Library/Keychains/login.keychain-db")
# 0.7.0 (C-5): a separate keychain (GA4_BRIDGE_KEYCHAIN) beside a client file is honoured only in a
# QA build (build-0.7.0.py --variant qa rewrites this line to True; the release scan refuses True).
KEYCHAIN_OVERRIDE_ALLOWED = False
# 0.6.0 (D4): the Owner's build command (O7) places Google's installed-app client file HERE.
EMBEDDED_CLIENT = os.path.join(HERE, "oauth-client.json")
# 0.6.0 (amendment 2): the helper runs inside the extension, one per user, the port is the lock.
HELPER_PORT = int(os.environ.get("GA4_HELPER_PORT") or 50812)    # 0 disables the helper
HELPER_SERVICE = "grabmcp-ga4-helper"
HELPER_RECHECK = float(os.environ.get("GA4_HELPER_RECHECK") or 30.0)
PENDING_SUFFIX = ".pending"     # 1.0 helper store (E2-02): a token verified there, not yet final
SEC_NOT_FOUND = 44              # `security find-generic-password`: no such item
KEYCHAIN_SERVICE = "ga4-bridge"

# Why the last credential attempt ended as it did; truthful_message() uses it so a locked
# keychain or a refused client file is never reported as "not set up".
CRED_STATE = {"state": "unknown", "detail": ""}


def log(msg):
    """Launcher diagnostics go to stderr. A secret must never reach here (V3-5)."""
    sys.stderr.write("[ga4-bridge] %s\n" % msg)
    sys.stderr.flush()


# ----------------------------------------------------------------- V3: the ADC file
def proc_start(pid):
    """How the OS reports that pid's start time, or None if it cannot be established.

    A pid is NOT an identity: pid counters wrap, and this machine's wrapped four times in a
    single session, so a stale pid can easily name a live stranger. (pid, start time) is the
    identity. `/bin/ps` is called by ABSOLUTE path because the hermetic proof environment
    runs with an empty PATH, where a bare `ps` would not resolve -- the kind of detail that
    makes a fix pass its test and fail in production.

    Three outcomes, deliberately distinguished:
        None  -- could not find out      (ps missing, blocked, timed out)
        ""    -- ps ran; the pid is gone (definitely dead)
        str   -- ps ran; this is its start time
    "I could not find out" is never "there is nothing there".
    """
    try:
        r = subprocess.run(["/bin/ps", "-p", str(int(pid)), "-o", "lstart="],
                           capture_output=True, text=True, timeout=10)
    except Exception:
        return None
    if r.returncode != 0:
        return ""
    return r.stdout.strip()


def owner_state(pid, recorded_start):
    """alive | dead | unknown for the process that wrote an ADC file."""
    try:
        pid = int(pid)
    except Exception:
        return "unknown"
    st = proc_start(pid)
    if st is None:
        return "unknown"
    if st == "":
        return "dead"
    if not recorded_start:
        return "unknown"
    return "alive" if st == recorded_start else "dead"


def sweep_stale():
    """Remove credential files that nobody is using any more: this version's per-instance files
    (`adc-<pid>.json`) and the 0.4.x shared `adc.json`. Each file is judged by its own recorded
    owner, exactly as before (see _sweep_one)."""
    swept = False
    for path in sorted(glob.glob(os.path.join(PRIVATE, "adc-*.json"))) + [LEGACY_ADC]:
        if path == ADC_PATH:
            continue
        swept = _sweep_one(path) or swept
    return swept


def _sweep_one(path):
    """Remove ONE credential file if, and only if, its owner is provably gone.

    Cleanup has to survive SIGKILL -- a `finally` block cannot run then, so without a sweep
    at start the secret would sit on disk until the next reboot. That is why this exists.

    But the host runs SEVERAL INSTANCES OF THIS CONNECTOR AT ONCE (measured 2026-10-04, and
    again 2026-10-05: every local MCP server is started in multiples). So "the file carries our
    marker" does NOT mean "the file is disposable" -- a LIVE peer's working credential carries
    the same marker. Only an owner that is PROVABLY GONE licenses a delete. When liveness cannot
    be established the sweep REFUSES: a secret that persists one extra session sits 0600 inside
    a 0700 directory we own and gets another sweep at the next start, while deleting a live
    peer's credential is neither bounded nor recoverable.
    """
    try:
        if not os.path.exists(path):
            return False
        with open(path, "r", encoding="utf-8") as fh:
            raw = fh.read(8192)
        if STALE_MARKER not in raw:
            log("refusing to delete %s: it is not ours" % path)
            return False
        owner_pid, owner_start = None, None
        try:
            doc = json.loads(raw)
            owner_pid = doc.get("_owner_pid")
            owner_start = doc.get("_owner_start")
        except Exception:
            pass
        if owner_pid is None:
            os.unlink(path)
            log("swept a stale credential file from a previous run (no owner recorded)")
            return True
        state = owner_state(owner_pid, owner_start)
        if state == "dead":
            os.unlink(path)
            log("swept a stale credential file: its owner (pid %s) is gone" % owner_pid)
            return True
        if state == "alive":
            log("NOT sweeping a credential file: a live instance (pid %s) owns it" % owner_pid)
            return False
        log("NOT sweeping a credential file: could not establish whether pid %s is alive, and a "
            "sweep that acts without knowing would delete a running instance's credential"
            % owner_pid)
        return False
    except FileNotFoundError:
        pass
    except Exception as exc:
        log("stale sweep could not complete: %s" % type(exc).__name__)
    return False


def write_adc(token_json):
    """Write THIS instance's credential file, STAMPED WITH ITS OWNER so a peer can tell it is in
    use. 0.5.0: written to a unique temporary file and renamed into place, because a restart
    rewrites it while the process runs, and a server started meanwhile must never read half a file.

    The extra keys ride alongside `_marker`, which Google's ADC parser has already accepted
    in every Stage 1 run -- a precedent, asserted in the suite rather than relied upon.
    """
    os.makedirs(PRIVATE, mode=0o700, exist_ok=True)
    os.chmod(PRIVATE, 0o700)
    payload = dict(token_json)
    payload["_owner_pid"] = os.getpid()
    payload["_owner_start"] = proc_start(os.getpid()) or ""
    fd, tmp = tempfile.mkstemp(prefix=".adc-", suffix=".tmp", dir=PRIVATE)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, ADC_PATH)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.chmod(ADC_PATH, 0o600)
    return ADC_PATH


def remove_adc():
    """Remove OUR ADC file -- never a peer's.

    The unguarded sweep was only half the defect. This runs on exit and on SIGTERM, so with
    instances sharing a directory an unconditional unlink here destroys a LIVE peer's
    credential too: the same bug arriving from the other end, and it would have survived a
    fix to the sweep alone.
    """
    try:
        with open(ADC_PATH, "r", encoding="utf-8") as fh:
            raw = fh.read(8192)
        owner_pid = None
        try:
            owner_pid = json.loads(raw).get("_owner_pid")
        except Exception:
            pass
        if owner_pid is not None and int(owner_pid) != os.getpid():
            log("not removing the ADC file: it belongs to pid %s, not to us" % owner_pid)
            return
        os.unlink(ADC_PATH)
        log("removed the ADC file")
    except FileNotFoundError:
        pass
    except Exception as exc:
        log("could not remove the ADC file: %s" % type(exc).__name__)


def keychain_status(path):
    """unlocked | locked | absent | unknown -- read WITHOUT any chance of a dialog.

    `security find-generic-password` against a LOCKED keychain can raise a SecurityAgent
    password dialog, which blocks for ever and looks exactly like a hang. So the lock state is
    read first through SecKeychainGetStatus, which only reports. Measured 2026-10-04 on a
    scratch copy: unlocked -> 7, locked -> 2, missing -> -25294; no dialog in any case.
    """
    try:
        sec = ctypes.cdll.LoadLibrary(ctypes.util.find_library("Security"))
        ref = ctypes.c_void_p()
        if sec.SecKeychainOpen(path.encode(), ctypes.byref(ref)) != 0:
            return "unknown"
        st = ctypes.c_uint32()
        rc = sec.SecKeychainGetStatus(ref, ctypes.byref(st))
        if rc == -25294:                       # errSecNoSuchKeychain
            return "absent"
        if rc != 0:
            return "unknown"
        return "unlocked" if st.value & 1 else "locked"
    except Exception:
        return "unknown"


def _governed_root(path):
    """The nearest ancestor that is a project or versioned tree (holds CLAUDE.md or .git)."""
    d = os.path.dirname(path)
    while d and d != os.path.dirname(d):
        if os.path.exists(os.path.join(d, "CLAUDE.md")) or os.path.exists(os.path.join(d, ".git")):
            return d
        d = os.path.dirname(d)
    return None


def keychain_path():
    """0.7.0 (C-5, Owner ruling 2026-10-06 21:25): a separate keychain (GA4_BRIDGE_KEYCHAIN) is
    honoured ONLY on the test route, where no client file is in force. The shipped package always
    carries its client file, so it reads the user's login keychain and nothing else."""
    if client_path() and not KEYCHAIN_OVERRIDE_ALLOWED:
        return LOGIN_KEYCHAIN
    return os.environ.get("GA4_BRIDGE_KEYCHAIN") or LOGIN_KEYCHAIN


def client_path():
    """The configured client file, else the one the build embedded, else None (test route)."""
    p = os.environ.get("GA4_OAUTH_CLIENT_JSON")
    if p:
        return p
    return EMBEDDED_CLIENT if os.path.exists(EMBEDDED_CLIENT) else None


def load_client_json(path, own_dir):
    """Read Google's installed-app client JSON IN PLACE. Returns (client, None) or (None, why).

    The four guards of RRK §2, each a test:
      1. the path is absolute and lies neither inside this component's own directory nor
         inside any project or versioned tree (an ancestor holding CLAUDE.md or .git) -- a
         client secret placed there is one `git add` or one seal away from being published;
      2. the file's mode grants nothing to group or other (0600 or tighter);
      3. it is never copied, logged or returned: only the two fields needed leave this function;
      4. (enforced by the pre-seal scan, not here) no sealed manifest lists such a file.
    """
    if not path or not os.path.isabs(path):
        return None, "the client file path must be absolute"
    real = os.path.realpath(path)
    # 0.6.0 (D4): the ONE file the build embeds is allowed inside the extension, and only it.
    # Guard 2 (mode) does not apply to it: it arrives by Claude's own install, whose file modes
    # we do not control, and it is a Desktop-type client (D6, recorded for the Reviewer).
    embedded = real == os.path.realpath(os.path.join(own_dir, "oauth-client.json"))
    if real.startswith(os.path.realpath(own_dir) + os.sep) and not embedded:
        return None, "the client file lies inside the extension's own directory"
    root = _governed_root(real)
    if root:
        return None, "the client file lies inside a project or versioned folder (%s)" % root
    try:
        st = os.stat(real)
    except OSError:
        return None, "the client file does not exist"
    if st.st_mode & 0o077 and not embedded:
        return None, "the client file is readable by others (mode %o); it must be 0600" % (
            st.st_mode & 0o777)
    try:
        with open(real, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        inst = doc.get("installed") or {}
        cid, csec = inst.get("client_id"), inst.get("client_secret")
    except Exception:
        return None, "the client file is not a Google installed-app client JSON"
    if not cid or not csec:
        return None, "the client file has no installed.client_id / client_secret"
    return {"client_id": cid, "client_secret": csec,
            "auth_uri": inst.get("auth_uri"), "token_uri": inst.get("token_uri")}, None


# ----------------------------------------------------------------- `security`, never killed
# C1-C3 (Reviewer 2026-10-05 09:04) and the 08:38 rule: a `security` process that may be waiting
# on a prompt is NEVER killed -- killing one crashed securityd on 2026-10-04 (DIAG-1). So no
# `subprocess.run(timeout=)` (it kills on timeout): Popen, a reader thread, and a bounded WAIT.
# Past the bound the caller is told "pending", the process is left alone, and it is recorded so
# that THIS instance (single flight) and ANY later instance (C3, via status.json) start no
# second read while it lives.
_SEC = {"proc": None}
_SEC_LOCK = threading.Lock()


def sec_call(args, stdin_text=None, bound=SEC_BOUND):
    """("done", rc, stdout) | ("pending", pid, None) | ("busy", pid, None) | ("error", None, None)"""
    with _SEC_LOCK:
        p = _SEC["proc"]
        if p is not None:
            if p.poll() is None:
                return ("busy", p.pid, None)
            _SEC["proc"] = None
        try:
            p = subprocess.Popen([SECURITY_BIN] + list(args),
                                 stdin=subprocess.PIPE if stdin_text is not None else subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                 start_new_session=True)   # E2-08: no group signal reaches it
        except Exception as exc:
            log("could not start `security`: %s" % type(exc).__name__)
            return ("error", None, None)
        _SEC["proc"] = p
    box = {"abandoned": False}

    def reader():
        try:
            box["out"] = p.communicate(input=stdin_text)
        except Exception:
            box["out"] = ("", "")
        with _SEC_LOCK:
            if _SEC["proc"] is p:
                _SEC["proc"] = None
            late = box["abandoned"]
        if late:
            status_event("credential_reread", outcome="late", sec_pid=p.pid)

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    t.join(bound)
    if t.is_alive():
        with _SEC_LOCK:
            box["abandoned"] = True
        log("a `security` call (pid %d) has not returned in %.0f s; a dialog may be up; "
            "it is left alone, never killed" % (p.pid, bound))
        return ("pending", p.pid, None)
    return ("done", p.returncode, (box.get("out") or ("", ""))[0])


def _pid_is_security(pid):
    """True if pid is a live process whose executable is `security`. ps only reports; no signal
    is ever sent to the process (L-KILL: a signal to a `security` process fails the run)."""
    try:
        r = subprocess.run(["/bin/ps", "-p", str(int(pid)), "-o", "comm="],
                           capture_output=True, text=True, timeout=10)
    except Exception:
        return False
    return r.returncode == 0 and os.path.basename(r.stdout.strip()) == "security"


def pending_read_elsewhere():
    """C3: the pid of a `security` read recorded as pending by ANY instance (this one, a peer, or
    the instance that ran before a Claude restart) that is still alive and has no `late`
    completion after it; else None."""
    pend = {}
    for ev in read_status_events():
        if ev.get("kind") != "credential_reread" or ev.get("sec_pid") is None:
            continue
        if ev.get("outcome") == "pending":
            pend[ev["sec_pid"]] = True
        elif ev.get("outcome") == "late":
            pend.pop(ev["sec_pid"], None)
    for pid in pend:
        if _pid_is_security(pid):
            return pid
    return None


def credential_from_keychain(allow_prompt=False):
    """Read the refresh token from the keychain named by absolute path.

    0.6.0 (P1, ruling D1): that is the user's LOGIN keychain unless one is configured -- by its
    absolute path, never "the default" or the search list. `security` is given the keychain path
    explicitly so it cannot fall through to the user's keychains. The lock state is checked
    FIRST (keychain_status), so a locked keychain becomes a truthful state instead of a dialog.
    A read that does not return is reported as pending and left running -- never killed.
    CRED_STATE["state"] is one of: ok, no_credential, pending, busy, sec_error, keychain_locked,
    keychain_absent, client_refused, no_keychain_configured, login_locked.

    0.7.0 (C-5): `allow_prompt` is True only for the re-read a QUESTION triggers (main.recover).
    """
    kc = keychain_path()
    account = os.environ.get("GA4_BRIDGE_ACCOUNT", REFRESH_ACCOUNT)
    if not kc:
        CRED_STATE.update(state="no_keychain_configured", detail="", sec_pid=None)
        return None
    ks = keychain_status(kc)
    bound = SEC_BOUND
    if ks == "locked" and kc == LOGIN_KEYCHAIN and client_path():
        # 0.7.0 (C-5, Owner ruling 2026-10-06 21:37): for the user's LOGIN keychain in the shipped
        # configuration, macOS's OWN unlock prompt is accepted; we add no prompt and no text. At
        # START nothing is read (no prompt as Claude starts; nothing is shown). A QUESTION reads it
        # anyway (allow_prompt): macOS may ask the user to unlock, and the read waits up to
        # LOGIN_UNLOCK_BOUND, never killed (sec_call). Past it: "pending" -> MSG_B, and the next
        # question reads again. A separate keychain (test route only) keeps the no-dialog rule.
        if not allow_prompt:
            CRED_STATE.update(state="login_locked", detail="", sec_pid=None)
            log("the login keychain is locked; it will be read when a question needs it")
            return None
        log("the login keychain is locked; reading it, so macOS can ask to unlock it")
        bound = LOGIN_UNLOCK_BOUND
    elif ks == "locked":
        CRED_STATE.update(state="keychain_locked", detail="", sec_pid=None)
        log("the credential keychain is LOCKED: unlock it, then restart the connector")
        return None
    if ks == "absent":
        CRED_STATE.update(state="keychain_absent", detail="", sec_pid=None)
        log("the configured credential keychain does not exist")
        return None
    cpath = client_path()
    if cpath:
        client, why = load_client_json(cpath, HERE)
        if not client:
            CRED_STATE.update(state="client_refused", detail=why, sec_pid=None)
            log("the OAuth client file was refused: %s" % why)
            return None
    else:
        # The mock-and-test route: no client file, so the client comes from env. Kept so the
        # S1/S2L suites keep running; a real run always sets GA4_OAUTH_CLIENT_JSON (RRK §4).
        client = {"client_id": os.environ.get("GA4_BRIDGE_CLIENT_ID",
                                              "test.apps.googleusercontent.com"),
                  "client_secret": os.environ.get("GA4_BRIDGE_CLIENT_SECRET",
                                                  "test-not-a-secret")}
    other = pending_read_elsewhere()
    if other is not None:
        CRED_STATE.update(state="pending", detail="", sec_pid=other)
        log("a keychain read (pid %s) is still pending; not starting a second one" % other)
        return None
    res = sec_call(["find-generic-password", "-a", account, "-s", KEYCHAIN_SERVICE, "-w", kc],
                   bound=bound)
    if res[0] in ("pending", "busy"):
        CRED_STATE.update(state=res[0], detail="", sec_pid=res[1])
        if res[0] == "pending":
            status_event("credential_reread", outcome="pending", sec_pid=res[1])
        return None
    if res[0] == "error":
        CRED_STATE.update(state="sec_error", detail="", sec_pid=None)
        return None
    if res[0] == "done" and res[1] == SEC_NOT_FOUND:
        # E2-02: the helper's store writes `<account>.pending` first and the final item last;
        # a store interrupted between those leaves the verified new token only there.
        res = sec_call(["find-generic-password", "-a", account + PENDING_SUFFIX,
                        "-s", KEYCHAIN_SERVICE, "-w", kc], bound=bound)
        if res[0] in ("pending", "busy"):
            CRED_STATE.update(state=res[0], detail="", sec_pid=res[1])
            if res[0] == "pending":
                status_event("credential_reread", outcome="pending", sec_pid=res[1])
            return None
        if res[0] == "error":
            CRED_STATE.update(state="sec_error", detail="", sec_pid=None)
            return None
        if res[1] == 0 and (res[2] or "").strip():
            if not pending_verified((res[2] or "").strip()) and not os.path.exists(LEGACY_FLAG):
                # r2 (iv): only a token the helper's store VERIFIED in the pending item counts;
                # an orphan of an abandoned add is not a credential
                CRED_STATE.update(state="no_credential", detail="", sec_pid=None)
                log("a pending item exists that no store verified; it is not used")
                return None
            log("the credential was read from the store's pending item (an interrupted store)")
    if res[1] == SEC_NOT_FOUND:
        CRED_STATE.update(state="no_credential", detail="", sec_pid=None)
        log("no credential in the keychain")
        return None
    if res[1] != 0:
        # E2-01 (launcher side): an error code is NOT "no credential"
        CRED_STATE.update(state="sec_error", detail="", sec_pid=None)
        log("the keychain read failed (rc=%d); not treated as 'no credential'" % res[1])
        return None
    refresh = (res[2] or "").strip()
    if not refresh:
        CRED_STATE.update(state="no_credential", detail="", sec_pid=None)
        return None
    CRED_STATE.update(state="ok", detail="", sec_pid=None)
    return {
        "type": "authorized_user",
        "client_id": client["client_id"],
        "client_secret": client["client_secret"],
        "refresh_token": refresh,
        "_marker": STALE_MARKER,
    }


def pending_verified(token):
    """r2 (iv): True if the helper's marker holds this token's SHA-256."""
    try:
        with open(PENDING_MARKER, encoding="utf-8") as fh:
            want = fh.read().strip()
    except OSError:
        return False
    return hmac.compare_digest(want, hashlib.sha256(token.encode()).hexdigest())


def token_sha(cred):
    """The SHA-256 of a credential's refresh token: compared, never the token itself."""
    if not cred:
        return None
    return hashlib.sha256(cred["refresh_token"].encode()).hexdigest()


# ----------------------------------------------------------------- status events
# plan-04 WP-6: the run_id of the helper this launcher's supervisor last read from /health as OURS.
# Every "call" and "report" event carries it as `helper_run_id`, so the helper publishes only calls
# made while IT was the helper. Not secret (the helper's /health shows it to anyone).
HELPER_RUN = {"id": None}
_RUN_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
# PLAN-05 WP-H1 ("Ready in Claude"): one random 72-bit id per launcher PROCESS (not secret), and this
# process's identity (pid + `ps -o lstart=` start time, the owner_state rule). The three MCP lifecycle
# events carry all three, so the helper counts a session only while that very process is alive.
LAUNCHER_SESSION = os.urandom(9).hex()
SELF_ID = {"pid": os.getpid(), "pid_start": None}


def self_identity():
    """{launcher_session, pid, pid_start} for the WP-H1 events. pid_start is read once (None if ps
    could not answer; the helper then never counts the session)."""
    if SELF_ID["pid_start"] is None:
        st = proc_start(SELF_ID["pid"])
        SELF_ID["pid_start"] = st or None
    return {"launcher_session": LAUNCHER_SESSION, "pid": SELF_ID["pid"],
            "pid_start": SELF_ID["pid_start"]}


def note_helper_run(run_id):
    HELPER_RUN["id"] = run_id if isinstance(run_id, str) and _RUN_ID_RE.fullmatch(run_id) else None


def _status_lock():
    d = os.path.dirname(STATUS_PATH)
    os.makedirs(d, mode=0o700, exist_ok=True)
    fd = os.open(os.path.join(d, "status.lock"), os.O_RDWR | os.O_CREAT, 0o600)
    return fd


def read_status_events():
    """The recorded events, read under a SHARED lock. A damaged file reads as no events here;
    the writer preserves it (see status_event)."""
    try:
        fd = _status_lock()
    except Exception:
        return []
    try:
        fcntl.flock(fd, fcntl.LOCK_SH)
        with open(STATUS_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh).get("events", [])
    except Exception:
        return []
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def status_event(kind, **fields):
    """Append an event: time, tool, property id, and since 0.3.0 a call's arguments and the
    SHA-256 of its result (never the result), plus a credential state. Nothing else.

    The allow-list is enforced HERE rather than at the call sites, so a future caller cannot
    widen it by passing more fields. 0.5.0 (C8) adds exactly two: `outcome` (a fixed word) and
    `sec_pid` (the pid of a pending `security` read). Neither can carry a secret.

    0.5.0 (LCH-3): two instances run at once and both write here. 0.4.0 read, appended and
    rewrote through ONE fixed temporary name with no lock, so a shorter write landed over a
    longer one (valid JSON followed by the tail of the old text) and the other writer's event
    was lost. Now the whole read-modify-write holds an exclusive lock, every write goes through
    its own unique temporary file, and a file that cannot be read is PRESERVED as
    `status.json.corrupt-<time>-<pid>` -- never overwritten silently.
    """
    # PLAN-05 WP-H1 adds exactly four: launcher_session, pid, pid_start, tools_ok (none can carry
    # a secret: a random id, a process id, a start time, a boolean).
    allowed = {"tool", "property_id", "client", "arguments", "result_sha256", "ok", "state",
               "outcome", "sec_pid", "launcher_session", "pid", "pid_start", "tools_ok"}
    ev = {"at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "kind": kind}
    for k, v in fields.items():
        if k in allowed and v is not None:
            ev[k] = v
    # plan-04 WP-6: set HERE from the supervisor's record, never by a caller
    if kind in ("call", "report") and HELPER_RUN["id"]:
        ev["helper_run_id"] = HELPER_RUN["id"]
    fd = None
    try:
        fd = _status_lock()
        fcntl.flock(fd, fcntl.LOCK_EX)
        d = os.path.dirname(STATUS_PATH)
        events = []
        if os.path.exists(STATUS_PATH):
            try:
                with open(STATUS_PATH, "r", encoding="utf-8") as fh:
                    events = json.load(fh).get("events", [])
            except ValueError:
                keep = "%s.corrupt-%s-%d" % (STATUS_PATH, time.strftime("%Y%m%dT%H%M%S"),
                                             os.getpid())
                os.replace(STATUS_PATH, keep)
                log("the call record was unreadable; kept as %s, starting a new one"
                    % os.path.basename(keep))
                events = []
        events.append(ev)
        tfd, tmp = tempfile.mkstemp(prefix="status.", suffix=".tmp", dir=d)
        try:
            with os.fdopen(tfd, "w", encoding="utf-8") as fh:
                json.dump({"events": events}, fh, indent=1)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, STATUS_PATH)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except Exception as exc:
        log("status write failed: %s" % type(exc).__name__)
    finally:
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)


# ----------------------------------------------------------------- V6: the rewrite
def looks_like_error_payload(result):
    """Google's server answers a failed call with isError false and a JSON error in the text.

    Measured shape, Stage 0: content[0].text == '{"error": "Failed to execute tool ..."}'.
    Detection is on the PARSED payload, not a substring of the whole result, so an ordinary
    report that merely mentions the word 'error' is not mistaken for a failure.
    """
    if not isinstance(result, dict):
        return None
    content = result.get("content")
    if not isinstance(content, list) or not content:
        return None
    first = content[0]
    if not isinstance(first, dict) or first.get("type") != "text":
        return None
    text = first.get("text")
    if not isinstance(text, str):
        return None
    try:
        payload = json.loads(text)
    except Exception:
        return None
    if isinstance(payload, dict) and isinstance(payload.get("error"), str):
        return payload["error"]
    return None


# 0.7.0 (C-5, Owner ruling 2026-10-06 21:25): the user never sees a keychain message. The shipped
# package reads only the login keychain (keychain_path), and a keychain state that is not readable
# is answered with MSG_B, the approved generic text -- never a keychain word, a command or a path.
KEYCHAIN_STATES = frozenset({"keychain_locked", "keychain_absent", "no_keychain_configured",
                             "login_locked"})


def g5_text(state, detail=""):
    """The texts ruled at G5 (0.3.0). 0.7.0 (C-5): the keychain texts (F-B5 among them) are gone;
    a keychain state gives MSG_B instead (cred_state_text)."""
    if state == "client_refused":
        # CR3-2 (C-5): no detail in the text -- it can carry a folder path; the detail goes to the
        # log only (credential_from_keychain logs it where the refusal is decided).
        # AWAITING OWNER (O-1): proposed text, Planner drafting routed by the Reviewer
        return ("The extension couldn't start correctly. Reinstall it from the grabmcp website. "
                "If it still doesn't work, send a problem report to support@grabmcp.com.")
    return None


def cred_state_text(state, detail=""):
    """The text for a credential read that did not end "ok" (0.7.0: keychain states -> MSG_B)."""
    text = g5_text(state, detail)
    if text is None:
        text = MSG_B if state in KEYCHAIN_STATES or state in ("pending", "busy", "sec_error") \
            else MSG_A
    return text


def cred_failure_kind(raw):
    """"no_credential" | "revoked" | None. Built only from MEASURED texts (C6): google-auth's own
    no-credential messages (the "File ... was not found." form, since the variable is now always
    set), `invalid_grant`, and Google's 401 text from the Owner's 07:56 failure. Never widened by
    guess: a live text that does not match is reported and fixed in a later release (F-B11)."""
    if raw is None:
        return None
    low = raw.lower()
    if ("default credentials were not found" in low or "application default credentials" in low
            or ("was not found" in low and os.path.basename(ADC_PATH) in raw)):
        return "no_credential"
    if "invalid_grant" in low or "request had invalid authentication credentials" in low:
        return "revoked"
    return None


def truthful_message(raw):
    """Say what actually went wrong, in words a participant can act on.

    0.5.0: credential failures are normally decided by the re-read (main.recover); this is the
    fallback for a credential failure that reaches it without one, and the unchanged text for
    every other failure (C5)."""
    low = raw.lower()
    kind = cred_failure_kind(raw)
    if kind == "no_credential":
        st = CRED_STATE.get("state")
        return cred_state_text(st, CRED_STATE.get("detail", "")) if st != "ok" else MSG_A
    if kind == "revoked":
        return MSG_A
    # 0.7.0 (N-4): Google's own text is never shown; it goes to the log only.
    log("Google's server reported: %s" % raw.replace("\r", " ").replace("\n", " ")[:500])
    if "permission" in low or "403" in low:
        # F-B8
        # AWAITING OWNER (O-1): proposed text, Planner drafting routed by the Reviewer
        return ("This Google account doesn't have access to that Google Analytics property. "
                "Ask the property's administrator to give this account access, then ask "
                "your question again.")
    # F-B9
    # AWAITING OWNER (O-1): proposed text, Planner drafting routed by the Reviewer
    return ("Google Analytics couldn't complete this request. Ask your question again. If it "
            "still doesn't work, send a problem report to support@grabmcp.com.")


def normalise_property(value):
    """'449629553', 449629553 and 'properties/449629553' are the same property; anything else
    normalises to itself (and is then simply not in the list)."""
    s = str(value).strip()
    if s.startswith("properties/"):
        s = s[len("properties/"):]
    return s


def property_refusal(tool, args):
    """None when the call may go upstream, else the text the client is given instead.

    Fails CLOSED: a property tool with NO property id, or with two that disagree, is refused --
    the launcher never lets Google's server pick a property it did not check."""
    if tool in UNCHECKED_TOOLS:
        return None
    args = args if isinstance(args, dict) else {}
    given = [normalise_property(args[k]) for k in PROPERTY_KEYS if args.get(k) not in (None, "")]
    if given and all(g in ALLOWED_PROPERTIES for g in given):
        return None
    # F-B12 (0.7.0, N-4): no property id in the text; the site shows the supported property.
    # AWAITING OWNER (O-1): proposed text, Planner drafting routed by the Reviewer
    return ("This connector can read only the one Google Analytics property shown on the grabmcp "
            "website, so the request was not sent. Ask about that property instead.")


def annotate_tools(result):
    tools = result.get("tools")
    if not isinstance(tools, list):
        return result
    for t in tools:
        if not isinstance(t, dict):
            continue
        name = t.get("name")
        ann = dict(t.get("annotations") or {})
        ann["title"] = TITLES.get(name, name)
        ann["readOnlyHint"] = True
        t["annotations"] = ann
        if "title" not in t:
            t["title"] = ann["title"]
    return result


# ----------------------------------------------------------------- the proxy
class Upstream:
    """One child process running Google's server, with its own reader thread. 0.5.0 can hold
    more than one over a session: a restart starts a new one and drains the old (DRAIN_BOUND)."""

    def __init__(self, cmd, env, gen, on_line, on_eof):
        self.gen = gen
        self.proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=sys.stderr, env=env, text=True, bufsize=1)
        self.wlock = threading.Lock()
        threading.Thread(target=self._read, args=(on_line, on_eof), daemon=True).start()

    def _read(self, on_line, on_eof):
        try:
            for line in self.proc.stdout:
                on_line(self, line)
        except Exception:
            pass
        on_eof(self)

    def send(self, msg):
        with self.wlock:
            self.proc.stdin.write(json.dumps(msg) + "\n")
            self.proc.stdin.flush()

    def stop(self):
        # A SERVER child, never a `security` process: terminating it is allowed (C1 covers
        # `security` only).
        try:
            self.proc.terminate()
        except Exception:
            pass


# 0.6.2 v2 (re-review-4 M-4): every launcher->helper call goes through an opener with NO proxy.
# A plain urlopen honours http_proxy/HTTP_PROXY, and would send the pairing secret to a proxy.
NOPROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def helper_probe(port, out=None):
    """"ours" | "none" | "foreign" | "unknown" -- what answers on the helper port. `out`, if
    given, receives the /health document (0.6.2: its `version` and `run_id`)."""
    try:
        with NOPROXY.open("http://127.0.0.1:%d/health" % port, timeout=3) as f:
            doc = json.loads(f.read().decode() or "{}")
        if out is not None and isinstance(doc, dict):
            out.update(doc)
        return "ours" if doc.get("service") == HELPER_SERVICE else "foreign"
    except urllib.error.HTTPError:
        return "foreign"
    except urllib.error.URLError as exc:
        return "none" if isinstance(exc.reason, ConnectionRefusedError) else "unknown"
    except ValueError:
        return "foreign"
    except Exception:
        return "unknown"


def _vtuple(v):
    try:
        return tuple(int(x) for x in str(v).split("."))
    except (TypeError, ValueError):
        return None


def bundled_helper_version():
    """The VERSION of the helper.py shipped beside this launcher (0.6.2, P1)."""
    try:
        with open(os.path.join(HERE, "helper.py"), encoding="utf-8") as fh:
            m = re.search(r'^VERSION = "([0-9.]+)"$', fh.read(), re.M)
        return m.group(1) if m else None
    except OSError:
        return None


def pairing_from_keychain():
    """The helper's pairing secret, read like the credential (by path, never on a locked
    keychain, never killed), so the launcher can ask a stale helper to stop."""
    kc = keychain_path()
    if keychain_status(kc) != "unlocked":
        return None
    res = sec_call(["find-generic-password", "-a", "ga4-helper-pairing", "-s", KEYCHAIN_SERVICE,
                    "-w", kc])
    if res[0] == "done" and res[1] == 0:
        return (res[2] or "").strip() or None
    return None


def helper_env(base_env):
    """What the helper is told: where the credential and the client are, where the launcher's
    record is (its Claude row), and its own state file. Never a credential file of ours."""
    e = {k: v for k, v in base_env.items()
         if k not in ("GOOGLE_APPLICATION_CREDENTIALS", "GA4_BRIDGE_CLIENT_SECRET")}
    e.update(GA4_BRIDGE_KEYCHAIN=keychain_path(), GA4_BRIDGE_STATUS=STATUS_PATH,
             GA4_HELPER_STATE=HELPER_STATE_PATH, GA4_BRIDGE_STATE_DIR=STATE_DIR,
             GA4_HELPER_PORT=str(HELPER_PORT),
             GA4_HELPER_PARENT_WATCH="1",      # 0.6.2 (P2): it stops when we are gone
             # step 3 (b): the site is shown only the property this launcher allows
             GA4_BRIDGE_ALLOWED_PROPERTIES=",".join(sorted(ALLOWED_PROPERTIES)))
    c = client_path()
    if c:
        e["GA4_OAUTH_CLIENT_JSON"] = c
    return e


class HelperSupervisor:
    """One helper per user, whichever instance starts first (amendment 2, sec. 1.2).

    The helper binds 127.0.0.1:HELPER_PORT; the bind is atomic, so the port IS the lock. Every
    HELPER_RECHECK seconds this instance asks /health: our helper answering -> nothing to do
    (attached); nothing listening -> start one (a lost bind race makes it exit at once, and the
    next check attaches); something else answering -> start nothing, record helper_port_foreign.
    The helper is a child of the instance that started it and stops with it; the standing-by
    instance then starts its own within one recheck. Its stdout is NEVER ours: that is the MCP
    channel to Claude."""

    def __init__(self, base_env):
        self.base_env = base_env
        self.proc = None
        self.lock = threading.Lock()
        self.stop_ev = threading.Event()
        self.last = None
        self.unreplaceable = None      # run_id of a stale helper that has no /shutdown (P3)

    def _record(self, outcome):
        if outcome != self.last:
            status_event("helper", outcome=outcome)
            log("helper: %s" % outcome)
            self.last = outcome

    def _start(self):
        script = os.path.join(HERE, "helper.py")
        if not os.path.exists(script):
            self._record("helper_missing")
            return
        os.makedirs(PRIVATE, mode=0o700, exist_ok=True)
        fd = os.open(os.path.join(PRIVATE, "helper.log"),
                     os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            self.proc = subprocess.Popen([sys.executable, script], env=helper_env(self.base_env),
                                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                         stderr=fd)
        finally:
            os.close(fd)
        self._record("started")

    def check(self):
        handoff = None
        with self.lock:
            if self.stop_ev.is_set():
                return
            if self.proc is not None and self.proc.poll() is not None:
                self.proc = None
                self._record("exited")
            doc = {}
            state = helper_probe(HELPER_PORT, doc)
            # plan-04 WP-6: whose run the next call events belong to ("unknown" keeps the last)
            note_helper_run(doc.get("run_id") if state == "ours"
                            else HELPER_RUN["id"] if state == "unknown" else None)
            if state == "none" and self.proc is None:
                self._start()
            elif state == "ours":
                mine, theirs = _vtuple(bundled_helper_version()), _vtuple(doc.get("version"))
                if (self.proc is None and mine and theirs and theirs < mine
                        and doc.get("run_id") != self.unreplaceable):
                    handoff = doc
                else:
                    self._record("running" if self.proc is not None else "attached")
            elif state == "foreign":
                self._record("helper_port_foreign")
        if handoff is not None:
            self._handoff(handoff)            # M-1: OUTSIDE the lock (it makes slow calls)

    def _rec(self, outcome):
        with self.lock:
            self._record(outcome)

    def _handoff(self, doc):
        """0.6.2 (P1): the running helper is OLDER than ours -- an update installed while Claude
        was open. Ask it to stop through its paired /shutdown, wait for the port, start ours.
        Called WITHOUT the lock (re-review-4 M-1: the keychain read, the POST and the port wait
        are slow, and stop() must never wait behind them); the lock is taken only to record and to
        start. A helper older than 1.0.2 has no /shutdown (P3): recorded once as
        helper_stale_unreplaceable and left alone -- only a Claude restart replaces it."""
        secret = pairing_from_keychain()
        if self.stop_ev.is_set():
            return
        if not secret:
            self._rec("helper_handoff_no_pairing")
            return
        req = urllib.request.Request("http://127.0.0.1:%d/shutdown" % HELPER_PORT, data=b"{}",
                                     method="POST", headers={"X-Pair-Secret": secret,
                                                             "Content-Type": "application/json"})
        try:
            with NOPROXY.open(req, timeout=5) as f:
                code = f.status
        except urllib.error.HTTPError as e:
            code = e.code
        except Exception as exc:
            log("helper handoff: /shutdown failed: %s" % type(exc).__name__)
            self._rec("helper_handoff_failed")
            return
        if code == 404:
            with self.lock:
                self.unreplaceable = doc.get("run_id")
                self._record("helper_stale_unreplaceable")
            return
        if code != 200:
            self._rec("helper_handoff_refused")
            return
        end = time.time() + 15
        while (time.time() < end and not self.stop_ev.is_set()        # M-1: honours stop()
               and helper_probe(HELPER_PORT) != "none"):
            self.stop_ev.wait(0.25)
        with self.lock:
            if self.stop_ev.is_set() or self.proc is not None:
                return                                                # stopping: start nothing
            log("helper handoff: %s -> %s" % (doc.get("version"), bundled_helper_version()))
            self._start()
            self._record("helper_replaced")

    def run(self):
        while not self.stop_ev.is_set():
            try:
                self.check()
            except Exception as exc:
                log("helper supervisor: %s" % type(exc).__name__)
            self.stop_ev.wait(HELPER_RECHECK)

    def stop(self):
        """Our helper is a Python process, never `security`; its own `security` children run in
        their own sessions (E2-08) and are not signalled by this."""
        self.stop_ev.set()
        with self.lock:
            p, self.proc = self.proc, None
        if p is not None and p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
            status_event("helper", outcome="stopped")


def migrate_file(old, new):
    """N-5 (helper 1.1.0, launcher 0.7.0): copy a state file of the previous version into the state
    directory ONCE, atomically, and leave the old file in place. Only when the new file is absent and
    the old one exists. The copy is written to a unique temporary file and LINKED into place, which
    never replaces: whoever created the new file first wins. A failure is logged; the start goes on.
    This function is kept byte-identical in helper.py and launcher.py (a test compares them)."""
    if (os.path.abspath(old) == os.path.abspath(new) or os.path.exists(new)
            or not os.path.isfile(old)):
        return False
    d = os.path.dirname(os.path.abspath(new))
    tmp = None
    try:
        os.makedirs(d, mode=0o700, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".migrate.", suffix=".tmp", dir=d)
        with open(old, "rb") as src, os.fdopen(fd, "wb") as fh:
            fh.write(src.read())
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.link(tmp, new)
        log("state migrated from the extension folder: %s" % os.path.basename(new))
        return True
    except FileExistsError:
        return False
    except Exception as exc:
        log("state migration skipped: %s" % type(exc).__name__)
        return False
    finally:
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def legacy_flag_write(path):
    """E-1 (conformance r3): the "legacy pending ok" flag, 0600, atomic, fixed non-secret content.
    Written once, on the FIRST 0.7.0 start on this machine (the state directory did not exist yet),
    which is the only moment a pending item left by 0.6.x can still be waiting. A 0.7.0 store or a
    disconnect deletes it first, so no pending item that 0.7.0 itself writes can ever ride on it.
    This function is kept byte-identical in helper.py and launcher.py (a test compares them)."""
    d = os.path.dirname(path)
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(prefix=".legacy-pending-ok.", suffix=".tmp", dir=d)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("legacy-pending-ok 1\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        tmp = None
        log("first start on this machine: a pending item left by an earlier version is accepted")
    except OSError as exc:
        log("the legacy flag could not be written: %s" % type(exc).__name__)
    finally:
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def migrate_state():
    """0.7.0 (N-5): the state directory exists (0700) and holds the 0.6.x files once. E-1: on the
    FIRST start (the directory did not exist) the legacy flag is written. The launcher only READS
    the flag and never writes the marker: a store in the helper may be running at that moment, and a
    marker written from here could overwrite the store's own."""
    try:
        first = not os.path.isdir(STATE_DIR)
        os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
        os.chmod(STATE_DIR, 0o700)
        if first:
            legacy_flag_write(LEGACY_FLAG)
    except OSError as exc:
        log("state directory could not be prepared: %s" % type(exc).__name__)
    migrate_file(os.path.join(LEGACY_PRIVATE, "status.json"), STATUS_PATH)
    migrate_file(os.path.join(LEGACY_PRIVATE, "helper-state.json"), HELPER_STATE_PATH)


def lifecycle_event(kind, **extra):
    """PLAN-05 WP-H1: one MCP lifecycle event (mcp_initialize_ok, mcp_initialized, mcp_tools_list),
    stamped with this launcher's session id, pid and start time."""
    fields = dict(self_identity())
    fields.update(extra)
    status_event(kind, **fields)


def tools_complete(result):
    """WP-H1: True only if a tools/list result names ALL nine GA4 tools of the manifest (TITLES
    lists exactly those nine)."""
    tools = result.get("tools") if isinstance(result, dict) else None
    if not isinstance(tools, list):
        return False
    names = {t.get("name") for t in tools if isinstance(t, dict)}
    return set(TITLES) <= names


_NO_ID = object()


def main():
    migrate_state()
    sweep_stale()
    self_identity()                # WP-H1: our start time, read once before any event needs it

    env = dict(os.environ)
    supervisor = HelperSupervisor(dict(os.environ)) if HELPER_PORT else None
    cred = credential_from_keychain()
    # `sha` is the credential the RUNNING server loaded -- never merely the one last written
    # (E2-03); `adc` says this instance's credential file exists.
    held = {"sha": token_sha(cred), "adc": False}
    if cred:
        write_adc(cred)
        held["adc"] = True
        log("ADC file prepared for the server")
    else:
        log("starting with no credential (%s): calls needing Google will fail truthfully"
            % CRED_STATE["state"])
    # 0.5.0 (§2.3): ALWAYS pin google-auth to THIS instance's own file, present or not. With the
    # variable unset (0.4.0, when there was no credential), google.auth.default() falls through
    # to a gcloud user credential on the machine -- another account, used silently (F-B10).
    env["GOOGLE_APPLICATION_CREDENTIALS"] = ADC_PATH
    status_event("credential", state=CRED_STATE["state"])
    # The upstream server needs the ADC path and nothing else of ours: it is not told where the
    # client file or the keychain is, nor given the test client secret.
    for k in ("GA4_OAUTH_CLIENT_JSON", "GA4_BRIDGE_CLIENT_SECRET", "GA4_BRIDGE_KEYCHAIN"):
        env.pop(k, None)
    # Never probe the GCE metadata server. Found by S2L X-1/rc (0.3.0): with no credential,
    # google.auth.default() in Google's server tries 169.254.169.254 -- a non-loopback,
    # non-Google-API destination, on every failed call. We never run on Compute Engine, so the
    # probe can only leak traffic. google-auth honours the value "true" in LOWER case only
    # (compute_engine/_metadata.py: os.getenv(NO_GCE_CHECK) == "true").
    env["NO_GCE_CHECK"] = "true"

    server_dir = os.path.join(HERE, "server")
    env["PYTHONPATH"] = server_dir + os.pathsep + env.get("PYTHONPATH", "")
    # HOW THE UPSTREAM IS SPAWNED DEPENDS ON HOW WE WERE DELIVERED, and this is a real
    # architectural difference rather than a detail. Under uv (or any ordinary interpreter)
    # sys.executable is a Python and we can ask it to import Google's server. Inside a frozen
    # one-file binary sys.executable is THIS BINARY: there is no interpreter to spawn, so the
    # binary must re-exec itself with a sentinel and play the upstream in that second process.
    if getattr(sys, "frozen", False):
        cmd = [sys.executable, "--upstream"]
    else:
        cmd = [sys.executable, "-c",
               "from analytics_mcp.server import run_server; run_server()"]

    lock = threading.RLock()       # guards st, pending, ups and the queue
    out_lock = threading.Lock()    # one writer at a time on our stdout
    recover_lock = threading.Lock()  # single flight: one re-read and restart at a time
    pending = {}                   # client id -> the call it belongs to
    ups = []                       # every server child started this session (cleanup ends all)
    replay_waits = {}              # private replay id -> (Event, box)
    st = {"up": None, "gen": 0, "restarting": False, "queue": [], "init": None,
          "initialized": None, "shutting": False, "restarts": 0,
          "init_id": _NO_ID}       # WP-H1: the client's own initialize id, until its answer
    done = threading.Event()

    def to_client(msg):
        with out_lock:
            sys.stdout.write(json.dumps(msg) + "\n")
            sys.stdout.flush()

    def record_call(info, result, failed, outcome=None):
        # G6: EVERY call is recorded with its arguments and the digest of the result exactly as
        # delivered to the client (canonical JSON), never the result.
        digest = hashlib.sha256(json.dumps(result, sort_keys=True,
                                           separators=(",", ":")).encode()).hexdigest()
        status_event("call", tool=info.get("tool"), arguments=info.get("arguments"),
                     result_sha256=digest, ok=not failed, outcome=outcome)
        # a FAILED call records no report event (V6-5)
        if not failed and info.get("tool") in REPORT_TOOLS:
            status_event("report", tool=info.get("tool"), property_id=info.get("property_id"),
                         arguments=info.get("arguments"), result_sha256=digest)

    def deliver_text(info, mid, text):
        result = {"content": [{"type": "text", "text": text}], "isError": True}
        record_call(info, result, True)
        to_client({"jsonrpc": "2.0", "id": mid, "result": result})

    def send_to(up, msg):
        """Forward one client message to `up`. Called with `lock` held."""
        mid = msg.get("id")
        if msg.get("method") == "tools/call" and mid is not None:
            params = msg.get("params") or {}
            args = params.get("arguments") or {}
            pending[mid] = {"tool": params.get("name"), "arguments": args,
                            "property_id": args.get("property_id") or args.get("propertyId"),
                            "msg": msg, "up": up, "gen": up.gen, "retried": False}
        elif msg.get("method") == "tools/list" and mid is not None:
            pending[mid] = {"tool": "__list__", "msg": msg, "up": up, "gen": up.gen,
                            "retried": False}
        try:
            up.send(msg)
            return True
        except Exception:
            return False

    def on_line(up, line):
        line = line.strip()
        if not line:
            return
        try:
            msg = json.loads(line)
        except Exception:
            with out_lock:
                sys.stdout.write(line + "\n")
                sys.stdout.flush()
            return
        mid = msg.get("id")
        # C6: the response to a REPLAYED initialize carries our private id and is never shown.
        if isinstance(mid, str) and mid.startswith(REPLAY_PREFIX):
            w = replay_waits.pop(mid, None)
            if w:
                w[1]["msg"] = msg
                w[0].set()
            return
        with lock:
            info = pending.get(mid) if mid is not None else None
            if info is not None and info.get("up") is up:
                pending.pop(mid)
            else:
                info = None
        result = msg.get("result")
        # G6, completed in 0.4.0 (Reviewer F-2): a JSON-RPC ERROR response carries no
        # `result`, and 0.3.0 recorded nothing for it. It is a call that failed, and it is
        # recorded as one, with the digest of the error object as delivered.
        if info and info.get("tool") != "__list__" and "error" in msg and result is None:
            edig = hashlib.sha256(json.dumps(msg["error"], sort_keys=True,
                                             separators=(",", ":")).encode()).hexdigest()
            status_event("call", tool=info.get("tool"), arguments=info.get("arguments"),
                         result_sha256=edig, ok=False, state="jsonrpc_error")
        # WP-H1: the answer to the CLIENT's initialize (never a replay: those return above)
        init_ok = False
        if mid is not None and "error" not in msg and isinstance(result, dict):
            with lock:
                if st["init_id"] is not _NO_ID and mid == st["init_id"] and up is st["up"]:
                    st["init_id"] = _NO_ID
                    init_ok = True
        tools_ok = None
        if isinstance(result, dict) and info:
            if info.get("tool") == "__list__":
                msg["result"] = annotate_tools(result)
                tools_ok = tools_complete(msg["result"])
            else:
                raw = looks_like_error_payload(result)
                kind = cred_failure_kind(raw)
                if kind and not info.get("retried"):
                    # 0.5.0: re-read the keychain; maybe restart and retry ONCE. Off this
                    # reader thread, so the server's other answers keep flowing meanwhile.
                    threading.Thread(target=recover, args=(info, mid, kind),
                                     daemon=True).start()
                    return
                if raw is not None:
                    # a credential failure on the RETRY: the credential had changed and the
                    # retry still failed -> B (C4). Anything else keeps its ruled text (C5).
                    text = MSG_B if kind else truthful_message(raw)
                    msg["result"] = {"content": [{"type": "text", "text": text}],
                                     "isError": True}
                failed = raw is not None or bool(msg["result"].get("isError"))
                record_call(info, msg["result"], failed)
        to_client(msg)
        # WP-H1: recorded only AFTER the result was delivered to the client
        if init_ok:
            lifecycle_event("mcp_initialize_ok")
        if tools_ok is not None:
            lifecycle_event("mcp_tools_list", tools_ok=tools_ok)

    def on_eof(up):
        with lock:
            current = (up.gen == st["gen"] and not st["restarting"] and not st["shutting"])
        if current:
            cleanup("upstream-exit")

    def retry(info, mid):
        """Send the client's original call, under its ORIGINAL id, to the current server, once."""
        with lock:
            up = st["up"]
            info.update(up=up, gen=up.gen, retried=True)
            pending[mid] = info
            ok = True
            try:
                up.send(info["msg"])
            except Exception:
                ok = False
                pending.pop(mid, None)
        if not ok:
            deliver_text(info, mid, MSG_B)

    def drain_old(old):
        """Let the old server answer what it already has, up to DRAIN_BOUND; anything still
        unanswered then gets B (L-R10: answered exactly once, never lost); then end it."""
        end = time.time() + DRAIN_BOUND
        while time.time() < end:
            with lock:
                left = [m for m, i in pending.items() if i.get("up") is old]
            if not left:
                break
            time.sleep(0.1)
        with lock:
            left = [(m, pending.pop(m)) for m, i in list(pending.items()) if i.get("up") is old]
        for m, i in left:
            if i.get("tool") == "__list__":
                to_client({"jsonrpc": "2.0", "id": m,
                           "error": {"code": -32603, "message": MSG_B}})
            else:
                deliver_text(i, m, MSG_B)
        old.stop()

    def restart():
        """Start a new server, replay initialize under a private id, swap it in. True/False."""
        with lock:
            if st["shutting"] or st["init"] is None:
                return False
            st["restarting"] = True
            old = st["up"]
            gen = st["gen"] + 1

        def give_up():
            with lock:
                st["restarting"] = False
                q, st["queue"] = st["queue"], []
                for m in q:
                    send_to(st["up"], m)

        try:
            new = Upstream(cmd, env, gen, on_line, on_eof)
        except Exception as exc:
            log("restart: could not start the server: %s" % type(exc).__name__)
            give_up()
            return False
        with lock:
            ups.append(new)
            shutting = st["shutting"]
        if shutting:
            new.stop()
            return False
        rid = REPLAY_PREFIX + os.urandom(8).hex()
        ev, box = threading.Event(), {}
        replay_waits[rid] = (ev, box)
        init = dict(st["init"])
        init["id"] = rid
        try:
            new.send(init)
            answered = ev.wait(RESTART_BOUND) and "result" in box.get("msg", {})
        except Exception:
            answered = False
        if not answered:
            replay_waits.pop(rid, None)
            log("restart: the new server did not answer initialize within %.0f s" % RESTART_BOUND)
            new.stop()
            give_up()
            return False
        try:
            if st["initialized"]:
                new.send(st["initialized"])
        except Exception:
            pass
        with lock:
            if st["shutting"]:
                new.stop()
                return False
            st["up"], st["gen"] = new, gen
            st["restarts"] += 1
            q, st["queue"] = st["queue"], []
            for m in q:
                send_to(new, m)
            st["restarting"] = False
        threading.Thread(target=drain_old, args=(old,), daemon=True).start()
        log("restart: Google's server restarted with the new credential (restart %d)"
            % st["restarts"])
        return True

    def recover(info, mid, kind):
        """The 0.5.0 decision (§2.1, C3-C5): re-read, then A, B, a G5 text, or restart+retry."""
        with recover_lock:
            with lock:
                cur_gen, shutting = st["gen"], st["shutting"]
            if shutting:
                deliver_text(info, mid, MSG_B)
                return
            if info.get("gen", 0) < cur_gen:
                # a restart already happened after this call was sent: retry it on the new
                # server; no second re-read and no second restart (L-R1)
                retry(info, mid)
                return
            new_cred = credential_from_keychain(allow_prompt=True)   # C-5: macOS may prompt
            state = CRED_STATE.get("state")
            if state != "ok":
                outcome = {"no_credential": "absent", "keychain_locked": "locked"}.get(state, state)
                if state != "pending":    # a pending read was recorded when it was found
                    status_event("credential_reread", outcome=outcome,
                                 sec_pid=CRED_STATE.get("sec_pid"))
                deliver_text(info, mid, cred_state_text(state, CRED_STATE.get("detail", "")))
                return
            new_sha = token_sha(new_cred)
            if new_sha == held["sha"] and kind == "revoked":
                # C4: the credential Google refused is still the one we hold -> revoked -> A
                status_event("credential_reread", outcome="unchanged")
                deliver_text(info, mid, MSG_A)
                return
            # changed -- or, for "no_credential", a credential the running server never loaded
            status_event("credential_reread",
                         outcome="changed" if new_sha != held["sha"] else "unchanged")
            # The credential file is written ONLY under the cleanup lock and only while no
            # cleanup has run: a recovery still reading the keychain when stdin closes must not
            # write a secret AFTER cleanup removed this instance's file (it would sit on disk
            # until the next start's sweep).
            with cleanup_lock:
                if cleaned.is_set():
                    deliver_text(info, mid, MSG_B)
                    return
                try:
                    write_adc(new_cred)
                    # E2-03: only the FILE is new here. 0.5.0 also set held["sha"] now, so after
                    # a FAILED restart the next refusal of the OLD credential compared equal to
                    # the new one and gave a false A with no further restart.
                    held["adc"] = True
                except Exception as exc:
                    log("restart: could not write the credential file: %s" % type(exc).__name__)
                    status_event("upstream_restart", outcome="failed")
                    deliver_text(info, mid, MSG_B)
                    return
            ok = restart()
            status_event("upstream_restart", outcome="ok" if ok else "failed")
            if ok:
                held["sha"] = new_sha            # E2-03: the server now runs on it
            if not ok:
                deliver_text(info, mid, MSG_B)
                return
            retry(info, mid)

    cleaned = threading.Event()
    # 0.2.1 -- THE SHUTDOWN RACE. 0.2.0 set `cleaned` FIRST and did the work after. When
    # SIGTERM and stdin EOF arrived together, the stdin thread entered cleanup() and set the
    # flag; the SIGTERM handler then saw it set, returned at once, and sys.exit(0) ended the
    # process while the daemon thread was still inside remove_adc() -- exit 0, no log line,
    # and the credential file left on disk until the next start swept it (S2L V3-3c).
    #
    # Design: the whole cleanup runs under ONE lock, and the flag is set only AFTER the work.
    # A second caller therefore WAITS for an in-flight cleanup instead of skipping it, and
    # nobody can exit while the file is half-removed. The lock is RE-ENTRANT on purpose: a
    # signal handler runs on the MAIN thread, and if the main thread is itself inside
    # cleanup() when SIGTERM lands, a plain Lock would deadlock the process against itself.
    # 0.5.0: cleanup also marks the session as shutting down (a restart in progress then ends
    # its own new server, L-R3), ends EVERY server child it started, and never touches a
    # `security` process (C1).
    cleanup_lock = threading.RLock()

    def cleanup(source="exit"):
        # Which shutdown path arrived is logged BEFORE the lock, so a log that shows two
        # sources proves two paths really raced for this cleanup.
        log("shutdown: %s" % source)
        with cleanup_lock:
            if cleaned.is_set():
                return
            with lock:
                st["shutting"] = True
                left = list(pending.items())
                pending.clear()
                children = list(ups)
            # G6, completed in 0.4.0 (Reviewer F-2): a call still unanswered at shutdown is
            # recorded too, so "every call" includes the ones that never got a reply.
            for _mid, info in left:
                if info.get("tool") != "__list__":
                    status_event("call", tool=info.get("tool"),
                                 arguments=info.get("arguments"), ok=False,
                                 state="pending_at_shutdown")
            remove_adc()
            for u in children:
                u.stop()
            if supervisor is not None:
                supervisor.stop()
            cleaned.set()
            done.set()

    signal.signal(signal.SIGTERM, lambda *a: (cleanup("SIGTERM"), sys.exit(0)))
    signal.signal(signal.SIGINT, lambda *a: (cleanup("SIGINT"), sys.exit(0)))

    if supervisor is not None:
        threading.Thread(target=supervisor.run, daemon=True).start()
    first = Upstream(cmd, env, 0, on_line, on_eof)
    with lock:
        ups.append(first)
        st["up"] = first

    def from_client():
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except Exception:
                continue
            if msg.get("method") == "initialize":
                ci = (msg.get("params") or {}).get("clientInfo") or {}
                status_event("initialize", client=ci.get("name"))
                with lock:
                    st["init"] = msg
                    st["init_id"] = msg.get("id", _NO_ID)
            if msg.get("method") == "notifications/initialized":
                with lock:
                    st["initialized"] = msg
                lifecycle_event("mcp_initialized")        # WP-H1
            if msg.get("method") == "tools/call" and msg.get("id") is not None:
                params = msg.get("params")
                params = params if isinstance(params, dict) else {}    # re-review N9
                refusal = property_refusal(params.get("name"), params.get("arguments"))
                if refusal is not None:
                    # KPI-6: refused HERE, before any upstream server sees the call
                    result = {"content": [{"type": "text", "text": refusal}], "isError": True}
                    record_call({"tool": params.get("name"), "arguments": params.get("arguments")},
                                result, True, outcome="property_refused")
                    to_client({"jsonrpc": "2.0", "id": msg["id"], "result": result})
                    continue
            with lock:
                if st["restarting"]:
                    st["queue"].append(msg)      # L-R2: delivered in order to the new server
                    continue
                sent = send_to(st["up"], msg)
            if not sent:
                break
        cleanup("stdin-eof")

    threading.Thread(target=from_client, daemon=True).start()
    while not done.wait(1.0):
        pass
    for u in list(ups):
        try:
            u.proc.wait(timeout=5)
        except Exception:
            pass


if __name__ == "__main__":
    main()
