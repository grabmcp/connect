#!/usr/bin/env python3
"""The S2L helper — the only thing the website talks to, now with a real OAuth flow.

A NEW file under operations/20261004-p2-s2-local/. Stage 1's helper/helper.py is sealed and
is not modified; this one supersedes it for Stage 2 and the two can be diffed.

What Stage 1 had: /health, /status, an origin allow-list, a keychain-backed pairing secret,
and a Claude row read from the launcher's own status file.

What Stage 2 adds, and why each is here rather than "finished":
  * /connect/start now returns a REAL authorization URL with PKCE (S256) and a state value.
    Stage 1 returned {"would_open": ..., "performed": false} and made no call at all.
  * /connect/callback completes the code exchange on a SHORT-LIVED loopback listener.
  * token custody: the refresh token goes to a DEDICATED keychain by absolute path; the
    access token is held in memory ONLY and never written anywhere.
  * /disconnect revokes at the provider AND deletes locally, and reports those as TWO
    SEPARATE STATES (F5) -- "still connected" must never be shown once the local secret is
    gone, and a provider that refuses the revoke must not be reported as revoked.
  * persistence: connection state to a 0600 file, so a restart resumes without new setup.
    Stage 1's STATE was in-memory, which made that assertion fail by construction.

1.2.0 (PLAN-05, extension 0.8.0): the callback moved to the MAIN server (WP-H2: /callback, 303 on
every outcome, a non-secret pending-flow record that survives a restart); "Ready in Claude"
(WP-H1: claude_loaded, property_present, ready); a bounded SIGTERM handler and the shutdown record
(WP-H3); the site opened once on first readiness and owner-tab arbitration (WP-H4); POST
/claude/open (WP-H5); google_access_reason (WP-H6). The per-flow listener described above is gone.

Boundaries this file is built to:
  * loopback ONLY, for both the service and the callback;
  * the provider base URL arrives by CONFIGURATION and has NO default -- not the mock's and
    not Google's. Unset means refuse to start a flow, rather than guess which Google to call;
  * no token and no report content ever crosses the channel to the site;
  * "Google access verified" says nothing about Claude. The Claude row moves only when the
    launcher's own status file records a real report call.
"""
import base64
import ctypes
import ctypes.util
import hashlib
import hmac
import json
import os
import re
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer

# 1.0 (0.6.0, amendment 2 sec. 2.4): a LIST of site origins. The public site's two origins are
# built in; a test build adds its local origin through GA4_HELPER_ALLOWED_ORIGINS (comma list).
# The single-origin variable of the 0.5.0 helper is still honoured.
DEFAULT_ORIGINS = ("https://grabmcp.github.io", "https://connect.grabmcp.com")
ALLOWED_ORIGINS = frozenset(
    list(DEFAULT_ORIGINS)
    + [o.strip() for o in os.environ.get("GA4_HELPER_ALLOWED_ORIGINS", "").split(",") if o.strip()]
    + ([os.environ["GA4_HELPER_ALLOWED_ORIGIN"]] if os.environ.get("GA4_HELPER_ALLOWED_ORIGIN")
       else []))
SERVICE = "grabmcp-ga4-helper"
# Step 3, blocking item (b): the property the site SHOWS must be the one the launcher ALLOWS (F-B12
# tells the user the connector reads "only the one Google Analytics property shown on the grabmcp
# website"). The launcher hands the helper its build-time ALLOWED_PROPERTIES here (helper_env); the
# helper never shows any other property. Not set (the helper run alone) -> no property is shown.
SHOWN_PROPERTIES = frozenset(p.strip() for p in
                             os.environ.get("GA4_BRIDGE_ALLOWED_PROPERTIES", "").split(",")
                             if p.strip())
VERSION = "1.2.0"
DEFAULT_PORT = 50812
# The keychain SERVICE every item of ours is stored under (one constant, so a QA build renames it
# in exactly one place; build-0.7.0.py asserts that).
KEYCHAIN_SERVICE = "ga4-bridge"
LAUNCHER_STATUS = os.environ.get("GA4_BRIDGE_STATUS", "")
# 0.6.0 P1 custody (ruling D1): the user's LOGIN keychain, by path. 1.1.0 (C-5, Owner ruling
# 2026-10-06 21:25): a separate keychain is honoured ONLY on the test route (no client file) or in a
# QA build (build-0.7.0.py --variant qa rewrites the line below to True; the release scan refuses
# True). The shipped package always carries its client file, so it uses the login keychain only.
KEYCHAIN_OVERRIDE_ALLOWED = False
# PLAN-05 FX-5 (CR5-6, plan §6 "compiled-in constants only"): the four binary seams of 1.2.0
# (GA4_HELPER_OPEN_BIN, _LSOF_BIN, _LSAPPINFO_BIN, _BUNDLEID_BIN) are honoured ONLY when the line below
# is True. A release build keeps it off: the helper then runs /usr/bin/open, /usr/sbin/lsof and
# /usr/bin/lsappinfo, and reads bundle ids in-process, from constants only. build-0.8.0.py --variant qa
# rewrites the line to True; the release scan refuses True (as for KEYCHAIN_OVERRIDE_ALLOWED).
SEAMS_ALLOWED = False


def _seam(var, constant):
    """The compiled-in constant, unless seams are allowed AND the variable is set (tests, qa)."""
    return (os.environ.get(var) or constant) if SEAMS_ALLOWED else constant


LOGIN_KEYCHAIN = os.path.expanduser("~/Library/Keychains/login.keychain-db")
KEYCHAIN = (os.environ.get("GA4_BRIDGE_KEYCHAIN") or LOGIN_KEYCHAIN
            if KEYCHAIN_OVERRIDE_ALLOWED or not os.environ.get("GA4_OAUTH_CLIENT_JSON")
            else LOGIN_KEYCHAIN)
KEYCHAIN_PW = os.environ.get("GA4_BRIDGE_KEYCHAIN_PW", "")

HERE = os.path.dirname(os.path.abspath(__file__))
# 1.1.0 (N-5): state lives OUTSIDE the extension folder, which an update replaces. One per-user
# directory (0700); GA4_BRIDGE_STATE_DIR overrides it (tests, the QA build). The 1.0.x location,
# <extension>/.private/, is read once to migrate (migrate_file) and is never written again.
STATE_DIR = (os.environ.get("GA4_BRIDGE_STATE_DIR")
             or os.path.expanduser("~/Library/Application Support/GrabMCP/ga4-bridge"))
STATE_PATH = os.environ.get("GA4_HELPER_STATE") or os.path.join(STATE_DIR, "helper-state.json")
LEGACY_STATE_PATH = os.path.join(HERE, ".private", "helper-state.json")
# Code review 03 r2 (candidate iv): the SHA-256 of the token the store last VERIFIED in the pending
# item. A pending item is a credential only if its hash matches this file; an orphan of an
# abandoned add never was verified, so it never matches. The launcher reads the same file (its
# helper_env gives this helper GA4_HELPER_STATE inside its own state directory).
PENDING_MARKER = os.path.join(os.path.dirname(os.path.abspath(STATE_PATH)), "pending-verified")
# E-1 (conformance r3): while this flag exists, a pending item with NO marker is accepted exactly as
# 0.6.3 accepted it (a 0.6.x store interrupted between its two adds), and the marker is written then.
LEGACY_FLAG = os.path.join(os.path.dirname(os.path.abspath(STATE_PATH)), "legacy-pending-ok")
SCOPE = "https://www.googleapis.com/auth/analytics.readonly"
# The keychain ACCOUNT the refresh token is written under -- SHARED with the launcher, which
# reads it (ruling G3). A test asserts the launcher reads exactly what this helper wrote.
REFRESH_ACCOUNT = "ga4-refresh-token"


def _governed_root(path):
    d = os.path.dirname(path)
    while d and d != os.path.dirname(d):
        if os.path.exists(os.path.join(d, "CLAUDE.md")) or os.path.exists(os.path.join(d, ".git")):
            return d
        d = os.path.dirname(d)
    return None


def load_client_json(path, own_dir):
    """Google's installed-app client JSON, read IN PLACE (RRK §2 guards 1-3; the same rules as
    the launcher's). Returns (client, None) or (None, why). Only the fields needed leave here."""
    if not path or not os.path.isabs(path):
        return None, "the client file path must be absolute"
    real = os.path.realpath(path)
    # 0.6.0 (D4): the ONE file the build embeds beside us is allowed, and only it; guard 2
    # (mode) does not apply to it -- Claude's install sets its mode, not us (D6).
    embedded = real == os.path.realpath(os.path.join(own_dir, "oauth-client.json"))
    if real.startswith(os.path.realpath(own_dir) + os.sep) and not embedded:
        return None, "the client file lies inside the helper's own directory"
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
        inst = (json.load(open(real, encoding="utf-8")).get("installed") or {})
    except Exception:
        return None, "the client file is not a Google installed-app client JSON"
    if not inst.get("client_id") or not inst.get("client_secret"):
        return None, "the client file has no installed.client_id / client_secret"
    return {"client_id": inst["client_id"], "client_secret": inst["client_secret"],
            "auth_uri": inst.get("auth_uri"), "token_uri": inst.get("token_uri")}, None


# ---- WHERE GOOGLE IS (ruling G1). Google serves the four endpoints from THREE hosts, so a
# single base cannot reach them; 0.2.x appended every path to one GA4_GOOGLE_BASE.
#   * TEST route: GA4_GOOGLE_BASE set -> all four derive from it (the mock serves them all).
#   * REAL route: GA4_OAUTH_CLIENT_JSON set -> auth_uri / token_uri come from Google's own
#     client file, revoke and the Admin API are Google's fixed hosts.
#   * Every endpoint stays individually env-overridable in both routes.
# With NEITHER configured the helper still refuses to start a flow: it never guesses a Google.
PROVIDER_BASE = os.environ.get("GA4_GOOGLE_BASE", "")
CLIENT_CONFIG_ERROR = None
_client = None
if os.environ.get("GA4_OAUTH_CLIENT_JSON"):
    _client, CLIENT_CONFIG_ERROR = load_client_json(os.environ["GA4_OAUTH_CLIENT_JSON"], HERE)
if _client:
    CLIENT_ID, CLIENT_SECRET = _client["client_id"], _client["client_secret"]
    _auth = _client.get("auth_uri") or "https://accounts.google.com/o/oauth2/v2/auth"
    _token = _client.get("token_uri") or "https://oauth2.googleapis.com/token"
    _revoke, _admin = "https://oauth2.googleapis.com/revoke", "https://analyticsadmin.googleapis.com"
elif PROVIDER_BASE and not CLIENT_CONFIG_ERROR:
    CLIENT_ID = os.environ.get("GA4_CLIENT_ID", "")
    CLIENT_SECRET = os.environ.get("GA4_CLIENT_SECRET", "")
    _auth, _token = PROVIDER_BASE + "/o/oauth2/v2/auth", PROVIDER_BASE + "/token"
    _revoke, _admin = PROVIDER_BASE + "/revoke", PROVIDER_BASE
else:
    CLIENT_ID = CLIENT_SECRET = ""
    _auth = _token = _revoke = _admin = ""
# Ruling G5 + Reviewer F-3 (0.4.0): on the REAL route (a client file is configured) the
# keychain is unlocked by the Owner, interactively, once per session. A keychain password in the
# environment is therefore REFUSED -- the helper will not start a flow -- and it is DISCARDED, so
# the only code that could put it in an argv (`security unlock-keychain -p`) can never run. The
# test route (GA4_GOOGLE_BASE, fake keychain) keeps its password.
REAL_ROUTE = bool(os.environ.get("GA4_OAUTH_CLIENT_JSON"))
if REAL_ROUTE and KEYCHAIN_PW:
    KEYCHAIN_PW = ""
    CLIENT_CONFIG_ERROR = CLIENT_CONFIG_ERROR or (
        # 1.1.0 (C-5): no shell command in any text that can reach the site
        "refused_env_password")
AUTH_URI = os.environ.get("GA4_AUTH_URI") or _auth
TOKEN_URI = os.environ.get("GA4_TOKEN_URI") or _token
REVOKE_URI = os.environ.get("GA4_REVOKE_URI") or _revoke
ADMIN_BASE = os.environ.get("GA4_ADMIN_BASE") or _admin
CONFIGURED = bool(AUTH_URI and TOKEN_URI and CLIENT_ID and not CLIENT_CONFIG_ERROR)

LOCK = threading.Lock()

# Non-secret connection state. Persisted so a restart resumes (V7-4).
STATE = {
    "helper": "running",
    "google_access": "not_connected",
    "property": None,
    # F5: the local copy and the provider-side authorization are SEPARATE facts.
    "local_credential": "absent",      # absent | present
    "provider_authorization": "none",  # none | granted | revoked | revoke_failed
    # V6-5: CORRELATION. A success is only current if it belongs to THIS connection and THIS
    # run of the helper. `connection_id` is minted fresh by every completed flow; the
    # verification record names the connection and the run it was made in.
    "connection_id": None,
    "verification": None,              # {"connection_id", "run_id", "at", "ok"} | None
    # KIT3 C4: the outcome of the LATEST authorization attempt, by its own id, so a caller can
    # wait for THIS flow instead of reading an older connection's "verified" as its result.
    "last_flow": None,                 # {"id", "outcome": pending|completed|cancelled|failed, "detail"}
}

# One id per helper PROCESS. A verification made by a previous run is history, not health:
# after a restart the persisted record is from another run and cannot be published as current.
RUN_ID = base64.urlsafe_b64encode(os.urandom(9)).decode().rstrip("=")
PERSISTED = ("google_access", "property", "local_credential", "provider_authorization",
             "connection_id", "verification")

# The access token lives here and nowhere else. Never persisted, never sent to the site.
_MEM = {"access_token": None, "expires_at": 0.0}
# in-flight authorization attempts: state -> {"verifier":..., "redirect":..., "at":...}
_PENDING = {}
# E2-05: the ONE flow in progress; a new /connect/start cancels it (outcome "superseded")
_ACTIVE_FLOW = {}


def log(msg):
    sys.stderr.write("[helper] %s\n" % msg)
    sys.stderr.flush()


def _one_line(s, n=500):
    """CR3-14: outside text for the log -- one line, at most n characters."""
    return str(s).replace("\r", " ").replace("\n", " ")[:n]


def _b64u(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


# ------------------------------------------------------------------ keychain custody
def keychain_state():
    """unlocked | locked | absent | unknown | not_configured -- read WITHOUT any dialog.

    `security` against a LOCKED keychain can raise a password dialog that blocks for ever.
    SecKeychainGetStatus only reports (measured: unlocked 7, locked 2, missing -25294)."""
    if not KEYCHAIN:
        return "not_configured"
    try:
        sec = ctypes.cdll.LoadLibrary(ctypes.util.find_library("Security"))
        ref = ctypes.c_void_p()
        if sec.SecKeychainOpen(KEYCHAIN.encode(), ctypes.byref(ref)) != 0:
            return "unknown"
        st = ctypes.c_uint32()
        rc = sec.SecKeychainGetStatus(ref, ctypes.byref(st))
        if rc == -25294:
            return "absent"
        if rc != 0:
            return "unknown"
        return "unlocked" if st.value & 1 else "locked"
    except Exception:
        return "unknown"


# 0.5.0 package (C2, Reviewer 2026-10-05 09:04; the 08:38 rule): `security` is NEVER killed.
# `subprocess.run(timeout=)` kills its child on timeout, and killing a `security` that waits on a
# prompt crashed securityd on 2026-10-04 (DIAG-1). So: Popen, a reader thread, a bounded WAIT;
# past the bound the caller gets None ("a dialog may be up"), the process is LEFT RUNNING, and no
# second `security` starts from this helper while it lives (single flight).
SEC_BOUND = 10.0
# 1.1.0 (C-5, Owner ruling 2026-10-06 21:37; lead decision B): storing a new token into a LOCKED
# login keychain is attempted anyway, so macOS's own unlock prompt can appear; the store waits up to
# this long. Past it the `security` call is abandoned (left running, never killed: DIAG-1) and the
# flow ends "keychain_write_failed" -> the callback page says "Sign-in didn't finish".
LOGIN_UNLOCK_BOUND = 60.0
_SEC_SERIAL = threading.Lock()      # one `security` at a time; a second caller WAITS its turn
_SEC_ABANDONED = {"p": None}        # a call that outlived SEC_BOUND, left running


def _sec_wait(argv, input_text=None, bound=None):
    """REGRESSION FIXED (found by the 0.5.0 run, custody 35/43): the first version REFUSED a call
    while another was running. This helper is a THREADED HTTP server -- a /status poll and a
    token store can overlap -- and the store then gave up, so a connect never stored its token.
    Now a second caller WAITS (bounded) for the call in progress, and only a call ABANDONED past
    its bound (a dialog may be up) makes later calls refuse, until it ends by itself."""
    bound = SEC_BOUND if bound is None else bound
    if not _SEC_SERIAL.acquire(timeout=SEC_BOUND):
        log("a keychain op is still in progress after %.0f s; not starting another" % SEC_BOUND)
        return None
    try:
        p0 = _SEC_ABANDONED["p"]
        if p0 is not None:
            if p0.poll() is None:
                log("a keychain op (pid %d) is still pending; not starting another" % p0.pid)
                return None
            _SEC_ABANDONED["p"] = None
        # E2-08: its OWN session, so a Ctrl-C or a signal to our process group never reaches
        # a `security` that may be waiting on a dialog.
        p = subprocess.Popen(argv, stdin=subprocess.PIPE if input_text is not None
                             else subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True, start_new_session=True)
        box = {}
        t = threading.Thread(target=lambda: box.setdefault("out", p.communicate(input=input_text)),
                             daemon=True)
        t.start()
        t.join(bound)
        if t.is_alive():
            _SEC_ABANDONED["p"] = p
            log("keychain op (pid %d) has not returned in %.0f s; a dialog may be up; it is left "
                "running, never killed" % (p.pid, bound))
            return None
        out, err = box["out"]
        return subprocess.CompletedProcess(argv, p.returncode, out, err)
    finally:
        _SEC_SERIAL.release()


_STORE = threading.local()          # 1.1.0 (C-5): set while refresh_token_set runs (this thread)


def _prompt_bound():
    """1.1.0 (C-5): the wait for a `security` call, or None to refuse it. A keychain that is not
    unlocked is never handed to `security` -- EXCEPT the LOGIN keychain during the token store
    (_STORE.active), where macOS's own unlock prompt is allowed and the wait is LOGIN_UNLOCK_BOUND."""
    if KEYCHAIN_PW:
        return SEC_BOUND
    ks = keychain_state()
    if ks == "unlocked":
        return SEC_BOUND
    if getattr(_STORE, "active", False) and ks == "locked" and KEYCHAIN == LOGIN_KEYCHAIN:
        log("the login keychain is locked; storing anyway, so macOS can ask to unlock it")
        return LOGIN_UNLOCK_BOUND
    return None


def _sec(args):
    """One `security` invocation, unlocking first, against the keychain by ABSOLUTE PATH.

    0.6.0 (P1): the login keychain unless another is configured -- always by absolute path,
    never "the default" or the search list, and never -A. A read is bounded by a WAIT that
    never kills (_sec_wait): if a SecurityAgent dialog ever appeared it would block for ever and
    look exactly like a hang, so it is reported as "a dialog may be up" and left alone.
    """
    if not KEYCHAIN:
        return None
    # Ruling G5: in a real run there is NO password in env; the Owner unlocks the keychain once
    # per session. A keychain that is not unlocked is therefore never handed to `security` --
    # that is where a dialog would come from -- and the caller reports it as locked.
    bound = _prompt_bound()
    if bound is None:
        return None
    if KEYCHAIN_PW:
        u = _sec_wait(["/usr/bin/security", "unlock-keychain", "-p", KEYCHAIN_PW, KEYCHAIN])
        if u is None or u.returncode != 0:
            log("keychain unlock failed rc=%s" % (u.returncode if u else "pending"))
            return None
    return _sec_wait(["/usr/bin/security"] + args + [KEYCHAIN], bound=bound)


def _sec_stdin(command):
    """One `security` command fed on STDIN (`security -i`), under the same unlock rules as
    _sec(): the command line -- and any secret in it -- never reaches an argv."""
    if not KEYCHAIN:
        return None
    bound = _prompt_bound()
    if bound is None:
        return None
    if KEYCHAIN_PW:
        u = _sec_wait(["/usr/bin/security", "unlock-keychain", "-p", KEYCHAIN_PW, KEYCHAIN])
        if u is None or u.returncode != 0:
            log("keychain unlock failed rc=%s" % (u.returncode if u else "pending"))
            return None
    return _sec_wait(["/usr/bin/security", "-i"], input_text=command + "\n", bound=bound)


_PAIR = {"v": None}
SEC_NOT_FOUND = 44          # `security find-/delete-generic-password`: the item does not exist
PENDING_ACCOUNT = REFRESH_ACCOUNT + ".pending"   # E2-02: verified new token, not yet final


def pairing_secret():
    """E2-06: read ONCE and kept in memory, like the access token. Before 1.0 every request
    spawned `security` (about 2 a second while a connect was polled)."""
    if _PAIR["v"]:
        return _PAIR["v"]
    r = _sec(["find-generic-password", "-a", "ga4-helper-pairing", "-s", KEYCHAIN_SERVICE, "-w"])
    v = r.stdout.strip() if r and r.returncode == 0 else None
    if v:
        _PAIR["v"] = v
    return v


def refresh_token_read():
    """E2-01: THREE answers, never two. ("present", token) | ("absent", None) | ("unknown", why).

    Before 1.0 a read that could not happen (a locked keychain, a `security` still pending or
    abandoned, any error code) returned None exactly like "no token", and /disconnect then
    skipped the revoke and persisted "absent" over a live credential. "absent" now means ONLY
    that `security` itself answered "not found"."""
    if not KEYCHAIN:
        return "unknown", "keychain_not_configured"
    kind, v = _read_account(REFRESH_ACCOUNT)
    if kind == "absent":
        # E2-02: a store interrupted after it deleted the old item holds the new one here --
        # but only a token the store VERIFIED there (r2, candidate iv); anything else is no credential
        kind, v = _read_account(PENDING_ACCOUNT)
        if kind == "present" and not pending_marker_matches(v):
            if os.path.exists(LEGACY_FLAG):
                # E-1: left by 0.6.x, which wrote no marker; accepted as 0.6.3 did, verified now
                try:
                    pending_marker_write(v)
                    log("a pending item left by an earlier version is used; its marker is written")
                except OSError as exc:
                    log("a pending item left by an earlier version is used; its marker could not "
                        "be written: %s" % type(exc).__name__)
                return kind, v
            log("a pending item exists that no store verified; it is not used as a credential")
            return "absent", None
    return kind, v


def legacy_flag_clear():
    """E-1: the FIRST act of any 0.7.0 store and of a disconnect."""
    try:
        os.unlink(LEGACY_FLAG)
    except FileNotFoundError:
        pass
    except OSError as exc:
        log("the legacy flag could not be removed: %s" % type(exc).__name__)


def _sha(token):
    return hashlib.sha256(token.encode()).hexdigest()


def pending_marker_matches(token):
    try:
        with open(PENDING_MARKER, encoding="utf-8") as fh:
            return hmac.compare_digest(fh.read().strip(), _sha(token))
    except OSError:
        return False


def pending_marker_write(token):
    """Atomic, 0600, beside the state file: written ONLY after the pending read-back matched."""
    d = os.path.dirname(PENDING_MARKER)
    os.makedirs(d, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".pending-verified.", suffix=".tmp", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(_sha(token))
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, PENDING_MARKER)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def pending_marker_clear():
    try:
        os.unlink(PENDING_MARKER)
    except FileNotFoundError:
        pass
    except OSError as exc:
        log("the pending marker could not be removed: %s" % type(exc).__name__)


def _read_account(account):
    r = _sec(["find-generic-password", "-a", account, "-s", KEYCHAIN_SERVICE, "-w"])
    if r is None:
        return "unknown", ("keychain_locked" if keychain_state() == "locked"
                           else "keychain_busy_or_unreadable")
    if r.returncode == SEC_NOT_FOUND:
        return "absent", None
    if r.returncode != 0:
        return "unknown", "keychain_rc_%d" % r.returncode
    v = r.stdout.strip()
    if not v or v == "mock-refresh-PLACEHOLDER":
        return "absent", None
    return "present", v


def refresh_token_get():
    kind, v = refresh_token_read()
    return v if kind == "present" else None


def refresh_token_set(value):
    """Store the refresh token WITHOUT it ever appearing in an argv (0.4.0).

    Until 0.4.0 this ran `security add-generic-password ... -w <token>`, so the refresh token
    sat in a process argument list, readable by any process of the same user with `ps` for as
    long as `security` ran. Found when the tap began recording child argv (Reviewer F-3 asked
    the same of the keychain PASSWORD). The command now goes to `security -i` on STDIN; the
    item still trusts /usr/bin/security (-T), which is how it is read back. `security -i` can
    exit 0 even when the command inside fails, so success is judged by READING THE TOKEN BACK.
    A value that could break the stdin command line (quote, whitespace) is refused, not
    escaped: Google's refresh tokens contain neither.
    """
    if not value or any(c in value for c in "\"' \t\r\n\\"):
        log("refresh token refused: it contains a character the keychain command cannot carry")
        return False
    # E2-02 (Reviewer 11:10: no `-U`, which raised a SecurityAgent dialog on 2026-10-04 20:45).
    # Before 1.0 the old item was deleted FIRST, so a failed or abandoned add lost the working
    # credential. Now: the new token goes to a PENDING item and is read back; only then is the
    # old item deleted and the final one written and read back; then the pending item goes.
    # Only add and delete are used -- the operations 0.5.0 ran in every KIT6 run with no prompt.
    # 1.1.0 (C-5): every step of the store may meet a locked LOGIN keychain (_STORE.active).
    # One store at a time, and never beside a late-store cleanup (CR3-1).
    with _STORE_MUTEX:
        legacy_flag_clear()                 # E-1: before the first `security` call of this store
        _STORE.active = True
        try:
            return _store(value)
        finally:
            _STORE.active = False


_STORE_MUTEX = threading.Lock()
ORPHAN_WAIT_S = 600.0       # CR3-1: how long a late-store cleanup waits for a readable keychain


def _abandoned_proc():
    p = _SEC_ABANDONED["p"]
    return p if p is not None and p.poll() is None else None


def _after_abandoned_store(p, value):
    """CR3-1 (code review 03 r1): a store step was ABANDONED at its bound (a prompt left up) and may
    still complete late. The flow has already been reported failed, so a late write must not leave a
    working credential behind it. This thread WAITS for that `security` to end by itself -- no signal
    of any kind (C1-C3, DIAG-1) -- then, once the keychain is readable, removes the pending item if
    it holds THIS store's token, and makes the persisted state match what the keychain now holds."""
    def run():
        p.wait()
        end = time.time() + ORPHAN_WAIT_S
        while time.time() < end and not _keychain_readable():
            time.sleep(0.5)
        if not _keychain_readable():
            log("late store: the keychain stayed locked; the pending item was not checked")
            return
        restored = False
        with _STORE_MUTEX:
            if _read_account(PENDING_ACCOUNT) == ("present", value):
                verified = pending_marker_matches(value)
                final_is_new = _read_account(REFRESH_ACCOUNT) == ("present", value)
                if not verified or final_is_new:
                    # an orphan (never verified), or a store whose final add completed late: the
                    # pending item is not needed either way
                    r = _sec(["delete-generic-password", "-a", PENDING_ACCOUNT, "-s",
                              KEYCHAIN_SERVICE])
                    gone = r is not None and r.returncode in (0, SEC_NOT_FOUND)
                    if gone:
                        pending_marker_clear()
                    log("late store: the abandoned write completed after the flow failed; its "
                        "pending item (%s) was %s" % ("verified" if verified else "never verified",
                                                      "removed" if gone else "NOT removed"))
            kind, v = refresh_token_read()
            with LOCK:
                if kind == "absent":
                    STATE["google_access"] = "not_connected"
                    STATE["local_credential"] = "absent"
                    STATE["connection_id"] = None
                    STATE["verification"] = None
                elif kind == "present" and v == value:
                    # CR3-16: the NEW grant is the credential in force (its final item was written
                    # late, or the verified pending item holds it). Published like
                    # reconcile_from_keychain: a connection exists, unverified until re-verified.
                    STATE["local_credential"] = "present"
                    STATE["provider_authorization"] = "granted"
                    STATE["connection_id"] = _b64u(os.urandom(9))
                    STATE["google_access"] = "verified"
                    STATE["verification"] = None
                    restored = True
            if kind in ("absent", "present"):
                state_save()
            log("late store: settled (%s%s)" % (kind, ", the new connection is in force"
                                                if restored else ""))
        if restored and CONFIGURED:
            reverify_after_restart()
    threading.Thread(target=run, daemon=True).start()


def _store(value):
    def add(account):
        return _sec_stdin('add-generic-password -a %s -s %s -T /usr/bin/security '
                          '-w "%s" "%s"' % (account, KEYCHAIN_SERVICE, value, KEYCHAIN))

    def delete(account):
        r = _sec(["delete-generic-password", "-a", account, "-s", KEYCHAIN_SERVICE])
        return r is not None and r.returncode in (0, SEC_NOT_FOUND)

    def failed():
        p = _abandoned_proc()
        if p is not None:                               # CR3-1: it may still write, late
            _after_abandoned_store(p, value)
        return False

    if not delete(PENDING_ACCOUNT):                     # a stale pending item from before
        return failed()
    if add(PENDING_ACCOUNT) is None or _read_account(PENDING_ACCOUNT) != ("present", value):
        log("refresh token store: the new token could not be verified; the old one is intact")
        delete(PENDING_ACCOUNT)
        return failed()
    try:
        pending_marker_write(value)                      # r2 (iv): this pending item is VERIFIED
    except OSError as exc:                               # FLAG-1: fail the flow, never hang it
        log("refresh token store: the pending marker could not be written (%s); the old token is "
            "intact" % type(exc).__name__)
        delete(PENDING_ACCOUNT)
        return failed()
    if not delete(REFRESH_ACCOUNT):
        log("refresh token store: the old item could not be removed; the new token stays pending")
        return failed()
    if add(REFRESH_ACCOUNT) is None or _read_account(REFRESH_ACCOUNT) != ("present", value):
        log("refresh token store: the final item could not be verified; the new token is read "
            "from the pending item")
        ok = refresh_token_read() == ("present", value)
        if not ok:
            failed()                                     # CR3-16: the final add may land late
        return ok
    if delete(PENDING_ACCOUNT):
        pending_marker_clear()
    return True


def refresh_token_clear():
    """True only when the item is GONE: deleted now, or `security` says it was not there.
    FLAG-4 / E-1: the pending marker and the legacy flag go too."""
    legacy_flag_clear()
    pending_marker_clear()
    ok = True
    for account in (REFRESH_ACCOUNT, PENDING_ACCOUNT):
        r = _sec(["delete-generic-password", "-a", account, "-s", KEYCHAIN_SERVICE])
        ok = ok and r is not None and r.returncode in (0, SEC_NOT_FOUND)
    return ok


# ------------------------------------------------------------------ persistence
_SAVE_LOCK = threading.Lock()


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


def state_save():
    """E2-04: one save at a time, a snapshot taken under LOCK, written to a unique temporary
    file and renamed into place. Before 1.0 several threads truncated and rewrote the file in
    place, so two saves could leave JSON plus a tail, and a crash an empty file."""
    d = os.path.dirname(os.path.abspath(STATE_PATH))
    os.makedirs(d, mode=0o700, exist_ok=True)
    with LOCK:
        snap = {k: STATE[k] for k in PERSISTED}
    with _SAVE_LOCK:
        fd, tmp = tempfile.mkstemp(prefix=".helper-state.", suffix=".tmp", dir=d)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(snap, fh)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, STATE_PATH)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise


def state_load():
    if not os.path.exists(STATE_PATH):
        return
    try:
        d = json.load(open(STATE_PATH, encoding="utf-8"))
    except Exception:
        log("state file unreadable; starting not_connected")
        return
    for k in PERSISTED:
        if k in d:
            STATE[k] = d[k]
    # The persisted state is a CLAIM. The keychain is the fact: if the secret is gone, the
    # claim is corrected rather than trusted, so a restart can never report a credential
    # that is not there.
    # Only a keychain that could be READ may correct the claim: a locked one says nothing about
    # whether the secret is there, and "absent" would be a false negative (ruling G5).
    if STATE["local_credential"] == "present" and _keychain_readable() \
            and refresh_token_read()[0] == "absent":
        log("persisted state claimed a credential that the keychain does not hold; corrected")
        STATE["local_credential"] = "absent"
        STATE["google_access"] = "not_connected"
        STATE["connection_id"] = None
        STATE["verification"] = None


def _keychain_readable():
    return bool(KEYCHAIN_PW) or keychain_state() == "unlocked"


def record_verification(ok, prop, err=None):
    """Set google_access from a verification JUST MADE, and record whose it was (V6-5).
    PLAN-05 WP-H6: the failure's error word is kept IN MEMORY for google_access_reason (this run
    only; never persisted, never published as such)."""
    with LOCK:
        STATE["google_access"] = "verified" if ok else "not_verified"
        STATE["property"] = prop
        STATE["verification"] = {"connection_id": STATE["connection_id"], "run_id": RUN_ID,
                                 "at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "ok": bool(ok)}
        _LAST_VERIFY_ERR["err"] = None if ok else (err if isinstance(err, str) else "unknown")


# PLAN-05 WP-H6: google_access_reason, from the error words this helper already returns
# (access_token / _get_summaries / verify_google_access). F-5: anything unclassified is "unknown".
ADMIN_POLICY = "admin_policy_enforced"
_LAST_VERIFY_ERR = {"err": None}


def access_reason(err):
    """"revoked_or_unrenewable" | "transient" | "unknown" | None for one error word.
      invalid_grant                                   -> revoked_or_unrenewable
      unreachable / unreachable_*, http_5xx, http_429,
      a timeout                                       -> transient
      no_credential                                   -> None (not connected)
      anything else (http_403, refresh_malformed ...) -> unknown
    A failure naming admin_policy_enforced is NEVER transient."""
    if err is None or err == "no_credential":
        return None
    if not isinstance(err, str):
        return "unknown"
    low = err.lower()
    if ADMIN_POLICY in low:
        return "unknown"
    if low == "invalid_grant":
        return "revoked_or_unrenewable"
    if (low == "unreachable" or low.startswith("unreachable_") or low == "http_429"
            or re.fullmatch(r"http_5\d\d", low) or "timeout" in low or "timedout" in low):
        return "transient"
    return "unknown"


def google_access_reason(access=None):
    """WP-H6 for /status and /verify: the reason of THIS run's latest failed verification, while the
    published access says it failed ("not_verified"); None otherwise."""
    access = published_access() if access is None else access
    if access != "not_verified":
        return None
    with LOCK:
        v = STATE.get("verification") or {}
        err = _LAST_VERIFY_ERR["err"]
    if v.get("run_id") != RUN_ID or v.get("ok"):
        return None
    return access_reason(err)


def published_access():
    """What /status may SAY about Google access, as opposed to what was last stored.

    V6-5: "stale success cannot imply current health". A stored "verified" is published only
    if the verification record names the CURRENT connection and the CURRENT run. Otherwise
    the honest word is "unverified": a connection exists, and nothing in this run has checked
    it. Two ways a stale success used to leak, both measured by the custody suite:
      * a RECONNECT -- between the new code exchange and the new verification, the old
        connection's "verified" was still on display for the new one;
      * a RESTART -- the persisted "verified" was read back from disk and shown as current
        although no call had been made by this process.
    """
    if not _keychain_readable() and KEYCHAIN:
        return "keychain_locked" if keychain_state() == "locked" else "keychain_unavailable"
    with LOCK:
        g = STATE["google_access"]
        v = STATE["verification"] or {}
        if g == "verified" and not (v.get("connection_id") == STATE["connection_id"]
                                    and v.get("run_id") == RUN_ID and v.get("ok")):
            return "unverified"
        return g


def claude_row():
    """Read-only from the launcher's status file. Moves only on a real report call.

    "Google access verified" must leave this UNVERIFIED (clarification 7): proving Google
    authorization says nothing about whether Claude ever called us.
    """
    if not LAUNCHER_STATUS or not os.path.exists(LAUNCHER_STATUS):
        return {"last_report_at": None, "last_tool": None, "verified": False}
    try:
        doc = json.load(open(LAUNCHER_STATUS))
        evs = doc.get("events", []) if isinstance(doc, dict) else []
    except Exception:
        return {"last_report_at": None, "last_tool": None, "verified": False}
    # 0.6.3 v2 (F2, found by its test): a wrong-shape record must never fail /status
    reports = [e for e in (evs if isinstance(evs, list) else [])
               if isinstance(e, dict) and e.get("kind") == "report"]
    if not reports:
        return {"last_report_at": None, "last_tool": None, "verified": False}
    last = reports[-1]
    return {"last_report_at": last.get("at"), "last_tool": last.get("tool"), "verified": True}


# plan-04 WP-6 (Q-R9, separate proofs): four distinct states in /status. Each new field carries
# only booleans, timestamps and tool names -- never a token, a code, a query or response contents.
def _launcher_events():
    """The launcher's recorded events, read-only; any shape problem reads as no events."""
    if not LAUNCHER_STATUS or not os.path.exists(LAUNCHER_STATUS):
        return []
    try:
        doc = json.load(open(LAUNCHER_STATUS, encoding="utf-8"))
        evs = doc.get("events", []) if isinstance(doc, dict) else []
    except Exception:
        return []
    return [e for e in (evs if isinstance(evs, list) else []) if isinstance(e, dict)]


def _event_time(at):
    try:
        return datetime.strptime(at, "%Y-%m-%dT%H:%M:%S%z")
    except (TypeError, ValueError):
        return None


def _str_or_none(v):
    return v if isinstance(v, str) else None


def google_authorized():
    """WP-6: the current connection's flow completed (a connection id exists and the provider
    granted it) and a credential is present. Says nothing about verification or Claude."""
    with LOCK:
        return bool(STATE["connection_id"] and STATE["local_credential"] == "present"
                    and STATE["provider_authorization"] == "granted")


def claude_tool_used(evs):
    """WP-6: {at, tool, ok} of the launcher's most recent "call" event made while THIS helper run
    was the helper (the launcher stamps `helper_run_id` from our /health). Failed calls count."""
    for e in reversed(evs):
        if e.get("kind") == "call" and e.get("helper_run_id") == RUN_ID:
            return {"at": _str_or_none(e.get("at")), "tool": _str_or_none(e.get("tool")),
                    "ok": e.get("ok") is True}
    return None


def answer_success(evs, access):
    """WP-6: {at, tool} of the most recent non-failed REPORT call later than the CURRENT
    verification's `at`, that verification made in this run -- the site's claudeProven guard
    (Google verified now, verification.run_id == run_id, report time > verification time)."""
    if access != "verified":
        return None
    with LOCK:
        v = dict(STATE["verification"] or {})
    if v.get("run_id") != RUN_ID or not v.get("ok"):
        return None
    vat = _event_time(v.get("at"))
    if vat is None:
        return None
    for e in reversed(evs):
        if e.get("kind") != "report" or e.get("ok") is False:
            continue
        at = _event_time(e.get("at"))
        if at is not None and at > vat:
            return {"at": e.get("at"), "tool": _str_or_none(e.get("tool"))}
    return None


# ------------------------------------------------------------------ PLAN-05 WP-H1: "Ready in Claude"
# claude_loaded.ok is true only if SOME launcher session that is ALIVE NOW (its pid exists and its
# `ps -o lstart=` start time equals the one it recorded -- the launcher's own owner_state rule) has
# (1) delivered a successful result to the client's `initialize`, (2) seen
# `notifications/initialized`, and (3) delivered a `tools/list` result naming all nine GA4 tools (its
# LATEST tools/list event says tools_ok). A request alone, an old success or a dead session never counts.
LIFECYCLE_KINDS = ("mcp_initialize_ok", "mcp_initialized", "mcp_tools_list")
ALIVE_CACHE_S = 2.0
_ALIVE = {}                        # (pid, start) -> (alive, checked_at); a DEAD process stays dead
_ALIVE_LOCK = threading.Lock()


def proc_start(pid):
    """The launcher's rule, same three answers: None (could not find out), "" (the pid is gone),
    or its start time as `ps -o lstart=` prints it."""
    try:
        r = subprocess.run(["/bin/ps", "-p", str(int(pid)), "-o", "lstart="],
                           capture_output=True, text=True, timeout=5)
    except Exception:
        return None
    if r.returncode != 0:
        return ""
    return r.stdout.strip()


def process_alive(pid, start):
    """True | False | None (unknown) for the process (pid, recorded start time)."""
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0 or not isinstance(start, str) \
            or not start:
        return False
    key = (pid, start)
    now = time.time()
    with _ALIVE_LOCK:
        hit = _ALIVE.get(key)
        if hit is not None and (hit[0] is False or now - hit[1] < ALIVE_CACHE_S):
            return hit[0]
    st = proc_start(pid)
    if st is None:
        return None
    alive = st == start
    with _ALIVE_LOCK:
        if len(_ALIVE) > 512:
            _ALIVE.clear()
        _ALIVE[key] = (alive, now)
    return alive


def claude_loaded(evs=None):
    """WP-H1: {"ok": bool, "at": str|None}. `at` is the time the qualifying session completed its
    last step (the latest of its three events); with several, the most recent."""
    evs = _launcher_events() if evs is None else evs
    sessions = {}
    for e in evs:
        kind = e.get("kind")
        sid = e.get("launcher_session")
        if kind not in LIFECYCLE_KINDS or not isinstance(sid, str) or not sid:
            continue
        s = sessions.setdefault(sid, {"pid": e.get("pid"), "pid_start": e.get("pid_start"),
                                      "steps": {}, "consistent": True})
        if (e.get("pid"), e.get("pid_start")) != (s["pid"], s["pid_start"]):
            s["consistent"] = False          # one session id, two processes: never counted
        s["steps"][kind] = e                 # the LATEST event of each kind
    best = None
    for s in sessions.values():
        steps = s["steps"]
        if not s["consistent"] or any(k not in steps for k in LIFECYCLE_KINDS):
            continue
        if steps["mcp_tools_list"].get("tools_ok") is not True:
            continue
        times = [_event_time(steps[k].get("at")) for k in LIFECYCLE_KINDS]
        if any(t is None for t in times):
            continue
        done = max(range(3), key=lambda i: times[i])
        cand = (times[done], steps[LIFECYCLE_KINDS[done]].get("at"), s)
        if best is not None and best[0] >= cand[0]:
            continue
        if process_alive(s["pid"], s["pid_start"]) is True:
            best = cand
    if best is None:
        return {"ok": False, "at": None}
    return {"ok": True, "at": best[1]}


def property_present(access):
    """WP-H1 / UX-7: THIS run's verification found the build's allowed property."""
    if access != "verified":
        return False
    with LOCK:
        prop = STATE.get("property")
        v = STATE.get("verification") or {}
    return bool(isinstance(prop, dict) and str(prop.get("id")) in SHOWN_PROPERTIES
                and v.get("run_id") == RUN_ID and v.get("ok"))


# ------------------------------------------------------------------ provider calls

def tls_context():
    """0.6.1 (O8 live defect, 2026-10-05 12:45): the extension's interpreter can be a python.org
    build whose OpenSSL has NO CA bundle (its `etc/openssl/cert.pem` absent until "Install
    Certificates" is run), so stdlib TLS to Google failed with CERTIFICATE_VERIFY_FAILED and the
    code exchange was reported as "unreachable". The pinned `certifi` bundle (requirements.txt)
    is used; the stdlib default only if certifi is missing."""
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where()), "certifi"
    except Exception:
        return ssl.create_default_context(), "stdlib-default"


TLS, TLS_SOURCE = tls_context()


def _post_form(url, form):
    body = urllib.parse.urlencode(form).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15, context=TLS) as f:
            return f.status, f.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:
        why = _why(e)
        log("outbound POST %s failed before any answer: %s" % (urllib.parse.urlsplit(url).netloc, why))
        return 0, json.dumps({"error": "unreachable", "detail": why})


def _why(e):
    """The exception TYPE (and an SSL/URL reason's type) for the "unreachable" detail -- never a
    URL query, a header or a body, so no secret can reach the log."""
    r = getattr(e, "reason", None)
    return type(e).__name__ + (":" + type(r).__name__ if r is not None else "") + (
        ":" + getattr(r, "reason", "") if getattr(r, "reason", None) else "")


def access_token(force=False):
    """A valid access token, refreshing if needed. Never persisted.

    `force` skips the cache. It exists because our own expiry clock is NOT authoritative:
    the provider can invalidate a token before we think it expires -- clock skew, or a
    server-side revocation. Measured by V6-1, which failed on exactly that: the cached token
    looked fresh to us, the provider rejected it, and the helper reported "not verified"
    instead of refreshing. v1.1's V6 requires expiry to trigger a refresh, so trusting only
    our own clock was a defect, not a simplification.
    """
    if not force:
        with LOCK:
            if _MEM["access_token"] and _MEM["expires_at"] > time.time() + 30:
                return _MEM["access_token"], None
    kind, rt = refresh_token_read()
    if kind == "unknown":
        return None, rt                     # E2-01: unreadable is not "no credential"
    if kind == "absent":
        return None, "no_credential"
    s, b = _post_form(TOKEN_URI,
                      {"grant_type": "refresh_token", "refresh_token": rt,
                       "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET})
    if s != 200:
        try:
            err = json.loads(b).get("error", "refresh_failed")
        except Exception:
            err = "refresh_failed"
        if not isinstance(err, str):
            err = "refresh_failed"
        # PLAN-05 WP-H6: a 5xx or 429 from the token endpoint is reported as "http_<code>" (a
        # temporary failure, like the same answer from the Admin API), whatever word its body
        # carries -- except admin_policy_enforced, which is a policy and never temporary.
        if (s >= 500 or s == 429) and err != ADMIN_POLICY:
            err = "http_%d" % s
        log("refresh failed: %s %s" % (s, err))
        return None, err
    try:
        d = json.loads(b)
    except Exception:
        return None, "refresh_malformed"
    with LOCK:
        _MEM["access_token"] = d.get("access_token")
        _MEM["expires_at"] = time.time() + float(d.get("expires_in") or 0)
    # The REAL access-token lifetime, as the provider states it (the value only, never the
    # token): the real run reads it from the helper log to discharge "real token lifetimes".
    log("token response: expires_in=%s" % d.get("expires_in"))
    return _MEM["access_token"], None


def _get_summaries(tok):
    req = urllib.request.Request(ADMIN_BASE + "/v1beta/accountSummaries",
                                 headers={"Authorization": "Bearer " + tok})
    try:
        with urllib.request.urlopen(req, timeout=15, context=TLS) as f:
            return f.status, f.read().decode(), None
    except urllib.error.HTTPError as e:
        return e.code, "", "http_%d" % e.code
    except Exception as e:
        log("outbound GET accountSummaries failed before any answer: %s" % _why(e))
        return 0, "", "unreachable_%s" % type(e).__name__


def verify_google_access():
    """The MINIMAL verification call (S5-4): accountSummaries, no arguments.

    It is the only GA4 surface that proves authorization without naming a property and
    without returning report content. No report tool is invoked here.

    A 401 is retried ONCE with a forced refresh, and once only: the provider's view of
    expiry beats ours, but a loop of refresh-and-retry against a genuinely revoked
    credential would be the "needless reauthorization" v1.1's V6 forbids.
    """
    tok, err = access_token()
    if not tok:
        return False, err, None
    status, body, err = _get_summaries(tok)
    if status == 401:
        log("provider rejected a token we believed valid; refreshing once and retrying")
        with LOCK:
            _MEM["access_token"] = None
            _MEM["expires_at"] = 0.0
        tok, err2 = access_token(force=True)
        if not tok:
            return False, err2 or "refresh_failed", None
        status, body, err = _get_summaries(tok)
    if err:
        return False, err, None
    if status != 200:
        return False, "http_%d" % status, None
    try:
        d = json.loads(body)
    except Exception:
        return False, "malformed_response", None
    # Minimal identifying metadata only: the property id and name. No report content.
    # Step 3 (b): the ALLOWED property, wherever it is in the list; none -> no property.
    prop = None
    for acc in d.get("accountSummaries", []):
        for ps in acc.get("propertySummaries", []):
            pid = (ps.get("property") or "").split("/")[-1]
            if pid in SHOWN_PROPERTIES:
                prop = {"id": pid, "name": ps.get("displayName")}
                break
        if prop:
            break
    return True, None, prop


# ------------------------------------------------------------------ the OAuth callback (PLAN-05 WP-H2)
# Until helper 1.1.0 every flow had its own EPHEMERAL loopback listener (and a superseded flow a
# lingering one), so a helper restarted mid-consent could not answer the browser's re-sent redirect
# at all (CH-3). From 1.2.0 the redirect URI is the MAIN server, http://127.0.0.1:<its port>/callback.
#   * /callback is routed BEFORE the Origin check: a navigation from Google carries no Origin (CH-9).
#   * EVERY outcome answers 303 to the flow's <return_to>#return=<flow_id> (the site's page when no
#     valid return_to came); never a page of ours, never a browser error from us. A second hit
#     answers the same 303 (idempotent). No match (unknown or expired) -> 303 to the site's page
#     + "#return", with no id.
#   * A redirect is matched to its flow ONLY by sha256(state). The PKCE verifier and the raw state
#     stay in memory, exactly as before (E2-05). What survives a restart is the NON-SECRET pending-flow
#     record {flow_id, state_sha256, return_to, origin, started_at} in the state directory (0600),
#     kept until it is matched or CALLBACK_WAIT_S passes; a redirect matched to it by a restarted
#     helper (the verifier is gone, so no exchange) publishes last_flow "interrupted".
# HLP-1 (the 2026-10-06 hang of a single-threaded callback listener) cannot recur: the main server is
# threaded, every 303 closes its connection, and the handler has a socket timeout.
# 1.1.0 (N-13): how long a flow waits for Google's redirect (the site's own timeout is this plus 15 s).
CALLBACK_WAIT_S = 600
# 1.1.0 (C-5, lead decision B): a redirect that carries a valid code waits for the flow's outcome
# (exchange + store, which can wait LOGIN_UNLOCK_BOUND on macOS's unlock prompt) before the 303, so the
# page that loads already finds the flow's outcome in /status.
# CR3-6: the exchange (15 s, _post_form) + LOGIN_UNLOCK_BOUND + a margin of SIX further keychain
# steps of the store at SEC_BOUND each (delete, add, read-back, delete, add, read-back).
CALLBACK_RESULT_WAIT_S = 15 + LOGIN_UNLOCK_BOUND + 6 * SEC_BOUND
# The site deploys as the GitHub Pages site of the repo grabmcp/connect, at the path /connect/ of the
# first built-in origin (no literal origin is written here: the qa build's no-release-value scan reads
# comments too). Used only when a flow has no valid return_to, and for a redirect that matches nothing.
CALLBACK_DEFAULT_RETURN = DEFAULT_ORIGINS[0] + "/connect/#return"
RETURN_FRAGMENT = "return"
# plan-04 WP-1's opt-in {"return_mode": "redirect"} is still accepted; since 1.2.0 every flow answers
# 303 whatever the mode.
RETURN_MODE_REDIRECT = "redirect"
FLOW_KEEP_S = CALLBACK_WAIT_S   # a matched flow keeps answering the same 303 this long after its match
PENDING_FLOWS_PATH = os.path.join(os.path.dirname(os.path.abspath(STATE_PATH)), "pending-flows.json")
PENDING_RECORD_KEYS = ("flow_id", "state_sha256", "return_to", "origin", "started_at")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_FLOW_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
# state_sha256 -> the flow. Memory only; a flow holds no verifier and no raw state (_PENDING does).
_FLOWS = {}
_FLOWS_FILE_LOCK = threading.Lock()


def valid_return_to(value, origin):
    """1.1.0 (N-2): `return_to` is kept only if it is an absolute http(s) URL whose origin IS the
    request's admitted Origin. Anything else is ignored (None), never an error.
    Step 3 (I3/I4): the ONLY fragment allowed is "#return" (the site's `<origin><path>#return`);
    any other fragment, an empty one ("...#"), or a second "#" is refused."""
    if not isinstance(value, str) or not origin or len(value) > 2048 or not value.isascii():
        return None
    if any(c in value for c in "\\\"'<> \t\r\n") or any(ord(c) < 0x20 or ord(c) == 0x7f
                                                       for c in value):
        return None
    try:
        u = urllib.parse.urlsplit(value)
        _port = u.port                    # a malformed port raises here
    except ValueError:
        return None
    if u.scheme not in ("http", "https") or not u.netloc or "@" in u.netloc:
        return None
    if "%s://%s" % (u.scheme, u.netloc) != origin:
        return None
    if "#" in value and (value.count("#") != 1 or u.fragment != RETURN_FRAGMENT):
        return None
    return value


def redirect_location(return_to, flow_id):
    """The 303's Location: the flow's STORED, validated return_to with its fragment replaced by
    "#return=<flow_id>" (flow_id is not secret). Nothing from any request; no code, no token."""
    if not return_to or not flow_id:
        return None
    return return_to.split("#", 1)[0] + "#" + RETURN_FRAGMENT + "=" + flow_id


def flow_location(return_to, flow_id):
    """WP-H2: every outcome's Location -- the flow's return_to, else the site's page."""
    return redirect_location(return_to or CALLBACK_DEFAULT_RETURN, flow_id)


def state_sha256(state):
    return hashlib.sha256(state.encode("utf-8")).hexdigest()


def _now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def _iso_epoch(at):
    t = _event_time(at)
    return t.timestamp() if t is not None else None


def _new_flow(flow_id, sha, return_to, origin, tab, started_at=None, status="pending"):
    now = time.time()
    t0 = _iso_epoch(started_at) if started_at else now
    return {"flow_id": flow_id, "state_sha256": sha, "return_to": return_to, "origin": origin,
            "started_at": started_at or _now_iso(), "t0": t0, "tab": tab,
            # pending | matched (exchange running) | ended | superseded | interrupted (restored)
            "status": status, "result": None, "arrived": threading.Event(),
            "cancel": threading.Event(), "done": threading.Event(),
            "keep_until": t0 + CALLBACK_WAIT_S, "location": flow_location(return_to, flow_id),
            "claude": None}


def _prune_flows_locked():
    """Called under LOCK: a flow that is no longer running is forgotten after its keep time."""
    now = time.time()
    for h in [h for h, f in _FLOWS.items()
              if f["status"] not in ("pending", "matched") and f["keep_until"] < now]:
        del _FLOWS[h]


# ---- the non-secret pending-flow record (CH-3), one file in the state directory
def read_pending_records():
    """The unexpired, well-formed records. Anything else in the file is ignored."""
    try:
        with open(PENDING_FLOWS_PATH, encoding="utf-8") as fh:
            doc = json.load(fh)
    except FileNotFoundError:
        return []
    except Exception:
        log("the pending-flow record is unreadable; it is ignored")
        return []
    recs = doc.get("flows") if isinstance(doc, dict) else None
    out, now = [], time.time()
    for r in recs if isinstance(recs, list) else []:
        if not isinstance(r, dict) or set(r) != set(PENDING_RECORD_KEYS):
            continue
        if not (isinstance(r["flow_id"], str) and _FLOW_ID_RE.fullmatch(r["flow_id"])
                and isinstance(r["state_sha256"], str) and _SHA256_RE.fullmatch(r["state_sha256"])
                and (r["return_to"] is None or isinstance(r["return_to"], str))
                and (r["origin"] is None or r["origin"] in ALLOWED_ORIGINS)):
            continue
        t = _iso_epoch(r["started_at"])
        if t is None or now - t > CALLBACK_WAIT_S or t - now > 60:
            continue
        if r["return_to"] is not None and valid_return_to(r["return_to"], r["origin"]) is None:
            continue
        out.append(r)
    return out


def _write_pending_records(recs):
    d = os.path.dirname(PENDING_FLOWS_PATH)
    os.makedirs(d, mode=0o700, exist_ok=True)
    if not recs:
        try:
            os.unlink(PENDING_FLOWS_PATH)
        except FileNotFoundError:
            pass
        return
    fd, tmp = tempfile.mkstemp(prefix=".pending-flows.", suffix=".tmp", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump({"flows": recs}, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, PENDING_FLOWS_PATH)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def pending_record_add(flow):
    """Written BEFORE the authorization URL leaves, so a restart from then on can still answer."""
    rec = {k: flow[k] for k in PENDING_RECORD_KEYS}
    with _FLOWS_FILE_LOCK:
        recs = [r for r in read_pending_records() if r["flow_id"] != rec["flow_id"]]
        try:
            _write_pending_records(recs + [rec])
        except OSError as exc:
            log("the pending-flow record could not be written: %s" % type(exc).__name__)


def pending_record_remove(flow_id):
    """The flow ended (or was matched after a restart): its record goes; expired ones go too."""
    with _FLOWS_FILE_LOCK:
        recs = read_pending_records()
        keep = [r for r in recs if r["flow_id"] != flow_id]
        if keep == recs and (keep or not os.path.exists(PENDING_FLOWS_PATH)):
            return
        try:
            _write_pending_records(keep)
        except OSError as exc:
            log("the pending-flow record could not be updated: %s" % type(exc).__name__)


def restore_pending_flows():
    """At start: every unexpired record becomes an "interrupted" flow in memory, so a redirect the
    browser re-sends to this run is still matched (by sha256(state)) and answered with its own 303.
    Returns the records (the newest last)."""
    recs = sorted(read_pending_records(), key=lambda r: _iso_epoch(r["started_at"]) or 0)
    with LOCK:
        for r in recs:
            _FLOWS[r["state_sha256"]] = _new_flow(r["flow_id"], r["state_sha256"], r["return_to"],
                                                  r["origin"], None, started_at=r["started_at"],
                                                  status="interrupted")
    return recs


def publish_interrupted(flow_id, cause=None):
    """last_flow = {id, outcome "interrupted", detail null[, cause]} -- unless a NEWER flow of this run
    is already the latest attempt."""
    with LOCK:
        cur = STATE.get("last_flow") or {}
        if cur.get("id") not in (None, flow_id):
            return False
        lf = {"id": flow_id, "outcome": "interrupted", "detail": None}
        if cause:
            lf["cause"] = cause
        elif cur.get("id") == flow_id and cur.get("cause"):
            lf["cause"] = cur["cause"]
        STATE["last_flow"] = lf
    return True


def _match_interrupted(flow):
    """A re-sent redirect matched a restored record: the record goes, the flow is published as
    interrupted (the code is NOT exchanged: the verifier died with the previous run)."""
    first = False
    with LOCK:
        if not flow.get("matched_once"):
            flow["matched_once"] = first = True
            flow["keep_until"] = max(flow["keep_until"], time.time() + FLOW_KEEP_S)
    if first:
        pending_record_remove(flow["flow_id"])
        publish_interrupted(flow["flow_id"])
        open_handoff(flow.get("origin"))
        log("a redirect for a flow of a previous run arrived; answered, nothing exchanged")


def _complete_flow(flow, state_key, timeout=None):
    """Wait for this flow's redirect (or its supersession, or its deadline), then exchange the code.
    Returns (ok, detail)."""
    if timeout is None:
        timeout = CALLBACK_WAIT_S          # 1.1.0 (N-13): read at call time, never captured
    end = flow["t0"] + timeout
    q = pending = None
    try:
        flow["arrived"].wait(max(0.0, end - time.time()))
    finally:
        # E2-05: the verifier never outlives its flow, whatever the outcome
        with LOCK:
            pending = _PENDING.pop(state_key, None)
            q = flow["result"]
            if q is None and flow["status"] == "pending":
                flow["status"] = "superseded" if flow["cancel"].is_set() else "ended"
            # FX-4 (CR5-1): a flow whose redirect ARRIVED stays the active flow, and keeps its
            # pending record, until _run_flow has published its outcome -- the exchange and the
            # keychain store can take CALLBACK_RESULT_WAIT_S, and a SIGTERM in that window must
            # still leave the shutdown record, and a reopened helper must still match the re-sent
            # redirect. Only a flow that got NO redirect is released here.
            if q is None and _ACTIVE_FLOW.get("flow") is flow:
                _ACTIVE_FLOW.clear()
        if q is None:
            pending_record_remove(flow["flow_id"])
    if q is None and flow["cancel"].is_set():
        return False, "superseded"
    if q is None:
        return False, "timeout"
    # The state check happens HERE, before any exchange: a callback whose state we did not
    # issue is refused by us, not by the provider.
    if q.get("state") != state_key or pending is None:
        log("callback state mismatch; refused before any exchange")
        return False, "state_mismatch"
    if q.get("error"):
        log("user did not consent: %s" % _one_line(q.get("error")))
        return False, q.get("error")
    code = q.get("code")
    if not code:
        return False, "no_code"
    s, b = _post_form(TOKEN_URI,
                      {"grant_type": "authorization_code", "code": code,
                       "code_verifier": pending["verifier"],
                       "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET,
                       "redirect_uri": pending["redirect"]})
    if s != 200:
        try:
            err = json.loads(b).get("error_description") or json.loads(b).get("error")
        except Exception:
            err = "exchange_failed"
        log("code exchange refused: %s %s" % (s, err))
        return False, "exchange_refused"
    try:
        d = json.loads(b)
    except Exception:
        return False, "exchange_malformed"
    rt = d.get("refresh_token")
    if not rt:
        return False, "no_refresh_token"
    if not refresh_token_set(rt):
        # E2-02: the old credential (if any) is untouched by a failed update. The new grant is
        # NOT revoked here: at Google a revoke may end the user's whole grant for this client,
        # the working old token included (not measured), so it is left to expire unused.
        return False, "keychain_write_failed"
    with LOCK:
        _MEM["access_token"] = d.get("access_token")
        _MEM["expires_at"] = time.time() + float(d.get("expires_in") or 0)
        STATE["local_credential"] = "present"
        STATE["provider_authorization"] = "granted"
        STATE["connection_id"] = _b64u(os.urandom(9))
    # The REAL access-token lifetime, as the provider states it (the value only, never the
    # token): the real run reads it from the helper log to discharge "real token lifetimes".
    log("token response: expires_in=%s" % d.get("expires_in"))
    state_save()
    return True, None


def _run_flow(flow, state_key):
    """The flow's own thread: wait, exchange, publish last_flow, then verify (the old finish())."""
    flow_id = flow["flow_id"]
    ok, detail = False, "internal_error"
    try:
        ok, detail = _complete_flow(flow, state_key, CALLBACK_WAIT_S)
    finally:
        # FX-4: the outcome is published, and only THEN does a matched flow stop being the active
        # flow and lose its pending record (in one LOCK section with the publication, so a SIGTERM
        # sees either "pending + active" or "published + released", never a gap)
        with LOCK:
            if (STATE.get("last_flow") or {}).get("id") == flow_id:
                STATE["last_flow"] = {
                    "id": flow_id,
                    "outcome": "completed" if ok else (
                        "cancelled" if detail == "access_denied" else
                        "superseded" if detail == "superseded" else "failed"),
                    "detail": None if ok else detail}
            if flow["status"] == "matched":
                flow["status"] = "ended"
            if _ACTIVE_FLOW.get("flow") is flow:
                _ACTIVE_FLOW.clear()
        pending_record_remove(flow_id)
        flow["done"].set()                 # the waiting 303 goes now: /status has the outcome
    if not ok:
        # DEFECT FIXED (found by S4-6a). This used to set google_access to
        # "not_connected" unconditionally, so a user who CANCELLED a
        # RE-authorisation was told the connection was gone while the existing
        # credential was still present and working. That is a false negative that
        # invites exactly the "needless reauthorization" v1.1's V6 forbids.
        # A failed attempt must not change the standing of a connection it never
        # touched: only report not_connected when there is nothing to fall back on.
        # E2-01: only a keychain that ANSWERED "not found" may downgrade the state;
        # an unreadable one says nothing, so the standing state is kept.
        kind, _v = refresh_token_read()
        with LOCK:
            if kind == "absent":
                STATE["google_access"] = "not_connected"
                STATE["local_credential"] = "absent"
        state_save()
        log("flow did not complete: %s%s" % (
            detail,
            "; the existing credential is untouched and still in force"
            if kind == "present" else
            "; the keychain could not be read (%s), the state is unchanged" % _v
            if kind == "unknown" else ""))
        return
    ok2, err, prop = verify_google_access()
    record_verification(ok2, prop, err)
    state_save()
    log("flow complete; google_access=%s" % STATE["google_access"])


# ------------------------------------------------------------------ owner tab (PLAN-05 WP-H4, NEW-E2)
# ONE authoritative live surface. Every page sends its random per-tab id (`tab`, memory only, never
# logged). A granted request (an admitted Origin) carrying `tab` is a CLAIM:
#   * no owner, or an owner no longer live (not seen for OWNER_STALE_S and no pending sign-in)
#     -> the claimant owns; the first granted claimant owns;
#   * an owner whose sign-in is pending keeps ownership (a /connect/start from another tab -> 409)
#     WHILE IT STILL POLLS. FX-1 (UX-14): in the same-tab design the owner page navigates away to
#     Google, so a pending owner is silent; a Back press that reloads the page (no back-forward cache)
#     comes back with a NEW tab id. Once the pending owner has been silent for OWNER_STALE_S, the
#     FIRST granted claimant FROM THE FLOW'S ORIGIN takes ownership. The pending flow is NOT cancelled:
#     its redirect still lands on #return=<id> and opens the hand-off below; a /connect/start from the
#     new owner supersedes it (E2-05). Another origin, or any claimant while the owner polls: refused;
#   * a HAND-OFF: right after the helper opened the site (WP-H4) or a flow's redirect was answered,
#     the first NEW tab id from that origin takes over (the helper-opened page, or the page that came
#     back from Google with a fresh id); while a hand-off is open nobody else takes over.
TAB_RE = re.compile(r"[A-Za-z0-9_-]{8,64}")
OWNER_STALE_S = 15.0
HANDOFF_S = 120.0
_OWNER = {"tab": None, "origin": None, "seen": 0.0}
_HANDOFF = {"origin": None, "until": 0.0}
_SEEN_TABS = {}
# FX-12 (CR5-3): tab ids that RELEASED ownership (POST /release by the owner), the last RELEASED_KEEP.
# A /status the departing page sent just before its beacon may land after it; it must not make the
# departed tab the owner again, so a released id never claims.
RELEASED_KEEP = 64
_RELEASED = {}


def valid_tab(v):
    return v if isinstance(v, str) and TAB_RE.fullmatch(v) else None


def _owner_pending_locked():
    f = _ACTIVE_FLOW.get("flow")
    return bool(f is not None and _OWNER["tab"] and f.get("tab") == _OWNER["tab"]
                and f["status"] == "pending")


def _pending_takeover_locked(origin, now):
    """FX-1: the owner's sign-in is pending, the owner tab has been silent for OWNER_STALE_S, and the
    claimant comes from the origin that started that flow."""
    f = _ACTIVE_FLOW.get("flow")
    return bool(_owner_pending_locked() and now - _OWNER["seen"] >= OWNER_STALE_S
                and origin is not None and origin in ALLOWED_ORIGINS
                and f.get("origin") == origin)


def _handoff_open_locked(now):
    return bool(_HANDOFF["origin"]) and now < _HANDOFF["until"]


def owner_exists_locked(now=None):
    now = time.time() if now is None else now
    return bool(_OWNER["tab"]) and (_owner_pending_locked() or _handoff_open_locked(now)
                                    or now - _OWNER["seen"] <= OWNER_STALE_S)


def claim_owner_locked(tab, origin, start=False):
    """Called under LOCK for a granted request carrying `tab`. `start`: a /connect/start that passed
    the not_owner check -- the tab that starts a sign-in owns it."""
    if not tab or origin not in ALLOWED_ORIGINS or tab in _RELEASED:      # FX-12: never re-claims
        return
    now = time.time()
    fresh = tab not in _SEEN_TABS
    _SEEN_TABS[tab] = now
    if len(_SEEN_TABS) > 256:
        for k in sorted(_SEEN_TABS, key=_SEEN_TABS.get)[:128]:
            del _SEEN_TABS[k]
    cur = _OWNER["tab"]
    if cur == tab:
        _OWNER["seen"] = now
        return
    if cur is not None and _owner_pending_locked():
        if _pending_takeover_locked(origin, now):          # FX-1
            _OWNER.update(tab=tab, origin=origin, seen=now)
        return
    if _handoff_open_locked(now):
        take = fresh and origin == _HANDOFF["origin"]
        if take:
            _HANDOFF.update(origin=None, until=0.0)
        take = take or start
    else:
        take = start or not owner_exists_locked(now)
    if take:
        _OWNER.update(tab=tab, origin=origin, seen=now)


def owner_blocks_locked(tab, origin=None):
    """NEW-E2: another tab owns, with its sign-in pending -- unless FX-1's takeover applies to this
    claimant (the owner silent for OWNER_STALE_S, the claimant from the flow's origin)."""
    return (bool(_OWNER["tab"]) and _OWNER["tab"] != tab and _owner_pending_locked()
            and not _pending_takeover_locked(origin, time.time()))


def release_owner_locked(tab):
    """FX-3: the owner tab gives up ownership at once (its page is going away). The hand-off and any
    pending flow are left as they are. True if `tab` was the owner."""
    if not tab or _OWNER["tab"] != tab:
        return False
    _OWNER.update(tab=None, origin=None, seen=0.0)
    _RELEASED[tab] = time.time()                          # FX-12
    while len(_RELEASED) > RELEASED_KEEP:
        del _RELEASED[min(_RELEASED, key=_RELEASED.get)]
    return True


def owner_view_locked(tab):
    return {"exists": owner_exists_locked(), "is_you": bool(tab) and _OWNER["tab"] == tab}


def open_handoff(origin):
    """The next NEW tab id from `origin` takes ownership (within HANDOFF_S)."""
    if origin in ALLOWED_ORIGINS:
        with LOCK:
            _HANDOFF.update(origin=origin, until=time.time() + HANDOFF_S)


# ------------------------------------------------------------------ the HTTP surface
# FX-2: the longest POST body the helper reads; a longer one is not read and its connection is closed
MAX_POST_BODY = 8192
# PLAN-05 WP-H2/H4: a query string, as it appears in a request line (cut from every log line)
_QUERY_RE = re.compile(r"\?[^\s\"]*")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 30            # E2-18: an idle keep-alive connection no longer pins a thread

    def log_message(self, fmt, *args):
        # Logged, unlike Stage 1's silent handler. E2RIG exists because that silence made a
        # browser block and a helper refusal indistinguishable in the evidence.
        # PLAN-05 WP-H2/H4: every QUERY STRING is cut from the log line -- Google's redirect carries
        # the authorization code and the state, and /status carries the page's tab id.
        sys.stderr.write("[helper-http] %s\n" % _QUERY_RE.sub("", fmt % args))
        sys.stderr.flush()

    def _see_other(self, location):
        """WP-H2: 303 to a Location built only from stored values; no body, no referrer, nothing
        cached, the connection closed."""
        self.close_connection = True
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        sys.stderr.write("[helper-req] %s\n" % json.dumps(
            {"at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "method": self.command,
             "path": self.path.split("?")[0], "origin": self.headers.get("Origin"),
             "code": 303}))
        sys.stderr.flush()

    def _callback(self):
        """WP-H2: Google's redirect, on the main server, BEFORE any Origin check (a navigation from
        Google carries none, CH-9). Matched ONLY by sha256(state); 303 on every outcome."""
        try:
            q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(self.path).query))
        except Exception:
            q = {}
        state = q.get("state")
        flow, first = None, False
        if isinstance(state, str) and state:
            h = state_sha256(state)
            with LOCK:
                _prune_flows_locked()
                flow = _FLOWS.get(h)
                # only the FIRST redirect of a running flow is recorded; a superseded flow (U-19)
                # and every later hit only answer
                if flow is not None and flow["status"] == "pending" and not flow["cancel"].is_set():
                    flow["result"] = q
                    flow["status"] = "matched"
                    flow["keep_until"] = max(flow["keep_until"], time.time() + FLOW_KEEP_S)
                    first = True
            if first:
                flow["arrived"].set()
            elif flow is not None and flow["status"] == "interrupted":
                _match_interrupted(flow)
        if flow is None:
            return self._see_other(CALLBACK_DEFAULT_RETURN)
        if first:
            flow["done"].wait(CALLBACK_RESULT_WAIT_S)
            # FX-10 (CR5-4): the hand-off opens just BEFORE the 303, after the exchange and store,
            # so a slow store (macOS's keychain prompt) cannot expire it before the page lands
            open_handoff(flow.get("origin"))
        return self._see_other(flow["location"])

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        origin = self.headers.get("Origin")
        if origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.end_headers()
        self.wfile.write(body)
        sys.stderr.write("[helper-req] %s\n" % json.dumps(
            {"at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "method": self.command,
             "path": self.path.split("?")[0], "origin": self.headers.get("Origin"),
             "code": code}))
        sys.stderr.flush()

    def _send_empty(self, code):
        """A bodiless answer (FX-3: /release -> 204), with the same CORS and request-log lines."""
        self.send_response(code)
        origin = self.headers.get("Origin")
        if origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Content-Length", "0")
        self.end_headers()
        sys.stderr.write("[helper-req] %s\n" % json.dumps(
            {"at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "method": self.command,
             "path": self.path.split("?")[0], "origin": self.headers.get("Origin"),
             "code": code}))
        sys.stderr.flush()

    def _authorised(self, paired_only=False):
        """1.0: the SITE is admitted by its Origin, which a browser sets and a page cannot
        change; the site holds no secret (Reviewer 11:02). A request with NO Origin is a local
        tool and must carry the pairing secret. `paired_only` endpoints (/compare) refuse ANY
        Origin, so no web page can ever reach them."""
        origin = self.headers.get("Origin")
        if origin is not None:
            if paired_only:
                return (403, "not available to a web page")
            if origin not in ALLOWED_ORIGINS:
                return (403, "origin not allowed")
            return None
        want = pairing_secret()
        if not want:
            if KEYCHAIN and not _keychain_readable():
                return (503, "credential_store_unavailable")   # 1.1.0 (C-5): no instruction
            return (503, "helper not paired")
        if not hmac.compare_digest(self.headers.get("X-Pair-Secret") or "", want):
            return (401, "not paired")
        return None

    def do_OPTIONS(self):
        """E2-18: the CORS preflight a browser sends before a JSON POST from the site."""
        note_poll(self)                            # WP-H4
        origin = self.headers.get("Origin")
        if origin not in ALLOWED_ORIGINS:
            return self._send(403, {"error": "origin not allowed"})
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Max-Age", "600")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _public_state(self, tab=None):
        out = {k: STATE[k] for k in ("helper", "property", "local_credential",
                                     "provider_authorization", "connection_id")}
        # Step 3 (b): a property recorded earlier (a persisted state) that is not allowed is not shown
        prop = out["property"]
        if not (isinstance(prop, dict) and str(prop.get("id")) in SHOWN_PROPERTIES):
            out["property"] = None
        out["google_access"] = published_access()
        out["keychain"] = keychain_state()
        out["last_flow"] = STATE.get("last_flow")
        v = STATE["verification"]
        out["verification"] = ({k: v.get(k) for k in ("connection_id", "run_id", "at")}
                               if v else None)
        out["run_id"] = RUN_ID
        out["claude"] = claude_row()
        # plan-04 WP-6: four distinct states (booleans, timestamps and tool names only)
        evs = _launcher_events()
        out["helper_ready"] = True
        out["google_authorized"] = google_authorized()
        out["claude_tool_used"] = claude_tool_used(evs)
        out["answer_success"] = answer_success(evs, out["google_access"])
        # PLAN-05 WP-H1 (KPI-3): ready = verified AND property_present AND claude_loaded.ok
        out["claude_loaded"] = claude_loaded(evs)
        out["property_present"] = property_present(out["google_access"])
        out["ready"] = bool(out["google_access"] == "verified" and out["property_present"]
                            and out["claude_loaded"]["ok"])
        out["google_access_reason"] = google_access_reason(out["google_access"])   # WP-H6
        out["claude_frontmost"] = claude_frontmost_view(out["ready"])     # WP-H5, FX-15: ready only
        # WP-H4 (NEW-E2): the owner tab, relative to the asking tab; a granted request carrying
        # `tab` is a claim (made here, before the answer)
        origin = self.headers.get("Origin")
        with LOCK:
            claim_owner_locked(tab, origin)
            out["owner"] = owner_view_locked(tab)
        return out

    def do_GET(self):
        note_poll(self)                            # WP-H4
        path = self.path.split("?", 1)[0]
        if self.path == "/health":
            return self._send(200, {"helper": "running", "service": SERVICE, "version": VERSION,
                                    "run_id": RUN_ID})
        if path == "/callback":                    # WP-H2: BEFORE _authorised()
            return self._callback()
        if path == "/status":                      # WP-H2: matched without the query string
            bad = self._authorised()
            if bad:
                return self._send(bad[0], {"error": bad[1]})
            try:
                tab = valid_tab(dict(urllib.parse.parse_qsl(
                    urllib.parse.urlsplit(self.path).query)).get("tab"))
            except Exception:
                tab = None
            return self._send(200, self._public_state(tab))
        return self._send(404, {"error": "no such path"})

    def _read_body(self):
        """FX-2 (INTERFACE-05 §6.1): the request body, read and kept, BEFORE any answer -- on every
        POST, whatever its path or outcome -- so a kept-alive connection never carries an unread body
        into the next request line (the 1.2.0 draft answered /verify without reading its "{}", and the
        next request line read "{}GET /status" -> 501). Up to MAX_POST_BODY bytes; a longer body, a
        malformed or negative Content-Length, or a chunked body is NOT read and the connection is
        closed after the answer (self._body None). No Content-Length -> no body (b"")."""
        self._body = b""
        te = (self.headers.get("Transfer-Encoding") or "").lower()
        raw = self.headers.get("Content-Length")
        try:
            n = int(raw) if raw is not None else 0
        except ValueError:
            n = -1
        if "chunked" in te or n < 0 or n > MAX_POST_BODY:
            self._body = None
            self.close_connection = True
            return
        if n:
            self._body = self.rfile.read(n)
            if len(self._body) != n:              # the client sent less than it announced
                self.close_connection = True

    def _json_body(self):
        """The body as a JSON object, or {} (no body, too long, not JSON, not an object)."""
        try:
            v = json.loads(self._body or b"{}")
        except Exception:
            return {}
        return v if isinstance(v, dict) else {}

    def do_POST(self):
        self._read_body()                          # FX-2: FIRST, on every POST route
        # Step 3 (CR3-12/G-5): /connect/callback-wait is no longer admitted. It had no branch here
        # (an admitted request got NO answer and waited out the client's timeout), no caller and no
        # test since 0.6.3; it now gets this 404 like any unknown path.
        note_poll(self)                            # PLAN-05 WP-H4
        if self.path not in ("/connect/start", "/disconnect", "/verify", "/compare", "/shutdown",
                             "/claude/open", "/release"):
            return self._send(404, {"error": "no such path"})
        if self._body is None and self.path != "/release":
            # CR5-9 (lead): a body that was not read (too long, chunked, a bad Content-Length) is never
            # acted on: 413, and the connection closes (_read_body set close_connection). /release
            # answers 204 regardless (below), and changes nothing without a readable tab.
            return self._send(413, {"error": "body_too_large"})
        bad = self._authorised(paired_only=(self.path in ("/compare", "/shutdown")))
        if bad:
            return self._send(bad[0], {"error": bad[1]})

        if self.path == "/release":
            # FX-3 (INTERFACE-05 §6.2): the page's pagehide beacon. {"tab": id} as JSON or as
            # text/plain holding the same JSON. The owner tab releases ownership at once; a pending
            # flow is NOT cancelled (its callback still lands through the hand-off). Anything else:
            # no change. Always 204, no body.
            tab = valid_tab(self._json_body().get("tab"))
            with LOCK:
                released = release_owner_locked(tab)
            if released:
                log("the owner tab released ownership")
            return self._send_empty(204)

        if self.path == "/claude/open":
            # PLAN-05 WP-H5: the body (read by _read_body, FX-2) is IGNORED: no text in it ever
            # reaches an argv
            code, body = claude_open()
            return self._send(code, body)

        if self.path == "/shutdown":
            # 0.6.2 (P1, O8 13:00): a launcher bundling a NEWER helper asks this one to stop, so
            # an update takes effect without restarting Claude. Paired local tools only (no
            # Origin, the pairing secret), like /compare. This process stops listening and
            # exits; a `security` it may have left running is in its own session and untouched.
            log("shutdown requested by a paired local caller (version %s)" % VERSION)
            self._send(200, {"stopping": True, "version": VERSION})
            _stop_serving("shutdown requested")
            return

        if self.path == "/compare":
            # KPI-3, ruling D3: the helper makes BOTH GA4 calls itself; the access token never
            # leaves this process. Paired local tools only (no Origin): the answer carries
            # report rows, which the site must never receive (D5 condition).
            try:
                if self._body is None:
                    raise ValueError("body too long")
                req = json.loads(self._body or b"{}")
                if not isinstance(req, dict):
                    raise ValueError("not an object")
            except Exception:
                return self._send(400, {"error": "bad request body"})
            which = req.get("which", "last")
            tok, err = access_token()
            if not tok:
                return self._send(503, {"error": "no_access", "detail": err})
            try:
                return self._send(200, {"compare": _compare_module().compare(
                    LAUNCHER_STATUS, lambda: _credentials_for(tok), which=which)})
            except Exception as exc:
                log("compare failed: %s" % type(exc).__name__)
                return self._send(500, {"error": "compare_failed", "detail": type(exc).__name__})

        if self.path == "/connect/start":
            # NO DEFAULT provider. Unset means refuse, not guess which Google to call.
            if not CONFIGURED:
                return self._send(503, {"error": "not configured",
                                        "detail": CLIENT_CONFIG_ERROR or
                                        "set GA4_OAUTH_CLIENT_JSON (real) or GA4_GOOGLE_BASE "
                                        "and GA4_CLIENT_ID (test); the helper will not guess"})
            # 1.1.0 (N-2): an OPTIONAL JSON body. PLAN-05: {return_to, return_mode, tab}. return_to is
            # kept only if its origin is the admitted Origin of this request; anything else (no body,
            # bad JSON, another origin) is ignored and never an error. return_mode is no longer needed
            # (every outcome answers 303, WP-H2); tab is the page's per-tab id (WP-H4).
            # CR3-12 / FX-2: the body was read by _read_body (a longer one is not read and the
            # connection ends after this answer)
            body = self._json_body()
            return_to = valid_return_to(body.get("return_to"), self.headers.get("Origin"))
            tab = valid_tab(body.get("tab"))
            origin = self.headers.get("Origin")
            origin = origin if origin in ALLOWED_ORIGINS else None
            flow_id = _b64u(os.urandom(9))
            verifier = _b64u(os.urandom(32))
            challenge = _b64u(hashlib.sha256(verifier.encode()).digest())
            state_key = _b64u(os.urandom(16))
            # WP-H2: the redirect URI is THIS server (its own bound port), never a per-flow listener
            redirect = "http://127.0.0.1:%d/callback" % self.server.server_address[1]
            flow = _new_flow(flow_id, state_sha256(state_key), return_to, origin, tab)
            with LOCK:
                refused = owner_blocks_locked(tab, origin)   # NEW-E2 (+ FX-1 takeover)
                if not refused:
                    old = _ACTIVE_FLOW.get("flow")
                    if old is not None:
                        old["cancel"].set()          # E2-05: the previous flow ends as superseded
                        old["arrived"].set()
                    _ACTIVE_FLOW.clear()
                    _ACTIVE_FLOW.update(flow=flow, flow_id=flow_id)
                    _prune_flows_locked()
                    _FLOWS[flow["state_sha256"]] = flow
                    _PENDING[state_key] = {"verifier": verifier, "redirect": redirect,
                                           "at": time.time()}
                    STATE["last_flow"] = {"id": flow_id, "outcome": "pending", "detail": None}
                    claim_owner_locked(tab, origin, start=True)
            if refused:
                return self._send(409, {"error": "not_owner"})
            pending_record_add(flow)       # CH-3: before the URL leaves, so a restart can answer
            note_claude_for_flow(flow)     # WP-H3: whose Claude Desktop this flow runs under
            url = AUTH_URI + "?" + urllib.parse.urlencode({
                "client_id": CLIENT_ID, "redirect_uri": redirect,
                "response_type": "code", "scope": SCOPE, "state": state_key,
                "code_challenge": challenge, "code_challenge_method": "S256",
                "access_type": "offline", "prompt": "consent"})
            threading.Thread(target=_run_flow, args=(flow, state_key), daemon=True).start()
            # The authorization URL and the flow id. NO verifier, NO state secret, and nothing the
            # site could replay.
            return self._send(200, {"authorize_url": url, "flow_id": flow_id})

        if self.path == "/verify":
            ok, err, prop = verify_google_access()
            record_verification(ok, prop, err)
            state_save()
            # "Google access verified" says NOTHING about Claude (clarification 7).
            access = published_access()
            return self._send(200, {"google_access": access,
                                    "property": prop, "error": err,
                                    "claude": claude_row(),
                                    # PLAN-05 WP-H6
                                    "google_access_reason": google_access_reason(access)})

        if self.path == "/disconnect":
            # F5: TWO SEPARATE STATES. The local copy and the provider-side authorization
            # are different facts and are reported as such. "still connected" must never be
            # shown once the local secret is gone, and a refused revoke must not be reported
            # as revoked.
            # E2-01: a keychain that could not be READ is reported as such. Nothing is revoked,
            # nothing is deleted, and nothing is persisted: the credential may well be there.
            kind, rt = refresh_token_read()
            if kind == "unknown":
                log("disconnect refused: the keychain could not be read (%s)" % rt)
                return self._send(503, {"error": "keychain_unreadable", "detail": rt,
                                        "local_credential": "unknown",
                                        "provider_authorization": "not_attempted",
                                        "google_access": published_access(),
                                        "claude": claude_row()})
            provider = "none"
            if kind == "present":
                s, b = _post_form(REVOKE_URI, {"token": rt})
                provider = "revoked" if s == 200 else "revoke_failed"
                if provider == "revoke_failed":
                    log("provider refused the revoke: HTTP %s" % s)
            # judged on the delete's OWN result: gone now, or `security` says it was not there
            local_cleared = refresh_token_clear()
            if not local_cleared:
                log("the local credential could not be deleted; it is reported as still present")
            with LOCK:
                _MEM["access_token"] = None
                _MEM["expires_at"] = 0.0
                STATE["provider_authorization"] = provider
                STATE["local_credential"] = "absent" if local_cleared else "present"
                if local_cleared or provider == "revoked":
                    STATE["google_access"] = "not_connected"
                if local_cleared:
                    STATE["property"] = None
                    STATE["connection_id"] = None
                    STATE["verification"] = None
            state_save()
            return self._send(200, {
                "local_credential": STATE["local_credential"],
                "provider_authorization": STATE["provider_authorization"],
                "google_access": STATE["google_access"],
                # What REMAINS, stated rather than implied (V7-5).
                "remains": {
                    "helper_installed": True,
                    "claude_extension_installed": "unknown_to_helper",
                    "past_claude_conversations": "untouched_and_outside_our_reach",
                },
                "claude": claude_row()})


def _compare_module():
    """bundle/helper_compare.py (A5), loaded by path from beside this file."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "grabmcp_helper_compare", os.path.join(HERE, "helper_compare.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _credentials_for(token):
    """An in-memory credentials object holding ONLY the access token: nothing written."""
    from google.oauth2.credentials import Credentials
    return Credentials(token=token)


def ensure_pairing():
    """0.6.0: the helper now starts with the extension, so it creates its own pairing secret the
    first time (rrk's `pairing-set` was a terminal step). Only when `security` itself answers
    "not found" -- never on an unreadable keychain -- and with the same -T ACL as the token."""
    if not KEYCHAIN or not _keychain_readable():
        return
    r = _sec(["find-generic-password", "-a", "ga4-helper-pairing", "-s", KEYCHAIN_SERVICE, "-w"])
    if r is None or r.returncode != SEC_NOT_FOUND:
        return
    secret = _b64u(os.urandom(24))
    w = _sec_stdin('add-generic-password -a ga4-helper-pairing -s %s -T /usr/bin/security '
                   '-w "%s" "%s"' % (KEYCHAIN_SERVICE, secret, KEYCHAIN))
    log("pairing secret %s" % ("created" if w is not None and pairing_secret() == secret
                               else "could NOT be created"))


def reverify_after_restart():
    """A restart RESUMES the connection without new setup (V7-4), but it does not resume the
    old verdict: the persisted "verified" belongs to another run. One minimal call re-earns it.
    Until it returns, /status says "unverified" -- true, and not a request to reconnect."""
    ok, err, prop = verify_google_access()
    record_verification(ok, prop, err)
    state_save()
    log("re-verified after restart: %s%s" % ("verified" if ok else "not_verified",
                                              "" if ok else " (%s)" % err))


# ------------------------------------------------------------------ shutdown record (PLAN-05 WP-H3)
# CH-2: the launcher ends this helper with SIGTERM on Claude's normal quit, and until 1.2.0 there was
# no handler (the process died at once). Now a BOUNDED handler (SIGTERM_BOUND_S, under the contract's
# 2 s) persists the FACTS of a sign-in that was still pending -- {flow_id, claude_pid,
# claude_pid_start, at} -- and exits. No cause is written at shutdown: at the NEXT start the record
# gets cause "claude_closed" ONLY if the recorded Claude Desktop process is gone (C-11); otherwise
# (the extension alone was disabled, updated or restarted) no cause is published. Either way that
# flow's last_flow becomes "interrupted". M-b (opening the browser on quit) is NOT built (gate §C).
CLAUDE_BUNDLE_ID = "com.anthropic.claudefordesktop"
SHUTDOWN_RECORD_PATH = os.path.join(os.path.dirname(os.path.abspath(STATE_PATH)),
                                    "shutdown-record.json")
SHUTDOWN_RECORD_KEYS = ("flow_id", "claude_pid", "claude_pid_start", "at")
SIGTERM_BOUND_S = 1.5
PARENT_WALK_MAX = 16
_CLAUDE = {"v": None}              # (pid, start) of the Claude Desktop process above us, once found


def proc_path(pid):
    """The executable path of `pid` (libproc proc_pidpath: no subprocess, not argv), or None."""
    try:
        lib = ctypes.CDLL("/usr/lib/libproc.dylib")
        buf = ctypes.create_string_buffer(4096)
        n = lib.proc_pidpath(ctypes.c_int(int(pid)), buf, ctypes.c_uint32(4096))
        return buf.value.decode("utf-8", "replace") if n > 0 else None
    except Exception:
        return None


def proc_parent(pid):
    """(ppid, start) of `pid` from ONE `ps` call, or None."""
    try:
        r = subprocess.run(["/bin/ps", "-p", str(int(pid)), "-o", "ppid=,lstart="],
                           capture_output=True, text=True, timeout=5)
    except Exception:
        return None
    parts = r.stdout.strip().split(None, 1) if r.returncode == 0 else []
    if len(parts) != 2 or not parts[0].isdigit():
        return None
    return int(parts[0]), parts[1].strip()


_APP_IDS = {}


def app_root(path):
    """The OUTERMOST "<name>.app" folder containing `path` (a helper app nested inside an app
    belongs to the outer one), or None."""
    if not isinstance(path, str):
        return None
    parts = path.split("/")
    for i, part in enumerate(parts):
        if part.endswith(".app"):
            return "/".join(parts[:i + 1])
    return None


def app_bundle_id(root):
    """CFBundleIdentifier of an app folder (its Contents/Info.plist), or None. Cached."""
    if not root:
        return None
    if root not in _APP_IDS:
        try:
            import plistlib
            with open(os.path.join(root, "Contents", "Info.plist"), "rb") as fh:
                v = plistlib.load(fh).get("CFBundleIdentifier")
            _APP_IDS[root] = v if isinstance(v, str) else None
        except Exception:
            _APP_IDS[root] = None
    return _APP_IDS[root]


# Test seam (like GA4_HELPER_OPEN_BIN): a program that prints the bundle id of the app a pid belongs
# to. Unset (the product) -> the in-process read above (libproc path -> outermost .app -> its
# Info.plist); no LaunchServices call either way.
BUNDLEID_BIN = _seam("GA4_HELPER_BUNDLEID_BIN", "")                    # FX-5: "" in a release
BUNDLEID_BOUND_S = 2.0
_BUNDLE_ID_SHAPE = re.compile(r"[A-Za-z0-9.-]{1,255}")


def bundle_id_of_pid(pid):
    """The bundle id of the app the process `pid` belongs to, or None."""
    if not BUNDLEID_BIN:
        return app_bundle_id(app_root(proc_path(pid)))
    try:
        r = subprocess.run([BUNDLEID_BIN, str(int(pid))], stdin=subprocess.DEVNULL,
                           capture_output=True, text=True, timeout=BUNDLEID_BOUND_S)
    except Exception:
        return None
    v = r.stdout.strip()
    return v if r.returncode == 0 and _BUNDLE_ID_SHAPE.fullmatch(v) else None


def find_claude_process(first=None):
    """WP-H3: walk the parent chain (helper -> launcher -> ... -> Claude Desktop) and return
    (pid, start) of the TOPMOST process whose executable lies in the Claude Desktop app, or None."""
    pid = os.getppid() if first is None else first
    found = None
    for _ in range(PARENT_WALK_MAX):
        if not isinstance(pid, int) or pid <= 1:
            break
        par = proc_parent(pid)
        if par is None:
            break
        if bundle_id_of_pid(pid) == CLAUDE_BUNDLE_ID:
            found = (pid, par[1])
        elif found is not None:
            break                       # above the app: the last match was its top process
        pid = par[0]
    return found


def note_claude_for_flow(flow):
    """At /connect/start, off the request thread: whose Claude Desktop this flow runs under (once per
    helper process; the parent chain does not change while this helper lives)."""
    def run():
        if _CLAUDE["v"] is None:
            _CLAUDE["v"] = find_claude_process()
        flow["claude"] = _CLAUDE["v"]
    threading.Thread(target=run, daemon=True).start()


def _write_json_0600(path, obj, prefix):
    d = os.path.dirname(path)
    os.makedirs(d, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=prefix, suffix=".tmp", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(obj, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_shutdown_record():
    """The facts of a pending sign-in at shutdown, or nothing. Returns the record written, or None."""
    got = LOCK.acquire(timeout=0.5)
    try:
        f = _ACTIVE_FLOW.get("flow")
        lf = STATE.get("last_flow") or {}
        pending = bool(f is not None and f["status"] in ("pending", "matched")
                       and lf.get("id") == f["flow_id"] and lf.get("outcome") == "pending")
        claude = (f.get("claude") or _CLAUDE["v"]) if f is not None else None
    finally:
        if got:
            LOCK.release()
    if not pending:
        return None
    rec = {"flow_id": f["flow_id"], "claude_pid": claude[0] if claude else None,
           "claude_pid_start": claude[1] if claude else None, "at": _now_iso()}
    _write_json_0600(SHUTDOWN_RECORD_PATH, rec, ".shutdown-record.")
    return rec


def _on_sigterm(signum, frame):
    """Bounded: the record is written on its own thread, joined for at most SIGTERM_BOUND_S; then
    the process exits whatever happened."""
    box = {}

    def run():
        try:
            box["rec"] = write_shutdown_record()
        except Exception as exc:
            box["err"] = type(exc).__name__
    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(SIGTERM_BOUND_S)
    rec = box.get("rec")
    log("stopping: SIGTERM%s" % (
        "; the pending sign-in %s was recorded" % rec["flow_id"] if rec else
        "; the shutdown record could not be written (%s)" % box["err"] if "err" in box else
        "; the shutdown record did not finish within %.1f s" % SIGTERM_BOUND_S if t.is_alive()
        else ""))
    os._exit(0)


def install_sigterm():
    signal.signal(signal.SIGTERM, _on_sigterm)


def consume_shutdown_record():
    """At start: (flow_id, cause) from the previous run's shutdown record, or None. The record is
    removed. cause = "claude_closed" ONLY if the recorded Claude Desktop process is gone (its pid is
    not alive with the recorded start time); unknown or alive -> None. A record older than
    CALLBACK_WAIT_S names a flow that can no longer finish and is dropped."""
    try:
        with open(SHUTDOWN_RECORD_PATH, encoding="utf-8") as fh:
            rec = json.load(fh)
    except FileNotFoundError:
        return None
    except Exception:
        rec = None
    try:
        os.unlink(SHUTDOWN_RECORD_PATH)
    except OSError:
        pass
    if not isinstance(rec, dict) or set(rec) != set(SHUTDOWN_RECORD_KEYS) \
            or not isinstance(rec["flow_id"], str) or not _FLOW_ID_RE.fullmatch(rec["flow_id"]):
        log("the shutdown record is malformed; ignored")
        return None
    t = _iso_epoch(rec["at"])
    if t is None or time.time() - t > CALLBACK_WAIT_S:
        return None
    pid, start = rec["claude_pid"], rec["claude_pid_start"]
    cause = None
    if isinstance(pid, int) and not isinstance(pid, bool) and isinstance(start, str) and start:
        if process_alive(pid, start) is False:
            cause = "claude_closed"
    return rec["flow_id"], cause


def restore_after_restart():
    """WP-H2 + WP-H3 at start: restore the pending-flow records, then publish the interrupted flow --
    the one the shutdown record names (with its cause, if shown), else the newest unexpired record."""
    recs = restore_pending_flows()
    sd = consume_shutdown_record()
    if sd is not None:
        publish_interrupted(sd[0], sd[1])
        log("the previous run ended during a sign-in; it is published as interrupted%s"
            % (" (Claude Desktop had quit)" if sd[1] else ""))
    elif recs:
        publish_interrupted(recs[-1]["flow_id"])
        log("the previous run ended during a sign-in (no shutdown record); published as interrupted")


# ------------------------------------------------------------------ opening the site (PLAN-05 WP-H4)
# On FIRST READINESS -- the first time Claude Desktop has loaded this extension (WP-H1's
# claude_loaded.ok) -- and only while setup is incomplete (no Google credential is saved), the helper
# opens the site ONCE per install (keyed on the extension folder's creation time, recorded as
# `announced_for` in the state directory), so the user does not have to find the page again.
#   * Which browser (CH-13): Chromium browsers share Chrome's User-Agent, so the helper identifies the
#     PROCESS that owns the polling connection's peer socket (`lsof`, a local read, on the next
#     request a page makes), maps its app bundle through the fixed allow-list BROWSER_BUNDLES, and
#     otherwise lets macOS pick (plain `open`).
#   * Which origin (CH-12): the owner tab's polled origin, else the polling request's, always one of
#     the built-in DEFAULT_ORIGINS -- never a request-supplied value.
#   * The URL: <origin>/connect/#ready=<run_id>, plus "&owner=1" only when an owner tab exists. The
#     argv is a LIST given to /usr/bin/open (no shell); nothing in it comes from a request except the
#     choice of an allow-listed origin and an allow-listed bundle id.
# The re-fronting after a restart that finds an interrupted record (M-b, UX-9 condition 3) is NOT built.
OPEN_BIN = _seam("GA4_HELPER_OPEN_BIN", "/usr/bin/open")             # FX-5: a fake only in qa/tests
LSOF_BIN = _seam("GA4_HELPER_LSOF_BIN", "/usr/sbin/lsof")             # FX-5: a fake only in qa/tests
BROWSER_BUNDLES = ("com.google.Chrome", "org.mozilla.firefox", "com.microsoft.edgemac",
                   "com.brave.Browser", "com.apple.Safari")
ANNOUNCE_PATH = os.path.join(os.path.dirname(os.path.abspath(STATE_PATH)), "announced.json")
ANNOUNCE_WATCH_S = 600.0       # how long after start the helper waits for Claude to load it
ANNOUNCE_POLL_S = 1.0
PEER_WAIT_S = 6.0              # the site polls every 2.5 s: wait for its next request
LSOF_BOUND_S = 2.0
OPEN_BOUND_S = 10.0
_PEER = {"want": threading.Event(), "got": threading.Event(), "bundle": None, "origin": None,
         "lock": threading.Lock()}
_LAST_POLL = {"origin": None, "at": 0.0}


def peer_owner_pid(peer_port):
    """The pid (not ours) whose socket's LOCAL end is 127.0.0.1:<peer_port>, by lsof; or None."""
    try:
        r = subprocess.run([LSOF_BIN, "-nP", "-iTCP@127.0.0.1:%d" % int(peer_port),
                            "-sTCP:ESTABLISHED", "-Fpn"], stdin=subprocess.DEVNULL,
                           capture_output=True, text=True, timeout=LSOF_BOUND_S)
    except Exception:
        return None
    pid, me, want = None, os.getpid(), "n127.0.0.1:%d->" % int(peer_port)
    for line in r.stdout.splitlines():
        if line.startswith("p"):
            pid = int(line[1:]) if line[1:].isdigit() else None
        elif line.startswith(want) and pid is not None and pid != me:
            return pid
    return None


def browser_bundle_of_pid(pid):
    """The allow-listed browser bundle the process belongs to (its own app, or the app of a parent:
    a browser's network process is a helper inside, or a child of, the browser), else None."""
    for _ in range(PARENT_WALK_MAX):
        if not isinstance(pid, int) or pid <= 1:
            return None
        bid = bundle_id_of_pid(pid)
        if bid in BROWSER_BUNDLES:
            return bid
        par = proc_parent(pid)
        if par is None:
            return None
        pid = par[0]
    return None


def note_poll(handler):
    """Every request with an admitted Origin: remember its origin; if the announcer is waiting for
    the polling browser, identify it NOW, while this request's connection is still open."""
    origin = handler.headers.get("Origin")
    if origin not in ALLOWED_ORIGINS:
        return
    _LAST_POLL.update(origin=origin, at=time.time())
    if not _PEER["want"].is_set():
        return
    with _PEER["lock"]:
        if not _PEER["want"].is_set():
            return
        _PEER["want"].clear()
    pid = peer_owner_pid(handler.client_address[1])
    _PEER.update(bundle=browser_bundle_of_pid(pid) if pid else None, origin=origin)
    _PEER["got"].set()


def install_key():
    """The extension folder's creation time (an update replaces the folder, so a new install)."""
    try:
        st = os.stat(HERE)
    except OSError:
        return None
    return "%.6f" % getattr(st, "st_birthtime", st.st_ctime)


def announced_for():
    try:
        with open(ANNOUNCE_PATH, encoding="utf-8") as fh:
            v = json.load(fh).get("announced_for")
        return v if isinstance(v, str) else None
    except Exception:
        return None


def setup_incomplete():
    with LOCK:
        return STATE["local_credential"] != "present"


def site_open_plan(peer_bundle, peer_origin):
    """(argv, origin) for opening the site: an argv LIST, compiled-in values only."""
    with LOCK:
        live = owner_exists_locked()
        owner_origin = _OWNER["origin"] if live else None
    origin = next((o for o in (owner_origin, peer_origin, _LAST_POLL["origin"])
                   if o in DEFAULT_ORIGINS), DEFAULT_ORIGINS[0])
    url = origin + "/connect/#ready=" + RUN_ID + ("&owner=1" if live else "")
    if peer_bundle in BROWSER_BUNDLES:
        return [OPEN_BIN, "-b", peer_bundle, url], origin
    return [OPEN_BIN, url], origin


def announce_once(watch_s=None):
    """WP-H4. Returns what it did: "already" | "not_loaded" | "complete" | "opened" | "open_failed"."""
    key = install_key()
    if key is None or announced_for() == key:
        return "already"
    end = time.time() + (ANNOUNCE_WATCH_S if watch_s is None else watch_s)
    while not claude_loaded()["ok"]:
        if time.time() >= end:
            return "not_loaded"
        time.sleep(ANNOUNCE_POLL_S)
    if announced_for() == key:
        return "already"
    try:                                      # recorded FIRST: once per install, even on a crash
        _write_json_0600(ANNOUNCE_PATH, {"announced_for": key}, ".announced.")
    except OSError as exc:
        log("the announcement record could not be written (%s); the site is not opened"
            % type(exc).__name__)
        return "open_failed"
    if not setup_incomplete():
        log("first readiness: setup is complete; the site is not opened")
        return "complete"
    _PEER["got"].clear()
    _PEER.update(bundle=None, origin=None)
    _PEER["want"].set()
    _PEER["got"].wait(PEER_WAIT_S)
    _PEER["want"].clear()
    argv, origin = site_open_plan(_PEER["bundle"], _PEER["origin"])
    open_handoff(origin)                      # the page we open takes ownership when it claims
    try:
        r = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=OPEN_BOUND_S)
        ok = r.returncode == 0
    except Exception:
        ok = False
    log("first readiness: the site was %s (%s)" % (
        "opened" if ok else "NOT opened", "an allow-listed browser" if len(argv) == 4
        else "the default browser"))
    return "opened" if ok else "open_failed"


def start_announcer():
    def run():
        try:
            announce_once()
        except Exception as exc:
            log("announcer: %s" % type(exc).__name__)
    threading.Thread(target=run, daemon=True).start()


# ------------------------------------------------------------------ opening Claude (PLAN-05 WP-H5)
# POST /claude/open, the site's "Open Claude Desktop" / "Try again" (click handlers only). Refused
# unless google_access is "verified" (409 not_verified); at most once per CLAUDE_OPEN_RATE_S (429
# rate_limited) EXCEPT the first call after a call that returned opened:false (UX-15). It runs
# ["/usr/bin/open", "-b", "com.anthropic.claudefordesktop"] (no shell, no text from the request), then
# reads the frontmost app (`lsappinfo front`, its bundle id compared HERE, bounded FRONT_BOUND_S):
# `open`'s exit 0 is not front-ness (CH-10). {opened} = exit 0 AND Claude frontmost. /status carries
# claude_frontmost {front: bool, at} -- a bool, never another app's identity (A-1, UX-22); while it is
# false it is read again on a later /status (Claude may come forward later) -- FX-11 (CR5-10): with no
# time limit, at most once per CLAUDE_FRONT_RECHECK_S, so LaunchFailed always learns Claude came forward.
LSAPPINFO_BIN = _seam("GA4_HELPER_LSAPPINFO_BIN", "/usr/bin/lsappinfo")   # FX-5: a fake only in qa
CLAUDE_OPEN_ARGV_TAIL = ("-b", CLAUDE_BUNDLE_ID)
CLAUDE_OPEN_RATE_S = 10.0
FRONT_BOUND_S = 2.0
FRONT_POLL_S = 0.25
CLAUDE_FRONT_RECHECK_S = 1.0
_ASN_RE = re.compile(r"ASN:0x[0-9a-fA-F]+-0x[0-9a-fA-F]+:?")
_BUNDLE_ID_RE = re.compile(r'"CFBundleIdentifier"\s*=\s*"([^"]*)"')
_CLAUDE_OPEN = {"last": None, "last_failed": False}
_CLAUDE_OPEN_LOCK = threading.Lock()
_FRONT = {"v": None, "checked": 0.0, "inflight": False}
_FRONT_LOCK = threading.Lock()


def claude_is_frontmost(bound=FRONT_BOUND_S):
    """True only if the frontmost app's bundle id is Claude Desktop's; anything else, including a
    failure to read, is False. The identity read never leaves this function."""
    end = time.time() + bound
    try:
        r = subprocess.run([LSAPPINFO_BIN, "front"], stdin=subprocess.DEVNULL, capture_output=True,
                           text=True, timeout=max(0.05, end - time.time()))
        asn = r.stdout.strip()
        if r.returncode != 0 or not _ASN_RE.fullmatch(asn):
            return False
        r2 = subprocess.run([LSAPPINFO_BIN, "info", "-only", "bundleid", asn],
                            stdin=subprocess.DEVNULL, capture_output=True, text=True,
                            timeout=max(0.05, end - time.time()))
        m = _BUNDLE_ID_RE.search(r2.stdout) if r2.returncode == 0 else None
        return bool(m) and m.group(1) == CLAUDE_BUNDLE_ID
    except Exception:
        return False


def wait_claude_front(bound=FRONT_BOUND_S):
    """Claude Desktop frontmost within `bound` seconds (activation is asynchronous)."""
    end = time.time() + bound
    while True:
        if claude_is_frontmost(max(0.05, end - time.time())):
            return True
        if time.time() + FRONT_POLL_S >= end:
            return False
        time.sleep(FRONT_POLL_S)


def _set_front(front):
    with _FRONT_LOCK:
        _FRONT["v"] = {"front": bool(front), "at": _now_iso()}
        _FRONT["checked"] = time.time()


def claude_frontmost_view(ready=False):
    """/status: the last front-ness read. FX-15 (CR5-20, KPI-4): it is read AGAIN only while `ready`
    (KPI-3: verified AND property_present AND claude_loaded.ok -- the screens that offer "Open Claude
    Desktop") and the last read was false, at most once per CLAUDE_FRONT_RECHECK_S, with no time limit
    (FX-11). Not ready -> the cached view, nothing spawned. The re-read is CLAIMED under _FRONT_LOCK
    (checked time + in-flight marker set before the subprocess), so concurrent /status calls run it
    once; the others return the cached view."""
    due = False
    with _FRONT_LOCK:
        v = _FRONT["v"]
        if (ready and v is not None and not v["front"] and not _FRONT["inflight"]
                and time.time() - _FRONT["checked"] >= CLAUDE_FRONT_RECHECK_S):
            _FRONT["inflight"] = True
            _FRONT["checked"] = time.time()
            due = True
    if due:
        front = False
        try:
            front = claude_is_frontmost()
        finally:
            with _FRONT_LOCK:
                _FRONT["v"] = {"front": bool(front), "at": _now_iso()}
                _FRONT["checked"] = time.time()
                _FRONT["inflight"] = False
                v = _FRONT["v"]
    return dict(v) if v is not None else None


def claude_open():
    """(code, body) for POST /claude/open, once its Origin was admitted."""
    if published_access() != "verified":
        return 409, {"error": "not_verified"}
    now = time.time()
    with _CLAUDE_OPEN_LOCK:
        last = _CLAUDE_OPEN["last"]
        if last is not None and now - last < CLAUDE_OPEN_RATE_S and not _CLAUDE_OPEN["last_failed"]:
            return 429, {"error": "rate_limited"}
        _CLAUDE_OPEN["last"] = now
        _CLAUDE_OPEN["last_failed"] = False   # the exemption is spent by this call
    try:
        r = subprocess.run([OPEN_BIN] + list(CLAUDE_OPEN_ARGV_TAIL), stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=OPEN_BOUND_S)
        exit_ok = r.returncode == 0
    except Exception:
        exit_ok = False
    front = wait_claude_front() if exit_ok else claude_is_frontmost()
    _set_front(front)
    opened = bool(exit_ok and front)
    with _CLAUDE_OPEN_LOCK:
        if _CLAUDE_OPEN["last"] == now:
            _CLAUDE_OPEN["last_failed"] = not opened
    log("open Claude Desktop: %s" % ("opened and frontmost" if opened else
                                     "open failed" if not exit_ok else "not frontmost"))
    return 200, {"opened": opened}


_SERVER = {"srv": None}


def _stop_serving(why):
    """Stop the HTTP server from another thread; main() then returns and the process exits."""
    srv = _SERVER["srv"]
    if srv is not None:
        log("stopping: %s" % why)
        threading.Thread(target=srv.shutdown, daemon=True).start()


def watch_parent():
    """0.6.2 (P2): started by a launcher (GA4_HELPER_PARENT_WATCH=1), this helper stops when that
    launcher is gone -- its parent pid changes (macOS re-parents an orphan to launchd, pid 1).
    A launcher killed without its cleanup can therefore no longer leave a stale helper behind."""
    if os.environ.get("GA4_HELPER_PARENT_WATCH") != "1":
        return
    first = os.getppid()

    def loop():
        while True:
            time.sleep(PARENT_CHECK_S)
            if os.getppid() != first:
                _stop_serving("the launcher that started this helper is gone (parent %d -> %d)"
                              % (first, os.getppid()))
                return
    threading.Thread(target=loop, daemon=True).start()


PARENT_CHECK_S = float(os.environ.get("GA4_HELPER_PARENT_CHECK_S") or 5.0)


def _launcher_read_pending():
    """True if the LAUNCHER's own record shows a keychain read still pending (a `security` process
    it started that has not returned) -- the helper then starts no second read beside it. Read-only;
    nothing is signalled -- `ps` only."""
    pend = set()
    try:                                  # 0.6.3 v2 (F2): ANY shape problem is "no pending read"
        doc = json.load(open(LAUNCHER_STATUS, encoding="utf-8")) if LAUNCHER_STATUS else {}
        evs = doc.get("events", []) if isinstance(doc, dict) else []
        for e in evs if isinstance(evs, list) else []:
            if not isinstance(e, dict) or e.get("kind") != "credential_reread":
                continue
            try:
                pid = int(e.get("sec_pid"))
            except (TypeError, ValueError):
                continue
            if e.get("outcome") == "pending":
                pend.add(pid)
            elif e.get("outcome") == "late":
                pend.discard(pid)
    except Exception:
        return False
    for pid in pend:                      # F3/F5: `ps` only (no signal of any kind), int, bounded
        try:
            comm = subprocess.run(["/bin/ps", "-o", "comm=", "-p", str(int(pid))],
                                  capture_output=True, text=True, timeout=5).stdout.strip()
        except Exception:
            continue
        if os.path.basename(comm) == "security":
            return True
    return False


def reconcile_from_keychain():
    """0.6.3 (O8 14:36): an update REPLACES the extension folder, and with it this helper's state
    file -- so a fresh helper reported "not connected" over a refresh token still in the keychain.
    With NO state file, the keychain is read ONCE: never on a locked keychain (that is where a
    dialog would come from), never beside a pending launcher read, never killed (_sec)."""
    if os.path.exists(STATE_PATH) or not KEYCHAIN:
        return
    if not _keychain_readable():
        log("no state file; the keychain is not unlocked, so it is not read (no dialog)")
        return
    if _launcher_read_pending():
        log("no state file; a launcher keychain read is still pending, so none is started here")
        return
    kind, val = refresh_token_read()      # F6: `val` is the token on "present", a reason otherwise
    if kind == "present":
        with LOCK:
            STATE["local_credential"] = "present"
            STATE["provider_authorization"] = "granted"
            STATE["connection_id"] = _b64u(os.urandom(9))
            # 0.6.3 v2 (F1): a connection EXISTS; nothing in this run has checked it yet. This is
            # published as "unverified" (published_access) -- never "not_connected" -- until the
            # re-verify records the truth (verified, or a truthful failure).
            STATE["google_access"] = "verified"
            STATE["verification"] = None
        state_save()
        log("no state file; a refresh token IS in the keychain -- connection restored, re-verifying")
    elif kind == "absent":
        log("no state file; no refresh token in the keychain -- not connected")
    else:
        log("no state file; the keychain could not be read (%s) -- state left as not connected" % val)


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


def prepare_state_dir():
    """CR3-13: the state directory exists and is 0700 -- an existing one is tightened too, but only
    if it IS the configured state root or lies inside it (r2 advisory): a GA4_HELPER_STATE that
    points elsewhere is never chmod-ed."""
    try:
        sd = os.path.dirname(os.path.abspath(STATE_PATH))
        root = os.path.abspath(STATE_DIR)
        first = not os.path.isdir(sd)
        os.makedirs(sd, mode=0o700, exist_ok=True)
        if first:
            legacy_flag_write(LEGACY_FLAG)       # E-1: the first start of this version here
        if sd == root or sd.startswith(root + os.sep):
            os.chmod(sd, 0o700)
        else:
            log("state directory is outside the state root; its mode is left as it is")
    except OSError as exc:
        log("state directory could not be prepared: %s" % type(exc).__name__)


def main():
    install_sigterm()                                # PLAN-05 WP-H3: before anything can be pending
    ensure_pairing()
    prepare_state_dir()
    migrate_file(LEGACY_STATE_PATH, STATE_PATH)      # 1.1.0 (N-5): before anything reads it
    state_load()
    restore_after_restart()                          # PLAN-05 WP-H2/H3
    reconcile_from_keychain()
    if STATE["local_credential"] == "present" and CONFIGURED and _keychain_readable():
        threading.Thread(target=reverify_after_restart, daemon=True).start()
    port = int(os.environ.get("GA4_HELPER_PORT", str(DEFAULT_PORT)))
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)   # loopback ONLY
    _SERVER["srv"] = srv
    watch_parent()
    start_announcer()                                # PLAN-05 WP-H4
    log("allowed origins: %s" % ", ".join(sorted(ALLOWED_ORIGINS)))
    log("TLS trust store: %s" % TLS_SOURCE)
    log("endpoints: auth=%s token=%s revoke=%s admin=%s" % (
        AUTH_URI or "-", TOKEN_URI or "-", REVOKE_URI or "-", ADMIN_BASE or "-"))
    if CLIENT_CONFIG_ERROR:
        log("the OAuth client file was REFUSED: %s" % CLIENT_CONFIG_ERROR)
    if not CONFIGURED:
        log("not configured -- flows will be refused")
    log("state file: %s" % STATE_PATH)
    log("listening on 127.0.0.1:%d" % srv.server_address[1])
    print(json.dumps({"port": srv.server_address[1]}), flush=True)
    srv.serve_forever()
    srv.server_close()
    log("stopped")


if __name__ == "__main__":
    main()
