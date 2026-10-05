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

Boundaries this file is built to:
  * loopback ONLY, for both the service and the callback listener;
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
VERSION = "1.0.1"
DEFAULT_PORT = 50812
LAUNCHER_STATUS = os.environ.get("GA4_BRIDGE_STATUS", "")
# 0.6.0 P1 custody (ruling D1): the user's LOGIN keychain unless one is configured, by path.
LOGIN_KEYCHAIN = os.path.expanduser("~/Library/Keychains/login.keychain-db")
KEYCHAIN = os.environ.get("GA4_BRIDGE_KEYCHAIN") or LOGIN_KEYCHAIN
KEYCHAIN_PW = os.environ.get("GA4_BRIDGE_KEYCHAIN_PW", "")
STATE_PATH = os.environ.get("GA4_HELPER_STATE", "helper-state.json")

HERE = os.path.dirname(os.path.abspath(__file__))
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
        "a keychain password in the environment is refused on the real route: unlock the "
        "keychain interactively with `security unlock-keychain <path>` and start the helper "
        "without GA4_BRIDGE_KEYCHAIN_PW")
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
_SEC_SERIAL = threading.Lock()      # one `security` at a time; a second caller WAITS its turn
_SEC_ABANDONED = {"p": None}        # a call that outlived SEC_BOUND, left running


def _sec_wait(argv, input_text=None):
    """REGRESSION FIXED (found by the 0.5.0 run, custody 35/43): the first version REFUSED a call
    while another was running. This helper is a THREADED HTTP server -- a /status poll and a
    token store can overlap -- and the store then gave up, so a connect never stored its token.
    Now a second caller WAITS (bounded) for the call in progress, and only a call ABANDONED past
    its bound (a dialog may be up) makes later calls refuse, until it ends by itself."""
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
        t.join(SEC_BOUND)
        if t.is_alive():
            _SEC_ABANDONED["p"] = p
            log("keychain op (pid %d) has not returned in %.0f s; a dialog may be up; it is left "
                "running, never killed" % (p.pid, SEC_BOUND))
            return None
        out, err = box["out"]
        return subprocess.CompletedProcess(argv, p.returncode, out, err)
    finally:
        _SEC_SERIAL.release()


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
    if not KEYCHAIN_PW and keychain_state() != "unlocked":
        return None
    if KEYCHAIN_PW:
        u = _sec_wait(["/usr/bin/security", "unlock-keychain", "-p", KEYCHAIN_PW, KEYCHAIN])
        if u is None or u.returncode != 0:
            log("keychain unlock failed rc=%s" % (u.returncode if u else "pending"))
            return None
    return _sec_wait(["/usr/bin/security"] + args + [KEYCHAIN])


def _sec_stdin(command):
    """One `security` command fed on STDIN (`security -i`), under the same unlock rules as
    _sec(): the command line -- and any secret in it -- never reaches an argv."""
    if not KEYCHAIN or (not KEYCHAIN_PW and keychain_state() != "unlocked"):
        return None
    if KEYCHAIN_PW:
        u = _sec_wait(["/usr/bin/security", "unlock-keychain", "-p", KEYCHAIN_PW, KEYCHAIN])
        if u is None or u.returncode != 0:
            log("keychain unlock failed rc=%s" % (u.returncode if u else "pending"))
            return None
    return _sec_wait(["/usr/bin/security", "-i"], input_text=command + "\n")


_PAIR = {"v": None}
SEC_NOT_FOUND = 44          # `security find-/delete-generic-password`: the item does not exist
PENDING_ACCOUNT = REFRESH_ACCOUNT + ".pending"   # E2-02: verified new token, not yet final


def pairing_secret():
    """E2-06: read ONCE and kept in memory, like the access token. Before 1.0 every request
    spawned `security` (about 2 a second while a connect was polled)."""
    if _PAIR["v"]:
        return _PAIR["v"]
    r = _sec(["find-generic-password", "-a", "ga4-helper-pairing", "-s", "ga4-bridge", "-w"])
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
        # E2-02: a store interrupted after it deleted the old item holds the new one here
        kind, v = _read_account(PENDING_ACCOUNT)
    return kind, v


def _read_account(account):
    r = _sec(["find-generic-password", "-a", account, "-s", "ga4-bridge", "-w"])
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
    def add(account):
        return _sec_stdin('add-generic-password -a %s -s ga4-bridge -T /usr/bin/security '
                          '-w "%s" "%s"' % (account, value, KEYCHAIN))

    def delete(account):
        r = _sec(["delete-generic-password", "-a", account, "-s", "ga4-bridge"])
        return r is not None and r.returncode in (0, SEC_NOT_FOUND)

    if not delete(PENDING_ACCOUNT):                     # a stale pending item from before
        return False
    if add(PENDING_ACCOUNT) is None or _read_account(PENDING_ACCOUNT) != ("present", value):
        log("refresh token store: the new token could not be verified; the old one is intact")
        delete(PENDING_ACCOUNT)
        return False
    if not delete(REFRESH_ACCOUNT):
        log("refresh token store: the old item could not be removed; the new token stays pending")
        return False
    if add(REFRESH_ACCOUNT) is None or _read_account(REFRESH_ACCOUNT) != ("present", value):
        log("refresh token store: the final item could not be verified; the new token is read "
            "from the pending item")
        return refresh_token_read() == ("present", value)
    delete(PENDING_ACCOUNT)
    return True


def refresh_token_clear():
    """True only when the item is GONE: deleted now, or `security` says it was not there."""
    ok = True
    for account in (REFRESH_ACCOUNT, PENDING_ACCOUNT):
        r = _sec(["delete-generic-password", "-a", account, "-s", "ga4-bridge"])
        ok = ok and r is not None and r.returncode in (0, SEC_NOT_FOUND)
    return ok


# ------------------------------------------------------------------ persistence
_SAVE_LOCK = threading.Lock()


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


def record_verification(ok, prop):
    """Set google_access from a verification JUST MADE, and record whose it was (V6-5)."""
    with LOCK:
        STATE["google_access"] = "verified" if ok else "not_verified"
        STATE["property"] = prop
        STATE["verification"] = {"connection_id": STATE["connection_id"], "run_id": RUN_ID,
                                 "at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "ok": bool(ok)}


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
        evs = json.load(open(LAUNCHER_STATUS)).get("events", [])
    except Exception:
        return {"last_report_at": None, "last_tool": None, "verified": False}
    reports = [e for e in evs if e.get("kind") == "report"]
    if not reports:
        return {"last_report_at": None, "last_tool": None, "verified": False}
    last = reports[-1]
    return {"last_report_at": last.get("at"), "last_tool": last.get("tool"), "verified": True}


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
    prop = None
    for acc in d.get("accountSummaries", []):
        for ps in acc.get("propertySummaries", []):
            prop = {"id": (ps.get("property") or "").split("/")[-1],
                    "name": ps.get("displayName")}
            break
        if prop:
            break
    return True, None, prop


# ------------------------------------------------------------------ the loopback callback
# REAL-RUN DEFECT HLP-1 (Reviewer 22:32, step 4 of the Owner's run). The callback was an
# HTTP/1.1 handler on a SINGLE-THREADED HTTPServer. After answering, handle() kept Chrome's
# keep-alive connection and blocked in readline() with no timeout, so serve_forever never got
# back to its loop. srv.shutdown() in complete_flow then waited on it, and so did the
# shutdown do_GET had spawned. The code exchange never ran, and the flow stayed `pending`.
# The S2L tests' clients closed their connections, which hid it. Now every reply closes its
# connection, every socket has a timeout, the server is threaded (an idle preconnect cannot
# pin the accept loop either), and complete_flow's stop is bounded.
CALLBACK_SOCKET_TIMEOUT = 5     # s: an idle or held browser socket releases its handler
CALLBACK_STOP_BOUND = 5         # s: the longest complete_flow waits for the listener to stop


class _CallbackServer(ThreadingHTTPServer):
    """One flow's loopback listener. Threaded, with daemon handlers and no join on close."""
    daemon_threads = True
    block_on_close = False


class _CallbackHandler(BaseHTTPRequestHandler):
    """Receives Google's redirect. Short-lived: it exists only for one flow."""
    protocol_version = "HTTP/1.1"
    timeout = CALLBACK_SOCKET_TIMEOUT
    box = None          # E2-05: set per flow on a subclass; never shared between two flows

    def log_message(self, *a):
        pass

    def _reply(self, code, msg):
        self.close_connection = True
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(msg)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(msg)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = dict(urllib.parse.parse_qsl(u.query))
        # Only the redirect counts, and only the FIRST one: a browser's /favicon.ico (or any
        # other request) on this port must not overwrite it.
        if u.path != "/callback" or not (q.get("state") or q.get("error")):
            return self._reply(404, b"Not found.")
        with self.box["lock"]:
            if self.box["result"] is None:
                self.box["result"] = q
        self._reply(200, b"You can close this window and return to the site.")


def start_callback_listener():
    """Bind an EPHEMERAL loopback port and serve this flow's redirect.

    Ephemeral because a fixed callback port is a fixed thing to collide with, and because the
    plan asserts the listener is not left listening afterwards.
    """
    box = {"result": None, "lock": threading.Lock(), "cancel": threading.Event()}
    handler = type("_FlowCallbackHandler", (_CallbackHandler,), {"box": box})
    srv = _CallbackServer(("127.0.0.1", 0), handler)     # loopback ONLY, port 0
    srv.box = box
    t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
    t.start()
    srv.serve_thread = t
    return srv, srv.server_address[1]


def _stop_callback(srv):
    """Stop one flow's listener with NO unbounded wait. shutdown() waits for the accept loop,
    so it runs in its own thread under a join bound; the listening socket is closed anyway."""
    s = threading.Thread(target=srv.shutdown, daemon=True)
    s.start()
    s.join(CALLBACK_STOP_BOUND)
    t = getattr(srv, "serve_thread", None)
    if t is not None:
        t.join(CALLBACK_STOP_BOUND)
    try:
        srv.server_close()
    except Exception:
        pass
    if s.is_alive() or (t is not None and t.is_alive()):
        log("callback listener did not stop within %ss; its socket is closed anyway"
            % CALLBACK_STOP_BOUND)


def complete_flow(srv, state_key, timeout=120):
    """Wait for the callback, then exchange the code. Returns (ok, detail)."""
    box = srv.box
    end = time.time() + timeout
    try:
        while time.time() < end and box["result"] is None and not box["cancel"].is_set():
            time.sleep(0.05)
        q = box["result"]
        _stop_callback(srv)
    finally:
        # E2-05: the verifier never outlives its flow, whatever the outcome
        with LOCK:
            pending = _PENDING.pop(state_key, None)
            if _ACTIVE_FLOW.get("srv") is srv:
                _ACTIVE_FLOW.clear()
    if box["cancel"].is_set() and q is None:
        return False, "superseded"
    if q is None:
        return False, "timeout"
    # The state check happens HERE, before any exchange: a callback whose state we did not
    # issue is refused by us, not by the provider.
    if q.get("state") != state_key or pending is None:
        log("callback state mismatch; refused before any exchange")
        return False, "state_mismatch"
    if q.get("error"):
        log("user did not consent: %s" % q.get("error"))
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


# ------------------------------------------------------------------ the HTTP surface
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 30            # E2-18: an idle keep-alive connection no longer pins a thread

    def log_message(self, fmt, *args):
        # Logged, unlike Stage 1's silent handler. E2RIG exists because that silence made a
        # browser block and a helper refusal indistinguishable in the evidence.
        sys.stderr.write("[helper-http] %s\n" % (fmt % args))
        sys.stderr.flush()

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
                return (503, "keychain locked: unlock it")
            return (503, "helper not paired")
        if not hmac.compare_digest(self.headers.get("X-Pair-Secret") or "", want):
            return (401, "not paired")
        return None

    def do_OPTIONS(self):
        """E2-18: the CORS preflight a browser sends before a JSON POST from the site."""
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

    def _public_state(self):
        out = {k: STATE[k] for k in ("helper", "property", "local_credential",
                                     "provider_authorization", "connection_id")}
        out["google_access"] = published_access()
        out["keychain"] = keychain_state()
        out["last_flow"] = STATE.get("last_flow")
        v = STATE["verification"]
        out["verification"] = ({k: v.get(k) for k in ("connection_id", "run_id", "at")}
                               if v else None)
        out["run_id"] = RUN_ID
        out["claude"] = claude_row()
        return out

    def do_GET(self):
        if self.path == "/health":
            return self._send(200, {"helper": "running", "service": SERVICE, "version": VERSION,
                                    "run_id": RUN_ID})
        if self.path == "/status":
            bad = self._authorised()
            if bad:
                return self._send(bad[0], {"error": bad[1]})
            return self._send(200, self._public_state())
        return self._send(404, {"error": "no such path"})

    def do_POST(self):
        if self.path not in ("/connect/start", "/connect/callback-wait", "/disconnect",
                             "/verify", "/compare"):
            return self._send(404, {"error": "no such path"})
        bad = self._authorised(paired_only=(self.path == "/compare"))
        if bad:
            return self._send(bad[0], {"error": bad[1]})

        if self.path == "/compare":
            # KPI-3, ruling D3: the helper makes BOTH GA4 calls itself; the access token never
            # leaves this process. Paired local tools only (no Origin): the answer carries
            # report rows, which the site must never receive (D5 condition).
            try:
                n = int(self.headers.get("Content-Length") or 0)
                req = json.loads(self.rfile.read(n) or b"{}") if n else {}
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
            flow_id = _b64u(os.urandom(9))
            with LOCK:
                STATE["last_flow"] = {"id": flow_id, "outcome": "pending", "detail": None}
            verifier = _b64u(os.urandom(32))
            challenge = _b64u(hashlib.sha256(verifier.encode()).digest())
            state_key = _b64u(os.urandom(16))
            srv, cbport = start_callback_listener()
            redirect = "http://127.0.0.1:%d/callback" % cbport
            with LOCK:
                old = _ACTIVE_FLOW.get("srv")
                if old is not None:
                    old.box["cancel"].set()      # E2-05: the previous flow ends as superseded
                _ACTIVE_FLOW.clear()
                _ACTIVE_FLOW.update(srv=srv, flow_id=flow_id)
                _PENDING[state_key] = {"verifier": verifier, "redirect": redirect,
                                       "at": time.time()}
            url = AUTH_URI + "?" + urllib.parse.urlencode({
                "client_id": CLIENT_ID, "redirect_uri": redirect,
                "response_type": "code", "scope": SCOPE, "state": state_key,
                "code_challenge": challenge, "code_challenge_method": "S256",
                "access_type": "offline", "prompt": "consent"})

            def finish():
                ok, detail = complete_flow(srv, state_key)
                with LOCK:
                    if (STATE.get("last_flow") or {}).get("id") == flow_id:
                        STATE["last_flow"] = {
                            "id": flow_id,
                            "outcome": "completed" if ok else (
                                "cancelled" if detail == "access_denied" else
                                "superseded" if detail == "superseded" else "failed"),
                            "detail": None if ok else detail}
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
                record_verification(ok2, prop)
                state_save()
                log("flow complete; google_access=%s" % STATE["google_access"])

            threading.Thread(target=finish, daemon=True).start()
            # The authorization URL and the callback port. NO verifier, NO state secret,
            # and nothing the site could replay.
            return self._send(200, {"authorize_url": url, "callback_port": cbport,
                                    "flow_id": flow_id})

        if self.path == "/verify":
            ok, err, prop = verify_google_access()
            record_verification(ok, prop)
            state_save()
            # "Google access verified" says NOTHING about Claude (clarification 7).
            return self._send(200, {"google_access": published_access(),
                                    "property": prop, "error": err,
                                    "claude": claude_row()})

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
    r = _sec(["find-generic-password", "-a", "ga4-helper-pairing", "-s", "ga4-bridge", "-w"])
    if r is None or r.returncode != SEC_NOT_FOUND:
        return
    secret = _b64u(os.urandom(24))
    w = _sec_stdin('add-generic-password -a ga4-helper-pairing -s ga4-bridge -T /usr/bin/security '
                   '-w "%s" "%s"' % (secret, KEYCHAIN))
    log("pairing secret %s" % ("created" if w is not None and pairing_secret() == secret
                               else "could NOT be created"))


def reverify_after_restart():
    """A restart RESUMES the connection without new setup (V7-4), but it does not resume the
    old verdict: the persisted "verified" belongs to another run. One minimal call re-earns it.
    Until it returns, /status says "unverified" -- true, and not a request to reconnect."""
    ok, err, prop = verify_google_access()
    record_verification(ok, prop)
    state_save()
    log("re-verified after restart: %s%s" % ("verified" if ok else "not_verified",
                                              "" if ok else " (%s)" % err))


def main():
    ensure_pairing()
    state_load()
    if STATE["local_credential"] == "present" and CONFIGURED and _keychain_readable():
        threading.Thread(target=reverify_after_restart, daemon=True).start()
    port = int(os.environ.get("GA4_HELPER_PORT", str(DEFAULT_PORT)))
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)   # loopback ONLY
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


if __name__ == "__main__":
    main()
