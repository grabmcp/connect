#!/usr/bin/env python3
"""rrk.py — the Owner's driver for the real run (kit §4). Every command REPORTS what it measured.

Why it exists (TASK KIT2):
  * F-1: the pairing secret must go into the DEDICATED keychain without the keychain ever being
    added to the user search list, and without any secret in argv. `security
    add-generic-password` prompts only when -w is the LAST option, but the keychain must be the
    last argument; measured on a scratch keychain, `... <keychain> -w` is a usage error. So
    `pairing-set` feeds the command to `security -i` on STDIN: the secret never appears in any
    argv, the item still trusts /usr/bin/security (-T), which the helper reads it with, and the
    search list is captured before and after and printed.
  * The site page only PROBES (/health, /status); it has no Connect, Disconnect or pairing
    field. Until it does, `connect`, `status` and `disconnect` drive the helper exactly as the
    site would: the allowed Origin and the pairing secret, read from the keychain at the moment
    of the call. The Owner never sees or types it.

Commands (the helper defaults to http://127.0.0.1:50802):
  keychain-create  record the user search list, create the dedicated keychain (the password is
                   PROMPTED by `security`), turn auto-lock off, RESTORE the search list, print
                   before / after / verdict (KIT3 C1: this logic lives here, tested, not in a
                   pasted shell block)
  move-client      rename the one downloaded client_secret_*.json to ga4-oauth-client.json,
                   mode 0600, and check it is the Desktop (installed) type (KIT3 C6)
  pairing-set      generate a pairing secret and store it in the keychain (replacing any)
  status           print the helper's /status
  connect          start a flow, open Google's consent page, wait for THIS flow's outcome
  disconnect       revoke and delete; print both states
  calls            print the launcher's call record (tool, arguments, ok, digest; KIT3 C2)
  adc-check        is there an adc.json in the extension's private directory? (step 9f)
  egress           sample the extension's process tree's sockets during a call (X-1)
  lock             lock the keychain and show it locked (the final step)
Every command also writes what it printed to --log (default: run-logs/<command>.log beside
this kit). Nothing secret is ever printed, so nothing secret is ever logged (KIT3 C7).
Exit codes: 0 done, 1 failed (said why), 3 keychain locked (unlock it and run again).
"""
import argparse
import ctypes
import glob
import os
import ctypes.util
import hashlib
import json
import secrets
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

ORIGIN = "http://localhost:50803"
SERVICE = "ga4-bridge"
PAIR_ACCOUNT = "ga4-helper-pairing"
# Overridable ONLY so the test suite can drive keychain-create against a FAKE `security` and
# never touch the real search list. The Owner never sets it.
SEC = os.environ.get("RRK_SECURITY", "/usr/bin/security")
LSOF = os.environ.get("RRK_LSOF", "/usr/sbin/lsof")      # likewise: test-only override
KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXT_ROOT = os.path.expanduser("~/Library/Application Support/Claude/Claude Extensions")


class _Tee:
    def __init__(self, path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.f = open(path, "a", encoding="utf-8")
        self.out = sys.stdout
        self.f.write("\n=== %s  rrk.py %s ===\n" % (time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                                                   " ".join(sys.argv[1:])))
    def write(self, x):
        self.out.write(x); self.f.write(x); self.f.flush()
    def flush(self):
        self.out.flush(); self.f.flush()


def say(ok, msg):
    print(("  ✓ " if ok else "  ✗ ") + msg, flush=True)


def keychain_state(path):
    """unlocked | locked | absent | unknown, read WITHOUT any dialog (SecKeychainGetStatus)."""
    try:
        lib = ctypes.cdll.LoadLibrary(ctypes.util.find_library("Security"))
        ref = ctypes.c_void_p()
        if lib.SecKeychainOpen(path.encode(), ctypes.byref(ref)) != 0:
            return "unknown"
        st = ctypes.c_uint32()
        rc = lib.SecKeychainGetStatus(ref, ctypes.byref(st))
        if rc == -25294:
            return "absent"
        if rc != 0:
            return "unknown"
        return "unlocked" if st.value & 1 else "locked"
    except Exception:
        return "unknown"


def require_unlocked(path):
    st = keychain_state(path)
    if st == "unlocked":
        say(True, "keychain %s is unlocked" % path)
        return
    if st == "locked":
        say(False, "keychain is LOCKED. Run:  security unlock-keychain %s   (type the password "
                   "at the prompt), then run this again" % path)
        sys.exit(3)
    say(False, "keychain %s is %s" % (path, st))
    sys.exit(1)


def sec_run(argv, input_text=None, bound=15.0):
    """Run `security` with a bounded WAIT that NEVER kills it (0.5.0 package, C2; the 08:38 rule:
    killing a `security` that waits on a prompt crashed securityd on 2026-10-04). Past the bound
    the driver says so plainly, leaves the process running, and stops (exit 4)."""
    # E2-08: its OWN session, so the Owner's Ctrl-C (a signal to the terminal's foreground
    # group) never reaches a `security` that may be waiting on a dialog.
    p = subprocess.Popen(argv, stdin=subprocess.PIPE if input_text is not None
                         else subprocess.DEVNULL, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True, start_new_session=True)
    box = {}
    t = threading.Thread(target=lambda: box.setdefault("out", p.communicate(input=input_text)),
                         daemon=True)
    t.start()
    t.join(bound)
    if t.is_alive():
        say(False, "a keychain command (pid %d) has not returned in %.0f s -- a macOS dialog may "
                   "be waiting for you. It is left running (never stopped by this tool). Answer "
                   "or close the dialog, then run this again." % (p.pid, bound))
        sys.exit(4)
    out, err = box["out"]
    return subprocess.CompletedProcess(argv, p.returncode, out, err)


def search_list():
    return sec_run([SEC, "list-keychains", "-d", "user"]).stdout


def search_list_checked():
    """(ok, text, why). KIT4 F-1: a "before" that was never actually READ must never be used:
    a failed or empty read once led to `list-keychains -s` with NO paths -- the login keychain
    removed from the search list -- and a printed IDENTICAL, because two failed reads compare
    equal. So: the read must exit 0, be non-empty, and contain the login keychain."""
    try:
        r = sec_run([SEC, "list-keychains", "-d", "user"])
    except Exception as e:
        return False, "", "the search-list read raised %s" % type(e).__name__
    if r.returncode != 0:
        return False, r.stdout, "the search-list read exited %d" % r.returncode
    if not r.stdout.strip():
        return False, r.stdout, "the search-list read returned nothing"
    if "login.keychain-db" not in r.stdout:
        return False, r.stdout, "the search list does not contain login.keychain-db"
    return True, r.stdout, ""


def secrets_dir_0700(path):
    """KIT4 F-4: ~/grabmcp-secrets is 0700 -- enforced, then CHECKED (a chmod that did not take
    must not pass)."""
    os.makedirs(path, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)
    mode = oct(os.stat(path).st_mode & 0o777)
    say(mode == "0o700", "%s is mode %s" % (path, mode))
    return mode == "0o700"


def security_stdin(command):
    """Run ONE `security` command fed on stdin (security -i): nothing of it reaches argv."""
    return sec_run([SEC, "-i"], input_text=command + "\n", bound=30.0)


_PAIR_CACHE = {}


def pairing_get(path):
    """E2-06: read ONCE per command; before 1.0 every helper call spawned `security`."""
    if path in _PAIR_CACHE:
        return _PAIR_CACHE[path]
    r = sec_run([SEC, "find-generic-password", "-a", PAIR_ACCOUNT, "-s", SERVICE, "-w", path])
    v = r.stdout.strip() if r.returncode == 0 else None
    if v:
        _PAIR_CACHE[path] = v
    return v


def sec_interactive(argv):
    """E2-07: a `security` that must PROMPT on this terminal (create-keychain). It keeps the
    terminal (no new session, or it could not prompt) and is WAITED for, never killed:
    `subprocess.run` SIGKILLs its child on ANY exception, a Ctrl-C included."""
    p = subprocess.Popen(argv)
    while True:
        try:
            return subprocess.CompletedProcess(argv, p.wait(), None, None)
        except KeyboardInterrupt:
            say(False, "interrupted -- the keychain command (pid %d) is NOT stopped by this "
                       "tool; waiting for it to finish" % p.pid)


def cmd_pairing_set(a):
    print("pairing-set: store a NEW pairing secret in %s" % a.keychain)
    require_unlocked(a.keychain)
    ok_b, before, why = search_list_checked()
    if not ok_b:
        say(False, "STOP: %s -- nothing was stored" % why)
        sys.exit(1)
    value = secrets.token_urlsafe(24)          # [A-Za-z0-9_-]: no quoting needed for security -i
    security_stdin('delete-generic-password -a %s -s %s "%s"' % (PAIR_ACCOUNT, SERVICE, a.keychain))
    r = security_stdin('add-generic-password -a %s -s %s -T %s -w %s "%s"'
                       % (PAIR_ACCOUNT, SERVICE, SEC, value, a.keychain))
    back = pairing_get(a.keychain)
    ok_a, after, _w = search_list_checked()
    ok_store = r.returncode == 0 and back == value
    say(ok_store, "pairing secret stored and read back from the keychain (%d chars; value not "
                  "shown)" % len(value))
    print("  search list BEFORE sha256 %s" % hashlib.sha256(before.encode()).hexdigest())
    print("  search list AFTER  sha256 %s" % hashlib.sha256(after.encode()).hexdigest())
    same = ok_a and before == after
    say(same, "search list unchanged" if same else
        "search list CHANGED or unreadable -- STOP and report it")
    sys.exit(0 if ok_store and same else 1)


def call(a, method, path, timeout=20):
    secret = pairing_get(a.keychain)
    if not secret:
        say(False, "no pairing secret in the keychain -- run pairing-set first")
        sys.exit(1)
    req = urllib.request.Request(a.helper + path, data=b"" if method == "POST" else None,
                                 method=method,
                                 headers={"Origin": ORIGIN, "X-Pair-Secret": secret})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as f:
            return f.status, json.loads(f.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or "{}")
        except Exception:
            return e.code, {}
    except Exception as e:
        return 0, {"_transport": type(e).__name__}


def show(code, body):
    print("  HTTP %s %s" % (code, json.dumps(body, sort_keys=True)))


def cmd_status(a):
    print("status: the helper's view")
    require_unlocked(a.keychain)
    code, body = call(a, "GET", "/status")
    show(code, body)
    sys.exit(0 if code == 200 else 1)


def cmd_connect(a):
    """Start a flow and wait for the outcome of THAT flow (KIT3 C4).

    An existing verified credential is not this flow's result: the helper reports the latest
    attempt by its own id (`last_flow`), so a cancel is reported as cancelled even while an
    older connection stays verified -- and a completed flow then waits for the verification of
    the NEW connection, not the old one.
    """
    print("connect: start the Google authorization")
    require_unlocked(a.keychain)
    code, body = call(a, "POST", "/connect/start")
    if code != 200 or not body.get("authorize_url") or not body.get("flow_id"):
        show(code, body)
        say(False, "the helper did not start a flow")
        sys.exit(1)
    url, fid = body["authorize_url"], body["flow_id"]
    before_conn = call(a, "GET", "/status")[1].get("connection_id")
    print("  flow %s started" % fid, flush=True)
    if a.no_open:
        print("AUTHORIZE_URL " + url, flush=True)
    else:
        subprocess.run(["/usr/bin/open", url], timeout=15)
        say(True, "Google's consent page opened in the browser. EXPECT the unverified-app "
                  "warning; proceed, then grant Analytics read-only")
    st, outcome, end = {}, "pending", time.time() + a.wait
    denied = 0
    while time.time() < end:
        code, st = call(a, "GET", "/status")
        if code in (401, 403):
            # KIT5 G-5: a REFUSAL is not transient. Three in a row and we stop at once, instead
            # of waiting out the whole window on a pairing secret or origin that is wrong.
            denied += 1
            if denied >= 3:
                show(code, st)
                say(False, "the helper REFUSES this driver (HTTP %s: %s) -- the pairing secret "
                           "or the allowed origin does not match; STOP" % (code, st.get("error")))
                sys.exit(1)
            time.sleep(1)
            continue
        denied = 0
        if code != 200:
            # KIT4 F-6: a transient transport error is NOT "another flow" -- say what it is
            # and keep waiting for this flow's outcome.
            print("  (the helper did not answer: HTTP %s %s -- still waiting)"
                  % (code, st.get("_transport", "")), flush=True)
            time.sleep(1)
            continue
        lf = st.get("last_flow") or {}
        if not lf.get("id"):
            # KIT5 G-5: after a helper RESTART it knows no flow at all; that is not "another
            # flow (None)" -- say what happened.
            say(False, "the helper no longer knows this flow (was it restarted?) -- run connect "
                       "again")
            sys.exit(1)
        if lf.get("id") != fid:
            say(False, "another flow (%s) replaced this one" % lf.get("id"))
            sys.exit(1)
        if lf.get("outcome") != "pending":
            outcome = lf.get("outcome")
            break
        time.sleep(1)
    print("  this flow: %s%s" % (outcome, (" (%s)" % (st.get("last_flow") or {}).get("detail"))
                                 if outcome in ("failed", "cancelled") else ""), flush=True)
    if outcome == "cancelled":
        show(code, st)
        say(False, "cancelled at Google's consent screen -- nothing changed: the connection "
                   "status above is whatever it was before")
        sys.exit(1)
    if outcome != "completed":
        show(code, st)
        say(False, "the flow did not complete (%s)" % outcome)
        sys.exit(1)
    while time.time() < end:
        code, st = call(a, "GET", "/status")
        v = st.get("verification") or {}
        if st.get("connection_id") and st.get("connection_id") != before_conn \
                and v.get("connection_id") == st.get("connection_id") \
                and st.get("google_access") in ("verified", "not_verified"):
            break
        time.sleep(1)
    show(code, st)
    done = st.get("google_access") == "verified"
    say(done, "Google access verified for the NEW connection" if done else
        "not verified (see the status above)")
    sys.exit(0 if done else 1)


def cmd_disconnect(a):
    print("disconnect: revoke at Google and delete the local copy")
    require_unlocked(a.keychain)
    code, body = call(a, "POST", "/disconnect")
    show(code, body)
    ok = code == 200 and body.get("local_credential") == "absent"
    say(ok, "local copy %s; Google authorization %s" % (body.get("local_credential"),
                                                       body.get("provider_authorization")))
    sys.exit(0 if ok else 1)


def cmd_keychain_create(a):
    print("keychain-create: %s" % a.keychain)
    if os.path.exists(a.keychain):
        say(False, "a keychain already exists at that path -- not touching it")
        sys.exit(1)
    ok_b, before, why = search_list_checked()
    if not ok_b:
        print(before.rstrip())
        say(False, "STOP: %s -- NOTHING was created, nothing was changed" % why)
        sys.exit(1)
    if not secrets_dir_0700(os.path.dirname(a.keychain)):
        say(False, "STOP: the secrets folder is not 0700 -- nothing was created")
        sys.exit(1)
    print("== search list BEFORE ==\n" + before.rstrip())
    print("  you will now be PROMPTED twice for the new keychain's password", flush=True)
    r = sec_interactive([SEC, "create-keychain", a.keychain])
    say(r.returncode == 0, "create-keychain exit %d" % r.returncode)
    if r.returncode != 0:
        sys.exit(1)
    sec_run([SEC, "set-keychain-settings", a.keychain])
    mid = search_list()
    print("== search list AFTER create-keychain ==\n" + mid.rstrip())
    paths = [shlex_first(l) for l in before.splitlines() if l.strip()]
    if not paths or not any(p_.endswith("login.keychain-db") for p_ in paths):
        say(False, "STOP: refusing to set a search list without the login keychain")
        sys.exit(1)
    sec_run([SEC, "list-keychains", "-d", "user", "-s"] + paths)
    ok_a, after, why_a = search_list_checked()
    if not ok_a:
        say(False, "the AFTER read failed: %s" % why_a)
    print("== search list AFTER restore ==\n" + after.rstrip())
    same = ok_a and after == before
    print("SEARCH LIST: %s" % ("IDENTICAL" if same else "DIFFERS -- STOP"))
    info = sec_run([SEC, "show-keychain-info", a.keychain])
    txt = (info.stdout + info.stderr).strip()
    print("  " + txt)
    say("no-timeout" in txt, "auto-lock is off" if "no-timeout" in txt else
        "auto-lock is NOT off -- STOP")
    sys.exit(0 if same and "no-timeout" in txt else 1)


def shlex_first(line):
    import shlex
    return shlex.split(line)[0]


def cmd_move_client(a):
    d = os.path.expanduser(a.dir)
    print("move-client: in %s" % d)
    if not secrets_dir_0700(d):
        sys.exit(1)
    target = os.path.join(d, "ga4-oauth-client.json")
    found = sorted(glob.glob(os.path.join(d, "client_secret_*.json")))
    if os.path.exists(target) and not found:
        say(True, "already in place: %s" % target)
    elif len(found) != 1:
        say(False, "expected exactly ONE client_secret_*.json, found %d -- STOP" % len(found))
        sys.exit(1)
    elif os.path.exists(target):
        say(False, "%s already exists AND a client_secret_*.json is present -- STOP" % target)
        sys.exit(1)
    else:
        os.rename(found[0], target)
        say(True, "renamed %s -> %s" % (os.path.basename(found[0]), os.path.basename(target)))
    os.chmod(target, 0o600)
    mode = oct(os.stat(target).st_mode & 0o777)
    try:
        doc = json.load(open(target, encoding="utf-8"))
    except Exception:
        doc = {}
    kind = "installed" if "installed" in doc else ("web" if "web" in doc else "unknown")
    say(mode == "0o600", "mode %s" % mode)
    say(kind == "installed", "client type: %s%s" % (kind, "" if kind == "installed" else
                                                    " -- NOT the Desktop client: STOP"))
    sys.exit(0 if mode == "0o600" and kind == "installed" else 1)


def _status_files(root):
    return sorted(glob.glob(os.path.join(root, "*", ".private", "status.json")))


def read_record(path, quiet=False):
    """The launcher's call record, read TOLERANTLY (LCH-3). 0.4.0 launchers could leave valid JSON
    followed by the tail of an older, longer write; json.load then raised and this tool crashed
    (2026-10-05 08:26). Now the first JSON document is read and anything after it is NAMED, with
    its byte count -- never silently dropped. Copies the 0.5.0 launcher kept of an unreadable
    record (status.json.corrupt-*) are listed too."""
    raw = open(path, encoding="utf-8", errors="replace").read()
    try:
        doc, end = json.JSONDecoder().raw_decode(raw.lstrip())
        tail = raw.lstrip()[end:].strip()
    except ValueError as e:
        if not quiet:
            say(False, "the record %s is not readable JSON at all (%s); %d bytes left untouched"
                % (path, e.msg, len(raw)))
        return []
    if tail and not quiet:
        say(False, "the record %s has %d trailing byte(s) after its first JSON document -- a "
                   "damaged write (LCH-3); the events below are the readable part" % (path, len(tail)))
    if not quiet:
        for c in sorted(glob.glob(path + ".corrupt-*")):
            print("  kept damaged record: %s (%d bytes)" % (c, os.path.getsize(c)))
    return doc.get("events", []) if isinstance(doc, dict) else []


def cmd_calls(a):
    root = os.path.expanduser(a.ext_root)
    print("calls: the launcher's call record under %s" % root)
    files = [f for f in _status_files(root)
             if os.path.exists(os.path.join(os.path.dirname(os.path.dirname(f)), "launcher.py"))]
    if not files:
        say(False, "no launcher status file found (the extension's folder name is UNVERIFIED; "
                   "send the Reviewer this output)")
        sys.exit(1)
    for f in files:
        print("  file: %s" % f)
        for e in read_record(f):
            # 0.5.0: the launcher's re-read and restart are part of the record the Owner reads here
            # (block G); 0.5.0-as-built omitted them, so a live restart was invisible (2026-10-05 10:23).
            if e.get("kind") in ("call", "credential", "initialize", "credential_reread",
                                 "upstream_restart"):
                print("  " + json.dumps(e, sort_keys=True))
    sys.exit(0)


def cmd_adc_check(a):
    root = os.path.expanduser(a.ext_root)
    print("adc-check: credential files under %s" % root)
    dirs = sorted(d for d in glob.glob(os.path.join(root, "*"))
                  if os.path.exists(os.path.join(d, "launcher.py")))
    if not dirs:
        say(False, "no extension folder with a launcher found (folder name UNVERIFIED)")
        sys.exit(1)
    left = []
    for d in dirs:
        # 0.5.0: one credential file per launcher instance (adc-<pid>.json), plus 0.4.x's adc.json
        found = sorted(glob.glob(os.path.join(d, ".private", "adc-*.json"))
                       + glob.glob(os.path.join(d, ".private", "adc.json")))
        print("  %s: %s" % (d, ", ".join(os.path.basename(x) for x in found) + " PRESENT"
                            if found else "no credential file (absent)"))
        left.extend(found)
    say(not left, "no credential file left" if not left else
        "a credential file is present -- if Claude Desktop is QUIT, this is a leftover")
    sys.exit(0 if not left else 1)


def _tree(roots):
    ps = subprocess.run(["/bin/ps", "-ax", "-o", "pid=,ppid="], capture_output=True,
                        text=True).stdout
    kids = {}
    for line in ps.splitlines():
        f = line.split()
        if len(f) == 2:
            kids.setdefault(int(f[1]), []).append(int(f[0]))
    out, todo = set(roots), list(roots)
    while todo:
        for c in kids.get(todo.pop(), []):
            if c not in out:
                out.add(c); todo.append(c)
    return out


IPRANGES = os.path.join(KIT, "tools", "ipranges")   # a SHIPPED snapshot; never fetched at run time
_RANGES = None


def _ranges():
    """(google_service_nets, cloud_customer_nets, snapshot_label) from the shipped snapshot of
    Google's published lists (gstatic.com/ipranges goog.json and cloud.json). goog.json lists
    every Google-owned range; cloud.json the part of it rented to Google Cloud CUSTOMERS. An
    address in goog.json and not in cloud.json is Google itself. A missing or unreadable
    snapshot classifies nothing, and says so: it must never make OTHER read as Google."""
    global _RANGES
    if _RANGES is None:
        import ipaddress
        try:
            g = json.load(open(os.path.join(IPRANGES, "goog.json"), encoding="utf-8"))
            c = json.load(open(os.path.join(IPRANGES, "cloud.json"), encoding="utf-8"))
            nets = lambda d: [ipaddress.ip_network(p_.get("ipv4Prefix") or p_.get("ipv6Prefix"))
                              for p_ in d.get("prefixes", [])]
            _RANGES = (nets(g), nets(c), "goog.json/cloud.json of %s" % g.get("creationTime"))
        except Exception as e:
            _RANGES = ([], [], "NO usable snapshot (%s): bare IPs stay OTHER" % type(e).__name__)
    return _RANGES


def _snapshot_age_days():
    """Days since the shipped snapshot's own creationTime; None if it cannot be read."""
    try:
        ct = json.load(open(os.path.join(IPRANGES, "goog.json"), encoding="utf-8"))["creationTime"]
        t0 = time.mktime(time.strptime(ct[:19], "%Y-%m-%dT%H:%M:%S"))
        return int((time.time() - t0) // 86400)
    except Exception:
        return None


def _classify(host):
    h = host.strip("[]")
    if h.startswith("127.") or h in ("localhost", "::1", "*"):
        return "loopback"
    if h.endswith((".googleapis.com", ".1e100.net", ".google.com", ".gstatic.com")):
        return "Google"
    import ipaddress
    try:
        a = ipaddress.ip_address(h)
    except ValueError:
        return "OTHER"                    # a name that is not Google's
    goog, cloud, _ = _ranges()
    if any(a in n for n in cloud if n.version == a.version):
        return "OTHER"                    # Google Cloud CUSTOMER range: not Google itself
    if any(a in n for n in goog if n.version == a.version):
        return "Google"                   # Google-owned, not rented: Google itself
    return "OTHER"


def _call_events_since(root, t0):
    """run_report call events recorded by any launcher under root at or after time t0."""
    out = []
    for f in _status_files(root):
        try:
            evs = read_record(f, quiet=True)
        except Exception:
            continue
        for e in evs:
            if e.get("kind") != "call" or e.get("tool") != "run_report":
                continue
            try:
                at = time.mktime(time.strptime(e.get("at", "")[:19], "%Y-%m-%dT%H:%M:%S"))
            except Exception:
                continue
            if at >= t0 - 1:
                out.append(e)
    return out


def cmd_egress(a):
    """X-1 for the real run: SAMPLE the sockets of the extension's process tree (launcher and
    Google's server) while the Owner asks a question.

    KIT5 G-1: observing NOTHING is not a pass. The verdict is PASS only if the window saw at
    least one Google destination AND a new run_report call was recorded by a launcher in the
    same window -- i.e. a real call happened while we watched. Otherwise INCONCLUSIVE (exit 2).
    KIT5 G-3: lsof runs WITHOUT -n so destinations are named by reverse DNS (Google's own:
    *.1e100.net, *.googleapis.com). An address with no reverse name shows as a bare IP and is
    listed as OTHER: report it -- it may still be Google (check it against Google's published
    ranges); OTHER is a question, not a verdict. A sample that times out is counted and shown.
    It is a SAMPLER: a connection shorter than one sample can be missed."""
    print("egress: sampling for %d s the process tree of every process whose command line "
          "contains %r (UNVERIFIED match: if none is found, pass --match with a fragment of the "
          "launcher's real path)" % (a.seconds, a.match))
    t0 = time.time()
    ps = subprocess.run(["/bin/ps", "-ax", "-o", "pid=,command="], capture_output=True,
                        text=True).stdout
    roots = [int(l.split(None, 1)[0]) for l in ps.splitlines()
             if a.match in l and "launcher.py" in l and "rrk.py" not in l]
    if not roots:
        say(False, "no launcher process found -- open Claude Desktop with the extension enabled, "
                   "or pass --match")
        sys.exit(2)
    print("  launchers: %s" % roots)
    seen, n, timeouts, end = {}, 0, 0, time.time() + a.seconds
    while time.time() < end:
        pids = _tree(roots)
        try:
            r = subprocess.run([LSOF, "-P", "-i", "-a", "-p",
                                ",".join(str(p_) for p_ in sorted(pids))],
                               capture_output=True, text=True, timeout=30)
            out = r.stdout
        except subprocess.TimeoutExpired:
            timeouts += 1
            out = ""
        n += 1
        for line in out.splitlines()[1:]:
            f = line.split()
            if len(f) < 9 or "->" not in f[8]:
                continue
            peer = f[8].split("->")[1]
            seen.setdefault(peer, _classify(peer.rpartition(":")[0]))
        time.sleep(0.5)
    print("  %d samples (%d timed out)" % (n, timeouts))
    print("  bare IPs classified against: %s" % _ranges()[2])
    age = _snapshot_age_days()
    if age is not None:
        print("  that snapshot is %d day(s) old%s" % (age, " -- STALE (over 90 days): ask for a "
                                                      "release with a fresh one" if age > 90 else ""))
    for peer, kind in sorted(seen.items()):
        print("  %-8s %s" % (kind, peer))
    other = [p_ for p_, k in seen.items() if k == "OTHER"]
    google = [p_ for p_, k in seen.items() if k == "Google"]
    calls = _call_events_since(os.path.expanduser(a.ext_root), t0)
    print("  run_report calls recorded in this window: %d" % len(calls))
    if other:
        say(False, "a destination that is not named as Google or loopback was seen -- report "
                   "it (a bare IP may still be Google)")
        sys.exit(1)
    if not google or not calls:
        say(False, "INCONCLUSIVE: %s -- ask the question again inside the window"
            % ("no Google destination was observed" if not google else
               "no run_report call was recorded in the window"))
        sys.exit(2)
    say(True, "PASS: %d Google destination(s), no other, during %d recorded run_report call(s)"
        % (len(google), len(calls)))
    sys.exit(0)


def cmd_lock(a):
    print("lock: %s" % a.keychain)
    sec_run([SEC, "lock-keychain", a.keychain])
    st = keychain_state(a.keychain)
    say(st == "locked", "keychain is %s" % st)
    sys.exit(0 if st == "locked" else 1)


def cmd_compare(a):
    """KPI-3: ONE Owner command. The paired helper makes both GA4 calls itself (ruling D3);
    this prints its answer side by side. No token ever reaches this process."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "rrk_compare", os.path.join(os.path.dirname(os.path.abspath(__file__)), "rrk_compare.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    secret = pairing_get(a.keychain)
    if not secret:
        say(False, "no pairing secret in the keychain -- the helper has not been set up")
        sys.exit(1)
    which = a.which if a.which == "last" else int(a.which)
    sys.exit(m.cmd_compare(a.helper, secret, which))


# Re-review N3: the 0.6.0 helper runs INSIDE the extension on 50812 and keeps its pairing secret in
# the LOGIN keychain (P1). `compare` therefore defaults to those; every other command keeps the
# 0.5.0 kit defaults, which the earlier kit and its tests rely on.
COMPARE_DEFAULTS = {"helper": "http://127.0.0.1:50812",
                    "keychain": os.path.expanduser("~/Library/Keychains/login.keychain-db")}


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("command", choices=["keychain-create", "move-client", "pairing-set", "status",
                                       "connect", "disconnect", "calls", "adc-check", "egress",
                                       "lock", "compare"])
    p.add_argument("--seconds", type=int, default=120)
    p.add_argument("--match", default="Claude Extensions")
    p.add_argument("--keychain", default=None)
    p.add_argument("--dir", default="~/grabmcp-secrets")
    p.add_argument("--ext-root", default=EXT_ROOT)
    p.add_argument("--log", default=None)
    p.add_argument("--helper", default=None)
    p.add_argument("--no-open", action="store_true", help="print the URL instead (tests)")
    p.add_argument("--wait", type=int, default=300)
    p.add_argument("--which", default="last", help="compare: 'last' or the report call's index")
    a = p.parse_args()
    if a.keychain is None:
        a.keychain = (COMPARE_DEFAULTS["keychain"] if a.command == "compare"
                      else os.path.expanduser("~/grabmcp-secrets/grabmcp-real.keychain-db"))
    if a.helper is None:
        a.helper = COMPARE_DEFAULTS["helper"] if a.command == "compare" else "http://127.0.0.1:50802"
    sys.stdout = _Tee(a.log or os.path.join(KIT, "run-logs", "%s.log" % a.command))
    {"keychain-create": cmd_keychain_create, "move-client": cmd_move_client,
     "pairing-set": cmd_pairing_set, "status": cmd_status, "connect": cmd_connect,
     "disconnect": cmd_disconnect, "calls": cmd_calls, "adc-check": cmd_adc_check,
     "egress": cmd_egress, "lock": cmd_lock, "compare": cmd_compare}[a.command](a)


if __name__ == "__main__":
    main()
