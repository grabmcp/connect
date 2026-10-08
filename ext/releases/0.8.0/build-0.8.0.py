#!/usr/bin/env python3
"""O7 -- the ONE build command for the 0.8.0 Claude extension (helper 1.2.0; derived from
build-0.7.0.py, PLAN-05 WP-X1: only the version changes; the variants, scans and checks are 0.7.0's).

    python3 ".../operations/20261002-p2-bridge-s1/releases/0.8.0/build-0.8.0.py" /abs/path/client.json
    python3 ".../releases/0.8.0/build-0.8.0.py" --variant qa [--qa-origin http://localhost:8765] /abs/client.json

Like 0.6.3 (gate conditions 1-2, Reviewer 12:05) it runs ONLY as the RELEASED copy, from its release
folder. It takes the extension's code from that folder, after verifying EVERY entry of the
`SHA256SUMS.txt` beside it, and Google's vendored server from `bundle/server`, after verifying it
against the pinned tree digest `SERVER-TREE.sha256` (itself sealed in SHA256SUMS.txt). Any
mismatch, a missing or an extra server file, refuses the build before anything is packed.

It stages the bundle in a fresh temporary folder (never inside a project folder), places YOUR
client file there as `oauth-client.json`, writes the allowed property into the launcher's one
build-time line (KPI-6, D2), packs an UNSIGNED `.mcpb`, checks the packed file against the stage,
removes the stage, and prints where the `.mcpb` is and its SHA-256.

  --property 449629553     the GA4 property the build may read (default: 449629553)
  --out ~/grabmcp-build    where the .mcpb is written (default; never inside a project folder)
  --variant release|qa     0.7.0 (INTERFACE-03 §6): `release` (default) packs the sealed files as
                           they are; `qa` rewrites the test constants in the STAGED copy only,
                           each rewrite asserted to apply exactly once:
                             manifest name ga4-bridge -> ga4-bridge-qa; helper port 50812 -> 50822;
                             keychain service ga4-bridge -> ga4-bridge-qa; helper service name
                             grabmcp-ga4-helper -> grabmcp-ga4-helper-qa; KEYCHAIN_OVERRIDE_ALLOWED
                             False -> True (helper and launcher); DEFAULT_ORIGINS -> only
                             --qa-origin; the state directory .../GrabMCP/ga4-bridge -> ...-qa;
                             0.8.0 (FX-5): the helper's binary-seam switch False -> True (only a qa
                             build honours GA4_HELPER_OPEN_BIN / _LSOF_BIN / _LSAPPINFO_BIN /
                             _BUNDLEID_BIN; a release runs its compiled-in binaries)
  --qa-origin URL          the ONE site origin a qa build admits (default http://localhost:8765)

Two scans run on the PACKED file, each with a control: a qa package must carry no release value,
and a release package no qa value. Before a scan is trusted it is run once on a seeded wrong copy
and must fail there (its control); a control that does not fail refuses the build.

The client file is read only to check its SHAPE (installed.client_id / client_secret present);
its values are never printed. The `.mcpb` CONTAINS the client file: keep it out of every
repository (D6). Nothing is uploaded anywhere: no network act.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
import zipfile

HERE = os.path.dirname(os.path.realpath(__file__))
# The ONLY supported location: <S1>/releases/<version>/build-<version>.py (gate condition 1).
S1 = os.path.dirname(os.path.dirname(HERE))
SERVER = os.path.join(S1, "bundle", "server")
MCPB = os.path.join(S1, "tools", "node_modules", ".bin", "mcpb")
FILES = ("launcher.py", "helper.py", "helper_compare.py", "manifest.json", "requirements.in",
         "requirements.txt")
VERSION = "0.8.0"
ALLOW_LINE = re.compile(r'^ALLOWED_PROPERTIES = frozenset\(\{"\d+"\}\)$', re.M)
DEFAULT_QA_ORIGIN = "http://localhost:8765"
STATE_DIR_RELEASE = '"~/Library/Application Support/GrabMCP/ga4-bridge"'
STATE_DIR_QA = '"~/Library/Application Support/GrabMCP/ga4-bridge-qa"'


def fail(msg):
    print("BUILD REFUSED: " + msg, flush=True)
    sys.exit(1)


# ---------------------------------------------------------------- variants (INTERFACE-03 §6)
def qa_rewrites(qa_origin):
    """{file: [(line regex, replacement line)]}: every rewrite a qa build makes. Each regex is a
    WHOLE line (re.M) and must match exactly once in its file."""
    return {
        "manifest.json": [
            (r'^  "name": "ga4-bridge",$', '  "name": "ga4-bridge-qa",'),
        ],
        "helper.py": [
            (r'^DEFAULT_PORT = 50812$', 'DEFAULT_PORT = 50822'),
            (r'^KEYCHAIN_SERVICE = "ga4-bridge"$', 'KEYCHAIN_SERVICE = "ga4-bridge-qa"'),
            (r'^SERVICE = "grabmcp-ga4-helper"$', 'SERVICE = "grabmcp-ga4-helper-qa"'),
            (r'^KEYCHAIN_OVERRIDE_ALLOWED = False$', 'KEYCHAIN_OVERRIDE_ALLOWED = True'),
            (r'^SEAMS_ALLOWED = False$', 'SEAMS_ALLOWED = True'),           # 0.8.0 FX-5
            (r'^DEFAULT_ORIGINS = \("https://grabmcp\.github\.io", "https://connect\.grabmcp\.com"\)$',
             'DEFAULT_ORIGINS = (%s,)' % json.dumps(qa_origin)),
            (r'^(\s+or os\.path\.expanduser\()' + re.escape(STATE_DIR_RELEASE) + r'(\)\))$',
             r'\g<1>' + STATE_DIR_QA.replace("\\", "\\\\") + r'\g<2>'),
        ],
        "launcher.py": [
            (r'^HELPER_PORT = int\(os\.environ\.get\("GA4_HELPER_PORT"\) or 50812\)(.*)$',
             r'HELPER_PORT = int(os.environ.get("GA4_HELPER_PORT") or 50822)\g<1>'),
            (r'^HELPER_SERVICE = "grabmcp-ga4-helper"$', 'HELPER_SERVICE = "grabmcp-ga4-helper-qa"'),
            (r'^KEYCHAIN_SERVICE = "ga4-bridge"$', 'KEYCHAIN_SERVICE = "ga4-bridge-qa"'),
            (r'^KEYCHAIN_OVERRIDE_ALLOWED = False$', 'KEYCHAIN_OVERRIDE_ALLOWED = True'),
            (r'^(\s+or os\.path\.expanduser\()' + re.escape(STATE_DIR_RELEASE) + r'(\)\))$',
             r'\g<1>' + STATE_DIR_QA + r'\g<2>'),
        ],
    }


def apply_qa(texts, qa_origin):
    """Rewrite {file: text} for a qa build. Returns (new_texts, None) or (None, why). Each rewrite
    must apply EXACTLY once, and nothing but the named lines may change."""
    out = dict(texts)
    for name, rules in qa_rewrites(qa_origin).items():
        t = out[name]
        for pat, rep in rules:
            rx = re.compile(pat, re.M)
            n = len(rx.findall(t))
            if n != 1:
                return None, "qa rewrite %r applied %d times in %s (must be exactly 1)" % (
                    pat[:60], n, name)
            t = rx.sub(rep, t)
        before, after = texts[name].splitlines(), t.splitlines()
        changed = sum(1 for a, b in zip(before, after) if a != b)
        if len(before) != len(after) or changed != len(rules):
            return None, "qa rewrites changed %d line(s) of %s, expected %d" % (
                changed, name, len(rules))
        out[name] = t
    return out, None


def release_samples():
    """(pattern, one representative value) for every value that must NEVER appear in a qa
    package. The sample is what the scan's control plants (CR3-7: one per pattern)."""
    return [(r"\b50812\b", "DEFAULT_PORT = 50812"),
            (r'"grabmcp-ga4-helper"', 'SERVICE = "grabmcp-ga4-helper"'),
            (r'"ga4-bridge"', 'KEYCHAIN_SERVICE = "ga4-bridge"'),
            (r"https://grabmcp\.github\.io", '"https://grabmcp.github.io"'),
            (r"https://connect\.grabmcp\.com", '"https://connect.grabmcp.com"'),
            (re.escape(STATE_DIR_RELEASE), STATE_DIR_RELEASE),
            (r"KEYCHAIN_OVERRIDE_ALLOWED = False", "KEYCHAIN_OVERRIDE_ALLOWED = False"),
            (r"SEAMS_ALLOWED = False", "SEAMS_ALLOWED = False")]                 # 0.8.0 FX-5


def qa_samples(qa_origins):
    """(pattern, one representative value) for every value that must NEVER appear in a release
    package."""
    return ([(r"\b50822\b", "DEFAULT_PORT = 50822"),
             (r"grabmcp-ga4-helper-qa", 'SERVICE = "grabmcp-ga4-helper-qa"'),
             (r"ga4-bridge-qa", 'KEYCHAIN_SERVICE = "ga4-bridge-qa"'),
             (r"KEYCHAIN_OVERRIDE_ALLOWED\s*=\s*True", "KEYCHAIN_OVERRIDE_ALLOWED = True"),
             (r"SEAMS_ALLOWED\s*=\s*True", "SEAMS_ALLOWED = True")]               # 0.8.0 FX-5
            + [(re.escape(o), '"%s"' % o) for o in qa_origins])


def release_values():
    """Values that must NEVER appear in a qa package."""
    return [pat for pat, _s in release_samples()]


def qa_values(qa_origins):
    """Values that must NEVER appear in a release package."""
    return [pat for pat, _s in qa_samples(qa_origins)]


OVERRIDE_ASSIGN = re.compile(r"^KEYCHAIN_OVERRIDE_ALLOWED\s*=", re.M)


def override_check(texts, want):
    """CR3-8: exactly ONE assignment of KEYCHAIN_OVERRIDE_ALLOWED in helper.py and launcher.py,
    and it is the literal `want` line. None if so, else why."""
    for n in ("helper.py", "launcher.py"):
        k = len(OVERRIDE_ASSIGN.findall(texts[n]))
        if k != 1 or texts[n].count("\nKEYCHAIN_OVERRIDE_ALLOWED = %s\n" % want) != 1:
            return "%s must assign KEYCHAIN_OVERRIDE_ALLOWED exactly once, to %s (%d found)" % (
                n, want, k)
    return None


SEAMS_ASSIGN = re.compile(r"^SEAMS_ALLOWED\s*=", re.M)


def seams_check(texts, want):
    """0.8.0 FX-5: exactly ONE assignment of SEAMS_ALLOWED in helper.py, the literal `want` line, and
    none in launcher.py. None if so, else why."""
    k = len(SEAMS_ASSIGN.findall(texts["helper.py"]))
    if k != 1 or texts["helper.py"].count("\nSEAMS_ALLOWED = %s\n" % want) != 1:
        return "helper.py must assign SEAMS_ALLOWED exactly once, to %s (%d found)" % (want, k)
    if SEAMS_ASSIGN.findall(texts["launcher.py"]):
        return "launcher.py must not assign SEAMS_ALLOWED"
    return None


def scan(texts, patterns):
    """[(file, pattern)] for every forbidden pattern found. Empty = clean."""
    hits = []
    for name in sorted(texts):
        for pat in patterns:
            if re.search(pat, texts[name]):
                hits.append((name, pat))
    return hits


def seeded(texts, value, name="helper.py"):
    """A copy of the package texts with ONE wrong value planted in `name`: the scan's control."""
    out = dict(texts)
    out[name] = out[name] + "\n# seeded control: %s\n" % value
    return out


def checked_scan(texts, pairs, label, seed_files=("helper.py", "launcher.py")):
    """CR3-7: the control first -- for EVERY (pattern, sample), the sample is planted in a copy of
    each seed file and that pattern alone must find it -- then the real scan with all patterns."""
    if not pairs:
        return "the %s scan has no patterns" % label
    for pat, sample in pairs:
        for name in seed_files:
            if not scan(seeded(texts, sample, name), [pat]):
                return "the %s scan's control did not fail for %r in a seeded %s" % (
                    label, pat, name)
    hits = scan(texts, [pat for pat, _s in pairs])
    if hits:
        return "the %s scan found forbidden values: %s" % (label, hits[:6])
    return None


def valid_origin(o):
    try:
        u = urllib.parse.urlsplit(o)
        u.port
    except ValueError:
        return False
    return (u.scheme in ("http", "https") and bool(u.hostname) and "@" not in u.netloc
            and u.path == "" and not u.query and not u.fragment and o == "%s://%s" % (
                u.scheme, u.netloc))


# ---------------------------------------------------------------- 0.6.3 machinery, unchanged
def governed_root(path):
    d = os.path.dirname(os.path.realpath(path))
    while d and d != os.path.dirname(d):
        if os.path.exists(os.path.join(d, "CLAUDE.md")) or os.path.exists(os.path.join(d, ".git")):
            return d
        d = os.path.dirname(d)
    return None


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 16), b""):
            h.update(b)
    return h.hexdigest()


def server_tree(root):
    """{relpath: sha256} of every file under Google's vendored server, bytecode excluded."""
    out = {}
    for d, dirs, fs in os.walk(root):
        dirs[:] = [x for x in dirs if x != "__pycache__"]
        for f in fs:
            if f.endswith(".pyc"):
                continue
            p = os.path.join(d, f)
            out[os.path.relpath(p, root)] = sha(p)
    return out


def verify_release():
    """Gate conditions 1-2: where we are, and that every input IS the released bytes."""
    if os.path.basename(os.path.dirname(HERE)) != "releases" or \
            os.path.basename(HERE) != VERSION or not os.path.isfile(os.path.join(HERE, "SHA256SUMS.txt")):
        fail("run the RELEASED copy: <...>/20261002-p2-bridge-s1/releases/%s/build-%s.py "
             "(this copy is at %s)" % (VERSION, VERSION, HERE))
    sums = {}
    for line in open(os.path.join(HERE, "SHA256SUMS.txt"), encoding="utf-8"):
        if line.strip():
            h, n = line.rstrip("\n").split("  ", 1)
            sums[n] = h
    need = set(FILES) | {"SERVER-TREE.sha256", os.path.basename(__file__)}
    if not need <= set(sums):
        fail("the release seal does not list: %s" % sorted(need - set(sums)))
    for n, h in sorted(sums.items()):
        p = os.path.join(HERE, n)
        if not os.path.isfile(p) or sha(p) != h:
            fail("the release file %s does not match its seal" % n)
    pinned = {}
    for line in open(os.path.join(HERE, "SERVER-TREE.sha256"), encoding="utf-8"):
        if line.strip():
            h, n = line.rstrip("\n").split("  ", 1)
            pinned[n] = h
    have = server_tree(SERVER) if os.path.isdir(SERVER) else {}
    if not pinned or have != pinned:
        diff = sorted(set(pinned.items()) ^ set(have.items()))
        fail("Google's server at %s does not match the pinned tree (%d difference(s), e.g. %s)"
             % (SERVER, len(diff), [x[0] for x in diff][:3]))
    return sums


def main():
    ap = argparse.ArgumentParser(description="Build the 0.8.0 grabmcp GA4 extension (.mcpb).")
    ap.add_argument("client_json")
    ap.add_argument("--property", default="449629553")
    ap.add_argument("--out", default=os.path.expanduser("~/grabmcp-build"))
    ap.add_argument("--variant", choices=("release", "qa"), default="release")
    ap.add_argument("--qa-origin", default=None)
    a = ap.parse_args()

    if a.variant == "release" and a.qa_origin is not None:
        fail("--qa-origin is for --variant qa only")
    qa_origin = a.qa_origin or DEFAULT_QA_ORIGIN
    if a.variant == "qa" and not valid_origin(qa_origin):
        fail("--qa-origin must be an origin: scheme://host[:port], no path")

    # ---- the client file: absolute, outside any project folder, the right SHAPE
    c = a.client_json
    if not os.path.isabs(c):
        fail("give the client file as an ABSOLUTE path")
    if not os.path.isfile(c):
        fail("the client file does not exist: %s" % c)
    root = governed_root(c)
    if root:
        fail("the client file lies inside a project or versioned folder (%s)" % root)
    try:
        inst = json.load(open(c, encoding="utf-8")).get("installed") or {}
    except Exception:
        fail("the client file is not JSON")
    if not inst.get("client_id") or not inst.get("client_secret"):
        fail("the client file is not a Google Desktop-app client (no installed.client_id / "
             "client_secret)")
    if not re.fullmatch(r"\d{6,12}", a.property):
        fail("--property must be a numeric GA4 property id")

    sums = verify_release()
    out = os.path.abspath(os.path.expanduser(a.out))
    if governed_root(os.path.join(out, "x")):
        fail("--out lies inside a project or versioned folder; the .mcpb carries the client file")
    if not os.access(MCPB, os.X_OK):
        fail("the mcpb packer is missing: %s" % MCPB)

    # ---- stage
    stage = tempfile.mkdtemp(prefix="grabmcp-ga4-%s-%s-" % (VERSION, a.variant))
    try:
        for f in FILES:
            # copyfile + an explicit mode: the release files are 0444, and the stage must be
            # writable for the one-line allowlist rewrite (found by the from-the-release test).
            shutil.copyfile(os.path.join(HERE, f), os.path.join(stage, f))
            os.chmod(os.path.join(stage, f), 0o644)
            if sha(os.path.join(stage, f)) != sums[f]:
                fail("staged %s differs from the release seal" % f)
        shutil.copytree(SERVER, os.path.join(stage, "server"),
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        man = json.load(open(os.path.join(stage, "manifest.json")))
        if man.get("version") != VERSION or "user_config" in man:
            fail("the bundle manifest is not the %s no-settings manifest" % VERSION)
        lp = os.path.join(stage, "launcher.py")
        t = open(lp, encoding="utf-8").read()
        if len(ALLOW_LINE.findall(t)) != 1:
            fail("the launcher's allowlist line was not found exactly once")
        t2 = ALLOW_LINE.sub('ALLOWED_PROPERTIES = frozenset({"%s"})' % a.property, t)
        # the ONE build-time line is the only difference from the released launcher
        if ALLOW_LINE.sub("X", t2) != ALLOW_LINE.sub("X", t):
            fail("the allowlist rewrite changed more than its one line")
        open(lp, "w", encoding="utf-8").write(t2)

        # ---- 0.7.0: the variant (INTERFACE-03 §6), on the STAGED copy only
        if a.variant == "qa":
            names = ("manifest.json", "helper.py", "launcher.py")
            texts = {n: open(os.path.join(stage, n), encoding="utf-8").read() for n in names}
            new, why = apply_qa(texts, qa_origin)
            if why:
                fail(why)
            for n in names:
                open(os.path.join(stage, n), "w", encoding="utf-8").write(new[n])
            if json.load(open(os.path.join(stage, "manifest.json"))).get("name") != "ga4-bridge-qa":
                fail("the qa manifest name did not take")

        dst = os.path.join(stage, "oauth-client.json")
        shutil.copyfile(c, dst)
        os.chmod(dst, 0o600)

        os.makedirs(out, mode=0o700, exist_ok=True)
        mcpb = os.path.join(out, "grabmcp-ga4-bridge%s.mcpb" % ("-qa" if a.variant == "qa" else ""))
        if os.path.exists(mcpb):
            os.replace(mcpb, mcpb + ".previous")
        r = subprocess.run([MCPB, "pack", stage, mcpb], capture_output=True, text=True)
        if r.returncode != 0 or not os.path.exists(mcpb):
            fail("mcpb pack failed (exit %d): %s" % (r.returncode, (r.stderr or r.stdout)[-400:]))

        # ---- the packed file IS the stage: same names, same bytes, nothing extra
        with zipfile.ZipFile(mcpb) as z:
            packed = {n: hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist()
                      if not n.endswith("/")}
            ours = {n: z.read(n).decode("utf-8") for n in FILES}
        staged = {}
        for d, _dirs, fs in os.walk(stage):
            for f in fs:
                p = os.path.join(d, f)
                staged[os.path.relpath(p, stage)] = sha(p)
        if packed != staged:
            fail("the packed .mcpb differs from the stage: %s" % sorted(
                set(packed.items()) ^ set(staged.items()))[:6])
        if any("__pycache__" in n or n.endswith(".pyc") for n in packed):
            fail("bytecode in the package")

        # ---- 0.7.0: the two scans, each proven by its control first (on the PACKED files)
        # C-5 (lead decision A, CR3-8): the keychain override is ONE assignment per file, off in a
        # release and on in a qa build; the release scan also refuses `= True` anywhere.
        if a.variant == "qa":
            why = (override_check(ours, "True") or seams_check(ours, "True")
                   or checked_scan(ours, release_samples(), "qa-has-no-release"))
        else:
            why = (override_check(ours, "False") or seams_check(ours, "False")
                   or checked_scan(ours, qa_samples(sorted({DEFAULT_QA_ORIGIN, qa_origin})),
                                   "release-has-no-qa"))
        if why:
            os.replace(mcpb, mcpb + ".refused")
            fail(why)
    finally:
        shutil.rmtree(stage, ignore_errors=True)

    print("BUILD OK  version %s  variant %s%s  property %s  unsigned  (release seal and server "
          "tree verified; scan and its control passed)"
          % (VERSION, a.variant, (" origin %s" % qa_origin) if a.variant == "qa" else "",
             a.property))
    print("  file    %s" % mcpb)
    print("  sha256  %s" % sha(mcpb))
    print("  %d files; contains oauth-client.json (keep this .mcpb OUT of every repository)"
          % len(packed))


if __name__ == "__main__":
    main()
