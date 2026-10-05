#!/usr/bin/env python3
"""O7 -- the Owner's ONE build command for the 0.6.1 Claude extension (amendment 2, D4).

    python3 ".../operations/20261002-p2-bridge-s1/releases/0.6.1/build-0.6.1.py" /abs/path/client.json

v2 (gate conditions 1-2, Reviewer 12:05): it runs ONLY as the RELEASED copy, from its release
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
import zipfile

HERE = os.path.dirname(os.path.realpath(__file__))
# The ONLY supported location: <S1>/releases/<version>/build-<version>.py (gate condition 1).
S1 = os.path.dirname(os.path.dirname(HERE))
SERVER = os.path.join(S1, "bundle", "server")
MCPB = os.path.join(S1, "tools", "node_modules", ".bin", "mcpb")
FILES = ("launcher.py", "helper.py", "helper_compare.py", "manifest.json", "requirements.in",
         "requirements.txt")
VERSION = "0.6.1"
ALLOW_LINE = re.compile(r'^ALLOWED_PROPERTIES = frozenset\(\{"\d+"\}\)$', re.M)


def fail(msg):
    print("BUILD REFUSED: " + msg, flush=True)
    sys.exit(1)


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
    ap = argparse.ArgumentParser(description="Build the 0.6.1 grabmcp GA4 extension (.mcpb).")
    ap.add_argument("client_json")
    ap.add_argument("--property", default="449629553")
    ap.add_argument("--out", default=os.path.expanduser("~/grabmcp-build"))
    a = ap.parse_args()

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
    stage = tempfile.mkdtemp(prefix="grabmcp-ga4-0.6.1-")
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
            fail("the bundle manifest is not the 0.6.1 no-settings manifest")
        lp = os.path.join(stage, "launcher.py")
        t = open(lp, encoding="utf-8").read()
        if len(ALLOW_LINE.findall(t)) != 1:
            fail("the launcher's allowlist line was not found exactly once")
        t2 = ALLOW_LINE.sub('ALLOWED_PROPERTIES = frozenset({"%s"})' % a.property, t)
        # the ONE build-time line is the only difference from the released launcher
        if ALLOW_LINE.sub("X", t2) != ALLOW_LINE.sub("X", t):
            fail("the allowlist rewrite changed more than its one line")
        open(lp, "w", encoding="utf-8").write(t2)
        dst = os.path.join(stage, "oauth-client.json")
        shutil.copyfile(c, dst)
        os.chmod(dst, 0o600)

        os.makedirs(out, mode=0o700, exist_ok=True)
        mcpb = os.path.join(out, "grabmcp-ga4-bridge.mcpb")
        if os.path.exists(mcpb):
            os.replace(mcpb, mcpb + ".previous")
        r = subprocess.run([MCPB, "pack", stage, mcpb], capture_output=True, text=True)
        if r.returncode != 0 or not os.path.exists(mcpb):
            fail("mcpb pack failed (exit %d): %s" % (r.returncode, (r.stderr or r.stdout)[-400:]))

        # ---- the packed file IS the stage: same names, same bytes, nothing extra
        with zipfile.ZipFile(mcpb) as z:
            packed = {n: hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist()
                      if not n.endswith("/")}
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
    finally:
        shutil.rmtree(stage, ignore_errors=True)

    print("BUILD OK  version %s  property %s  unsigned  (release seal and server tree verified)"
          % (VERSION, a.property))
    print("  file    %s" % mcpb)
    print("  sha256  %s" % sha(mcpb))
    print("  %d files; contains oauth-client.json (keep this .mcpb OUT of every repository)"
          % len(packed))


if __name__ == "__main__":
    main()
