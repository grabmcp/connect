#!/usr/bin/env python3
"""rrk compare (POC KPI-3, task A5): ask the HELPER to check one recorded report call.

The helper makes both GA4 calls itself (ruling D3); this CLI only POSTs {"which": ...} to
<helper_base>/compare with the pairing secret and NO Origin header, then prints what came
back side by side. Exit 0 only when VALUES and IDENTITY both match; 1 on a mismatch; 2 when
the helper could not be asked or answered something unreadable.

Wiring (done by the Executor in rrk.py / helper.py): `cmd_compare(helper_base, pair_secret,
which)` returns the exit code. The helper's answer is the dict from
helper_compare.compare(), either at the top level or under a "compare" key.
"""
import json
import sys
import urllib.error
import urllib.request


def _post(helper_base, pair_secret, which, timeout=120):
    url = helper_base.rstrip("/") + "/compare"
    req = urllib.request.Request(url, data=json.dumps({"which": which}).encode(), method="POST",
                                 headers={"X-Pair-Secret": pair_secret,
                                          "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as f:
            return f.status, f.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def _cell(v):
    return "-" if v is None else str(v)


def render(res, out=sys.stdout):
    w = out.write
    w("event #%s  recorded %s  property %s\n" % (_cell(res.get("event_index")),
                                                 _cell(res.get("recorded_at")),
                                                 _cell(res.get("property_id"))))
    w("arguments: %s\n\n" % json.dumps(res.get("arguments"), sort_keys=True))
    direct = res.get("direct_rows") or []
    tool = res.get("tool_rows") or []
    rows = []
    for i in range(max(len(direct), len(tool))):
        d = direct[i] if i < len(direct) else None
        t = tool[i] if i < len(tool) else None
        dims = " / ".join(map(str, (d or t)["dimensions"])) or "(total)"
        dm = ", ".join(map(str, d["metrics"])) if d else "(none)"
        tm = ", ".join(map(str, t["metrics"])) if t else "(none)"
        ok = "=" if d and t and d == t else "!="
        rows.append((str(i), dims, dm, tm, ok))
    head = ("#", "dimensions", "Google Data API", "MCP tool", "")
    widths = [max(len(r[c]) for r in rows + [head]) for c in range(5)]
    line = lambda r: "  ".join(r[c].ljust(widths[c]) for c in range(5)).rstrip() + "\n"
    w(line(head))
    w(line(tuple("-" * x for x in widths)))
    for r in rows:
        w(line(r))
    w("\nrows: Google Data API %s, MCP tool %s\n" % (_cell(res.get("direct_row_count")),
                                                  _cell(res.get("tool_row_count"))))
    w("recorded   sha256: %s\n" % _cell(res.get("recorded_sha256")))
    w("recomputed sha256: %s\n" % _cell(res.get("recomputed_sha256")))
    for n in res.get("notes") or []:
        w("note: %s\n" % n)
    for e in res.get("errors") or []:
        w("error: %s\n" % e)
    w("VALUES: %s\n" % ("MATCH" if res.get("values_match") is True else "MISMATCH"))
    w("IDENTITY: %s\n" % ("MATCH" if res.get("identity_match") is True else "MISMATCH"))


def cmd_compare(helper_base, pair_secret, which, out=sys.stdout):
    try:
        code, text = _post(helper_base, pair_secret, which)
    except Exception as e:
        out.write("compare: the helper could not be reached (%s)\n" % type(e).__name__)
        return 2
    try:
        res = json.loads(text)
    except ValueError:
        out.write("compare: HTTP %d, unreadable answer\n" % code)
        return 2
    if isinstance(res, dict) and isinstance(res.get("compare"), dict):
        res = res["compare"]
    if code != 200 or not isinstance(res, dict) or "values_match" not in res:
        out.write("compare: HTTP %d: %s\n" % (code, json.dumps(res)[:400]))
        return 2
    render(res, out)
    return 0 if res.get("values_match") is True and res.get("identity_match") is True else 1
