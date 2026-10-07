#!/usr/bin/env python3
"""POC KPI-3 (task A5): "the tool's answer equals Google's own data".

The helper -- never the site, never the CLI -- makes the GA4 calls itself (Reviewer ruling D3);
the access token comes from `credentials_factory()` (the helper's in-memory token) and never
leaves this module: not in the return value, not in a log line, not in an exception text.

Two checks against ONE recorded `report` event of the launcher's status file:

  (a) VALUES   -- the GA4 Data API `runReport` called DIRECTLY over REST (urllib), with the
                  recorded MCP arguments translated to the REST body; its rows are compared
                  with the rows inside the result produced by (b).
  (b) IDENTITY -- Google's own vendored `analytics_mcp` server answers the SAME arguments
                  in-process, through the very MCP handler the server registers
                  (coordinator.app.request_handlers[CallToolRequest]); the result is put in
                  the wire form the MCP session sends (ServerResult.model_dump(by_alias=True,
                  mode="json", exclude_none=True), see mcp/shared/session.py), which the
                  launcher forwards UNCHANGED for a successful run_report (launcher.on_line);
                  its canonical SHA-256 (launcher.record_call's formula) is compared with the
                  recorded `result_sha256`.

Credential seam for (b): analytics_mcp/tools/client.py `_get_credentials` (line 78). Both
`create_data_api_client` and its siblings look the name up in the module's globals at call
time, so it is replaced in-process for the duration of one call (under a lock) and restored.
No ADC file is written, and google.auth.default() is never reached.
"""
import asyncio
import copy
import hashlib
import json
import os
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER_DIR = os.path.join(HERE, "server")
GOOGLE_DATA_API = "https://analyticsdata.googleapis.com"
BASE_ENV = "GA4_COMPARE_DATA_API_BASE"
REPORT_TOOL = "run_report"
_SEAM_LOCK = threading.Lock()
_RELATIVE = re.compile(r"^(today|yesterday|[0-9]+daysAgo)$")
# top-level MCP argument -> REST body field (the tool's own translation, core.run_report)
_SCALARS = (("limit", "limit"), ("offset", "offset"), ("currency_code", "currencyCode"))


class CompareError(Exception):
    pass


# ----------------------------------------------------------------- the record
def load_report_events(status_path):
    with open(status_path, "r", encoding="utf-8") as fh:
        events = json.load(fh).get("events", [])
    return [e for e in events
            if isinstance(e, dict) and e.get("kind") == "report" and e.get("tool") == REPORT_TOOL]


def pick_event(events, which="last"):
    if not events:
        raise CompareError("the status file records no run_report report event")
    if which in (None, "last"):
        return len(events) - 1, events[-1]
    if isinstance(which, bool):
        raise CompareError("which must be 'last' or an integer index")
    try:
        idx = int(which)
    except (TypeError, ValueError):
        raise CompareError("which must be 'last' or an integer index")
    if not -len(events) <= idx < len(events):
        raise CompareError("index %d is out of range: %d run_report report event(s) recorded"
                           % (idx, len(events)))
    return idx % len(events), events[idx]


# ----------------------------------------------------------------- (a) direct REST
def property_rn(value):
    s = str(value).strip()
    if s.startswith("properties/"):
        s = s.split("/")[-1]
    if not s.isdigit():
        raise CompareError("invalid property id in the recorded arguments")
    return "properties/%d" % int(s)


def _camel(key):
    head, *rest = key.split("_")
    return head + "".join(p[:1].upper() + p[1:] for p in rest)


def _camelize(obj):
    """Proto field names (snake_case, what the tool takes) -> REST JSON names. Keys only:
    values (dimension names, enum words, match strings) are never touched."""
    if isinstance(obj, dict):
        return {_camel(k): _camelize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_camelize(v) for v in obj]
    return obj


def rest_request(arguments):
    """(property resource name, REST body) for the arguments, mirroring core.run_report: the
    optional fields are sent only when the tool would set them (it tests truthiness)."""
    a = arguments
    body = {
        "dimensions": [{"name": d} for d in (a.get("dimensions") or [])],
        "metrics": [{"name": m} for m in (a.get("metrics") or [])],
        "dateRanges": _camelize(a.get("date_ranges") or []),
    }
    if a.get("return_property_quota"):
        body["returnPropertyQuota"] = True
    if a.get("dimension_filter"):
        body["dimensionFilter"] = _camelize(a["dimension_filter"])
    if a.get("metric_filter"):
        body["metricFilter"] = _camelize(a["metric_filter"])
    if a.get("order_bys"):
        body["orderBys"] = _camelize(a["order_bys"])
    for src, dst in _SCALARS:
        if a.get(src):
            body[dst] = a[src]
    return property_rn(a.get("property_id")), body


def resolve_base(base_url=None):
    """Resolved PER CALL. Only Google's own host or a loopback test server may receive the
    token: an injected base pointing anywhere else is refused, never followed."""
    base = base_url if base_url is not None else os.environ.get(BASE_ENV) or GOOGLE_DATA_API
    base = base.rstrip("/")
    u = urllib.parse.urlsplit(base)
    if base == GOOGLE_DATA_API:
        return base
    if u.scheme in ("http", "https") and u.hostname in ("127.0.0.1", "localhost", "::1"):
        return base
    raise CompareError("refused Data API base %r: only %s or a loopback address"
                       % (base, GOOGLE_DATA_API))


def _tls():
    """0.6.1: the pinned certifi bundle (the extension's interpreter may have no CA store)."""
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


def direct_run_report(prop_rn, body, token, base_url=None, timeout=30):
    url = "%s/v1beta/%s:runReport" % (resolve_base(base_url), prop_rn)
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Authorization": "Bearer " + token,
                                          "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_tls()) as f:
            return json.loads(f.read().decode())
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode(errors="replace")[:600]
        except Exception:
            detail = ""
        raise CompareError("Data API answered HTTP %d: %s" % (e.code, detail))
    except urllib.error.URLError as e:
        raise CompareError("Data API unreachable: %s" % type(e.reason).__name__)


# ----------------------------------------------------------------- (b) Google's own tool
def _ensure_server_path():
    if SERVER_DIR not in sys.path:
        sys.path.insert(0, SERVER_DIR)


def _run(coro):
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    box = {}

    def runner():
        try:
            box["v"] = asyncio.run(coro)
        except BaseException as e:  # re-raised in the caller's thread
            box["e"] = e
    t = threading.Thread(target=runner)
    t.start()
    t.join()
    if "e" in box:
        raise box["e"]
    return box["v"]


def tool_result(arguments, credentials):
    """The MCP `tools/call` result for run_report, as Google's server puts it on the wire."""
    _ensure_server_path()
    import analytics_mcp.coordinator as coordinator
    import analytics_mcp.tools.client as gclient
    from mcp import types
    req = types.CallToolRequest(method="tools/call",
                                params=types.CallToolRequestParams(name=REPORT_TOOL,
                                                                   arguments=arguments))
    handler = coordinator.app.request_handlers[types.CallToolRequest]
    with _SEAM_LOCK:
        original = gclient._get_credentials
        gclient._get_credentials = lambda: credentials
        try:
            served = _run(handler(req))
        finally:
            gclient._get_credentials = original
    return served.model_dump(by_alias=True, mode="json", exclude_none=True)


def canonical_sha(result):
    """launcher.record_call's digest, byte for byte."""
    return hashlib.sha256(json.dumps(result, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def tool_payload(result):
    try:
        content = result.get("content") or []
        return json.loads(content[0]["text"])
    except Exception:
        return None


# ----------------------------------------------------------------- rows
def _vals(cells):
    return [c.get("value") for c in (cells or [])]


def rows_of(resp):
    """REST (camelCase) and proto-dict (snake_case) responses to one plain shape."""
    out = []
    for r in (resp or {}).get("rows") or []:
        out.append({"dimensions": _vals(r.get("dimensionValues", r.get("dimension_values"))),
                    "metrics": _vals(r.get("metricValues", r.get("metric_values")))})
    return out


def headers_of(resp):
    resp = resp or {}
    dh = resp.get("dimensionHeaders", resp.get("dimension_headers")) or []
    mh = resp.get("metricHeaders", resp.get("metric_headers")) or []
    return [h.get("name") for h in dh], [h.get("name") for h in mh]


def _key(row):
    return json.dumps(row, sort_keys=True)


# ----------------------------------------------------------------- notes
def date_notes(arguments, recorded_at, today=None):
    notes, sensitive = [], False
    rel = []
    for dr in arguments.get("date_ranges") or []:
        for k in ("start_date", "end_date", "startDate", "endDate"):
            v = dr.get(k) if isinstance(dr, dict) else None
            if isinstance(v, str) and _RELATIVE.match(v):
                rel.append(v)
    if rel:
        sensitive = True
        today = today or time.strftime("%Y-%m-%d")
        rec_day = (recorded_at or "")[:10]
        notes.append("the recorded call used relative date(s) %s: IDENTITY is time-sensitive "
                     "(they resolve against the property's time zone at call time)"
                     % ", ".join(sorted(set(rel))))
        if rec_day and rec_day != today:
            notes.append("recorded on %s, compared on %s: the relative dates now resolve to "
                         "different days, so an IDENTITY mismatch is EXPECTED and does not by "
                         "itself show a defect" % (rec_day, today))
    if any(v in ("today", "yesterday") for v in rel):
        notes.append("the range touches today/yesterday: GA4 may still be processing those "
                     "days, so values can move between the recorded call and now")
    return notes, sensitive


def _scrub(obj, secret):
    if not secret:
        return obj
    if isinstance(obj, str):
        return obj.replace(secret, "[redacted]")
    if isinstance(obj, dict):
        return {_scrub(k, secret): _scrub(v, secret) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_scrub(v, secret) for v in obj]
    return obj


# ----------------------------------------------------------------- the check
def compare(status_path, credentials_factory, which="last", base_url=None):
    idx, ev = pick_event(load_report_events(status_path), which)
    arguments = copy.deepcopy(ev.get("arguments") or {})
    recorded_sha = ev.get("result_sha256")
    notes, sensitive = date_notes(arguments, ev.get("at"))
    out = {"which": which, "event_index": idx, "recorded_at": ev.get("at"),
           "property_id": ev.get("property_id"), "arguments": arguments,
           "direct_rows": None, "tool_rows": None, "direct_row_count": None,
           "tool_row_count": None, "values_match": False, "order_match": None,
           "recorded_sha256": recorded_sha, "recomputed_sha256": None,
           "identity_match": False, "identity_time_sensitive": sensitive,
           "errors": [], "notes": notes}
    creds = credentials_factory()
    token = getattr(creds, "token", None)
    try:
        if not token:
            raise CompareError("no access token is held: connect first")
        # (b) IDENTITY -- Google's own tool
        payload = None
        try:
            result = tool_result(copy.deepcopy(arguments), creds)
            out["recomputed_sha256"] = canonical_sha(result)
            out["identity_match"] = bool(recorded_sha) and out["recomputed_sha256"] == recorded_sha
            payload = tool_payload(result)
            if result.get("isError") or not isinstance(payload, dict) or "error" in payload:
                err = (payload or {}).get("error") if isinstance(payload, dict) else None
                out["errors"].append("tool: %s" % (err or "the tool returned an error result"))
                payload = None
        except Exception as e:
            out["errors"].append("tool: %s: %s" % (type(e).__name__, e))
        # (a) VALUES -- the Data API directly
        direct = None
        try:
            prop, body = rest_request(arguments)
            direct = direct_run_report(prop, body, token, base_url=base_url)
        except Exception as e:
            out["errors"].append("direct: %s" % e)
        if direct is not None:
            out["direct_rows"] = rows_of(direct)
            out["direct_row_count"] = direct.get("rowCount", 0)
        if payload is not None:
            out["tool_rows"] = rows_of(payload)
            out["tool_row_count"] = payload.get("row_count", payload.get("rowCount", 0))
        if direct is not None and payload is not None:
            same_rows = Counter(map(_key, out["direct_rows"])) == Counter(map(_key, out["tool_rows"]))
            same_heads = headers_of(direct) == headers_of(payload)
            same_count = int(out["direct_row_count"] or 0) == int(out["tool_row_count"] or 0)
            out["values_match"] = same_rows and same_heads and same_count
            out["order_match"] = out["direct_rows"] == out["tool_rows"]
            if not same_heads:
                out["notes"].append("the dimension/metric headers differ")
            if same_rows and not out["order_match"]:
                out["notes"].append("same rows, different order")
    except CompareError as e:
        out["errors"].append(str(e))
    finally:
        creds = None
    return _scrub(out, token)
