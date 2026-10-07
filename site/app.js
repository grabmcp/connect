/* Connect Google Analytics to Claude: the page logic.
 *
 * The page talks ONLY to the helper that runs inside the Claude extension on this Mac, at
 * the loopback address below (helper contract 1.0; 1.1.0 features are feature-detected). It
 * holds no secret, never receives a token, and never shows the sign-in address it is given.
 *
 * Instruction P step 3: the views are the approved design's frames, one section[data-state] each:
 *   S0 = D-p2 (disclose) -> S1 = D-p3 (install) -> PAIR = D-p4 (pair; ready / not found /
 *   permission denied in its status area) -> S4 = D-p5 (full disclosure) -> Google's screens
 *   (D-p6, their own tab; "#return" is the fallback) -> S6 = D-p8 (Google verified) -> S7 = D-p9 (ask
 *   Claude) -> S8 = D-p10 (Claude verified). F3 = D-p7 (4a). F4 is not drawn (brief p.17/p.18).
 *   RET is the moment after the return while the helper's test call runs (not drawn).
 * N-1: nothing is sent to 127.0.0.1 before a user click. Detection starts at "Find the helper",
 * the click the design precedes with its browser-prompt announcement (D-p4).
 * A-8: the #return load is the user's click on the callback "Return to grabmcp"; within N-1 per
 * Reviewer ruling 2026-10-07 05:39:54 (A-8). FLAG U-18: #return opened in another browser or after
 * the permission was revoked is undrawn (Owner to rule).
 * FLAG R-1: one page with in-page progress; the design's drawn paths (/connect/…) are not built
 * as routes (brief p.4).
 */
(function () {
  "use strict";

  // The helper's fixed port (contract 1.0). The page takes NO port from its address (gate
  // condition 3, Reviewer 12:05); the tests serve a copy with this one constant rewritten.
  var HELPER_PORT = 50812;

  // D6, the ONE switch. Owner ruling 2026-10-05 12:11: the .mcpb is downloaded from this site
  // (true). false = the participant opens a file they received instead.
  var MCPB_ON_SITE = true;

  var TICK_MS = 2500;              // how often the page checks the helper, once started
  var REQUEST_TIMEOUT_MS = 8000;   // one request may take this long before it counts as failed
  // N-13: the helper's callback window (CALLBACK_WAIT_S = 600) plus a 15 s margin.
  var FLOW_TIMEOUT_MS = 600000 + 15000;
  var SEARCH_FAIL_MS = 10000;      // a network failure persisting 10 s -> "Helper not found"
  var RETURN_TO_SINCE = [1, 1, 0]; // helper version that accepts `return_to` (INTERFACE-03 §3)
  var RETURN_HASH = "#return";     // the fragment the callback page's return action carries

  // Where the page keeps its place across a reload (p.8 "חזרה אחרי הפרעה", p.17): the tab's own
  // history entry state. No storage API is used (site check :257 forbids it without an approved
  // amendment), so a reopen in a NEW tab is not restored (FLAG U-11).
  var STATE_KEY = "grabmcpView";

  var BASE = "http://127.0.0.1:" + HELPER_PORT;

  // Owner ruling C-5 (21:25): the helper's credential-store states never reach the user as
  // such; they read as a sign-in that could not be saved, with Try again (the F4 path).
  var CREDENTIAL_STORE_DOWN = { keychain_locked: true, keychain_unavailable: true };
  // AWAITING OWNER (O-1)
  var SIGNIN_NOT_SAVED = "Your Google sign-in couldn’t be saved on this Mac. Try connecting again.";

  function signinSaved(s) {
    return !!s && s.local_credential === "present";
  }

  var $ = function (id) { return document.getElementById(id); };

  // ------------------------------------------------------------------ the step bar (design)
  // Labels and looks exactly as each frame draws them. D-p3 draws the short labels; D-p10 draws
  // no bar at all.
  var FULL = ["1 · Disclose", "2 · Install", "3 · Pair helper", "4 · Google access",
    "5 · Claude connection"];
  var SHORT_S1 = ["1 · Disclose", "2 · Install", "3 · Pair", "4 · Google", "5 · Claude"];
  var DONE = " — done";

  function bar(view) {
    // Each entry: [label, look]; looks: done | active | active-ok | active-warn | done-ok | todo
    var L = FULL;
    switch (view) {
      case "S0":
        return [[L[0], "active"], [L[1], "todo"], [L[2], "todo"], [L[3], "todo"], [L[4], "todo"]];
      case "S1":
        L = SHORT_S1;             // FLAG I-1: D-p3 draws the short labels
        return [[L[0] + DONE, "done"], [L[1], "active"], [L[2], "todo"], [L[3], "todo"], [L[4], "todo"]];
      case "PAIR":
        return [[L[0] + DONE, "done"], [L[1] + DONE, "done"], [L[2], "active"], [L[3], "todo"], [L[4], "todo"]];
      case "S4": case "RET": case "F4":
        return [[L[0] + DONE, "done"], [L[1] + DONE, "done"], [L[2] + DONE, "done"], [L[3], "active"], [L[4], "todo"]];
      case "F3":
        return [[L[0] + DONE, "done"], [L[1] + DONE, "done"], [L[2] + DONE, "done"],
          [L[3] + " — not granted", "active-warn"], [L[4], "todo"]];
      case "S6":
        return [[L[0] + DONE, "done"], [L[1] + DONE, "done"], [L[2] + DONE, "done"],
          [L[3] + " — verified", "active-ok"], [L[4], "todo"]];
      case "S7":
        return [[L[0] + DONE, "done"], [L[1] + DONE, "done"], [L[2] + DONE, "done"],
          [L[3] + " — verified", "done-ok"], [L[4], "active"]];
      default:
        return null;            // FLAG I-2: S8 (D-p10) draws no step bar
    }
  }

  var state = {
    view: "S0",          // the current frame
    pair: "idle",        // PAIR's status area: idle | searching | ready | notfound | denied
    polling: false,      // the helper poll runs (only ever started by a click, N-1)
    searching: false,    // a "find the helper" search is open
    searchStartedAt: 0,
    restoreTo: null,     // the frame stored before a reload (p.8 / p.17)
    found: false,        // /health answered "running" to this page on the last check
    lastHealthAt: null,  // when that last successful check finished (ms)
    version: null,       // /health version, e.g. "1.1.0"
    refused: null,       // /status refused this page (HTTP code), if it did
    status: null,        // the last /status answer
    lastProperty: null,  // U-20: the last property /status named on this connection (D-p9 keeps it)
    flowBusy: false,     // a /connect/start request is in flight
    flow: null,          // {id, startedAt} of the sign-in this page started (site tab waits on D-p5)
    gen: 0,              // CRP-4: bumped when the page leaves D-p5; a late /connect/start answer is dropped
    statusReqAt: 0,      // CRP-6: when the request behind state.status was sent (ms)
    failCause: ""        // F4's one cause line
  };

  (function applyGetVariant() {
    var dl = $("get-download"), rx = $("get-received");
    dl.hidden = !MCPB_ON_SITE;
    rx.hidden = MCPB_ON_SITE;
    // The inactive variant's control is no primary at all.
    var off = MCPB_ON_SITE ? $("received-btn") : $("download-link");
    off.removeAttribute("data-owner");
    off.hidden = true;
    $("s1-download-line").hidden = !MCPB_ON_SITE;
    $("s1-received-line").hidden = MCPB_ON_SITE;
    if (!MCPB_ON_SITE) {
      $("f1-install-link").removeAttribute("href");
      $("f1-install-link").removeAttribute("download");
    }
  })();

  // D-p2 "Detected on this computer: macOS". The design is drawn for macOS only.
  (function detectOs() {
    var p = "";
    try {
      p = (navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || "";
    } catch (e) { p = ""; }
    // FLAG A-3: only "macOS" is drawn; the non-macOS names are undrawn.
    var name = /mac/i.test(p) ? "macOS" : /win/i.test(p) ? "Windows" : /linux/i.test(p) ? "Linux" : p;
    $("detected-os").textContent = name;
  })();

  // ------------------------------------------------------------------ the place across a reload
  function remember(view) {
    try {
      var o = {};
      o[STATE_KEY] = view;
      history.replaceState(o, "", location.pathname + location.search);
    } catch (e) { /* the page still works, without restore */ }
  }
  function remembered() {
    try { return (history.state && history.state[STATE_KEY]) || null; } catch (e) { return null; }
  }
  var loadedAt = Date.now();

  // ------------------------------------------------------------------ talking to the helper
  // Every call resolves (never rejects): {network: true} when the helper could not be reached
  // at all (not running, blocked by the browser, or not allowing this page).
  function call(method, path, body) {
    var opts = { method: method, mode: "cors", cache: "no-store", credentials: "omit" };
    if (method === "POST") {
      opts.headers = { "Content-Type": "application/json" };
      opts.body = body || "{}";
    }
    var timer = null;
    if (typeof AbortController === "function") {
      var ctl = new AbortController();
      opts.signal = ctl.signal;
      timer = setTimeout(function () { ctl.abort(); }, REQUEST_TIMEOUT_MS);
    }
    return fetch(BASE + path, opts).then(function (r) {
      return r.text().then(function (t) {
        var data = null;
        try { data = JSON.parse(t); } catch (e) { data = null; }
        return { network: false, status: r.status, data: data };
      });
    }).catch(function () {
      return { network: true, status: 0, data: null };
    }).then(function (res) {
      if (timer) { clearTimeout(timer); }
      return res;
    });
  }

  function versionAtLeast(v, min) {
    if (typeof v !== "string") { return false; }
    var p = v.split(".");
    for (var i = 0; i < min.length; i++) {
      var n = parseInt(p[i], 10);
      if (isNaN(n)) { n = 0; }
      if (n !== min[i]) { return n > min[i]; }
    }
    return true;
  }

  // D-p4 "Permission denied": the browser's own record of the user's choice on its local
  // network prompt. Feature-detected; a browser without it never shows the denied state.
  function lnaDenied() {
    if (!navigator.permissions || typeof navigator.permissions.query !== "function") {
      return Promise.resolve(false);
    }
    var names = ["loopback-network", "local-network-access", "local-network"];
    return Promise.all(names.map(function (n) {
      try {
        return navigator.permissions.query({ name: n }).then(function (r) {
          return !!r && r.state === "denied";
        }, function () { return false; });
      } catch (e) { return Promise.resolve(false); }
    })).then(function (a) {
      for (var i = 0; i < a.length; i++) { if (a[i]) { return true; } }
      return false;
    });
  }

  // ------------------------------------------------------------------ presentation helpers

  // The helper and the launcher write "%Y-%m-%dT%H:%M:%S%z" (e.g. +0300); a colon is added so
  // every browser parses it. Numbers are epoch seconds or milliseconds.
  function toDate(v) {
    var d = null;
    if (typeof v === "number") {
      d = new Date(v < 1e12 ? v * 1000 : v);
    } else if (typeof v === "string") {
      d = new Date(v.replace(/([+-]\d{2})(\d{2})$/, "$1:$2"));
    }
    return (d && !isNaN(d.getTime())) ? d : null;
  }

  // The design's time form, "2 Oct, 19:36".
  function when(v) {
    var d = toDate(v);
    if (!d) { return null; }
    return d.toLocaleString("en-GB", { day: "numeric", month: "short",
      hour: "2-digit", minute: "2-digit" });
  }

  // D-p4's "Checked at [19:31]".
  function hhmm(ms) {
    return new Date(ms).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
  }

  // " at <strong>time</strong>" after a sentence, as the frames bold the time.
  function atStrong(node, t) {
    node.textContent = "";
    if (!t) { return; }
    node.appendChild(document.createTextNode(" at "));
    var b = document.createElement("strong");
    b.textContent = t;
    node.appendChild(b);
  }

  function propertyParts() {
    var prop = state.status && state.status.property;
    // FLAG U-20 (undrawn state; Owner to rule): when Google access is no longer verified on the same connection (a failed verification records no property), D-p9 (and its Copy example) keeps the property this page already showed; the drawn line and example are unchanged. FLAG U-21: if none was ever named, the existing O-1 fallback texts stay.
    if (!prop || !(prop.name || prop.id)) {
      var last = state.lastProperty;
      if (state.status && state.status.google_access !== "verified" && last && last.cid === state.status.connection_id) {
        return { name: last.name, id: last.id };
      }
      return null;
    }
    var name = typeof prop.name === "string" ? prop.name : "";
    var id = (typeof prop.id === "string" || typeof prop.id === "number") ? String(prop.id) : "";
    state.lastProperty = { name: name, id: id, cid: state.status.connection_id };
    return { name: name, id: id };
  }

  // D-p9 "[Property name] · ID [property ID]", the name in bold.
  function renderProperty(node) {
    node.textContent = "";
    var p = propertyParts();
    if (!p) {
      // AWAITING OWNER (O-1)
      node.textContent = "The extension has not named the property yet.";
      return;
    }
    var b = document.createElement("strong");
    b.textContent = p.name;     // FLAG U-15 (undrawn; Owner to rule): a property without a name leaves the slot empty
    node.appendChild(b);
    if (p.id) { node.appendChild(document.createTextNode(" · ID " + p.id)); }
  }

  function exampleText() {
    var p = propertyParts();
    // The frame's text; "my website" when no property is named: AWAITING OWNER (O-1)
    return "How many users visited " + (p && p.name ? p.name : "my website") + " last week?";
  }

  // FLAG U-16 (undrawn; Owner to rule): the non-verified Google lines on D-p9/D-p10 are removed.

  function googleProvenAt(s) {
    // D-p10 shows Google access last proven at the time of Claude's report call: a report call
    // that succeeded is also a Google call. The later of the two times is shown.
    var v = toDate(s && s.verification && s.verification.at);
    var c = toDate(s && s.claude && s.claude.last_report_at);
    if (v && c) { return when(v > c ? v.getTime() : c.getTime()); }
    return when((v || c) ? (v || c).getTime() : null);
  }

  // ------------------------------------------------------------------ rendering
  function renderBar() {
    var b = bar(state.view);
    $("stepbar").hidden = !b;
    if (!b) { return; }
    for (var i = 0; i < 5; i++) {
      var li = $("pill-" + (i + 1));
      li.textContent = b[i][0];
      li.className = "pill " + b[i][1];
      if (/^active/.test(b[i][1])) { li.setAttribute("aria-current", "step"); }
      else { li.removeAttribute("aria-current"); }
    }
  }

  function renderPanels() {
    var panels = document.querySelectorAll("section[data-state]");
    for (var i = 0; i < panels.length; i++) {
      panels[i].hidden = panels[i].getAttribute("data-state") !== state.view;
    }
    // PAIR's status area: one result at a time; "Find the helper" only before a result.
    var inPair = state.view === "PAIR";
    $("pair-ready").hidden = !(inPair && state.pair === "ready");
    $("pair-notfound").hidden = !(inPair && state.pair === "notfound");
    $("pair-denied").hidden = !(inPair && state.pair === "denied");
    // Each primary is hidden by its OWN attribute too, so getComputedStyle(button).display is
    // "none" outside its state. One enabled primary per state (AT-DOM-0).
    var key = inPair ? "PAIR-" + (state.pair === "searching" ? "idle" : state.pair) : state.view;
    var prim = document.querySelectorAll("[data-owner]");
    for (var j = 0; j < prim.length; j++) {
      prim[j].hidden = prim[j].getAttribute("data-owner") !== key;
    }
    $("find-btn").disabled = state.pair === "searching";
    $("connect-btn").disabled = state.flowBusy;
  }

  function renderTexts() {
    var s = state.status;

    // FLAG U-14 (undrawn; Owner to rule): the D-p4 search line is removed.
    // FLAG U-13 (undrawn; Owner to rule): the D-p5 waiting lines are removed.

    if (state.view === "PAIR" && state.pair === "ready") {
      $("pair-checked").textContent = hhmm(state.lastHealthAt || Date.now());
    }

    if (state.view === "S6" && s) {
      var t6 = when(s.verification && s.verification.at);
      atStrong($("s6-at"), t6);
      $("s6-google-at").textContent = t6 || "—";
    }

    if (state.view === "S7") {
      $("example-question").textContent = "“" + exampleText() + "”";
      renderProperty($("s7-property"));
      if (s) {
        var g7 = $("s7-google");
        if (s.google_access === "verified") {
          var t7 = when(s.verification && s.verification.at);
          g7.textContent = "Verified" + (t7 ? " · " + t7 : "");
          g7.className = "st-ok";
        } else {
          g7.textContent = "";      // FLAG U-16 (undrawn; Owner to rule)
          g7.className = "st-bad";
        }
      }
    }

    if (state.view === "S8" && s) {
      var c = s.claude || {};
      var t8 = when(c.last_report_at);
      atStrong($("s8-at"), t8);
      $("s8-claude-at").textContent = t8 || "—";
      $("s8-google-at").textContent = googleProvenAt(s) || "—";
      var g8 = $("s8-google-st");
      if (s.google_access === "verified") {
        g8.textContent = "Verified";
        g8.className = "st-ok";
      } else {
        g8.textContent = "";        // FLAG U-16 (undrawn; Owner to rule)
        g8.className = "st-bad";
      }
    }

    if (state.view === "F4") {
      $("f4-cause").textContent = state.failCause;
    }
  }

  function render() {
    renderBar();
    renderPanels();
    renderTexts();
  }

  function go(view) {
    var changed = view !== state.view;
    if (state.view === "S4" && view !== "S4") { state.gen += 1; }   // CRP-4: leaving D-p5
    state.view = view;
    if (view !== "RET") { remember(view); }
    render();
    if (changed) {
      var h = $("h-" + view);
      if (h && typeof h.focus === "function") { try { h.focus(); } catch (e) { /* ignore */ } }
    }
  }

  function pairShow(result) {
    state.pair = result;
    if (state.view !== "PAIR") { go("PAIR"); } else { render(); }
  }

  // ------------------------------------------------------------------ the search
  function startSearch() {
    state.searching = true;
    state.searchStartedAt = Date.now();
    state.pair = "searching";
    state.polling = true;
    if (state.view !== "PAIR") { go("PAIR"); } else { render(); }
    tick(false);
  }

  function usable() {
    return state.found && !state.refused && !!state.status;
  }

  // G-2 guard (Reviewer addendum 1; D-p10 MUST NOT "show a stale success as current"; p.17):
  // only a report call made AFTER this run's Google verification proves the Claude connection.
  function claudeProven(s) {
    var c = (s && s.claude) || {};
    if (c.verified !== true) { return false; }
    // CRP-5: Google verified now, by a verification made in THIS helper run.
    if (s.google_access !== "verified" || !s.verification || !s.run_id ||
        s.verification.run_id !== s.run_id) { return false; }
    var r = toDate(c.last_report_at);
    var v = toDate(s.verification && s.verification.at);
    return !!(r && v && r.getTime() > v.getTime());
  }

  // A verified Google connection restores the verified state (p.8, p.17): S8 when Claude has
  // made a report call, else S7 when the page was on S7 before the reload, else S6.
  function restoreVerified() {
    var s = state.status;
    if (!s || s.google_access !== "verified") { return false; }
    if (claudeProven(s)) { go("S8"); }
    else if (state.restoreTo === "S7") { go("S7"); }
    else { go("S6"); }
    state.restoreTo = null;
    return true;
  }

  // FLAG U-9: a refused page or a search that runs past SEARCH_FAIL_MS shows "Helper not found"
  // (or "Permission denied"), the existing failure handling, with no new copy.
  function searchFailed() {
    state.searching = false;
    return lnaDenied().then(function (denied) {
      if (state.view === "PAIR" || state.view === "RET") {
        pairShow(denied ? "denied" : "notfound");
      }
    });
  }

  function afterPoll() {
    var v = state.view;
    if (v === "RET") { return afterReturn(); }
    if (v === "S4" && state.flow) { return checkFlow(); }
    if (v === "PAIR") {
      if (usable()) {
        if (state.pair === "ready") { render(); return; }
        state.searching = false;
        if (!restoreVerified()) { pairShow("ready"); }
        return;
      }
      if (state.searching) {
        if (state.found && state.refused) {
          // N-4: no raw code in user text; the HTTP code goes to the console only.
          if (typeof console !== "undefined" && console.warn) {
            console.warn("helper refused /status: HTTP " + state.refused);
          }
          return searchFailed();
        }
        if (Date.now() - state.searchStartedAt >= SEARCH_FAIL_MS) { return searchFailed(); }
      }
      render();
      return;
    }
    if (v === "S6" || v === "S7" || v === "S8") {
      var s = state.status;
      // FLAG U-17: after disconnect, show reconnect step (brief p.8/p.12; Owner to rule)
      if (s && s.google_access === "not_connected") { state.pair = "ready"; go("PAIR"); return; }
      if (s && CREDENTIAL_STORE_DOWN[s.google_access] && !signinSaved(s)) {   // C-5
        failGoogle(SIGNIN_NOT_SAVED);
        return;
      }
      // FLAG U-12: D-p8 or D-p9 -> D-p10 on a proven report (p.17 + G-2 guard); never from 4a or D-p5.
      if ((v === "S6" || v === "S7") && s && claudeProven(s)) { go("S8"); return; }
    }
    render();
  }

  // ------------------------------------------------------------------ the return from Google
  // FLAG U-10: a sign-in that fails, or a test call that fails before D-p8, goes to F4 (the
  // existing failure handling, no new copy; not drawn in the design).
  function failGoogle(cause) {
    state.flow = null;
    hideFallback();
    state.failCause = cause;
    go("F4");
  }

  // Judge the helper's last sign-in (p.8 "המוצר מזהה תוצאה ומחזיר למסע"; p.17). `lf` must be the
  // flow in question. Returns true when a frame was decided.
  function judgeFlow(s, lf) {
    if (!lf || !lf.outcome || lf.outcome === "pending") { return false; }
    if (lf.outcome === "cancelled") { state.flow = null; hideFallback(); go("F3"); return true; }
    if (lf.outcome === "superseded") { failSuperseded(); return true; }
    if (lf.outcome !== "completed") {
      if (lf.detail === "timeout") {
        // AWAITING OWNER (O-1)
        failGoogle("We didn’t hear back from Google in time. Nothing new was connected.");
      } else if (lf.detail === "keychain_write_failed") {
        failGoogle(SIGNIN_NOT_SAVED);
      } else {
        // AWAITING OWNER (O-1)
        failGoogle("Google’s answer could not be completed, so nothing new was connected.");
      }
      return true;
    }
    // completed: wait for the helper's real test call (D-p6: "A real test call runs, then
    // step 5").
    // p.8: the verified state and its matching next step; Claude counts only under the G-2 guard.
    if (s.google_access === "verified") {
      state.flow = null; hideFallback(); go("S6"); return true;   // UD-5: D-p8; U-12 then advances
    }
    if (CREDENTIAL_STORE_DOWN[s.google_access] && !signinSaved(s)) {
      failGoogle(SIGNIN_NOT_SAVED);
      return true;
    }
    // CRP-1: "not_verified" is final only when it belongs to the CURRENT connection; a stale one
    // from an earlier attempt means the test call is still running: keep waiting.
    if (s.google_access === "not_verified" && s.verification &&
        s.verification.connection_id === s.connection_id) {
      // AWAITING OWNER (O-1)
      failGoogle("You signed in, but Google did not confirm access to your Analytics.");
      return true;
    }
    return false;
  }

  function failSuperseded() {
      // AWAITING OWNER (O-1)
      failGoogle("A newer sign-in attempt replaced this one, perhaps from another tab. " +
        "Nothing new was connected.");
  }

  function flowTimedOut(startedAt) {
    if (Date.now() - startedAt <= FLOW_TIMEOUT_MS) { return false; }
    // AWAITING OWNER (O-1)
    failGoogle("We didn’t hear back from the Google sign-in. If you closed that tab, try " +
      "again.");
    return true;
  }

  // The site tab waits on D-p5 while Google's screens run in their own tab, and advances by
  // itself on the result (p.8). D-p5 shows only its drawn content while waiting (U-13).
  function checkFlow() {
    var s = state.status;
    var lf = s && s.last_flow;
    // CRP-6: a newer sign-in (another tab) replaced this one. Judged only on a /status asked for
    // after this flow started, so an answer already in flight is never misread.
    if (s && lf && lf.id && lf.id !== state.flow.id && state.statusReqAt > state.flow.startedAt) {
      failSuperseded();
      return;
    }
    if (s && lf && lf.id === state.flow.id && judgeFlow(s, lf)) { return; }
    if (flowTimedOut(state.flow.startedAt)) { return; }
    render();
  }

  // The fallback path: the load came through the callback page's return action (the tab could
  // not close itself). Decide the right frame from /status: never S0 (p.8, p.18).
  // FLAG U-2: the site side of the callback return (the callback page itself is the helper's).
  function afterReturn() {
    if (!usable()) {
      if (state.found && state.refused) { return searchFailed(); }
      if (Date.now() - state.searchStartedAt >= SEARCH_FAIL_MS) { return searchFailed(); }
      render();
      return;
    }
    var s = state.status;
    var lf = s.last_flow;
    // This load keeps no flow id (no storage, see STATE_KEY): the helper's latest sign-in is
    // judged.
    if (judgeFlow(s, lf)) { return; }
    if (!lf) {
      // No sign-in to judge: show what the helper proves.
      if (s.google_access === "verified") { go("S6"); return; }   // UD-5: D-p8; U-12 then advances
      go("S4");
      return;
    }
    if (flowTimedOut(loadedAt)) { return; }
    render();
  }

  function returnTo() {
    return location.origin + location.pathname + RETURN_HASH;
  }

  function hideFallback() {
    $("signin-fallback").hidden = true;
    $("signin-link").removeAttribute("href");
  }

  // D-p5 "Continue to Google" opens Google's screens in their own tab (p.8 "המשך פותח את האישור");
  // this tab stays on D-p5 and follows the result. The callback page closes itself; when it
  // cannot, its one return action brings the user back with "#return".
  function startConnect() {
    if (state.flowBusy) { return; }
    // Open the tab NOW, inside the click, so the browser does not block it as a pop-up. No
    // placeholder text is written into it (the Reviewer removed "Opening Google…").
    // FLAG U-19: a re-click of "Continue to Google" while a Google tab is open leaves the earlier tab open; finishing consent there reaches a stopped flow (helper supersedes it). Undrawn; Owner to rule. CRP-2 close() is ineffective with opener=null (measured, probe_close.py).
    var w = null;
    try { w = window.open("", "_blank"); } catch (e) { w = null; }
    if (w) { try { w.opener = null; } catch (e) { /* ignore */ } }
    var gen = state.gen;                       // CRP-4
    state.flowBusy = true;
    state.flow = null;
    hideFallback();
    // FLAG U-13 (undrawn; Owner to rule): the "Starting the Google sign-in" line is removed.
    render();

    // Helper >= 1.1.0 takes `return_to`; 1.0.3 gets today's empty body (INTERFACE-03 §3, §4).
    var body = versionAtLeast(state.version, RETURN_TO_SINCE) ?
      JSON.stringify({ return_to: returnTo() }) : "{}";

    call("POST", "/connect/start", body).then(function (res) {
      state.flowBusy = false;
      if (gen !== state.gen) {
        // CRP-4: the page left D-p5 (e.g. "Back") while the start was in flight: drop it.
        if (w) { try { w.close(); } catch (e) { /* ignore */ } }
        render();
        return;
      }
      var d = res.data || {};
      if (res.network || res.status !== 200 || typeof d.authorize_url !== "string" ||
          typeof d.flow_id !== "string") {
        if (w) { try { w.close(); } catch (e) { /* ignore */ } }
        // N-4: a cause line, never a raw code.
        failGoogle(res.network ?
          // AWAITING OWNER (O-1)
          "We couldn’t reach the extension, so the sign-in didn’t start. Make sure Claude " +
          "Desktop is open." :
          // AWAITING OWNER (O-1)
          "The extension couldn’t start the Google sign-in. Try again in a moment.");
        return;
      }
      state.flow = { id: d.flow_id, startedAt: Date.now() };
      var opened = false;
      if (w && !w.closed) {                    // CRP-3: a tab the user already closed is not "opened"
        try { w.location.replace(d.authorize_url); opened = true; } catch (e) { opened = false; }
      }
      if (!opened) {
        // FLAG p.17 "מגבלת דפדפן מקבלת חלופת חזרה ברורה": the pop-up was blocked; the existing
        // fallback link (O-1) opens Google's screens.
        $("signin-link").href = d.authorize_url;
        $("signin-fallback").hidden = false;
      }
      if (!state.polling) { state.polling = true; }
      render();
      tick(false);
    });
  }

  function toBeforeGoogle() {
    state.flow = null;
    hideFallback();
    if (!state.polling) { state.polling = true; tick(false); }
    go("S4");
  }

  // ------------------------------------------------------------------ copy the example (N-7)
  // FLAG backlog: copy feedback not in design D-p9 (Owner 04:48). The copy runs; no result line.
  function copyExample() {
    var text = exampleText();
    try {
      if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
        navigator.clipboard.writeText(text).then(null, function () { /* no visible line */ });
      }
    } catch (e) { /* no visible line */ }
  }

  // ------------------------------------------------------------------ the polling loop
  var timer = null;
  var running = false;

  function tick(once) {
    if (!state.polling) { return Promise.resolve(); }
    if (running) {
      if (!once) { schedule(); }
      return Promise.resolve();
    }
    running = true;
    return call("GET", "/health").then(function (h) {
      var ok = !h.network && h.status === 200 && h.data && h.data.helper === "running";
      state.found = !!ok;
      if (!ok) {
        state.status = null;
        state.refused = null;
        return null;
      }
      state.version = typeof h.data.version === "string" ? h.data.version : null;
      var reqAt = Date.now();
      return call("GET", "/status").then(function (s) {
        if (s.network) {
          state.found = false;
          state.status = null;
          state.refused = null;
        } else if (s.status !== 200 || !s.data) {
          state.refused = s.status || "?";
          state.status = null;
        } else {
          state.refused = null;
          state.status = s.data;
          state.statusReqAt = reqAt;
          state.lastHealthAt = Date.now();
        }
      });
    }).then(function () {
      return afterPoll();
    }).catch(function () {
      render();
    }).then(function () {
      running = false;
      if (!once) { schedule(); }
    });
  }

  function schedule() {
    if (timer) { clearTimeout(timer); }
    timer = null;
    if (!state.polling) { return; }
    timer = setTimeout(function () { tick(false); }, TICK_MS);
  }

  // ------------------------------------------------------------------ controls
  $("download-link").addEventListener("click", function () { go("S1"); });   // the download proceeds
  $("received-btn").addEventListener("click", function () { go("S1"); });
  // FLAG K-1: "I've finished installing" kept as drawn; the brief p.8 says the product detects
  // completion. Detection starts at "Find the helper" (Reviewer Q2).
  $("installed-btn").addEventListener("click", function () {                // D-p3 -> D-p4, no request
    state.pair = "idle";
    go("PAIR");
  });
  $("find-btn").addEventListener("click", startSearch);                     // N-1: the first request
  $("f1-retry-btn").addEventListener("click", startSearch);
  $("denied-retry-btn").addEventListener("click", startSearch);
  // FLAG U-7 (target: the existing installer download) + FLAG A-4: "Download the installer" also
  // shows D-p3.
  $("f1-install-link").addEventListener("click", function () {              // the download proceeds
    state.searching = false;
    go("S1");
  });
  $("continue-btn").addEventListener("click", function () { go("S4"); });
  // FLAG U-6: "Back" -> the previous frame, D-p4 "Helper ready" (lead 04:29).
  $("back-btn").addEventListener("click", function () {
    state.flow = null;
    hideFallback();
    state.pair = "ready";
    go("PAIR");
  });
  $("connect-btn").addEventListener("click", startConnect);
  // FLAG T-CLAUDE-OPEN: "Next: open Claude Desktop" shows D-p9; opening the app is not proven.
  $("next-claude-btn").addEventListener("click", function () { go("S7"); });
  $("copy-btn").addEventListener("click", copyExample);
  $("f3-retry-btn").addEventListener("click", toBeforeGoogle);   // FLAG I-3: 4a "Try again" -> D-p5 (the map arrow)
  $("f4-retry-btn").addEventListener("click", toBeforeGoogle);
  // No-ops: drawn controls whose target no frame or brief defines (lead interim rules).
  function noop(e) { if (e && e.preventDefault) { e.preventDefault(); } }
  $("help-link").addEventListener("click", noop);         // FLAG U-7 (Help)
  $("get-claude").addEventListener("click", noop);        // FLAG U-7 (Get Claude Desktop)
  $("steps-link").addEventListener("click", noop);        // FLAG U-7 (Steps for your browser)
  $("cancel-setup-link").addEventListener("click", noop); // FLAG U-4 (Cancel setup)
  $("manage-btn").addEventListener("click", noop);        // FLAG K-5 pending Reviewer

  // ------------------------------------------------------------------ the first frame
  // N-1: no request to 127.0.0.1 on a plain load.
  // A-8: the #return load is the user's click on the callback "Return to grabmcp"; within N-1 per Reviewer ruling 2026-10-07 05:39:54 (A-8). FLAG U-18: #return opened in another browser or after the permission was revoked is undrawn (Owner to rule).
  if (location.hash === RETURN_HASH) {
    try { history.replaceState(null, "", location.pathname + location.search); } catch (e) { /* keep */ }
    state.view = "RET";
    state.searching = true;
    state.searchStartedAt = Date.now();
    state.polling = true;
    render();
    tick(false);
  } else {
    // FLAG K-2: no detection before a click (N-1), so an active install never skips the
    // download on D-p2. FLAG U-11: a reload restores the verified state at the first click.
    var last = remembered();
    if (last === "S1") {
      state.view = "S1";
    } else if (last && last !== "S0") {
      // A reload or reopen after the install: the pair frame, whose click restores the
      // verified state (p.8, p.17), at the first click N-1 allows.
      state.view = "PAIR";
      state.pair = "idle";
      state.restoreTo = last;
    }
    render();
  }
})();
