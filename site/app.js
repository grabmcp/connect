/* Connect Google Analytics to Claude: the page logic.
 *
 * The page talks ONLY to the helper that runs inside the Claude extension on this Mac, at
 * the loopback address below (helper contract 1.0; 1.1.0 features are feature-detected). It
 * holds no secret, never receives a token, and never shows the sign-in address it is given.
 *
 * The page is a STAGED journey (BEHAVIOUR-CONTRACT-03, as amended by plan v1.2 §7):
 *   S0 disclose -> S1 install (merged S1/S2) -> S3 found -> S4 before Google -> S5 waiting
 *   -> S6 Google verified -> S7 ask Claude -> S8 Claude verified; failures F1, F3, F4, and
 *   CX (setup cancelled from F3). Each state is one section[data-state] in index.html.
 * N-1: nothing is sent to 127.0.0.1 before the user clicks (S0's two controls, S1's primary).
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
  var SEARCH_FAIL_MS = 10000;      // contract S2: a network failure persisting 10 s -> F1
  var RETURN_TO_SINCE = [1, 1, 0]; // helper version that accepts `return_to` (INTERFACE-03 §3)

  var BASE = "http://127.0.0.1:" + HELPER_PORT;

  // Owner ruling C-5 (21:25): the helper's credential-store states never reach the user as
  // such; they read as a sign-in that could not be saved, with Try again (the F4 path).
  var CREDENTIAL_STORE_DOWN = { keychain_locked: true, keychain_unavailable: true };
  // AWAITING OWNER (O-1)
  var SIGNIN_NOT_SAVED = "Your Google sign-in couldn’t be saved on this Mac. Try connecting again.";
  // CR3-4: the store is unreadable right now but the sign-in IS saved; the launcher reads it
  // with macOS's own prompt at question time, so no new consent is asked for.
  // AWAITING OWNER (O-1)
  var SIGNIN_SAVED = "Your Google sign-in is saved on this Mac.";

  function signinSaved(s) {
    return !!s && s.local_credential === "present";
  }

  var $ = function (id) { return document.getElementById(id); };

  // Which step (A-4) each state belongs to, in journey order.
  var STEP_ORDER = ["disclose", "install", "find", "google", "claude"];
  var STEP_OF = {
    S0: "disclose", S1: "install", S3: "find", F1: "find",
    S4: "google", S5: "google", S6: "google", F3: "google", F4: "google", CX: "google",
    S7: "claude", S8: "claude"
  };

  var state = {
    view: "S0",          // the current contract state
    polling: false,      // the SIG-H poll runs (only ever started by a click, N-1)
    searching: false,    // a "find the extension" search is open (S0/S1/F1 -> S3 or F1)
    searchStartedAt: 0,
    installClicked: false,
    everFound: false,
    found: false,        // /health answered "running" to this page on the last check
    lastHealthAt: null,  // when that last successful check finished (ms)
    version: null,       // /health version, e.g. "1.0.3"
    refused: null,       // /status refused this page (HTTP code), if it did
    status: null,        // the last /status answer
    flow: null,          // {id, startedAt, done} of the sign-in this page started
    flowBusy: false,     // a /connect/start request is in flight
    failCause: "",       // F4's one cause line
    claudeBaseline: null, // claude.last_report_at seen when S6 was entered
    disconnectBusy: false
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

  // A short machine word from the helper (e.g. "access_denied") may be shown; anything else
  // is not echoed, so nothing long or secret-looking ever reaches the screen.
  function safeWord(v) {
    // Owner ruling C-5: a word naming the credential store or the system tool is never echoed.
    return (typeof v === "string" && /^[A-Za-z0-9_.\- ]{1,40}$/.test(v) &&
      !/keychain|security|credential/i.test(v)) ? v : null;
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

  // ------------------------------------------------------------------ presentation helpers
  function say(node, text, kind) {
    node.textContent = text;
    node.className = "status" + (kind ? " " + kind : "");
  }

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

  // N-11: every proof line carries its time, as in the design ("2 Oct, 19:36").
  function when(v) {
    var d = toDate(v);
    if (!d) { return null; }
    return d.toLocaleString("en-GB", { day: "numeric", month: "short",
      hour: "2-digit", minute: "2-digit" });
  }

  function clock(ms) {
    return new Date(ms).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit",
      second: "2-digit" });
  }

  function propertyParts() {
    var prop = state.status && state.status.property;
    if (!prop || !(prop.name || prop.id)) { return null; }
    var name = typeof prop.name === "string" ? prop.name : "";
    var id = (typeof prop.id === "string" || typeof prop.id === "number") ? String(prop.id) : "";
    return { name: name, id: id };
  }

  function propertyText() {
    var p = propertyParts();
    if (!p) {
      // AWAITING OWNER (O-1)
      return "The extension has not named the property yet.";
    }
    return (p.name || "(no name)") + (p.id ? " · ID " + p.id : "");
  }

  function exampleText() {
    var p = propertyParts();
    // AWAITING OWNER (O-1)
    return "How many users visited " + (p && p.name ? p.name : "my website") + " last week?";
  }

  function googleVerifiedLine() {
    var s = state.status || {};
    var at = when(s.verification && s.verification.at);
    // AWAITING OWNER (O-1)
    return "Google access: verified" + (at ? " at " + at : "") + ".";
  }

  function googleText(s) {
    var ga = s.google_access;
    if (ga === "verified") { return [googleVerifiedLine(), "ok"]; }
    // AWAITING OWNER (O-1): this line only
    if (ga === "not_connected") { return ["Google is not connected yet.", ""]; }
    if (ga === "unverified") {
      // AWAITING OWNER (O-1)
      return ["You connected Google before. The extension is checking that access again; " +
        "this page continues by itself.", "wait"];
    }
    if (ga === "not_verified") {
      // AWAITING OWNER (O-1)
      return ["Google did not confirm access to your Analytics just now. Continue to " +
        "connect Google again.", "bad"];
    }
    // Owner ruling C-5: no user text names the credential store; both states read the same.
    if (CREDENTIAL_STORE_DOWN[ga]) {
      // AWAITING OWNER (O-1)
      return signinSaved(s) ? [SIGNIN_SAVED, ""] : [SIGNIN_NOT_SAVED, "bad"];
    }
    // AWAITING OWNER (O-1)
    return ["Google access: unknown (the extension reported “" + (safeWord(ga) || "?") + "”).", "bad"];
  }

  // ------------------------------------------------------------------ rendering
  function renderSteps() {
    var active = STEP_OF[state.view];
    var ai = STEP_ORDER.indexOf(active);
    for (var i = 0; i < STEP_ORDER.length; i++) {
      var key = STEP_ORDER[i];
      var li = $("step-" + key);
      var isActive = i === ai, isDone = i < ai;
      li.classList.toggle("active", isActive);
      li.classList.toggle("done", isDone);
      li.classList.toggle("todo", i > ai);
      if (isActive) { li.setAttribute("aria-current", "step"); } else { li.removeAttribute("aria-current"); }
      $("body-" + key).hidden = !isActive;     // finished and future steps stay collapsed
      var flag = "";
      if (isDone) {
        // AWAITING OWNER (O-1): the step flags
        flag = (key === "install" && !state.installClicked && !state.everFound) ? "skipped" :
          (key === "google") ? "verified" : "done";
      } else if (isActive) {
        if (state.view === "S6" || state.view === "S8") { flag = "verified"; }
        else if (state.view === "F3") { flag = "not granted"; }
        else if (state.view === "F4") { flag = "didn’t finish"; }
        else if (state.view === "F1") { flag = "not found"; }
      }
      $("flag-" + key).textContent = flag ? " — " + flag : "";
    }
  }

  function renderPanels() {
    var panels = document.querySelectorAll("section[data-state]");
    for (var i = 0; i < panels.length; i++) {
      panels[i].hidden = panels[i].getAttribute("data-state") !== state.view;
    }
    // Each primary is hidden by its OWN attribute too, so getComputedStyle(button).display is
    // "none" outside its state (a hidden ancestor alone does not change a child's computed
    // display). One enabled primary per state (AT-DOM-0).
    var prim = document.querySelectorAll("[data-owner]");
    for (var j = 0; j < prim.length; j++) {
      prim[j].hidden = prim[j].getAttribute("data-owner") !== state.view;
    }
    $("connect-btn").disabled = state.flowBusy || !!state.flow;
    $("restart-btn").disabled = state.flowBusy;
    $("disconnect-area").hidden = !(state.view === "S6" || state.view === "S8");
    $("disconnect-btn").disabled = state.disconnectBusy;
  }

  function searchLine() {
    // AWAITING OWNER (O-1)
    return state.searching ? "Looking for the extension on this Mac…" : "";
  }

  function renderTexts() {
    var s = state.status;

    say($("s0-search"), state.view === "S0" ? searchLine() : "", "wait");
    say($("s1-search"), state.view === "S1" ? searchLine() : "", "wait");

    if (state.view === "S3") {
      // AWAITING OWNER (O-1)
      say($("s3-proof"), "Found on this Mac, checked at " + clock(state.lastHealthAt || Date.now()) +
        ". This proves the extension only: Google and Claude are not connected yet.", "ok");
      if (s && s.google_access && s.google_access !== "not_connected") {
        var g = googleText(s);
        say($("s3-google"), g[0], g[1]);
      } else {
        say($("s3-google"), "", "");
      }
    }

    if (state.view === "F1") {
      if (state.found && state.refused) {
        // ADD-11 (N-4): no raw code in user text; the HTTP code goes to the console only.
        if (typeof console !== "undefined" && console.warn) {
          console.warn("helper refused /status: HTTP " + state.refused);
        }
        // AWAITING OWNER (O-1)
        $("f1-text").textContent = "The extension is running, but it did not accept this page. " +
          "Make sure you opened this page from its usual address.";
      } else {
        // AWAITING OWNER (O-1)
        $("f1-text").textContent = "It runs inside Claude Desktop, so Claude Desktop must be " +
          "open. It may also not be installed yet.";
      }
      // AWAITING OWNER (O-1)
      say($("f1-search"), "This page keeps checking every few seconds.", "wait");
    }

    if (state.view === "S5") {
      // AWAITING OWNER (O-1)
      say($("s5-status"), (state.flow && state.flow.done) ?
        "Google sign-in finished. Checking access to your Analytics…" :
        "Waiting for you to finish in the Google tab…", "wait");
    }

    if (state.view === "S6" && s) {
      var at6 = when(s.verification && s.verification.at);
      // AWAITING OWNER (O-1)
      say($("s6-proof"), "Google access verified" + (at6 ? " at " + at6 : "") + ". This proves " +
        "Google access only; Claude hasn’t used it yet.", "ok");
      $("s6-property").textContent = propertyText();
    }

    if (state.view === "S7") {
      $("example-question").textContent = "“" + exampleText() + "”";
      $("s7-property").textContent = propertyText();
      if (s) {
        var g7 = googleText(s);
        say($("s7-google"), g7[0], g7[1]);
      }
      // AWAITING OWNER (O-1)
      say($("s7-claude"), "Claude connection: waiting for your first question in Claude. This " +
        "page updates by itself when Claude makes its first successful report call.", "wait");
    }

    if (state.view === "S8" && s) {
      var c = s.claude || {};
      var at8 = when(c.last_report_at);
      // AWAITING OWNER (O-1)
      say($("s8-proof"), "Claude made a successful report call" + (at8 ? " at " + at8 : "") + ".", "ok");
      var g8 = googleText(s);
      say($("s8-google"), g8[0], g8[1]);
    }

    if (state.view === "F4") {
      $("f4-cause").textContent = state.failCause;
    }

    // Lost the helper after it was found, outside the search states.
    $("helper-lost").hidden = !(state.polling && state.everFound && !state.found &&
      state.view !== "S0" && state.view !== "S1" && state.view !== "F1" && state.view !== "CX");
  }

  function render() {
    renderSteps();
    renderPanels();
    renderTexts();
  }

  function go(view) {
    var changed = view !== state.view;
    state.view = view;
    if (view === "S6") {
      var c = (state.status && state.status.claude) || {};
      state.claudeBaseline = c.verified === true ? c.last_report_at : null;
    }
    render();
    if (changed) {
      var h = $("h-" + view);
      if (h && typeof h.focus === "function") { try { h.focus(); } catch (e) { /* ignore */ } }
    }
  }

  // ------------------------------------------------------------------ the search (SIG-H)
  function startSearch() {
    state.searching = true;
    state.searchStartedAt = Date.now();
    state.polling = true;
    render();
    tick(false);
  }

  // S3 shortcut (contract S3; A-1): a verified Google connection skips to S6, or to S8 when
  // Claude has also made a report call.
  function shortcut() {
    var s = state.status;
    if (!s || s.google_access !== "verified") { return false; }
    var c = s.claude || {};
    go(c.verified === true ? "S8" : "S6");
    return true;
  }

  function usable() {
    return state.found && !state.refused && !!state.status;
  }

  function afterPoll() {
    var v = state.view;
    if (state.searching && (v === "S0" || v === "S1" || v === "F1")) {
      if (usable()) {
        state.searching = false;
        if (!shortcut()) { go("S3"); }
        return;
      }
      if ((state.found && state.refused) ||
          Date.now() - state.searchStartedAt >= SEARCH_FAIL_MS) {
        state.searching = false;
        go("F1");
        return;
      }
    } else if (v === "F1") {
      if (usable()) { if (!shortcut()) { go("S3"); } return; }
    } else if (v === "S3") {
      if (usable() && shortcut()) { return; }
    } else if (v === "S5") {
      checkFlow();
      return;
    } else if (v === "S6" || v === "S7" || v === "S8") {
      var s = state.status;
      if (s && s.google_access === "not_connected") { go("S3"); return; }   // e.g. after Disconnect
      if (s && CREDENTIAL_STORE_DOWN[s.google_access] && !signinSaved(s)) {   // C-5; CR3-4
        failGoogle(SIGNIN_NOT_SAVED);
        return;
      }
      if (v === "S7" && s) {
        var c = s.claude || {};
        if (c.verified === true && c.last_report_at !== state.claudeBaseline) { go("S8"); return; }
      }
    }
    render();
  }

  // ------------------------------------------------------------------ the sign-in flow
  function failGoogle(cause) {
    state.flow = null;
    state.failCause = cause;
    hideFallback();
    go("F4");
  }

  function hideFallback() {
    $("signin-fallback").hidden = true;
    $("signin-link").removeAttribute("href");
  }

  function checkFlow() {
    var s = state.status;
    if (!state.flow) { render(); return; }
    var lf = s && s.last_flow;
    if (!state.flow.done && lf && lf.id === state.flow.id && lf.outcome && lf.outcome !== "pending") {
      if (lf.outcome === "completed") {
        state.flow.done = true;
      } else if (lf.outcome === "cancelled") {
        state.flow = null;
        hideFallback();
        go("F3");
        return;
      } else if (lf.outcome === "superseded") {
        // AWAITING OWNER (O-1)
        failGoogle("A newer sign-in attempt replaced this one, perhaps from another tab. " +
          "Nothing new was connected.");
        return;
      } else if (lf.detail === "timeout") {
        // CR3-3: the helper publishes a timeout as outcome "failed", detail "timeout".
        // AWAITING OWNER (O-1)
        failGoogle("We didn’t hear back from Google in time. Nothing new was connected.");
        return;
      } else if (lf.detail === "keychain_write_failed") {
        // CR3-3: the cause was local (the sign-in could not be stored), not Google.
        failGoogle(SIGNIN_NOT_SAVED);
        return;
      } else {
        // AWAITING OWNER (O-1)
        failGoogle("Google’s answer could not be completed, so nothing new was connected.");
        return;
      }
    }
    if (state.flow.done && s) {
      if (s.google_access === "verified") {
        state.flow = null;
        hideFallback();
        go("S6");
        return;
      }
      // CR3-4: a saved sign-in is not "couldn't be saved"; S5 keeps waiting for the
      // verification, and "Start again" (CR3-5) is the way out.
      if (CREDENTIAL_STORE_DOWN[s.google_access] && !signinSaved(s)) {
        failGoogle(SIGNIN_NOT_SAVED);
        return;
      }
      if (s.google_access === "not_verified") {
        // AWAITING OWNER (O-1)
        failGoogle("You signed in, but Google did not confirm access to your Analytics.");
        return;
      }
    }
    if (Date.now() - state.flow.startedAt > FLOW_TIMEOUT_MS) {
      // AWAITING OWNER (O-1)
      failGoogle("We didn’t hear back from the Google sign-in. If you closed that tab, try " +
        "again.");
      return;
    }
    render();
  }

  function returnTo() {
    return location.origin + location.pathname;    // location.href without query or fragment
  }

  function startConnect() {
    if (state.flowBusy || state.flow) { return; }
    // Open the new tab NOW, inside the click, so the browser does not block it as a pop-up.
    var w = null;
    try { w = window.open("", "_blank"); } catch (e) { w = null; }
    if (w) {
      try {
        w.opener = null;
        // AWAITING OWNER (O-1): both lines
        w.document.title = "Opening Google…";
        w.document.body.textContent = "Opening the Google sign-in page…";
      } catch (e) { /* the tab still works without the placeholder text */ }
    }
    state.flowBusy = true;
    hideFallback();
    say($("disconnect-status"), "", "");
    // AWAITING OWNER (O-1)
    say($("connect-status"), "Starting the Google sign-in…", "wait");
    render();

    // Helper >= 1.1.0 takes `return_to` for the callback page's way back; 1.0.3 gets today's
    // empty body (INTERFACE-03 §3, §4).
    var body = versionAtLeast(state.version, RETURN_TO_SINCE) ?
      JSON.stringify({ return_to: returnTo() }) : "{}";

    call("POST", "/connect/start", body).then(function (res) {
      state.flowBusy = false;
      say($("connect-status"), "", "");
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
      state.flow = { id: d.flow_id, startedAt: Date.now(), done: false };
      var opened = false;
      if (w) {
        try { w.location.replace(d.authorize_url); opened = true; } catch (e) { opened = false; }
      }
      if (!opened) {
        $("signin-link").href = d.authorize_url;
        $("signin-fallback").hidden = false;
      }
      go("S5");
    });
  }

  // CR3-5: S5's one secondary. A new /connect/start supersedes the old flow at the helper
  // (E2-05); the old flow's outcome no longer matches this page's flow id, so it is ignored.
  function restartConnect() {
    state.flow = null;
    hideFallback();
    startConnect();
  }

  function toBeforeGoogle() {
    state.flow = null;
    hideFallback();
    if (!state.polling) { state.polling = true; tick(false); }
    go("S4");
  }

  function cancelSetup() {
    state.flow = null;
    state.polling = false;
    if (timer) { clearTimeout(timer); timer = null; }
    go("CX");
  }

  // ------------------------------------------------------------------ copy the example (N-7)
  function copyExample() {
    var text = exampleText();
    var node = $("copy-status");
    // AWAITING OWNER (O-1): both lines
    var okText = "Copied. Paste it into a new conversation in Claude.";
    var failText = "Couldn’t copy automatically. Select the question above and copy it yourself.";
    var p = null;
    try {
      if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
        p = navigator.clipboard.writeText(text);     // inside the click (user activation)
      }
    } catch (e) { p = null; }
    if (!p) { say(node, failText, "bad"); return; }
    p.then(function () { say(node, okText, "ok"); },
           function () { say(node, failText, "bad"); });
  }

  // ------------------------------------------------------------------ disconnect
  // AWAITING OWNER (O-1): every sentence below (inherited from 0.6.3). "under Security,
  // third-party connections" names Google's own account section, not the `security` tool
  // (G-4, exempt from C-5 by the lead's ruling); it is marked so the Owner can reword it.
  function disconnectText(res) {
    if (res.network) {
      return ["Could not reach the extension, so nothing was disconnected. Open Claude Desktop " +
        "and try again.", "bad"];
    }
    var d = res.data || {};
    if (res.status === 503 && (d.error === "keychain_unreadable" ||
        d.error === "credential_store_unavailable")) {
      // Owner ruling C-5. AWAITING OWNER (O-1)
      return ["Nothing was disconnected. Try again in a moment.", "bad"];
    }
    if (res.status !== 200) {
      // N-4: no raw code in user text; the HTTP status and the helper's word go to the
      // console only.
      if (typeof console !== "undefined" && console.warn) {
        console.warn("disconnect answered HTTP " + res.status +
          (safeWord(d.error) ? ": " + safeWord(d.error) : ""));
      }
      // AWAITING OWNER (O-1)
      return ["Disconnect did not work. Try again in a moment.", "bad"];
    }
    var local = d.local_credential;
    var prov = d.provider_authorization;
    var parts = [];
    var full = (local === "absent") && (prov === "revoked" || prov === "none");
    parts.push(full ? "Disconnected." : "Only partly disconnected.");
    if (local === "absent") {
      parts.push("The saved Google sign-in is no longer on this Mac.");
    } else if (local === "present") {
      parts.push("The saved Google sign-in could NOT be removed from this Mac.");
    } else {
      parts.push("Whether a Google sign-in is still saved on this Mac is unknown.");
    }
    if (prov === "revoked") {
      parts.push("Google confirmed that the access is withdrawn.");
    } else if (prov === "none") {
      parts.push("There was no Google access to withdraw.");
    } else if (prov === "revoke_failed") {
      // AWAITING OWNER (O-1) (G-4)
      parts.push("Google did not confirm withdrawing the access; you can remove it yourself in " +
        "your Google Account, under Security, third-party connections.");
    } else {
      parts.push("Google was not asked to withdraw the access.");
    }
    parts.push("Claude Desktop and the extension stay installed, and your past Claude " +
      "conversations are not changed.");
    return [parts.join(" "), full ? "ok" : "bad"];
  }

  function startDisconnect() {
    if (state.disconnectBusy) { return; }
    state.disconnectBusy = true;
    // AWAITING OWNER (O-1)
    say($("disconnect-status"), "Disconnecting…", "wait");
    render();
    call("POST", "/disconnect").then(function (res) {
      state.disconnectBusy = false;
      var t = disconnectText(res);
      say($("disconnect-status"), t[0], t[1]);
      return tick(true);
    });
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
          state.everFound = true;
          state.lastHealthAt = Date.now();
        }
      });
    }).then(function () {
      afterPoll();
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
  $("already-btn").addEventListener("click", startSearch);                  // A-1: one click
  $("installed-btn").addEventListener("click", function () {                // A-2: one click
    state.installClicked = true;
    startSearch();
  });
  $("f1-retry-btn").addEventListener("click", startSearch);
  $("f1-install-link").addEventListener("click", function () {              // A-1: F1's fallback
    state.searching = false;
    go("S1");
  });
  $("continue-btn").addEventListener("click", function () { go("S4"); });
  $("connect-btn").addEventListener("click", startConnect);
  $("restart-btn").addEventListener("click", restartConnect);
  $("next-claude-btn").addEventListener("click", function () { go("S7"); });
  $("copy-btn").addEventListener("click", copyExample);
  $("f3-retry-btn").addEventListener("click", toBeforeGoogle);
  $("f4-retry-btn").addEventListener("click", toBeforeGoogle);
  $("resume-btn").addEventListener("click", toBeforeGoogle);
  $("cancel-setup-btn").addEventListener("click", cancelSetup);
  $("disconnect-btn").addEventListener("click", startDisconnect);

  // N-1: no request to 127.0.0.1 here. The poll starts only from a click above.
  render();
})();
