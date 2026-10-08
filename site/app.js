/* Connect Google Analytics to Claude: the journey logic (WP-S2, PLAN-05 v1.1, INTERFACE-05).
 *
 * The page talks ONLY to the helper inside the Claude extension on this Mac, at the loopback
 * address below (helper 1.2.0). It holds no secret, never receives a token, stores nothing
 * (no storage API of any kind), writes no markup (every view change goes through
 * GrabViews.render from views.js) and never injects a question anywhere.
 *
 * Which screen shows is decided from the helper's state (/status), never from the page:
 *   plan s3.1 N1-N15, s3.2 R1-R3 and R-resume, s4 state rules, s5 "ready", s6 privacy.
 * Signals: perm = navigator.permissions.query loopback-network (fallback local-network-access);
 * a query that rejects or throws counts as "unsupported" (F-4 / UX-18).
 * No loopback request is made on load unless perm is "granted" (T-STATIC-NO-AUTO-REQUEST).
 */
(function () {
  "use strict";

  // The helper's fixed port. ONE constant line: the tests serve a copy with it rewritten.
  var HELPER_PORT = 50812;
  var BASE = "http://127.0.0.1:" + HELPER_PORT;

  var TICK_MS = 2500;                  // N4/N5: /health polling, fixed cadence
  var PERM_REQUERY_MS = 2500;          // N3/UX-8: re-query the permission (no network)
  var DOWNLOAD_BOUND_MS = 600000;      // N4: up to 10 min after the Download click, then N5
  var FINISHING_MS = 20000;            // N8 -> N10: "Finishing setup..." shows at most 20 s (UX-13)
  var REQUEST_TIMEOUT_MS = 8000;       // one loopback request may take this long
  // FX-6 (INTERFACE-05 s7.4): each timeout exceeds the helper's worst case for its route.
  var VERIFY_TIMEOUT_MS = 75000;       // POST /verify: keychain read + up to four Google calls
  var OPEN_TIMEOUT_MS = 15000;         // the helper's Claude-open call (open 10 s + front check 2 s)
  var AWAY_RESUME_MS = 10000;          // if the same-tab navigation to Google never happens
  var TEMP_DELAYS_MS = [5000, 10000, 20000];   // N12 back-off ...
  var TEMP_EVERY_MS = 30000;                   // ... then every 30 s while the page is visible
  var RETURN_TO_PATH = "/connect/";    // return_to = origin + "/connect/#return" (lead's task)
  var CHANNEL_NAME = "grabmcp-connect";
  var CLAUDE_LINK = "claude://";       // exactly this, never with a question (T-STATIC-NO-PROMPT)
  var PERM_NAMES = ["loopback-network", "local-network-access"];
  var ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
  var FOCUS_INTENT_MS = 20000;         // UXB-6: a click's own outcome (the open call is bounded at 15 s)

  var $ = function (id) { return document.getElementById(id); };

  // ------------------------------------------------------------------ the per-tab id
  // Random, in memory only (never stored, never shown); sent as ?tab= on /status and in the
  // /connect/start body (helper: [A-Za-z0-9_-]{8,64}). A new one after a bfcache restore (pageshow).
  function newTabId() {
    var abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    var b = new Uint8Array(16), s = "", i;
    if (window.crypto && typeof window.crypto.getRandomValues === "function") {
      window.crypto.getRandomValues(b);
    } else {
      for (i = 0; i < b.length; i++) { b[i] = Math.floor(Math.random() * 256); }
    }
    for (i = 0; i < b.length; i++) { s += abc.charAt(b[i] & 63); }
    return s;
  }
  var TAB = newTabId();

  // ------------------------------------------------------------------ the page's state
  var S = {
    perm: "unknown",      // granted | prompt | denied | unsupported
    view: null,           // the state shown (GrabViews.STATES), null before the first decision
    sub: null,
    status: null,         // the last good /status answer
    ctx: null,            // how this load arrived: see parseHash()
    loadVerify: false,    // R1/UX-16: a fresh POST /verify at this load, before deciding
    justVerified: false,  // the /status being judged was read right after our own /verify
    verifying: false,
    unverifiedSince: 0,   // N8: a completed flow whose verification the helper is still running
    downloaded: false,    // the Download click happened (download polling may run, N4)
    dlStartedAt: 0,       // when the current 10-minute bound started
    waitGrab: false,      // WAITING "grabmcp" after a claude:// Open button (N5, N13, R3)
    waitClaude: false,    // WAITING "claude" after NotLoaded's Open button (N10)
    finishStarted: false, // N8 "Finishing setup..." timer started
    finishingExpired: false,
    isOwner: false,       // /status.owner.is_you on the last read
    startedFlowId: null,  // the flow this page started (then navigated to Google)
    starting: false,      // a /connect/start is in flight
    opening: false,       // the helper's Claude-open call is in flight
    away: false,          // navigating to Google: no polling
    reached: false,       // FX-13: this page has had an answer from the helper (/health or /status)
    noPermModel: false,   // FX-14: #return / #ready load in a browser without the permission (unsupported)
    gen: 0                // bumped when a user act or a denial makes an in-flight read stale
  };

  // ------------------------------------------------------------------ talking to the helper
  // Every call resolves (never rejects): {network: true} when the helper could not be reached
  // at all (not running, blocked by the browser, or timed out).
  function call(method, path, body, timeoutMs) {
    var opts = { method: method, mode: "cors", cache: "no-store", credentials: "omit" };
    if (method === "POST") {
      opts.headers = { "Content-Type": "application/json" };
      opts.body = body || "{}";
    }
    var timer = null;
    if (typeof AbortController === "function") {
      var ctl = new AbortController();
      opts.signal = ctl.signal;
      timer = setTimeout(function () { ctl.abort(); }, timeoutMs || REQUEST_TIMEOUT_MS);
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

  // ------------------------------------------------------------------ the permission (perm)
  var permName = null;     // the permission name this browser answered for
  var permWatched = null;  // the PermissionStatus whose onchange is watched

  function queryName(n) {  // a throw, a rejection or a non-promise all become one promise
    return new Promise(function (res) { res(navigator.permissions.query({ name: n })); });
  }

  function queryPerm() {
    if (!navigator.permissions || typeof navigator.permissions.query !== "function") {
      return Promise.resolve("unsupported");
    }
    function tryName(i) {
      if (i >= PERM_NAMES.length) { return Promise.resolve("unsupported"); }
      var name = PERM_NAMES[i];
      return queryName(name).then(function (st) {
        if (!st || typeof st.state !== "string") { return tryName(i + 1); }
        permName = name;
        if (!permWatched) {
          permWatched = st;
          st.onchange = function () { setPerm(typeof st.state === "string" ? st.state : "prompt"); };
        }
        return st.state;
      }, function () { return tryName(i + 1); });
    }
    var start = permName ? PERM_NAMES.indexOf(permName) : 0;
    return tryName(start < 0 ? 0 : start).then(null, function () { return "unsupported"; });
  }

  // Re-query on a timer, on visibilitychange and on focus: no network, a query raises no prompt.
  function requery() {
    queryPerm().then(setPerm);
  }

  function setPerm(state) {
    if (state === S.perm) { return; }
    S.perm = state;
    if (S.view === null) { return; }          // boot has not decided yet
    if (state === "granted") {
      if (S.view === "A") { go("A"); return; }   // the note hides; the click reads /health first (N1)
      if (S.view === "LNABLOCKED" && !S.downloaded) {
        // N3 for a #return / #ready load: now granted, decide as that load would have.
        if (S.ctx.kind === "return" && !S.ctx.settled) { go("CHECKING", { sub: "checking" }); }
        else { S.loadVerify = true; }
      }
      tickNow();                              // N2/N3: /health FIRST; B only if it is silent
      return;
    }
    if (state === "denied") {
      S.gen += 1;                             // a read still in flight must not undo this
      if (S.view === "A") { go("A"); return; }
      if (S.view !== "PASSIVE" && S.view !== "LNABLOCKED") { go("LNABLOCKED"); }
      stopPoll();
      return;
    }
    if (S.view === "A") { go("A"); }          // the LNA note shows only while "prompt"
  }

  // ------------------------------------------------------------------ rendering (views.js only)
  function front(s) {
    return !!(s && s.claude_frontmost && s.claude_frontmost.front === true);
  }

  function pad2(n) { return (n < 10 ? "0" : "") + n; }
  var MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

  // The helper and the launcher write "%Y-%m-%dT%H:%M:%S%z" (e.g. +0300); a colon is added so
  // every browser parses it.
  function toDate(v) {
    if (typeof v !== "string") { return null; }
    var d = new Date(v.replace(/([+-]\d{2})(\d{2})$/, "$1:$2"));
    return isNaN(d.getTime()) ? null : d;
  }

  // R1 "Last used in Claude": F-9 proposal (Owner-pending): "today, HH:MM" / "yesterday, HH:MM",
  // else "D Mon, HH:MM"; null (line hidden) when never used.
  function lastUsedText(s) {
    var d = toDate(s && s.claude && s.claude.last_report_at);
    if (!d) { return null; }
    var hm = pad2(d.getHours()) + ":" + pad2(d.getMinutes());
    var today = new Date();
    var y = new Date(today.getFullYear(), today.getMonth(), today.getDate() - 1);
    function same(a, b) {
      return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() &&
        a.getDate() === b.getDate();
    }
    if (same(d, today)) { return "today, " + hm; }
    if (same(d, y)) { return "yesterday, " + hm; }
    return d.getDate() + " " + MONTHS[d.getMonth()] + ", " + hm;
  }

  // UXB-6: the new state's heading, else its visible status line, else its first paragraph.
  var focusIntent = null, focusPlaced = null;   // focusPlaced: the element this code last focused
  function focusTarget(sec) {
    var h = sec.querySelector("h1, h2, h3");
    if (h) { return h; }
    var st = sec.querySelectorAll('[role="status"]');
    for (var i = 0; i < st.length; i++) { if (!st[i].hidden) { return st[i]; } }
    return sec.querySelector("p");
  }
  function moveFocusIfClickHidden(shown, hadPlaced) {
    if (!shown) { return; }
    var fi = focusIntent, move = false;
    if (fi && Date.now() - fi.at > FOCUS_INTENT_MS) { focusIntent = fi = null; }
    if (fi && shown !== fi.section && fi.section.hidden) { move = true; focusIntent = null; }
    // the same click's chain (e.g. Try now -> Checking -> R1): focus this code placed would
    // otherwise fall to <body> when its section hides
    if (!move && hadPlaced && (focusPlaced.hidden || !shown.contains(focusPlaced))) { move = true; }
    if (!move) { return; }
    var t = focusTarget(shown);
    if (!t) { return; }
    t.setAttribute("tabindex", "-1");
    try { t.focus({ preventScroll: true }); } catch (e) { /* ignore */ }
    focusPlaced = t;
  }

  function show(view, opts) {
    opts = opts || {};
    // KPI-3 gate (plan s5): D and R1 render ONLY on status.ready.
    if ((view === "D" || view === "R1") && !(S.status && S.status.ready === true)) { return; }
    var o = {};
    if (opts.sub) { o.sub = opts.sub; }
    if (opts.variant) { o.variant = opts.variant; }
    if (view === "A") { o.lnaNote = S.perm === "prompt"; }
    if (view === "D") {
      var p = S.status && S.status.property;
      if (p && typeof p.name === "string" && p.name !== "") { o.property = p.name; }
    }
    if (view === "R1") { o.lastUsed = lastUsedText(S.status); }
    S.view = view;
    S.sub = opts.sub || null;
    var hadPlaced = !!focusPlaced && document.activeElement === focusPlaced;
    moveFocusIfClickHidden(window.GrabViews.render(view, o), hadPlaced);
  }

  // Every state change goes through here: it keeps the timers in step with the view.
  function go(view, opts) {
    opts = opts || {};
    if (S.finishStarted && !(view === "CHECKING" && opts.sub === "finishing")) {
      S.finishingExpired = true;
      if (finishTimer) { clearTimeout(finishTimer); finishTimer = null; }
    }
    if (view !== "TEMPERROR" && !(view === "CHECKING" && S.verifying)) { tempStop(); }
    if (view !== "WAITING") { S.waitClaude = false; S.waitGrab = false; }
    show(view, opts);
    if (view === "TEMPERROR") { tempEnsure(); }
  }

  function readyView() {
    // D after a sign-in this page came back from (N8 -> N9); R1 for a load that finds the
    // helper ready (R1, R-resume).
    return S.ctx && S.ctx.afterFlow ? "D" : "R1";
  }

  // ------------------------------------------------------------------ the decision (plan s3, s4)
  // Returns {view, sub, variant} or {verify: true} (run POST /verify, then decide again).
  function decide(s) {
    var ga = s.google_access, lf = (s.last_flow && typeof s.last_flow === "object") ? s.last_flow : null;
    var C = S.ctx;

    // (1) The flow this load came back for (#return=<id>): N8, N11, N13's resolution.
    if (C.kind === "return" && !C.settled) {
      var match = !!(lf && C.returnId && lf.id === C.returnId);
      if (!match) {
        C.settled = true;                 // nothing matches: decide from the helper's state
      } else if (lf.outcome === "pending") {
        return { view: "CHECKING", sub: "checking" };
      } else {
        C.settled = true;
        if (lf.outcome === "completed") {
          C.afterFlow = true;             // N8
        } else if (lf.outcome === "interrupted") {
          // s3.4: decide from saved state: access saved -> N8 (no new consent); not saved -> N11
          if (ga === "not_connected") { C.failed = true; } else { C.afterFlow = true; }
        } else if (lf.outcome === "cancelled" || lf.outcome === "failed") {
          C.failed = true;                // N11
        }
        // "superseded" (another start replaced it): the helper's state decides
      }
    }
    if (C.failed) {
      // N11 NotFinished stays while the helper still names this flow as the latest one.
      if (lf && lf.id === C.returnId) { return { view: "NOTFINISHED" }; }
      C.failed = false;
    }

    // (2) R1/UX-16: a FRESH access test at this load (not while a sign-in is pending).
    if (S.loadVerify) {
      S.loadVerify = false;
      if (ga !== "not_connected" && ga !== "keychain_locked" && ga !== "keychain_unavailable" &&
          !(lf && lf.outcome === "pending")) {
        return { verify: true };
      }
    }

    // (3) N15: LaunchFailed stays while ready, until Claude is frontmost at a later read (UX-22).
    if (S.view === "LAUNCHFAILED" && s.ready === true) {
      return front(s) ? { view: readyView() } : { view: "LAUNCHFAILED" };
    }

    // (4) KPI-3: ready = verified AND property_present AND claude_loaded.ok (the helper's word).
    if (s.ready === true) { return { view: readyView() }; }

    // (5) R-resume: a pending sign-in keeps its screen live (never a dead C, UX-14).
    if (lf && lf.outcome === "pending" && ga !== "verified") {
      if (S.view === "C" || S.view === "R2" || S.view === "NOTFINISHED") { return { view: S.view }; }
      return { view: "C" };
    }

    if (ga === "verified") {
      // F-11 / UX-7: the allowed property is missing -> never D or R1; interim N11.
      if (s.property_present !== true) { return { view: "NOTFINISHED" }; }
      // verified, Claude has not loaded GrabMCP yet
      if (C.afterFlow && !S.finishingExpired) {
        startFinishing();
        return { view: "CHECKING", sub: "finishing" };
      }
      if (S.waitClaude) { return { view: "WAITING", sub: "claude" }; }
      return { view: "NOTLOADED" };
    }
    if (ga === "unverified") {
      // A connection exists that nothing in this helper run has checked.
      if (C.afterFlow && lf && lf.outcome === "completed" && !S.justVerified) {
        // N8: the helper verifies a completed flow itself; wait for it (bounded), then ask.
        if (!S.unverifiedSince) { S.unverifiedSince = Date.now(); }
        if (Date.now() - S.unverifiedSince < FINISHING_MS) { return { view: "CHECKING", sub: "checking" }; }
      }
      if (S.justVerified) { return { view: "TEMPERROR" }; }
      return { verify: true };
    }
    if (ga === "not_verified") {
      var why = s.google_access_reason;
      if (why === "revoked_or_unrenewable") { return { view: "R2" }; }      // s4.3: only confirmed
      if (why === "transient" || why === "unknown") { return { view: "TEMPERROR" }; }  // N12, F-5
      if (S.justVerified) { return { view: "TEMPERROR" }; }
      return { verify: true };            // a failure recorded by an earlier helper run
    }
    if (ga === "not_connected") { return { view: "C" }; }
    // keychain_locked / keychain_unavailable / anything else: no p3 screen of its own. Retry;
    // never ask for reconnect or install (s4.2, s4.3). FLAG to the lead.
    return { view: "TEMPERROR" };
  }

  function onStatus(s) {
    S.reached = true;
    S.status = s;
    S.waitGrab = false;
    var lf = s.last_flow;
    if (S.startedFlowId && !(lf && lf.id === S.startedFlowId && lf.outcome === "pending")) {
      S.startedFlowId = null;
    }
    // ONE live surface: the helper's owner tab (WP-H4, NEW-E2).
    var own = s.owner;
    if (own && typeof own === "object") {
      if (own.is_you === true) {
        if (!S.isOwner) { S.isOwner = true; announce("owner"); }
      } else {
        S.isOwner = false;
        if (own.exists === true) { standDown(); return null; }
      }
    }
    var d = decide(s);
    if (s.google_access !== "unverified") { S.unverifiedSince = 0; }
    if (d.verify) { return runVerify(); }
    go(d.view, d);
    return null;
  }

  // A read's answer is acted on only if nothing made it stale meanwhile.
  function stale(g) {
    return g !== S.gen || S.perm === "denied" || S.away || (S.view === "A" && !S.downloaded);
  }

  // The helper did not answer (or refused /status).
  function onSilent() {
    var v = S.view;
    if (v === "PASSIVE") { return; }
    if (v === "WAITING" && S.waitGrab) { return; }       // "Waiting for GrabMCP..." until it answers
    if (S.downloaded && (v === "A" || v === "B" || v === "NOTDETECTED" || v === "LNABLOCKED")) {
      // Download-click polling (N4/N5): B, then NotDetected after the bound; polling goes on.
      // From A (granted) or LnaBlocked (just granted) this was the "/health FIRST" read.
      if (v === "A" || v === "LNABLOCKED") { S.dlStartedAt = Date.now(); go("B"); return; }
      if (v === "B" && Date.now() - S.dlStartedAt >= DOWNLOAD_BOUND_MS) { go("NOTDETECTED"); }
      return;
    }
    if (S.startedFlowId) {
      // "a loaded page with a flow it started" (N13): decide like its #return landing.
      S.ctx = newCtx("return", S.startedFlowId);
      S.startedFlowId = null;
    }
    if (S.ctx.kind === "return" && !S.ctx.settled) {
      // N13: ONLY while the helper is silent (A-4: beats R3). Exact copy only on the
      // correlated record (C-11), which only an earlier read of this page can have shown.
      var lf = S.status && S.status.last_flow;
      var exact = !!(lf && lf.id === S.ctx.returnId && lf.cause === "claude_closed");
      go("INTERRUPTED", { variant: exact ? "exact" : "neutral" });
      return;
    }
    go("R3");
  }

  // ------------------------------------------------------------------ the polling loop
  var pollTimer = null, running = false, again = false, recheckWanted = false;

  function shouldPoll() {
    if (S.away || S.perm === "denied") { return false; }
    if (S.view === "A" && !S.downloaded) { return false; }   // N1: A makes no request
    if (S.perm === "granted" || S.noPermModel) { return true; }
    return S.downloaded && S.view !== "LNABLOCKED";   // prompt / unsupported: only after the click
  }

  function stopPoll() {
    if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; }
  }

  function schedule() {
    stopPoll();
    if (shouldPoll()) { pollTimer = setTimeout(tick, TICK_MS); }
  }

  function tickNow() {
    stopPoll();
    if (running) { again = true; return; }
    tick();
  }

  function read() {
    return call("GET", "/health").then(function (h) {
      var ok = !h.network && h.status === 200 && h.data && h.data.helper === "running";
      if (!ok) { return { silent: true }; }
      S.reached = true;
      return call("GET", "/status?tab=" + TAB).then(function (s) {
        if (s.network || s.status !== 200 || !s.data || typeof s.data !== "object") {
          return { silent: true };
        }
        return { status: s.data };
      });
    });
  }

  function tick() {
    pollTimer = null;
    if (!shouldPoll()) { return; }
    if (S.view === "NOTDETECTED" && document.hidden) { schedule(); return; }   // N5: while visible
    running = true;
    var work, g = S.gen;
    if (recheckWanted) {
      recheckWanted = false;
      work = runVerify();
    } else {
      work = read().then(function (r) {
        if (stale(g)) { return null; }
        return r.silent ? onSilent() : onStatus(r.status);
      });
    }
    Promise.resolve(work).then(null, function () { /* the next tick decides */ }).then(function () {
      running = false;
      if (again) { again = false; tick(); } else { schedule(); }
    });
  }

  // POST /verify (the fresh access test), then /status, then decide. CHECKING shows meanwhile.
  function runVerify() {
    if (S.verifying) { return null; }   // FX-6: never a second /verify while one is in flight
    var g = S.gen;
    S.verifying = true;
    go("CHECKING", { sub: "checking" });
    return call("POST", "/verify", "{}", VERIFY_TIMEOUT_MS).then(function (v) {
      if (stale(g)) { S.verifying = false; return null; }
      if (v.network) {
        // FX-6 (KPI-5): a slow helper is not a silent one. On a timeout (or any failure to get an
        // answer) ask /health before "can't reach": if it answers -> TempError, never R3 or Interrupted.
        return call("GET", "/health").then(function (h) {
          S.verifying = false;
          if (stale(g)) { return null; }
          if (!h.network && h.status === 200 && h.data && h.data.helper === "running") {
            S.reached = true;
            go("TEMPERROR");
            return null;
          }
          return onSilent();
        });
      }
      return call("GET", "/status?tab=" + TAB).then(function (s) {
        S.verifying = false;
        if (stale(g)) { return null; }
        if (s.network || s.status !== 200 || !s.data || typeof s.data !== "object") {
          return onSilent();
        }
        S.justVerified = true;
        try { onStatus(s.data); } finally { S.justVerified = false; }
        return null;
      });
    });
  }

  // ------------------------------------------------------------------ N8 "Finishing setup..."
  var finishTimer = null;
  function startFinishing() {
    if (S.finishStarted) { return; }
    S.finishStarted = true;
    finishTimer = setTimeout(function () {
      finishTimer = null;
      S.finishingExpired = true;
      tickNow();                       // -> N10 NotLoaded unless ready by now
    }, FINISHING_MS);
  }

  // ------------------------------------------------------------------ N12 TempError back-off
  var temp = { active: false, n: 0, timer: null };
  function tempEnsure() {
    if (!temp.active) { temp.active = true; temp.n = 0; }
    if (!temp.timer && !S.verifying) { tempSchedule(); }
  }
  function tempSchedule() {
    var ms = temp.n < TEMP_DELAYS_MS.length ? TEMP_DELAYS_MS[temp.n] : TEMP_EVERY_MS;
    temp.timer = setTimeout(tempFire, ms);
  }
  function tempFire() {
    temp.timer = null;
    if (S.view !== "TEMPERROR") { return; }
    if (temp.n >= TEMP_DELAYS_MS.length && document.hidden) { tempSchedule(); return; }
    temp.n += 1;
    recheck();
  }
  function tempStop() {
    temp.active = false;
    temp.n = 0;
    if (temp.timer) { clearTimeout(temp.timer); temp.timer = null; }
  }
  function recheck() {
    if (temp.timer) { clearTimeout(temp.timer); temp.timer = null; }
    recheckWanted = true;
    tickNow();
  }

  // ------------------------------------------------------------------ owner tab and stand-down
  var chan = null;
  function openChannel() {
    if (chan || typeof BroadcastChannel !== "function") { return; }
    try {
      chan = new BroadcastChannel(CHANNEL_NAME);
      chan.onmessage = onPeer;
    } catch (e) { chan = null; }
  }
  function closeChannel() {
    if (chan) { try { chan.close(); } catch (e) { /* ignore */ } chan = null; }
  }
  function announce(kind) {
    if (chan) { try { chan.postMessage({ t: kind, tab: TAB }); } catch (e) { /* ignore */ } }
  }
  var beforePassive = null;
  function standDown() {
    S.isOwner = false;
    if (S.view !== "PASSIVE") { beforePassive = S.view; }
    if (finishTimer) { clearTimeout(finishTimer); finishTimer = null; }
    go("PASSIVE");
  }
  function onPeer(ev) {
    var m = ev && ev.data;
    if (!m || typeof m !== "object" || m.tab === TAB) { return; }
    if (m.t === "owner") {
      if (S.view !== null) { standDown(); }
    } else if (m.t === "release" && S.view === "PASSIVE") {
      if (shouldPoll()) { tickNow(); }                 // the helper says who owns now
      else if (beforePassive) { go(beforePassive); }   // no request allowed: back where it was
    }
  }

  // ------------------------------------------------------------------ actions
  function newCtx(kind, returnId) {
    return { kind: kind, returnId: returnId || "", owner: false,
      settled: false, afterFlow: false, failed: false };
  }

  // #return=<flow_id> (or #return), #ready=<run_id>[&owner=1], else a plain load.
  function parseHash() {
    var h = location.hash || "";
    if (h === "#return" || h.indexOf("#return=") === 0) {
      var id = h.slice(8);
      return newCtx("return", ID_RE.test(id) ? id : "");
    }
    if (h.indexOf("#ready=") === 0) {
      var c = newCtx("ready", "");
      var parts = h.slice(1).split("&");
      for (var i = 0; i < parts.length; i++) { if (parts[i] === "owner=1") { c.owner = true; } }
      return c;
    }
    return newCtx("plain", "");
  }

  // N1 "Download and install" (the anchor downloads in the same gesture; never prevented).
  function onDownloadClick() {
    S.downloaded = true;
    S.dlStartedAt = Date.now();
    if (S.perm === "denied") { stopPoll(); go("LNABLOCKED"); return; }   // N3
    // granted: /health FIRST, B only when it is silent (UX-2, UX-17).
    // prompt / unsupported: B at once (p3 draws B under the browser's prompt), then /health.
    if (S.perm !== "granted") { go("B"); }
    tickNow();
  }

  // N6 / N11 / R2: same-tab Google.
  function startGoogle() {
    if (S.starting) { return; }
    S.starting = true;
    var body = JSON.stringify({ return_to: location.origin + RETURN_TO_PATH + "#return",
      return_mode: "redirect", tab: TAB });
    call("POST", "/connect/start", body).then(function (r) {
      S.starting = false;
      var d = (r.data && typeof r.data === "object") ? r.data : {};
      if (!r.network && r.status === 200 && typeof d.authorize_url === "string" &&
          /^https?:\/\//.test(d.authorize_url) && typeof d.flow_id === "string") {
        S.startedFlowId = d.flow_id;
        S.gen += 1;
        S.away = true;
        stopPoll();
        setTimeout(function () { if (S.away) { S.away = false; tickNow(); } }, AWAY_RESUME_MS);
        location.assign(d.authorize_url);
        return;
      }
      if (!r.network && r.status === 409 && d.error === "not_owner") { standDown(); return; }
      tickNow();                         // silent -> R3; otherwise the helper's state decides
    });
  }

  // "Open Claude Desktop" on N5, N13, R3 (contract s5.4): the browser link, then p3's
  // "Waiting for GrabMCP..." while polling goes on.
  function openClaudeLinkAndWait() {
    location.href = CLAUDE_LINK;
    S.waitGrab = true;
    go("WAITING", { sub: "grabmcp" });
  }

  // "Open Claude Desktop" on D, R1 and NotLoaded (contract s5.4): the helper's open call, made from
  // these three click handlers only (T-STATIC-ONE-CALLER). No timer, load or retry path calls it.
  function openClaudeViaHelper(fromNotLoaded) {
    if (S.opening) { return; }
    S.opening = true;
    if (fromNotLoaded) {
      S.waitClaude = true;
      go("WAITING", { sub: "claude" });        // p3: "Waiting for Claude Desktop..."
    }
    call("POST", "/claude/open", "{}", OPEN_TIMEOUT_MS).then(function (r) {
      S.opening = false;
      if (!r.network && r.status === 200 && r.data && typeof r.data.opened === "boolean") {
        if (r.data.opened) { return; }         // Claude is in front; NotLoaded keeps waiting
        if (fromNotLoaded) {                   // UX-19: a failed open from N10 returns to N10
          S.waitClaude = false;
          tickNow();
          return;
        }
        if (S.status && S.status.ready === true) { go("LAUNCHFAILED"); return; }   // N15
        tickNow();
        return;
      }
      // Refused (409 not_verified, 429 rate_limited, 403) or no answer: never LaunchFailed (UX-15).
      if (fromNotLoaded) { S.waitClaude = false; }
      tickNow();
    });
  }

  // ------------------------------------------------------------------ controls
  // UXB-6: remember which section a click came from, so show() can move focus when the click
  // hides that section (and only then).
  function on(id, fn) {
    var el = $(id);
    if (!el) { return; }
    el.addEventListener("click", function (e) {
      var sec = el.closest ? el.closest("section[data-state]") : null;
      focusIntent = sec ? { section: sec, at: Date.now() } : null;
      return fn(e);
    });
  }

  on("b-dl", onDownloadClick);
  // b-again ("Download it again" on B) is a download link: the browser serves the file again.
  on("b-redl", function () {                 // N5 -> the file again AND back to B (N4), UX-12
    var a = $("b-dl");
    if (a) { a.click(); }                    // runs onDownloadClick: a new 10-minute bound
    if (S.view !== "LNABLOCKED") { go("B"); }
  });
  on("b-how", function () {
    var box = $("howbox");
    if (box) { box.hidden = false; }
  });
  on("b-ocd", openClaudeLinkAndWait);        // N5
  on("b-oc2", openClaudeLinkAndWait);        // N13
  on("b-open", openClaudeLinkAndWait);       // R3
  on("b-again2", function () {               // N15 "Try again": the browser link (contract s5.4)
    location.href = CLAUDE_LINK;
  });
  on("b-google", startGoogle);               // N6
  on("b-cont", startGoogle);                 // N11
  on("b-rec", startGoogle);                  // R2
  on("b-try", recheck);                      // N12 "Try now"
  on("b-claude", function () { openClaudeViaHelper(false); });      // N9 D
  on("b-claude-r1", function () { openClaudeViaHelper(false); });   // R1
  on("b-oc", function () { openClaudeViaHelper(true); });           // N10 NotLoaded
  on("b-inst", function (e) {                // R3 "Install it" -> N1
    if (e && e.preventDefault) { e.preventDefault(); }
    S.ctx = newCtx("plain", "");
    S.downloaded = false;
    S.noPermModel = false;
    S.gen += 1;
    stopPoll();
    go("A");
  });

  // ------------------------------------------------------------------ resume (R-resume)
  document.addEventListener("visibilitychange", function () {
    requery();
    if (!document.hidden && S.view !== null && shouldPoll()) { tickNow(); }
  });
  window.addEventListener("focus", requery);
  window.addEventListener("pageshow", function (e) {
    if (!e || !e.persisted) { return; }
    // Back from Google or a back-forward-cache restore: re-read /status; never a dead C (UX-14).
    // The id this page released on pagehide can never own again (helper FX-12): a NEW id, before
    // the re-read. The old one is simply abandoned; nothing else is sent.
    TAB = newTabId();
    S.isOwner = false;
    S.away = false;
    S.starting = false;
    S.opening = false;
    openChannel();
    requery();
    if (S.view !== null && shouldPoll()) { tickNow(); }
  });
  window.addEventListener("pagehide", function () {
    // FX-3 (INTERFACE-05 s6.3): tell the helper this document left, so a reload or a Back from
    // Google lands on a live screen at once. Here and nowhere else. FX-13 (CR5-8): sent whenever
    // THIS page has reached the helper (whatever the permission value), never by a page that has
    // not: the beacon only follows requests a granted load or the user's click already caused.
    // A string body is text/plain: no preflight. Payload exactly {"tab":"<id>"} (KPI-4).
    if (S.reached && navigator.sendBeacon) {
      try { navigator.sendBeacon(BASE + "/release", JSON.stringify({ tab: TAB })); } catch (e) { /* ignore */ }
    }
    if (S.isOwner) { announce("release"); }
    closeChannel();
    stopPoll();
  });

  // ------------------------------------------------------------------ the first decision
  function boot() {
    S.ctx = parseHash();
    if (S.perm === "granted") {
      if (S.ctx.kind === "return") { go("CHECKING", { sub: "checking" }); }   // N8 provisional
      else { S.loadVerify = true; }
      tickNow();
      return;
    }
    // FX-14 (Reviewer UXB-5 ruling): no permission model means no prompt can be raised, so a
    // #return / #ready load goes exactly as a granted one (never A for saved access, plan s3.4).
    // A plain load, and "prompt" on any load, stay on A with no request.
    if (S.perm === "unsupported" && S.ctx.kind !== "plain") {
      S.noPermModel = true;
      go("CHECKING", { sub: "checking" });
      if (S.ctx.kind !== "return") { S.loadVerify = true; }
      tickNow();
      return;
    }
    // N3 / UX-2: a #ready or #return load while denied is LnaBlocked, never A.
    if (S.perm === "denied" && S.ctx.kind !== "plain") { go("LNABLOCKED"); return; }
    go("A");                                   // N1: no request on load
  }

  openChannel();
  setInterval(requery, PERM_REQUERY_MS);
  queryPerm().then(function (st) {
    S.perm = st;
    boot();
  });
})();
