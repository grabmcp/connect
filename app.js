/* Connect Google Analytics to Claude: the page logic.
 *
 * The page talks ONLY to the helper that runs inside the Claude extension on this Mac, at
 * the loopback address below (helper contract 1.0). It holds no secret, never receives a
 * token, and never shows the sign-in address it is given.
 */
(function () {
  "use strict";

  // The helper's fixed port (contract 1.0). The page takes NO port from its address (gate
  // condition 3, Reviewer 12:05); the tests serve a copy with this one constant rewritten.
  var HELPER_PORT = 50812;

  // D6, the ONE switch (Reviewer 11:24): false = the participant opens the file they RECEIVED
  // (default until the Owner rules); true = the page offers the download. No rebuild either way.
  var MCPB_ON_SITE = false;

  var TICK_MS = 2500;              // how often the page checks the helper
  var REQUEST_TIMEOUT_MS = 8000;   // one request may take this long before it counts as failed
  var FLOW_TIMEOUT_MS = 10 * 60 * 1000;

  var BASE = "http://127.0.0.1:" + HELPER_PORT;

  var $ = function (id) { return document.getElementById(id); };

  (function applyGetVariant() {
    var dl = $("get-download"), rx = $("get-received");
    if (dl && rx) {
      dl.hidden = !MCPB_ON_SITE;
      rx.hidden = MCPB_ON_SITE;
    }
  })();
  var el = {
    helper: $("helper-status"),
    connectBtn: $("connect-btn"),
    connect: $("connect-status"),
    retryBtn: $("retry-btn"),
    fallback: $("signin-fallback"),
    fallbackLink: $("signin-link"),
    google: $("google-status"),
    claude: $("claude-status"),
    disconnectBtn: $("disconnect-btn"),
    disconnect: $("disconnect-status")
  };

  var state = {
    checked: false,      // at least one /health attempt has finished
    found: false,        // /health answered "running" to this page
    refused: null,       // /status refused this page (HTTP code), if it did
    status: null,        // the last /status answer
    flow: null,          // {id, startedAt} of the sign-in this page started
    flowBusy: false,     // a /connect/start request is in flight
    disconnectBusy: false,
    keepConnectMsg: false  // keep the last sign-in result on screen until the next action
  };

  // ------------------------------------------------------------------ talking to the helper
  // Every call resolves (never rejects): {network: true} when the helper could not be reached
  // at all (not running, blocked by the browser, or not allowing this page).
  function call(method, path) {
    var opts = { method: method, mode: "cors", cache: "no-store", credentials: "omit" };
    if (method === "POST") {
      opts.headers = { "Content-Type": "application/json" };
      opts.body = "{}";
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
    return (typeof v === "string" && /^[A-Za-z0-9_.\- ]{1,40}$/.test(v)) ? v : null;
  }

  function say(node, text, kind) {
    node.textContent = text;
    node.className = "status" + (kind ? " " + kind : "");
  }

  function markDone(stepId, done) {
    var s = $(stepId);
    if (s) { s.classList.toggle("done", !!done); }
  }

  // ------------------------------------------------------------------ rendering
  function renderHelper() {
    if (!state.checked) {
      say(el.helper, "Checking whether the extension is running…", "wait");
    } else if (!state.found) {
      say(el.helper, "Extension not found yet. Open Claude Desktop (with the GA4 extension " +
        "installed), then this page will continue by itself.", "wait");
    } else if (state.refused) {
      say(el.helper, "The extension is running, but it did not accept this page (error " +
        state.refused + "). Make sure you opened this page from its usual address.", "bad");
    } else {
      say(el.helper, "Extension found. It is running inside Claude Desktop.", "ok");
    }
    markDone("step-helper", state.found && !state.refused);
  }

  function googleText(s) {
    var ga = s.google_access;
    var prop = s.property;
    if (ga === "verified") {
      var t = "Google access verified.";
      if (prop && (prop.name || prop.id)) {
        var name = typeof prop.name === "string" ? prop.name : "";
        var id = (typeof prop.id === "string" || typeof prop.id === "number") ? String(prop.id) : "";
        t += " Analytics property: " + (name || "(no name)") + (id ? " (ID " + id + ")" : "") + ".";
      }
      return [t, "ok"];
    }
    if (ga === "not_connected") { return ["Not connected to Google yet.", ""]; }
    if (ga === "unverified") {
      return ["Connected before. The extension is checking Google access again…", "wait"];
    }
    if (ga === "not_verified") {
      return ["Connected, but Google did not confirm access to your Analytics just now. " +
        "Try “Connect Google Analytics” again.", "bad"];
    }
    if (ga === "keychain_locked") {
      return ["Your Mac’s keychain is locked, so the saved Google sign-in cannot be used. " +
        "Unlock your Mac; this page will update by itself.", "bad"];
    }
    if (ga === "keychain_unavailable") {
      return ["The extension cannot use your Mac’s keychain, so it cannot keep a Google " +
        "sign-in on this Mac.", "bad"];
    }
    return ["Google access: unknown (the extension reported “" + (safeWord(ga) || "?") + "”).", "bad"];
  }

  function renderGoogle() {
    var s = state.status;
    if (!state.found || state.refused || !s) {
      say(el.google, "Cannot check right now: the extension is not reachable.", "");
      markDone("step-google", false);
      markDone("step-connect", false);
      return;
    }
    var g = googleText(s);
    say(el.google, g[0], g[1]);
    markDone("step-google", s.google_access === "verified");
    markDone("step-connect", s.google_access === "verified");
  }

  function renderClaude() {
    var s = state.status;
    if (!state.found || state.refused || !s) {
      say(el.claude, "Cannot check right now: the extension is not reachable.", "");
      markDone("step-claude", false);
      markDone("step-ask", false);
      return;
    }
    var c = s.claude || {};
    if (c.verified === true) {
      var t = "Claude has read your Analytics.";
      if (typeof c.last_report_at === "string" || typeof c.last_report_at === "number") {
        var d = new Date(typeof c.last_report_at === "number" && c.last_report_at < 1e12 ?
          c.last_report_at * 1000 : c.last_report_at);
        if (!isNaN(d.getTime())) { t += " Last time: " + d.toLocaleString() + "."; }
      }
      say(el.claude, t, "ok");
    } else if (s.google_access !== "verified") {
      say(el.claude, "Not yet: first connect Google Analytics (step 4), then ask Claude (step 6).", "");
    } else {
      say(el.claude, "Waiting for Claude to read your Analytics. This page checks every few seconds.", "wait");
    }
    markDone("step-claude", c.verified === true);
    markDone("step-ask", c.verified === true);
  }

  function renderButtons() {
    var usable = state.found && !state.refused && !!state.status;
    el.connectBtn.disabled = !usable || state.flowBusy || !!state.flow;
    el.retryBtn.disabled = !usable || state.flowBusy || !!state.flow;
    el.disconnectBtn.disabled = !usable || state.disconnectBusy;
  }

  function renderConnectIdle() {
    if (state.flow || state.flowBusy || state.keepConnectMsg) { return; }
    if (!state.found || state.refused || !state.status) {
      say(el.connect, "This button works once the extension has been found (step 3).", "");
    } else if (state.status.google_access === "verified") {
      say(el.connect, "Google Analytics is connected. You only need this button again if you " +
        "want to use a different Google account.", "");
    } else {
      say(el.connect, "Ready. Click the button; a Google sign-in tab will open.", "");
    }
  }

  function render() {
    renderHelper();
    renderGoogle();
    renderClaude();
    renderConnectIdle();
    renderButtons();
  }

  // ------------------------------------------------------------------ the sign-in flow
  function showRetry(show) {
    el.retryBtn.hidden = !show;
  }

  function finishFlow(lf) {
    state.flow = null;
    state.keepConnectMsg = true;
    var outcome = lf.outcome;
    if (outcome === "completed") {
      showRetry(false);
      say(el.connect, "Google sign-in finished.", "ok");
    } else if (outcome === "cancelled") {
      showRetry(true);
      say(el.connect, "The Google sign-in was cancelled, so nothing new was connected. " +
        "You can try again.", "bad");
    } else if (outcome === "superseded") {
      showRetry(true);
      say(el.connect, "This sign-in was replaced by a newer attempt. If you are not sure " +
        "which one you finished, try again.", "bad");
    } else {
      showRetry(true);
      var why = safeWord(lf.detail);
      say(el.connect, "The Google sign-in did not finish" + (why ? " (reason: " + why + ")" : "") +
        ". Nothing new was connected. You can try again.", "bad");
    }
    el.fallback.hidden = true;
    el.fallbackLink.removeAttribute("href");
  }

  function checkFlow() {
    if (!state.flow || !state.status) { return; }
    var lf = state.status.last_flow;
    if (lf && lf.id === state.flow.id && lf.outcome && lf.outcome !== "pending") {
      finishFlow(lf);
      return;
    }
    if (Date.now() - state.flow.startedAt > FLOW_TIMEOUT_MS) {
      state.flow = null;
      state.keepConnectMsg = true;
      showRetry(true);
      say(el.connect, "We did not hear back from the Google sign-in. If you closed that tab, " +
        "click “Try again”.", "bad");
    }
  }

  function startConnect() {
    if (state.flowBusy || state.flow) { return; }
    // Open the new tab NOW, inside the click, so the browser does not block it as a pop-up.
    var w = null;
    try { w = window.open("", "_blank"); } catch (e) { w = null; }
    if (w) {
      try {
        w.opener = null;
        w.document.title = "Opening Google…";
        w.document.body.textContent = "Opening the Google sign-in page…";
      } catch (e) { /* the tab still works without the placeholder text */ }
    }
    state.flowBusy = true;
    state.keepConnectMsg = true;
    showRetry(false);
    el.fallback.hidden = true;
    say(el.connect, "Starting the Google sign-in…", "wait");
    renderButtons();

    call("POST", "/connect/start").then(function (res) {
      state.flowBusy = false;
      var d = res.data || {};
      if (res.network || res.status !== 200 || typeof d.authorize_url !== "string" ||
          typeof d.flow_id !== "string") {
        if (w) { try { w.close(); } catch (e) { /* ignore */ } }
        showRetry(true);
        if (res.network) {
          say(el.connect, "Could not reach the extension, so the sign-in did not start. " +
            "Make sure Claude Desktop is open, then try again.", "bad");
        } else {
          var code = safeWord(d.error);
          say(el.connect, "The extension could not start the Google sign-in (error " + res.status +
            (code ? ": " + code : "") + "). Try again in a moment.", "bad");
        }
        renderButtons();
        return;
      }
      state.flow = { id: d.flow_id, startedAt: Date.now() };
      var opened = false;
      if (w) {
        try { w.location.replace(d.authorize_url); opened = true; } catch (e) { opened = false; }
      }
      if (!opened) {
        el.fallbackLink.href = d.authorize_url;
        el.fallback.hidden = false;
      }
      say(el.connect, "A Google sign-in tab is open. Choose your Google account there and allow " +
        "access, then come back to this tab. Waiting for you to finish…", "wait");
      renderButtons();
    });
  }

  // ------------------------------------------------------------------ disconnect
  function disconnectText(res) {
    if (res.network) {
      return ["Could not reach the extension, so nothing was disconnected. Open Claude Desktop " +
        "and try again.", "bad"];
    }
    var d = res.data || {};
    if (res.status === 503 && d.error === "keychain_unreadable") {
      return ["Nothing was disconnected. The extension could not read your Mac’s keychain, so " +
        "it cannot tell whether a Google sign-in is saved, and it did not ask Google to withdraw " +
        "access. Unlock your Mac, then click Disconnect again.", "bad"];
    }
    if (res.status !== 200) {
      var code = safeWord(d.error);
      return ["Disconnect did not work (the extension answered with error " + res.status +
        (code ? ": " + code : "") + "). Nothing is confirmed as removed.", "bad"];
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
    say(el.disconnect, "Disconnecting…", "wait");
    renderButtons();
    call("POST", "/disconnect").then(function (res) {
      state.disconnectBusy = false;
      state.keepConnectMsg = false;
      var t = disconnectText(res);
      say(el.disconnect, t[0], t[1]);
      showRetry(false);
      return tick(true);
    });
  }

  // ------------------------------------------------------------------ the polling loop
  var timer = null;
  var running = false;

  function tick(once) {
    if (running) {
      if (!once) { schedule(); }
      return Promise.resolve();
    }
    running = true;
    return call("GET", "/health").then(function (h) {
      var ok = !h.network && h.status === 200 && h.data && h.data.helper === "running";
      state.checked = true;
      state.found = !!ok;
      if (!ok) {
        state.status = null;
        state.refused = null;
        return null;
      }
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
        }
      });
    }).then(function () {
      checkFlow();
      render();
    }).catch(function () {
      render();
    }).then(function () {
      running = false;
      if (!once) { schedule(); }
    });
  }

  function schedule() {
    if (timer) { clearTimeout(timer); }
    timer = setTimeout(function () { tick(false); }, TICK_MS);
  }

  el.connectBtn.addEventListener("click", startConnect);
  el.retryBtn.addEventListener("click", startConnect);
  el.disconnectBtn.addEventListener("click", startDisconnect);

  render();
  tick(false);
})();
