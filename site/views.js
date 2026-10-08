/* views.js: WP-S1 view helper (UI Developer), PLAN-05 v1.1, INTERFACE-05 §4.
 *
 * PRESENTATION ONLY. No journey logic, no network, no storage, no timers, no event handlers.
 * The journey (WP-S2, app.js) decides WHICH state to show; this file only shows it.
 *
 *   GrabViews.render(state, opts) -> the shown <section>
 *     state  one of GrabViews.STATES ("A", "B", "CHECKING", ...); anything else throws.
 *     opts   optional:
 *       sub        CHECKING "checking"|"finishing", WAITING "grabmcp"|"claude" (default the first)
 *       variant    INTERRUPTED "neutral"|"exact" (default "neutral")
 *       progress   0..3: override the progress bar. Default: p3's progress(n) for the state;
 *                  WAITING has none in p3 (its show() call leaves the bar as it was), so the
 *                  bar is left untouched unless `progress` is given.
 *       lnaNote    A only: false hides the browser-permission note (p3 draws it only while
 *                  the browser has not decided); true shows it. Omitted = shown.
 *       property   D: the property's display name, written as text. Omitted = unchanged.
 *       lastUsed   R1: the "Last used in Claude" text. A non-empty string fills and shows the
 *                  line; null or "" hides it (F-9: hidden when never used). Omitted = unchanged.
 *   GrabViews.progress(n)  renders ol#prog exactly as p3's progress(n); 0 empties it.
 *
 * Entering a state (it was hidden before) resets what p3 resets by drawing the screen afresh:
 * every <details> closes and every [data-reset-hidden] element (LnaBlocked's #howbox) hides.
 * Revealing #howbox on b-how is the click handler's job (app.js), as in p3.
 */
(function () {
  "use strict";

  var STATES = ["A", "LNABLOCKED", "B", "NOTDETECTED", "C", "CHECKING", "TEMPERROR", "NOTLOADED",
    "NOTFINISHED", "INTERRUPTED", "D", "LAUNCHFAILED", "R1", "R2", "R3", "WAITING", "PASSIVE"];

  // p3: the progress(n) call at the top of each screen function. PASSIVE has no p3 screen: no bar.
  var PROGRESS = { A: 1, LNABLOCKED: 1, B: 1, NOTDETECTED: 1, C: 2, CHECKING: 2, TEMPERROR: 2,
    NOTLOADED: 2, NOTFINISHED: 2, INTERRUPTED: 2, D: 3, LAUNCHFAILED: 3, R1: 0, R2: 0, R3: 0,
    PASSIVE: 0 };

  // Sub-states: [attribute on the section, attribute on its parts, allowed values (first = default)].
  var SUBS = {
    CHECKING: ["data-sub", "data-sub-part", ["checking", "finishing"]],
    WAITING: ["data-sub", "data-sub-part", ["grabmcp", "claude"]],
    INTERRUPTED: ["data-variant", "data-variant-part", ["neutral", "exact"]]
  };

  // p3: items=[['Install','Installed'],['Google access','Google access'],['Claude','Claude']]
  var ITEMS = [["Install", "Installed"], ["Google access", "Google access"], ["Claude", "Claude"]];
  var SVG = "http://www.w3.org/2000/svg";

  function checkIcon() {
    // p3 ICON_CHECK at 13 x 13 (the done dot)
    var s = document.createElementNS(SVG, "svg");
    var attrs = { width: "13", height: "13", viewBox: "0 0 16 16", fill: "none",
      stroke: "currentColor", "stroke-width": "2", "stroke-linecap": "round",
      "stroke-linejoin": "round", "aria-hidden": "true", focusable: "false" };
    for (var k in attrs) { s.setAttribute(k, attrs[k]); }
    var p = document.createElementNS(SVG, "path");
    p.setAttribute("d", "M3 8.5 L6.5 12 L13 4.5");
    s.appendChild(p);
    return s;
  }

  function progress(cur) {
    var prog = document.getElementById("prog");
    if (!prog) { return; }
    while (prog.firstChild) { prog.removeChild(prog.firstChild); }
    if (cur === 0) { return; }
    for (var i = 0; i < ITEMS.length; i++) {
      var n = i + 1, li = document.createElement("li"), dot = document.createElement("span");
      dot.className = "dot";
      li.appendChild(dot);
      if (n < cur) {
        li.className = "done";
        dot.appendChild(checkIcon());
        li.appendChild(document.createTextNode(ITEMS[i][1]));
      } else {
        if (n === cur) { li.className = "cur"; li.setAttribute("aria-current", "step"); }
        dot.textContent = String(n);
        li.appendChild(document.createTextNode(ITEMS[i][0]));
      }
      prog.appendChild(li);
    }
  }

  function each(list, fn) { for (var i = 0; i < list.length; i++) { fn(list[i]); } }

  function render(state, opts) {
    opts = opts || {};
    if (STATES.indexOf(state) < 0) { throw new Error("views.js: unknown state " + state); }
    var target = null;
    each(document.querySelectorAll("section[data-state]"), function (s) {
      if (s.getAttribute("data-state") === state) { target = s; }
    });
    if (!target) { throw new Error("views.js: no section for state " + state); }

    var entering = target.hidden;
    each(document.querySelectorAll("section[data-state]"), function (s) { s.hidden = s !== target; });
    if (entering) {
      each(target.querySelectorAll("details"), function (d) { d.open = false; });
      each(target.querySelectorAll("[data-reset-hidden]"), function (e) { e.hidden = true; });
    }

    var sub = SUBS[state];
    if (sub) {
      var want = state === "INTERRUPTED" ? opts.variant : opts.sub;
      if (want === undefined) { want = sub[2][0]; }
      if (sub[2].indexOf(want) < 0) { throw new Error("views.js: " + state + " has no sub-state " + want); }
      target.setAttribute(sub[0], want);
      each(target.querySelectorAll("[" + sub[1] + "]"), function (e) {
        e.hidden = e.getAttribute(sub[1]) !== want;
      });
    }

    if (state === "A" && opts.lnaNote !== undefined) {
      each(target.querySelectorAll('[data-part="lna-note"]'), function (e) { e.hidden = !opts.lnaNote; });
    }
    if (state === "D" && typeof opts.property === "string" && opts.property !== "") {
      each(target.querySelectorAll('[data-slot="property"]'), function (e) { e.textContent = opts.property; });
    }
    if (state === "R1" && opts.lastUsed !== undefined) {
      var row = target.querySelector('[data-part="last-used"]');
      var has = typeof opts.lastUsed === "string" && opts.lastUsed !== "";
      if (has) {
        each(target.querySelectorAll('[data-slot="last-used"]'), function (e) { e.textContent = opts.lastUsed; });
      }
      if (row) { row.hidden = !has; }
    }

    var n = opts.progress !== undefined ? opts.progress : PROGRESS[state];
    if (n !== undefined) { progress(n); }
    return target;
  }

  window.GrabViews = { render: render, progress: progress, STATES: STATES.slice() };
})();
