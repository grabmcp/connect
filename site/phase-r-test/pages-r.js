/* LA-06 phase-R test page: the status page, pointed at the real 0.9.0 helper's routes.
   Adapted from the phase-M pages accepted by the Owner (phase-m/pages/pages.js, 17,787 B): the same
   state logic, messages A, B and C, tense rule and progress record, with the mock backend removed
   (tier 2 is `not run` under R-O2) and the mock helper's /status replaced by the real helper's
   GET /health and GET /status.
   No framework, no build step, and no host but the helper on this computer (http://127.0.0.1).

   Helper calls (D2 ruling, RVW 18:16:22; the table is phase-r/ENDPOINTS.md):
   - on load, in every mode: GET /health and GET /status only;
   - in test mode, and only from a click on its button: POST /verify, POST /connect/start,
     POST /claude/open. Nothing else. No beacon on page hide, no `tab` claim on /status. */
'use strict';

/* The page-facing run config, a static file loaded before this script (runtime-config.js). A missing
   or malformed key puts the page in `config-missing`, and it calls nothing. */
const CONFIG = window.LA06R_CONFIG;

const isText = (v) => typeof v === 'string' && v.length > 0;
const isMs = (v) => typeof v === 'number' && Number.isFinite(v) && v > 0;
const isMsOrZero = (v) => typeof v === 'number' && Number.isFinite(v) && v >= 0;
/* The only host this page may call: the helper on this computer, by address, never by name. */
const isLoopbackBase = (v) => typeof v === 'string' && /^http:\/\/127\.0\.0\.1:[0-9]{1,5}$/.test(v);

const NEEDS = {
  helperBaseUrl: isLoopbackBase,
  boundBMs: isMs,
  explainerLeadMs: isMsOrZero,
  pollIntervalMs: isMs,
  freshnessFMs: isMs
};

/* Fixed by the page, not by the run config: the helper's routes and what /health must say. */
const PAGE = {
  healthPath: '/health',
  statusPath: '/status', // no query string: no `tab`, so the page never claims the helper's owner tab
  service: 'grabmcp-ga4-helper',
  permissionNames: ['local-network-access', 'loopback-network'],
  omitMessageA: false
};

const STORE_PROGRESS = 'la06r.progress.';

/* Status labels, proposed for the run config's label list; none is self-confirmed (R-2, P12).
   "[time]" marks a <time> slot. */
const LABELS = {
  'config-missing': 'This test page is not configured',
  'waiting-component': 'Waiting for the component',
  'blocked': 'Browser blocked access',
  'no-prompt': 'This browser cannot verify the connection',
  'connected': 'Connected',
  'last-seen': 'Last confirmed connected at [time]'
};
const ACCESS_LABELS = {
  'not-verified': 'Google access not verified yet',
  'verified': 'Google access verified',
  'last-verified': 'Google access last verified at [time]'
};

/* TEST MODE. The address fragment #mode=test reveals the test controls; so does #return=…, the
   fragment the helper's sign-in redirect lands on. THE FRAGMENT IS A MODE SWITCH, NOT A SECRET:
   anyone can type it, and the page has no server to check it against. It only shows buttons. It
   never makes a call by itself: every POST below fires only from a click on its button. */
const testMode = () => /^#(mode=test|return(=[A-Za-z0-9_-]*)?)$/.test(location.hash);

function missingKeys() {
  if (!CONFIG || typeof CONFIG !== 'object') return ['window.LA06R_CONFIG'];
  const out = [];
  for (const [key, ok] of Object.entries(NEEDS)) {
    if (!Object.hasOwn(CONFIG, key) || !ok(CONFIG[key])) out.push(key);
  }
  return out;
}

/* Without a usable run config the page shows `config-missing` and calls nothing. */
function configMissing() {
  const keys = missingKeys();
  if (!keys.length) return false;
  document.body.dataset.configMissing = keys.join(', ');
  document.querySelector('[data-role="config-missing-keys"]').textContent = keys.join(', ');
  document.querySelector('[data-panel="config-missing"]').hidden = false;
  return true;
}

function readJson(key) {
  try {
    return JSON.parse(sessionStorage.getItem(key));
  } catch {
    return null;
  }
}

function writeJson(key, value) {
  sessionStorage.setItem(key, JSON.stringify(value));
}

/* The progress record P11 compares, exposed on <body> for the harness. Under R-O2 there is no
   backend, so the request id is made by the page and says so (data-ids-issued-by="page"). */
function exposeRecord(rec) {
  const d = document.body.dataset;
  d.signupSession = rec.signupSession;
  d.requestId = rec.requestId;
  d.pairing = rec.pairing;
  d.reachedStep = rec.reachedStep;
  d.helperRunId = rec.helperRunId;
  d.connectionId = rec.connectionId;
  d.idsIssuedBy = 'page';
}

function saveRecord(rec) {
  writeJson(STORE_PROGRESS + rec.requestId, rec);
  exposeRecord(rec);
}

function newRequestId() {
  const b = new Uint8Array(9);
  crypto.getRandomValues(b);
  return 'rq-' + Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

/* The request this tab is working on: the one named by ?request= if this tab holds it (a return
   after "Show me how", or after the sign-in redirect), else a new one. No network call. */
function loadOrCreateRecord() {
  const url = new URL(location.href);
  const named = url.searchParams.get('request');
  const held = named && readJson(STORE_PROGRESS + named);
  if (held) {
    document.body.dataset.recordSource = 'resumed';
    return held;
  }
  const rec = {
    requestId: newRequestId(),
    signupSession: 'none: no sign-up page under R-O2',
    pairing: 'origin-admitted: the 0.9.0 helper takes no pairing code',
    reachedStep: 'request',
    helperRunId: '',
    connectionId: ''
  };
  url.searchParams.set('request', rec.requestId);
  history.replaceState(null, '', url.pathname + url.search + url.hash);
  document.body.dataset.recordSource = 'new';
  saveRecord(rec);
  return rec;
}

/* ---------- status ---------- */

const statusEl = () => document.getElementById('status');
const currentState = () => statusEl().dataset.state;

/* The states in which the page keeps reading the helper. */
const OBSERVING = ['waiting-component', 'connected', 'last-seen'];

let seq = 0;
let timer = null;
let loop = 0; // the current read loop; an older loop stops at its next step
let deadline = 0;
let loopbackOpen = false;
let permStatus = null;

/* What this page load has observed from the helper. */
const seen = {
  licence: null,        // the first answer of the current helper run (GET /health + GET /status)
  last: null,           // the latest answer
  helperAnsweredAt: 0,  // page clock, ms: the helper's last answer
  status: null,         // the body of the last GET /status answer
  lastVerifiedAt: ''    // verification.at of the last verification that matched the current run
};

function setState(state, ev) {
  const el = statusEl();
  el.dataset.state = state;
  el.dataset.stateSeq = String(++seq);
  el.dataset.stateChangedAt = new Date().toISOString();
  if (ev) {
    el.dataset.eventId = ev.event_id ?? '';
    el.dataset.eventTier = ev.tier;
    el.dataset.eventObservedAt = ev.observedAt ?? '';
  }
  renderLabel(el.querySelector('[data-role="status-label"]'), LABELS[state], 'last-seen-at');
  document.body.dataset.state = state;

  for (const panel of document.querySelectorAll('[data-shows-in]')) {
    panel.hidden = !panel.dataset.showsIn.split(' ').includes(state);
  }
  if (state !== 'waiting-component') showHelpExit(false);
  if (PAGE.omitMessageA) document.querySelector('[data-message="A"]').hidden = true;
  showTestControls();
}

function renderLabel(el, text, slotName) {
  const [before, after] = text.split('[time]');
  if (after === undefined) {
    el.textContent = before;
    return;
  }
  const slot = document.createElement('time');
  slot.dataset.field = slotName;
  el.replaceChildren(before, slot, after);
  showTimes();
}

/* Every time slot shows the last answer's time, never the licensing answer's (N4). */
function showTimes() {
  const at = seen.last ? (seen.last.observedAt ?? '') : '';
  for (const el of document.querySelectorAll('[data-field="last-seen-at"], [data-role="observed-at"]')) {
    el.dateTime = at;
    el.textContent = at || 'not reported';
  }
  for (const el of document.querySelectorAll('[data-field="last-verified-at"]')) {
    el.dateTime = seen.lastVerifiedAt;
    el.textContent = seen.lastVerifiedAt || 'not reported';
  }
  const d = statusEl().dataset;
  d.lastEventId = seen.last ? (seen.last.event_id ?? '') : '';
  d.lastEventObservedAt = at;
}

/* The documented exit to help, inside waiting-component. Not a control; it asserts nothing. */
function showHelpExit(on) {
  document.querySelector('[data-panel="help-exit"]').hidden = !on;
  statusEl().dataset.helpExit = on ? 'shown' : 'hidden';
}

/* The test controls: only in test mode, and only while connected (R-1: no control leads forward
   while the permission is blocked or unanswered). */
function showTestControls() {
  const on = testMode() && currentState() === 'connected';
  document.querySelector('[data-panel="test-controls"]').hidden = !on;
  document.body.dataset.mode = testMode() ? 'test' : 'default';
}

function fill(name, value) {
  if (value == null) return;
  for (const el of document.querySelectorAll(`[data-field="${name}"]`)) {
    el.textContent = value;
    el.dataset.filled = 'true';
  }
}

function fillSteps(name, steps) {
  if (!Array.isArray(steps) || !steps.length) return;
  for (const list of document.querySelectorAll(`[data-field="${name}"]`)) {
    list.replaceChildren(...steps.map((text) => {
      const li = document.createElement('li');
      li.textContent = text;
      return li;
    }));
    list.dataset.filled = 'true';
  }
}

/* The open fields, from the run config; without them every slot keeps its placeholder. */
function fillFields() {
  const f = CONFIG.fields || {};
  fill('permission-name', f.permissionName);
  fill('allow-label', f.allowLabel);
  fill('supported-browser', f.supportedBrowser);
  fillSteps('reenable-steps', f.reenableSteps);
  fillSteps('help-steps', f.reenableSteps);
}

/* The browser's own permission state, or null when it has no such permission. */
async function queryPermission() {
  if (!navigator.permissions) return null;
  for (const name of PAGE.permissionNames) {
    try {
      return await navigator.permissions.query({ name });
    } catch {
      // not a permission this browser knows; try the next name
    }
  }
  return null;
}

/* One GET to the helper: its JSON body, or null for no usable answer. */
async function getHelper(path) {
  try {
    const res = await fetch(new URL(path, CONFIG.helperBaseUrl), {
      method: 'GET', mode: 'cors', cache: 'no-store', credentials: 'omit', targetAddressSpace: 'loopback'
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

/* One read of the helper: GET /health, then GET /status. An answer counts only if /health names
   the helper's service and both routes report the same helper run. */
async function observe(rec) {
  // The helper only after message A has been on screen (annex 1 step 4).
  if (!loopbackOpen) return;
  const health = await getHelper(PAGE.healthPath);
  if (!health || health.service !== PAGE.service || health.helper !== 'running' || !isText(health.run_id)) return;
  const status = await getHelper(PAGE.statusPath);
  if (!status || status.run_id !== health.run_id) return;
  const ev = {
    event_id: 'helper-run:' + health.run_id,
    type: 'helper_answered',
    run_id: health.run_id,
    version: health.version ?? '',
    observedAt: new Date().toISOString(),
    tier: 'helper'
  };
  seen.helperAnsweredAt = Date.now();
  seen.status = status;
  seen.last = ev;
  // A new helper run (a restart) is a new licence; an answer from it never extends the old one.
  if (!seen.licence || seen.licence.run_id !== ev.run_id) seen.licence = ev;
  if (rec.helperRunId !== ev.run_id || rec.connectionId !== (status.connection_id ?? '')) {
    rec.helperRunId = ev.run_id;
    rec.connectionId = status.connection_id ?? '';
    saveRecord(rec);
  }
}

/* A live observation (N4, RK-36): the helper answered within F. */
const isLive = (now) => seen.helperAnsweredAt > 0 && now - seen.helperAnsweredAt <= CONFIG.freshnessFMs;

/* Google access, from the helper's own /status: "verified" only when its verification names the
   current connection and the current helper run, and only while the helper answers within F. */
function renderAccess() {
  const s = seen.status;
  if (!s) return;
  const v = s.verification;
  const matches = s.google_access === 'verified' && v && isText(v.connection_id)
    && v.connection_id === s.connection_id && v.run_id === s.run_id;
  if (matches && isText(v.at)) seen.lastVerifiedAt = v.at;
  const state = matches && isLive(Date.now()) ? 'verified' : seen.lastVerifiedAt ? 'last-verified' : 'not-verified';
  const el = document.getElementById('access');
  if (el.dataset.state !== state) {
    el.dataset.state = state;
    renderLabel(el.querySelector('[data-role="access-label"]'), ACCESS_LABELS[state], 'last-verified-at');
  }
  el.dataset.googleAccess = isText(s.google_access) ? s.google_access : '';
  const first = s.answer_success && isText(s.answer_success.at) ? s.answer_success.at : '';
  const panel = document.querySelector('[data-panel="first-result"]');
  panel.hidden = !first;
  const slot = panel.querySelector('[data-field="first-result-at"]');
  slot.dateTime = first;
  slot.textContent = first;
  showTimes();
}

async function poll(rec, gen) {
  if (gen !== loop || !OBSERVING.includes(currentState())) return;
  if (currentState() === 'waiting-component' && permStatus && permStatus.state === 'denied') return enterBlocked(rec);
  await observe(rec);
  const state = currentState();
  if (gen !== loop || !OBSERVING.includes(state)) return;

  if (seen.licence) {
    // Present tense only while a live observation holds; otherwise the past tense.
    if (!isLive(Date.now())) {
      if (state !== 'last-seen') setState('last-seen');
    } else if (state !== 'connected') {
      enterConnected(rec);
    }
    renderAccess();
  } else if (state === 'waiting-component' && Date.now() > deadline) {
    if (!permStatus) return enterNoPrompt();
    showHelpExit(permStatus.state === 'prompt');
  }
  showTimes();
  timer = setTimeout(() => poll(rec, gen), CONFIG.pollIntervalMs);
}

async function enterCheck(rec, resumed) {
  clearTimeout(timer);
  const gen = ++loop;
  rec.reachedStep = 'browser-check';
  saveRecord(rec);
  setState('waiting-component');
  showHelpExit(false);
  if (resumed) document.body.dataset.resumedFrom = 'blocked';

  permStatus = await queryPermission();
  if (gen !== loop) return;
  if (permStatus) permStatus.onchange = () => onPermissionChange(rec);
  if (permStatus && permStatus.state === 'denied') return enterBlocked(rec);

  loopbackOpen = false;
  const lead = PAGE.omitMessageA ? 0 : CONFIG.explainerLeadMs;
  deadline = Date.now() + lead + CONFIG.boundBMs;
  setTimeout(() => { loopbackOpen = true; }, lead);
  poll(rec, gen);
}

/* Message B. The reached step is not changed, so the return continues from it (R-3, P11). */
function enterBlocked(rec) {
  clearTimeout(timer);
  loop++;
  setState('blocked');
  watchReenable(rec);
}

async function watchReenable(rec) {
  if (currentState() !== 'blocked') return;
  const p = await queryPermission();
  if (currentState() !== 'blocked') return;
  if (p && p.state !== 'denied') return enterCheck(rec, true);
  timer = setTimeout(() => watchReenable(rec), CONFIG.pollIntervalMs);
}

function onPermissionChange(rec) {
  const state = currentState();
  if (permStatus.state === 'denied' && state === 'waiting-component') enterBlocked(rec);
  else if (permStatus.state !== 'denied' && state === 'blocked') enterCheck(rec, true);
}

/* Message C: the exit, with this request's own page URL. */
function enterNoPrompt() {
  clearTimeout(timer);
  document.querySelector('[data-role="request-url"]').textContent = location.href;
  setState('no-prompt');
}

/* Connected only on an answer from the helper's own routes, and only while it is live (N4). */
function enterConnected(rec) {
  rec.reachedStep = 'connected';
  saveRecord(rec);
  setState('connected', seen.licence);
}

/* ---------- test mode: the POST calls, each from a click only ---------- */

async function postHelper(path, body) {
  try {
    const res = await fetch(new URL(path, CONFIG.helperBaseUrl), {
      method: 'POST', mode: 'cors', cache: 'no-store', credentials: 'omit', targetAddressSpace: 'loopback',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    let data = null;
    try { data = await res.json(); } catch { data = null; }
    return { status: res.status, data };
  } catch {
    return { status: 0, data: null };
  }
}

function showResult(call, res, detail) {
  const line = `${call} answered ${res.status || 'nothing (not reached)'}${detail ? ': ' + detail : ''}`;
  document.querySelector('[data-role="test-result"]').textContent = line;
  document.body.dataset.lastTestCall = `${call} ${res.status}`;
}

const word = (v) => (isText(v) ? v : '');

/* A click handler that runs only for a real user gesture (event.isTrusted), only in test mode and
   only while connected. A script calling button.click() does not count. */
function onTestClick(control, fn) {
  const btn = document.querySelector(`[data-control="${control}"]`);
  btn.addEventListener('click', async (e) => {
    if (!e.isTrusted || !testMode() || currentState() !== 'connected') return;
    btn.disabled = true;
    try {
      await fn();
    } finally {
      btn.disabled = false;
    }
  });
}

function initTestControls() {
  onTestClick('verify', async () => {
    const res = await postHelper('/verify', {});
    const d = res.data || {};
    showResult('POST /verify', res, [word(d.google_access), word(d.error)].filter(Boolean).join(', '));
  });

  // The helper keeps return_to only if it is this page's own origin with the fragment "#return".
  onTestClick('connect-start', async () => {
    const link = document.querySelector('[data-control="continue-sign-in"]');
    document.querySelector('[data-panel="sign-in-link"]').hidden = true;
    link.setAttribute('href', '#');
    const res = await postHelper('/connect/start', { return_to: location.origin + location.pathname + location.search + '#return' });
    const d = res.data || {};
    let url = null;
    try {
      url = res.status === 200 && isText(d.authorize_url) ? new URL(d.authorize_url) : null;
    } catch {
      url = null;
    }
    if (url && url.protocol === 'https:') {
      // Not followed by the page: the user opens it with a second click.
      link.setAttribute('href', url.href);
      document.querySelector('[data-panel="sign-in-link"]').hidden = false;
      showResult('POST /connect/start', res, 'the sign-in page is ready');
    } else {
      showResult('POST /connect/start', res, word(d.error));
    }
  });

  onTestClick('claude-open', async () => {
    const res = await postHelper('/claude/open', {});
    const d = res.data || {};
    showResult('POST /claude/open', res, typeof d.opened === 'boolean' ? `opened ${d.opened}` : word(d.error));
  });

  window.addEventListener('hashchange', showTestControls);
}

/* ---------- start ---------- */

function initStatus() {
  if (configMissing()) {
    setState('config-missing');
    return;
  }
  fillFields();

  const showMeHow = document.querySelector('[data-control="show-me-how"]');
  const steps = document.getElementById('reenable-steps');
  showMeHow.addEventListener('click', (e) => {
    e.preventDefault();
    const open = steps.hidden;
    steps.hidden = !open;
    showMeHow.setAttribute('aria-expanded', String(open));
  });

  const copy = document.querySelector('[data-control="copy-link"]');
  const copyNote = document.querySelector('[data-role="copy-note"]');
  copy.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(location.href);
      copyNote.textContent = 'Link copied.';
    } catch {
      copyNote.textContent = 'Copy the link above by hand.';
    }
  });

  initTestControls();
  enterCheck(loadOrCreateRecord(), false);
}

initStatus();
