/* LA-06 phase-R test page: the page-facing part of the run config, as a static file.
   TEMPLATE VALUES: the run-config freeze (annex 1 step 3) waits for step 1, and rewrites this file
   from bundle/run-config.template.json. No secret, no account and no id lives here.
   helperBaseUrl must be http://127.0.0.1:<port>; the page refuses any other host (config-missing).
   `fields` are the open fields; null keeps the placeholder visible (annex 1: "captured by the run"). */
window.LA06R_CONFIG = {
  helperBaseUrl: 'http://127.0.0.1:50812',
  boundBMs: 10000,
  explainerLeadMs: 1500,
  pollIntervalMs: 1000,
  freshnessFMs: 10000,
  fields: {
    permissionName: null,
    allowLabel: null,
    supportedBrowser: null,
    reenableSteps: null
  }
};
