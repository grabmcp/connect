# ga4-bridge 0.6.3 — uv route only

0.6.2 v2 plus the state reconcile: with no state file the helper reads the keychain once at start, so an
update no longer shows "not connected" over a working credential. Built ONLY by the GitHub Actions
workflow in grabmcp/connect (the client comes from its encrypted secret) or by `build-0.6.3.py` run from
this folder. See CHANGELOG-at-0.6.3.md.
