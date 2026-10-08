# ga4-bridge 0.8.0 — uv route only (build-05, PLAN-05 v1.1)

The GA4 v2 build for the p3 journey: helper 1.2.0. The callback moved to the helper's own port (one 303 on
every outcome, a non-secret pending-flow record that survives a restart); "Ready in Claude" (claude_loaded,
property_present, ready); a bounded SIGTERM handler and the correlated shutdown record; the site opened once on
first readiness; owner-tab arbitration and POST /release; POST /claude/open; google_access_reason. The launcher
adds three MCP lifecycle events. Not shipped and not approved: the Reviewer gates the build-05 PR and the merge
is the Owner's. Built ONLY by the GitHub Actions workflow in grabmcp/connect (the client comes from its
encrypted secret) or by `build-0.8.0.py` run from this folder. See CHANGELOG-at-0.8.0.md.
