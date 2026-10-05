# ga4-bridge 0.6.1 — uv route only

0.6.0 plus the O8 fix: the helper's calls to Google use the pinned certifi trust store, because the
extension's interpreter can have none. Built ONLY by the GitHub Actions workflow in grabmcp/connect
(the client comes from its encrypted secret) or by `build-0.6.1.py` run from this folder.
See CHANGELOG-at-0.6.1.md.
