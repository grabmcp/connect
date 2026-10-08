# Changelog — ga4-bridge

Every released bundle is recorded here before it leaves this folder, and kept immutable under
`releases/<version>/`. A version is never rebuilt in place.

## Version scheme

`MAJOR.MINOR.PATCH`, decided by what a user would have to do differently:

| bump | when | examples |
|---|---|---|
| **PATCH** | dependency versions change; no behaviour change our code is responsible for | a routine or security update to a pinned package |
| **MINOR** | our own behaviour changes in a backward-compatible way | the credential-ownership fix; a manifest listing more tools |
| **MAJOR** | a user or an installed copy must be acted on | the credential file format changes incompatibly, `server.type` changes, a tool is removed |

**Rule: any change to the lock bumps at least PATCH**, and **no two artifacts ever share a
version number** — the version is the only handle a user has when asked to go back to one.

---

## 0.8.0 — 2026-10-08 (uv route only) — build-05, not yet approved

**MINOR: the GA4 v2 build for the p3 journey (PLAN-05 v1.1; contract build-05/notes/INTERFACE-05.md §1–§7).**
Helper 1.2.0. Built only by the GitHub Actions workflow in grabmcp/connect or by `build-0.8.0.py` run from
`releases/0.8.0/`. No `.mcpb` of this version has been published.

| artifact | sha256 |
|---|---|
| `helper.py` (helper 1.2.0) | `e54fa2a7f46dc28ce5729171ded9b9cbf37bfe54f7e32ff55d06672e25784d92` |
| `launcher.py` | `a30ced04223313f55c41cc4c6ef87cfeb870955e4d34df909211d55f0b0b52a4` |
| `manifest.json` (0.8.0) | `0a84c62b52b102e100dcce7cfa00fd817eaf0896d4aa0d2680cb63fa0edcb943` |
| `build-0.8.0.py` | `6ff8411c4e65356c879e58914bb74bf557ebdede5bdae745a063dc36a577cc8d` |

**The helper changed inside 0.8.0 after the round-2 freeze (round 3: org_blocked, re-front nonce;
INTERFACE-05 §8.1, §8.4):** round-2 `helper.py` `798b46034a8831bc6000111b7902ca143828d76ce67c751c21cb5b36ea7370c8`, round-3 `helper.py` `3f20757e24f990ec8b83bedaeb3229c9c18af984ccd23ca2f1411fd84255dfab`.
**MD-1/MD-2 (Reviewer 09:12:43, 10:48:42):** the re-front window restarts after a successful open, a /connect/start without a tab ends it, `_RF` drops its unused flow_id; `/verify` with no credential publishes `not_connected`; **CR5a-1 (Reviewer 10:56:47):** that `/verify` also clears `local_credential`, `connection_id` and `verification`; round-3 `helper.py` `3f20757e24f990ec8b83bedaeb3229c9c18af984ccd23ca2f1411fd84255dfab` -> `4738e749e9c0ed42ab78b77dfc0f338e1754c8e521cb86fc5cf0b49f1bec0b7a` -> `b08c66ffbaf9d2b7873ad2af1433d1a5e32289e7ca6989caf2f63e581130dde2`.
**MD-3 (Reviewer 11:51:08):** FR-1, a session's start-time identity no longer depends on the time zone or language (`ps` pinned to TZ=UTC0, LC_ALL=C; legacy local-time strings still accepted; launcher events add `pid_start_utc` and the credential file `_owner_start_utc`); FR-2 and FR-3, a keychain reconcile that could not run at start is re-attempted once the keychain can be read and no launcher read is pending (never on a locked keychain, single flight), and runs whenever no credential is held; the WP-H4 announcer waits while that reconcile is owed, within its own window; `helper.py` `b08c66ffbaf9d2b7873ad2af1433d1a5e32289e7ca6989caf2f63e581130dde2` -> `e54fa2a7f46dc28ce5729171ded9b9cbf37bfe54f7e32ff55d06672e25784d92`, `launcher.py` `467d3d5d95fcb08141b37ca2dc506f2f36ad8dca7f9430ece745cd9a65ee094f` -> `a30ced04223313f55c41cc4c6ef87cfeb870955e4d34df909211d55f0b0b52a4`.
Nothing else in this folder's code changed.

`helper_compare.py`, `requirements.in` and `requirements.txt` are byte-equal to 0.7.0's. Google's server tree
is unchanged: `SERVER-TREE.sha256` is carried from 0.7.0, and all 14 files match.
**Base:** helper.py and launcher.py were derived from `operations/20261002-p2-bridge-s1/bundle/`
(helper `fc13140f…`, launcher `b7865750…`; PLAN-05 §1), not from the 0.7.0 release bytes listed below.
**Approver:** pending. The Reviewer decides at the build-05 PR gate; the merge is the Owner's.

1. **"Ready in Claude" (WP-H1):** the launcher records `mcp_initialize_ok`, `mcp_initialized` and
   `mcp_tools_list` (`tools_ok`: all nine tools), each stamped with `launcher_session`, `pid` and `pid_start`;
   the event allow-list grows by exactly those four fields. `/status` gains `claude_loaded {ok, at}` (only a
   launcher process alive with its recorded start time counts), `property_present` and
   `ready = verified AND property_present AND claude_loaded.ok`.
2. **The callback on the helper port (WP-H2, FX-4):** the redirect URI is `http://127.0.0.1:<port>/callback`
   on the main server, routed before the Origin check. Every outcome answers 303 to
   `<return_to>#return=<flow_id>`; no match answers 303 to the site's page + `#return`. A redirect is matched
   only by sha256(state). The non-secret record `{flow_id, state_sha256, return_to, origin, started_at}`
   (0600) is kept until the flow's outcome is published or 600 s pass; a restarted helper answers the re-sent
   redirect and publishes `last_flow` "interrupted". The PKCE verifier, the raw state, the code and every token
   stay out of every file. The per-flow listener is gone (`callback_port` is no longer returned).
3. **Shutdown (WP-H3):** a SIGTERM handler bounded at 1.5 s persists `{flow_id, claude_pid, claude_pid_start,
   at}` while a sign-in is pending (from the start until its outcome is published). At the next start that
   flow is published "interrupted", with `cause: "claude_closed"` only if the recorded Claude Desktop process
   (found by walking the parent chain) is gone. **M-b** (released by the Reviewer, gate 2026-10-08
   06:43:05; PLAN-05 §3.4): within the same bound, and only for a pending flow matched by id whose setup
   browser was recorded at `/connect/start` and is allow-listed, the handler also runs `/usr/bin/open -b
   <that browser> <return_to>#return=<flow_id>` (neutral Interrupted; no cause is claimed at SIGTERM); the
   interrupted flow gives up tab ownership; the restarted helper brings that page to the front once more,
   on the first-readiness trigger (`refronted_for` in `announced.json`).
4. **Opening the site and the owner tab (WP-H4, FX-1, FX-3, FX-10, FX-12):** once per install (keyed on the
   extension folder's creation time, `announced.json`), on first readiness with no saved credential, the helper
   runs `/usr/bin/open [-b <allow-listed browser>] <origin>/connect/#ready=<run_id>[&owner=1]`, the browser
   found from the polling connection's peer process (`lsof`). `/status` gains `owner {exists, is_you}`
   (the per-tab id `tab`); `/connect/start` answers 409 `not_owner` while another tab's sign-in is pending and
   that tab still polls (after 15 s of silence the first claimant from the flow's origin takes over). `POST
   /release` (204) gives up ownership; a released tab id never claims again. The post-callback hand-off opens
   just before the 303.
5. **`POST /claude/open` (WP-H5, FX-11):** refused 409 unless verified; one per 10 s (429) except the first
   call after `opened:false`; runs `/usr/bin/open -b com.anthropic.claudefordesktop` (no shell), then
   `lsappinfo front` (2 s bound, compared in-process). `{opened}` and `/status.claude_frontmost {front, at}`
   carry a bool only; while it is false, and only while `/status` says `ready`, it is re-read (at most
   once a second, one re-read at a time; FX-15).
6. **`google_access_reason` (WP-H6):** `revoked_or_unrenewable` (invalid_grant), `transient` (unreachable,
   5xx, 429, timeouts; never admin_policy_enforced), `org_blocked` (any error naming admin_policy_enforced;
   round 3), `unknown`, or null; on `/status` and `/verify`. The token endpoint's 5xx/429 now reads
   `http_<code>`. Round 3 also adds a re-front nonce: the re-fronted page's URL carries `&rf=<nonce>` and,
   for 15 s, only the `/status` claim carrying it takes ownership (memory only, never logged).
7. **POST bodies (FX-2, CR5-9):** every POST body is read before the answer (at most 8192 B); a longer,
   chunked or malformed one is never acted on: 413 `body_too_large` (204 for `/release`), and the connection
   closes.
8. **Build variants (FX-5):** the binary seams `GA4_HELPER_OPEN_BIN`, `_LSOF_BIN`, `_LSAPPINFO_BIN` and
   `_BUNDLEID_BIN` are honoured only when the compiled-in switch is True; the qa variant sets it, the release
   scan refuses it (as for `KEYCHAIN_OVERRIDE_ALLOWED`). A release runs its binaries from constants only.
9. **Unchanged:** MSG_A and MSG_B (byte-identical), the scope `analytics.readonly`, one allowed property, the
   qa variant's port 50822, name, keychain service and state directory.

---

## 0.7.0 — 2026-10-06, re-cut 2026-10-07 (uv route only) — QA SEAL; re-cut again as 0.7.0 (same version) after the Owner's wording pass (O-1)

**MINOR: the GA4 UX sprint build (plan 03 v1.2 + ERRATA C-1…C-5; instruction RVW-INSTRUCTION-20261006-O).**
Helper 1.1.0. The new site and the new Claude-side texts are AWAITING OWNER (O-1): every user string is marked.
Built only by the GitHub Actions workflow in grabmcp/connect or by `build-0.7.0.py` run from `releases/0.7.0/`.

| artifact | sha256 |
|---|---|
| `helper.py` (helper 1.1.0) | `79edfb3fd1d851218f732f53e576f37680c73d676defe1b213974cd7b8a11698` |
| `launcher.py` | `43600d5150b32aab5d01feaefa4c41be8346ca343dfe3ad3d672d4b5f43b12b7` |
| `manifest.json` (0.7.0) | `c688d7fa674486dd627c7ac19b03ace78ce3123ff55696d4ac4d06b4c6cb6fb5` |
| `build-0.7.0.py` | `7aed9fceea0ac4bab8838e2ac2d0829b90f1ded00ac0459b8b1da1c3814da5f5` |

Google's server tree is unchanged: `SERVER-TREE.sha256` is carried from 0.6.3, and all 14 files match.

**Re-cut 2026-10-07 (instruction RVW-INSTRUCTION-20261007-P, the build conformed to the Owner-approved design):**
the version stays 0.7.0 (Reviewer 23:46:01; 0.7.0 never shipped). `helper.py` and `launcher.py` are replaced by the
bytes the final Tester run proved (Reviewer 07:15:07: released bytes = tested bytes); `manifest.json`,
`build-0.7.0.py`, `helper_compare.py` and the requirements are byte-unchanged. Changes in those bytes: MSG_A
exactly as brief p.12 (U+2019, three paragraphs); one allowed property handed to the helper; the callback
page always offers one return to `/connect/#return`; a superseded sign-in's callback answers "Sign-in didn't
finish" until its own deadline and never exchanges its code (U-19); only the first redirect counts.
Evidence: `operations/20261006-p2-ga4-ux-sprint/build-03/EXE-CONFORMANCE-REPORT-03-P.md`.
**Approver:** pending. The Reviewer decides at the build-03 PR gate; the merge is the Owner's (O-3).

1. **Callback and return (N-2, N-13):** `POST /connect/start` takes an optional `return_to`, kept only if its origin
   equals the admitted Origin. The callback page is an HTML outcome page: it closes itself, or offers "Return
   to grabmcp". `CALLBACK_WAIT_S` = 600 (site timeout 600 s + 15 s).
2. **C-5:** no user text names a keychain, the `security` tool or a path. Every item is written and read through
   `/usr/bin/security` with `-T /usr/bin/security`; the lead's measurement found no access prompt across the
   update. With a locked login keychain, a store waits up to 60 s for macOS's own unlock prompt; `security` is
   NEVER killed (C2/DIAG-1).
3. **The pending-verified marker:** a `.pending` item counts as a credential only if its sha256 matches
   `<state dir>/pending-verified`. That closes the late-store orphan race (CR3-1). A one-time `legacy-pending-ok`
   flag, written on the first 0.7.0 start, keeps 0.6.3 behaviour for a pre-existing item (E-1, contract §5).
4. **N-5:** state moves to `~/Library/Application Support/GrabMCP/ga4-bridge/` (override
   `GA4_BRIDGE_STATE_DIR`), with a one-time migration.
5. **Build variants:** `--variant release|qa`. The qa build has its own name, port 50822 and keychain service, its
   origin is `--qa-origin`, and it honours `GA4_BRIDGE_KEYCHAIN`. Two scans with per-pattern controls; the release
   build can never carry `KEYCHAIN_OVERRIDE_ALLOWED = True`.
6. **Texts:** MSG_A is the Owner-approved N-14 text, byte-exact. F-B8, F-B9, F-B12 and client_refused are
   AWAITING OWNER (O-1). F-B5 is removed (C-5).

Evidence: `operations/20261006-p2-ga4-ux-sprint/build-03/` (EXE-BUILD-REPORT-03-v1.0.md, reviews/, test-runs/REPRODUCE.tsv).

---

## 0.6.3 — 2026-10-05 (uv route only)

**PATCH: after an update the site no longer shows "not connected" over a working credential (O8 14:34–14:39,
register F-C8).** The helper's state file lives in the extension folder, which an update replaces; the
refresh token survives in the login keychain, and Claude's tools kept answering (the Owner, 14:39).

| artifact | sha256 |
|---|---|
| `helper.py` (helper 1.0.3) | `95feac6b8310e50aacf65d532f8798b2a12060b422224e42f26f6fa7fbdfd4c3` |
| `manifest.json` (0.6.3) | `a1dc5cb153a786a88b5bd40dcada56b5e21703760df76ac306f9a09a2a132715` |

`launcher.py` is unchanged from 0.6.2 v2. **Approver:** pending — Reviewer, at the 0.6.3 gate. No UI change.

1. With NO state file, the helper reads the refresh token ONCE at start (the three-way read through the
   never-kill `_sec`): never on a locked keychain, never beside a pending launcher read. On "present" it
   restores `local_credential: present` and runs the existing re-verify.
2. Tests `poc_reconcile_063.py` R1–R4 with the 1.0.2 control. Buffer: move the state file out of the
   extension folder.
3. Helper 1.0.3 > 1.0.2, so the 0.6.2 → 0.6.3 update hands off by itself (P1, no Claude restart).
4. **Release v2 (re-review-6, Reviewer 14:44):** F1, a reconciled connection reads `unverified` at once
   (never `not_connected`) until the re-verify decides; F2, a wrong-shape launcher record can no longer
   crash the helper at start or fail `/status` (both readers); F3, the `ps` check is bounded with `int(pid)`;
   F5/F6, no existence signal, the token variable renamed. Tests `poc_reconcile_063b.py` 6/6 with the v1
   controls. The first seal is kept as `SHA256SUMS-v1.txt`.

---

## 0.6.2 — 2026-10-05 (uv route only)

**PATCH: an update now takes effect without restarting Claude (O8, 13:00–13:19, register F-C7).**
After the 0.6.1 install the 0.6.0 helper kept serving, because the new launcher attached to it.

| artifact | sha256 |
|---|---|
| `launcher.py` | `59f433f8763dc4bbca26342706dcbe366da7d6e473975dba974b5821c308afe4` |
| `helper.py` (helper 1.0.2) | `6a372628151efb734395a4828cc539043250309b173434080a8a86036deed13a` |
| `manifest.json` (0.6.2) | `744bbbb8ef216ab576b758c1e06ba91b3cf810c61464a7533705e7bced03465d` |

**Approver:** pending — Reviewer, at the 0.6.2 gate. No site UI or microcopy change (Reviewer 13:32).

1. **Hand-off (P1).** A launcher whose bundled helper is NEWER than the running one asks it to stop
   through the helper's paired-only `POST /shutdown` (no Origin; the pairing secret), waits for the
   port, and starts its own (`helper_replaced`). An older or equal bundled helper attaches as before.
2. **Orphan self-exit (P2).** A helper started by a launcher stops when that launcher is gone (its
   parent changes), so a launcher killed without cleanup no longer leaves a stale helper.
3. **Pre-0.6.2 helpers (P3).** A running 1.0.0/1.0.1 helper has no `/shutdown`: recorded once as
   `helper_stale_unreplaceable` and left alone; one Claude restart replaces it.
4. Tests `poc_a2b_handoff.py` H6–H8 with the 0.6.1 controls.
5. **Release v2 (re-review-4, Reviewer 13:52):** M-4, every launcher→helper call bypasses HTTP proxies
   (the pairing secret can no longer reach a proxy); M-1, the hand-off runs outside the supervisor lock and
   honours `stop()`. Tests `poc_m1m4.py` 7/7 with the v1 controls. The first seal is kept as `SHA256SUMS-v1.txt`.

---

## 0.6.1 — 2026-10-05 (uv route only)

**PATCH: a live defect in the sign-in path, found in the Owner's O8 session (12:45-12:48).** After Google's
consent the helper's code exchange failed "unreachable" (status 0): the extension's interpreter (python.org
3.11.5, chosen by `uv python find 3.11`) has no CA bundle for stdlib TLS (`CERTIFICATE_VERIFY_FAILED`).

| artifact | sha256 |
|---|---|
| `helper.py` (helper 1.0.1) | `bbb4c4983d026647e5f6591e1c90a76a02fa0251c44cbe6b253c04ff88b56a58` |
| `helper_compare.py` | `9e23886d955969c5395880a21a5f1840c125a2a6259fbda4cc85f18bd74e90c3` |
| `manifest.json` (0.6.1) | `e6a09e75fe1ccf3d55291fe93e663405dd2e71538baf4b1403feb71a4427d7ba` |

`launcher.py` is unchanged from 0.6.0 v2. **Approver:** pending — Reviewer, at the 0.6.1 gate.

1. The helper and `helper_compare` build their TLS context from the pinned `certifi` bundle
   (stdlib default only as a fallback); the helper logs its trust store at start.
2. Every outbound failure logs the exception TYPE (e.g. `URLError:SSLCertVerificationError`), never a
   URL query, header or body.
3. Test `poc_tls_061.py` (live, public, credential-free, under that interpreter): 0.6.1 reaches Google;
   the 0.6.0 controls reproduce the O8 failure.

---

## 0.6.0 — 2026-10-05 (uv route only; POC KPIs, scope v1.3)

**MINOR under this file's scheme: our behaviour changes** (no extension settings, the helper runs
inside the extension, login-keychain custody, a property allowlist), with nothing a user of 0.5.0
must act on beyond installing it.

| artifact | sha256 |
|---|---|
| `launcher.py` | `05225a01b2ad2cc6b44fdb98909041fe0b616b9eb9c04c035edd37d229cea195` |
| `helper.py` (helper 1.0, NEW in the bundle) | `e0648e89810889e0ee07b35376f217c9070c16504304bc2dabc0ba90cbf25e41` |
| `helper_compare.py` (NEW) | `a301750770edce2468676e42c1370621109174566fad79c91791428a67e30c1c` |
| `manifest.json` | `e90fc354fd85341e537da8a874b97a82f0e2af82481f187c6e1fd5ccc845d3ac` |

**The `.mcpb` is NOT built here.** It carries the Owner's OAuth client file, so it is built only by
the Owner's own command (O7, `build-0.6.0.py`, sealed in this release); its digest is recorded at O7.
It must never enter a repository (D6). **Approver:** pending — Reviewer, at the 0.6.0 build gate.
Plan: `operations/20261005-p2-poc-kpis/EXE-PLAN-POC-KPIS.md` + `-AMENDMENT-2.md`.

**Release v2 (gate 12:05, conditions 1, 2, 4):** the build command runs only as the released
copy, verifies every entry of the release `SHA256SUMS.txt` and Google's server against the pinned
`SERVER-TREE.sha256`, and refuses on any mismatch; the launcher's stale "0.7.0 surface" comment is
corrected (comment only). The first seal is kept as `SHA256SUMS-v1.txt`.

### What changed from 0.5.0

1. **No settings (A4).** The manifest has no `user_config`: the OAuth client is embedded by the
   build (`oauth-client.json`, the one in-extension file allowed), the credential keychain defaults
   to the user's LOGIN keychain by path (P1, ruling D1). `darwin` only; Python `>=3.11` (E2-17).
2. **The helper runs inside the extension (A2).** The launcher starts it with the extension's own
   runtime on 127.0.0.1:50812; the port is the lock; a second instance attaches; the helper stops
   with the instance that started it, and the other takes over within one recheck.
3. **Property allowlist (KPI-6, D2), fail-closed on tool names (re-review N1).** Only
   `get_account_summaries` goes upstream unchecked; every other tool must carry an allowed property
   id (build-time, default 449629553) or is refused before upstream with one truthful message.
4. **Exe.2 fixes:** a failed keychain read is never "no token" (E2-01); a token store never loses
   the old token (E2-02, no `-U`, a `.pending` item read back first); the launcher marks a credential
   held only after the restart that loaded it (E2-03); atomic, locked helper state (E2-04); per-flow
   OAuth callbacks (E2-05); the pairing secret read once (E2-06); `rrk` never kills `security` on
   Ctrl-C (E2-07); every `security` in its own session (E2-08); CORS preflight + socket timeout
   (E2-18). Reviews: `EXE2-RE-REVIEW-REPORT-0.6.0.md`, `EXE2-RE-REVIEW-2-REPORT-0.6.0.md` (KPI-7: MET).
5. **KPI-3:** the helper's paired-only `/compare` (ruling D3: no token leaves the helper) and
   `rrk.py compare`.

---

## 0.5.0 — 2026-10-05 (uv route only)

**MINOR under this file's scheme: our behaviour changes** (an automatic restart of Google's server,
new user-facing messages, an always-set credential variable, a credential file per instance).

| artifact | size | sha256 |
|---|---|---|
| `ga4-bridge-0.5.0.mcpb` (uv) | 79,564 | `e8da34933faf9251147b9fe306afcdd99b86139318bb7723ab8ba8d7edeb9864` |

**Approver:** pending — Reviewer, at the 0.5.0 build gate. Plan: `operations/20261005-p2-lch/EXE-PLAN-LCH-v1.1.md` (`d2d4e638…`).

### What changed from 0.4.0 (Owner ruling 2026-10-05 08:48–08:55; Reviewer conditions C1–C8)

1. **No Claude restart after a connect (LCH-1, option 2).** A call that fails for want of a
   credential (no credential, `invalid_grant`, or Google's 401 "Request had invalid authentication
   credentials") makes the launcher re-read the keychain. If the credential CHANGED, it rewrites this
   instance's credential file, restarts Google's server under the same stdio session (replaying
   `initialize` under a private id) and retries the call once.
2. **Two Owner-approved messages, verbatim.** **A** for no credential, or an UNCHANGED credential that
   is still refused (revoked); **B** for a changed credential whose restart or retry failed, or a
   keychain read still pending. Every other text is unchanged (the G5 texts, 403, generic).
3. **`GOOGLE_APPLICATION_CREDENTIALS` is always set** to the instance's own file, so google-auth can
   never fall through to a gcloud user credential on the machine (another account, silently).
4. **One credential file per instance** (`.private/adc-<pid>.json`, 0600): Claude Desktop starts every
   local extension twice. The 0.4.x shared `adc.json` is still swept.
5. **The call record survives two writers (LCH-3):** an exclusive lock, a unique temporary file per
   write, and an unreadable record kept as `status.json.corrupt-*`, never overwritten.
6. **`security` is never killed:** a bounded wait instead of `subprocess.run(timeout=)`; a read that
   does not return is left running, recorded as pending, and no second read starts while it lives.
7. The call record's allow-list gains exactly two fields: `outcome` and `sec_pid`.

`launcher.py` `7834e9e2…4a8c` → `0856888c3fb9d3184264a024d972cfe3860883e741977f35c7e4ab0eff2ac2d9`;
`manifest.json` → `53b44fe5f120eed7500b226a8b6c4a5a1ef8b0e9002d7fda8d60dfae91ea6510` (version only).
**Lock unchanged** (`requirements.txt` `8370081f…8d40`). The vendored server is byte-identical to 0.4.0's.

**Paired changes outside this artifact:**
- the helper (S2L folder) `helper.py` → `07c066f813047c5093d36b969ff36d4fdab90f0ded6272622cabc2062774d337`:
  its `security` calls wait without killing; a second call waits its turn;
- the Owner's driver `operations/20261004-p2-rrk/tools/rrk.py` → `dcba4dc6813f8f7a05b87246b47d42cb1fdfc55d42edee5a840b083696d67530`:
  never-kill keychain calls, a tolerant call-record reader, `adc-check` for per-instance files, and
  egress bare-IP classification against a shipped snapshot of Google's published ranges.

**Snapshot refresh policy (egress):** `tools/ipranges/goog.json` and `cloud.json` are refreshed at
each release build by a public, unauthenticated GET of `https://www.gstatic.com/ipranges/`. This
release ships syncToken `1791166273375`, creationTime `2026-10-04T19:11:13.375997` (goog.json
`ff9b2c77…ec82`, cloud.json `3bc02e49…1308`). The tool prints the snapshot's age, says "stale" past
90 days, and never fetches at run time.

### Test results

Run by `operations/20261005-p2-lch/tests/run-0.5.0.sh` against the unpacked 0.5.0 `.mcpb`, under the
KIT6 conditions; three runs, every one's evidence kept. Counts and evidence are in
`operations/20261005-p2-lch/EXE-REPORT-LCH.md`.

---

## 0.4.0 — 2026-10-04 (uv route only)

**MINOR under this file's scheme: our behaviour changes** (Reviewer 19:42: the scheme as
written decides the number).

| artifact | size | sha256 |
|---|---|---|
| `ga4-bridge-0.4.0.mcpb` (uv) | 73,633 | `375616aa577147356636f77b49a3d9e9d86798277e76b1c49b6ab4386746dcc6` |

**Approver:** pending — Reviewer, on the KIT2 completion entry.

### What changed from 0.3.0

1. **Every call is recorded (G6 completed, Reviewer F-2).** 0.3.0 recorded a call only when it
   came back with a `result`. Now a JSON-RPC **error** response is recorded as a failed call
   (`state: jsonrpc_error`, with the digest of the error object as delivered), and a call still
   **unanswered at shutdown** is recorded too (`state: pending_at_shutdown`).
2. **Shutdown-ordering fix:** the in-flight call table is created **before** the signal handlers
   are installed, because `cleanup()` now reads it and a SIGTERM may arrive at once.

`launcher.py` `538fa16a…4240` → `7834e9e2877d45f72cbdb51664e76c5a5e3dbbfb9abef60ac7c92f5e512e4a8c`; `manifest.json` → `a774bd00a9e6738a038f1b69734d4a1593e5ca3ae45e87e1f31938d13f8d5997` (version only).
**Lock unchanged** (`requirements.txt` `8370081f…8d40`).

**Paired changes outside this artifact:** the helper (S2L folder) **refuses a keychain password
from the environment on the real route** and so never puts one in argv (Reviewer F-3). The
Owner's real-run driver `operations/20261004-p2-rrk/tools/rrk.py` sets the pairing secret through
`security -i` on stdin (no argv, no search-list change) and drives connect, status and disconnect.

**Not rebuilt:** the frozen onefile/onedir artifacts stay at 0.2.0 — **do not use them**.

### Test results

Run by `operations/20261004-p2-s2-local/run-suites.sh` against the unpacked 0.4.0 `.mcpb` and the
mock Google; counts and evidence in that folder's `EXE-REPORT-S2L.md` §2 and `evidence/`.

---

## 0.3.0 — 2026-10-04 (uv route only)

**Real-run configuration: a FEATURE, so MINOR under this file's scheme** (Reviewer ruling 19:11,
which also settles that the scheme applies as written from now on; 0.2.1 stands as shipped).

| artifact | size | sha256 |
|---|---|---|
| `ga4-bridge-0.3.0.mcpb` (uv) | 73,328 | `e392535612adad9998992511180bdc4780da63a0b35fc675d6a6512f95c3766b` |

**Approver:** pending — Reviewer, on the RRI completion entry.

### What changed from 0.2.1

1. **`user_config` (G2).** The manifest declares two required settings, chosen once in Claude
   Desktop: `oauth_client_json` (`type: file`), the path of Google's installed-app client JSON,
   and `keychain_path` (`type: file`), the dedicated credential keychain. Both are substituted into
   `mcp_config.env` (`GA4_OAUTH_CLIENT_JSON`, `GA4_BRIDGE_KEYCHAIN`). 0.2.x passed `env: {}`, so
   under Claude Desktop the launcher never had a keychain and always started without a credential.
2. **The OAuth client comes from that file, read in place (G4, RRK §2).** The ADC file's
   `client_id`/`client_secret` are the client file's. 0.2.x used test defaults, which Google would
   refuse, because a refresh token is bound to its client. **Guards:** the path must be absolute;
   it may not lie inside the extension's directory or inside any project/versioned tree (an
   ancestor holding `CLAUDE.md` or `.git`); its mode must grant nothing to group or other. Only
   the two fields needed leave the reader. The child server is not told where the file is.
3. **One keychain account shared with the helper (G3):** `ga4-refresh-token`. 0.2.x read
   `ga4-bridge-test` and could never have found the token the helper wrote.
4. **A locked keychain is a truthful state (G5).** The lock is read with `SecKeychainGetStatus`,
   which cannot raise a dialog. A locked keychain is never handed to `security`. The launcher
   logs "LOCKED: unlock it", records it, and answers tool calls with the locked message, never
   "not set up".
5. **Every tool call is recorded (G6):** tool, full arguments, `ok`, and the SHA-256 of the
   result exactly as delivered, never the result itself.
6. **No GCE metadata probe (found by S2L `X-1/rc`).** With no credential, Google's
   `google.auth.default()` tried `169.254.169.254` (link-local, not a Google API host) on every
   failed call. The launcher now sets `NO_GCE_CHECK=true` (lower case: google-auth honours only
   that spelling) for its child.

`launcher.py` `e5e94efd…7de56` → `538fa16ac689f7d28a6a8522c419fc1caf1c74a4ec570050192d8e8cbb534240`; `manifest.json` → `a912fde7bc3df01ce4f19acdb3f93c7d603fbe02108eb27d268ef64a4a6bd7dc`. **Lock unchanged** (`requirements.txt` `8370081f…8d40`).

**Paired helper changes**, in `operations/20261004-p2-s2-local/helper/helper.py` and not part of
this artifact: four separately configured endpoints (G1); the same client file, guards and
shared account; the same silent lock check.

**Not rebuilt:** the frozen onefile/onedir artifacts stay at 0.2.0. **Do not use them:** they
carry the 0.2.0 shutdown race.

### Test results

Run by `operations/20261004-p2-s2-local/run-suites.sh` against the unpacked 0.3.0 `.mcpb` and the
mock Google; counts and evidence are in that folder's `EXE-REPORT-S2L.md` §2 and `evidence/`.
The 0.3.0-specific suites are `17-realconfig` (G1–G6 and the GCE fix, each with a control) and
`18-secret-scan` (guard 4).

---

## 0.2.1 — 2026-10-04 (uv route only)

**A defect fix in the launcher's shutdown, found by S2L. One artifact.**

| artifact | size | sha256 |
|---|---|---|
| `ga4-bridge-0.2.1.mcpb` (uv) | 70,247 | `477c5e33152df2168bd176155a375dfd11f8218d91cabafb6c9174f9b46f63f9` |

**Approver:** pending — Reviewer, on the L021 completion entry.

### What changed from 0.2.0

1. **Launcher shutdown race (defect fix).** With SIGTERM and stdin EOF arriving together, 0.2.0's
   `cleanup()` set its done-flag *before* removing the ADC file; the SIGTERM handler saw the flag,
   returned, and `sys.exit(0)` ended the process mid-removal — exit 0, no log line, the
   credential left on disk until the next start swept it (S2L `V3-3c`). Now the whole cleanup
   runs under one **re-entrant** lock and the flag is set only **after** the work, so a second
   caller waits for an in-flight cleanup instead of skipping it. Re-entrant because a signal
   handler runs on the main thread, which may itself be inside `cleanup()`; a plain lock would
   deadlock there. Each shutdown path is now logged (`shutdown: SIGTERM` / `stdin-eof` /
   `upstream-exit`), which is how a test proves two paths really raced.
   `launcher.py` `33a1c1f6…3dd` → `e5e94efda987f3930dfc6d94e8925eea234985d9b43716156514da4b4ef7de56`.
   **User-visible effect:** none, except that the credential file no longer survives this
   shutdown, and two extra stderr lines at exit.
2. `manifest.json` version `0.2.0` → `0.2.1` (`2475b78106e7eccd41bfa49f73f0036fea2457ad462b3872297820468da9e87d`). Nothing else in it changed.
3. **Lock unchanged:** `requirements.txt` `8370081f…8d40`, `requirements.in` `a7c01cf9…cb78`, the
   same bytes as 0.2.0. The vendored server is unchanged (the archive's other 16 entries are
   byte-identical to 0.2.0's).

**Version number.** By this file's own scheme a change in our behaviour is MINOR, which would
make this 0.3.0. It is **0.2.1** because the Reviewer's instruction (L021, 18:56) and clarification
F4 name it so; recorded here rather than silently resolved.

**Not rebuilt:** the frozen onefile/onedir artifacts stay at 0.2.0 and **still carry the race** —
their launcher `ga4_launcher.py` is byte-identical to 0.2.0's `launcher.py`.

### Test results

Run by `operations/20261004-p2-s2-local/run-suites.sh`; evidence in that folder's `evidence/`.

| suite | result |
|---|---|
| mock self-test | **18/18** |
| flow | **33/33** |
| adverse | **44/44** |
| double-dependent, unpacked 0.2.1 | **21/21** |
| site | **24/24** |
| custody, against the unpacked 0.2.1 launcher | **43/43** |
| manifests and artifacts | **7/7** |
| coverage gate negative control | **10/10** |
| coverage gate | **OK** |

**The defect's own test:** `V3-3c` passes: 20 shutdowns with SIGTERM and stdin EOF together, each confirmed to have raced, leave zero files. `V3-3c-ctl` passes: the same harness against 0.2.0 still leaves one.

---

## 0.2.0 — 2026-10-04

> **DO NOT USE the frozen onefile/onedir 0.2.0 artifacts: they carry the 0.2.0 shutdown race** (fixed in 0.2.1 for the uv route only; see 0.2.1). Marked 2026-10-04 per the Reviewer's L021 condition 4.

**Everything built in S1B. Three delivery artifacts, one source of truth.**

| artifact | size | sha256 |
|---|---|---|
| `ga4-bridge-0.2.0.mcpb` (uv) | 69,587 | `1a5f4883b4a3eaf67f08e13631360daef482360c44638a643ad4ce787dd3e932` |
| `ga4-bridge-frozen-0.2.0.mcpb` (onefile) | 41,494,439 | `7799140555e40bcbf3b6714362d80960048fc6db88e50ee2cdf6f0e9dbfda12c` |
| `ga4-bridge-frozen-onedir-0.2.0.mcpb` (onedir) | 49,075,397 | `8416d1ad8360fd87d155fb2350f0dec89cc92b1dca1ed056571733dc9c4ff9c5` |

**Approver:** pending — Reviewer, on the S1B completion entry.

### What changed from 0.1.0

1. **Credential ownership (defect fix).** The ADC file now records `_owner_pid` and
   `_owner_start`. `sweep_stale()` deletes only when that owner is provably gone and
   **refuses when liveness cannot be established**; `remove_adc()` deletes only a file this
   process owns.
   **Why:** Claude Desktop runs several instances of the connector at once, sharing one
   private directory, so 0.1.0's unconditional sweep deleted a **live** instance's credential
   and logged it as stale — and the victim then reported our truthful "access is not set up"
   message, which is right about what it can see and misleading about why.
   `launcher.py` `39f76e49…f53a` → `33a1c1f6eca5b3d3a81d50a5952125de64cc38932a35bc0d3344cf6d9d43c3dd`.
   **User-visible effect:** none when a single instance runs; with concurrent instances, calls
   that used to fail spuriously now keep working.
2. **Full dependency lock.** 0.1.0 shipped 6 direct pins with **0 hashes** and unpinned
   transitive dependencies. 0.2.0 ships **61 packages, every one pinned, 910 hashes**,
   consumed by the existing `mcp_config` so an install fails on any mismatch — verified by
   tampering, not by documentation. `requirements.txt` `a7c01cf9…785e` → `8370081fbe3676d8b7a258a5be328bc79762d82ca668bd52514226164b558d40`,
   with the direct list preserved as `requirements.in` (unchanged: `google-adk==2.10.0`,
   `google-analytics-admin==0.30.1`, `google-analytics-data==0.23.0`, `google-auth==2.59.1`,
   `httpx==0.28.1`, `mcp==1.30.0`).
   **Reason:** routine — first full lock. No advisory. No dependency VERSION changed.
3. **The uv manifest lists all 9 tools**, where 0.1.0 listed 2 (`get_account_summaries`,
   `run_report`). Tool annotations (`title`, `readOnlyHint`) are served in `tools/list`,
   because the 0.4 manifest schema fixes `tools[]` to `{name, description}` with
   `additionalProperties: false` and cannot carry them.
4. **Two new delivery routes**, both self-contained and needing no `uv` and no Python on the
   machine: frozen **onefile** and frozen **onedir**. Both are **ad-hoc signed only**;
   `spctl` rejects them, and onefile + quarantine is blocked with a malware warning.
   **onedir starts in 0.97 s against onefile's 14.1 s**, because a onefile binary re-extracts
   ~106 MB on every launch.

### Test results

| suite | result |
|---|---|
| packed uv bundle, unpacked into a fresh dir | **20/20** |
| credential ownership, against the unpacked launcher | **9/9** |
| frozen onefile | 15/15 |
| frozen onedir | 15/15 |
| locked dependency set | 6/6 |
| lock: cold-cache install reproduces exactly the 61 locked packages | pass |
| lock: a tampered hash makes the install fail | pass (exit 1, `Hash mismatch`) |

---

## 0.1.0 — released in Stage 1, 2026-10-02 (historical)

`ga4-bridge-0.1.0.mcpb`, 28,761 bytes, sha256 `c3b98fb84d627cf43b806ff706f62f94d76862a20c12af3849fe75a2b62ca735`. **This is exactly what the Owner
installed at E1 and the version a rollback returns to.** Kept unchanged in `releases/0.1.0/`.

- **Approver:** Reviewer, gated PASS on `EXE-REPORT-BRIDGE-S1-LOCAL.md` v1.1
  (`61f15e5edca96376facf5efab39898fd6aa6d5f594facffec58dbea799388a96`).
- **Dependencies:** 6 direct pins, **transitive unpinned and unhashed** — the gap 0.2.0 closes.
- **Manifest:** 2 tools listed, though the server serves 9.
- **Test results:** 51 criteria, 50 pass with V1-4 failing by design.
- **Note:** this version's archive was repacked once during the Stage 1 gate (finding F-6, a
  stale archive), so an archive bearing `0.1.0` may exist in two digests. The digest above is
  the one that passed the gate. This is the second reason the scheme forbids reusing a number —
  and S1B hit the same class of mistake again (see the addendum, R1).
