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
