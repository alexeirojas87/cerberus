# F6.B FIX attempt 2 — Independent Adversarial Verification (commit ddf72c4)

- **Unit**: F6.B / R9-6 — Appendix B CLI surface + API→CLI→dashboard parity matrix (attempt 2 fix)
- **Candidate**: commit `ddf72c4` on `r9-remediation` (parent `cb36c8a` verified: `git log -1 --format=%P` → `cb36c8a150fc1f30af6e16beff51465b08d59227`), 10 files, +1389/−111 (matches pack)
- **Reviewer**: independent adversarial re-verifier of the attempt-2 FIX (attempt 1: correctness FAIL 1×P1 + P2s; security PASS w/ remediate-before-gate P2s)
- **Date**: 2026-09-02 · Host: macOS arm64 (darwin) · fresh detached worktree
  `/var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/f6b-attempt2-verify` (removed after verification)
- **Method**: §8B gauntlet — all gates re-run from scratch (no target dir inherited), the F1 closure reproduced LIVE against a real release daemon, the F2 mutation test re-executed by this reviewer, a new-hole hunt over the fix's own restructuring (R1/R2), and SHA-256 hash equality against the pack's frozen block. "Couldn't run" = FAIL was respected; every command below was executed by this reviewer.

---

## 1. Commands run (verbatim, with exit codes)

| # | Command (from the worktree) | Exit | Result |
|---|---|---|---|
| S1 | `git -C /Users/alexeirojas/Work/Personal/Cerberus worktree add --detach …/f6b-attempt2-verify ddf72c4` | 0 | worktree at `ddf72c4` |
| S2 | `git log --oneline -3` / `git log -1 --format=%P` | 0 | parent = `cb36c8a150fc…` ✓ |
| S3 | `git diff --check cb36c8a..ddf72c4` | 0 | whitespace clean |
| S4 | `git status --porcelain` | 0 | pristine (no reviewer edits before the sanctioned mutation) |
| G1 | `rtk cargo fmt --all -- --check` | 0 | clean |
| G2 | `rtk cargo clippy --workspace --all-targets -- -D warnings` | 0 | "No issues found" |
| G3 | `rtk cargo test --workspace --all-targets` | 0 | **862 passed / 0 failed** (29 suites; matches builder's 862) |
| G4 | `rtk cargo test -p cerberus-packs --test production_pack_pr` | 0 | **19/19** |
| G5 | `rtk cargo test --release --test load_test -- --test-threads=1` | 0 | **14/14**; raw re-run lists `load_test_f3_3_honest_http_round_trip_gate … ok` and `load_test_json_many_leaf_context_reuse … ok` |
| G5b | `git diff cb36c8a..ddf72c4 -- tests/redos_fuzz.rs \| wc -c` | 0 | **0 bytes** — frozen rule byte-untouched |
| G5c | `rtk cargo test --release --test redos_fuzz -- --test-threads=1` | 0 | **11/11** |
| G6 | `rtk cargo test -p cerberus-proxy --test smoke_harness` | 0 | **69/69** |
| G7 | `rtk cargo test -p cerberus-proxy --test f6b_api_surface` | 0 | **10/10** |
| G8 | `rtk cargo test -p cerberus --test cli_surface_via_api` | 0 | **11/11** |
| G9 | `rtk cargo test -p cerberus --test pack_enable_disable_worker_e2e` | 0 | **1/1** (~1.2 s, real daemon) |
| G10 | `rtk cargo test -p cerberus --bin cerberus every_daemon_backed_cli_command_maps_to_a_real_api_route` | 0 | **1/1** (24 CLI rows through the live router) |
| G10 | `cargo build --release -p cerberus` (plain; smoke needs the bin) | 0 | release binary (16.5 s) |
| G11 | `bash tests/smoke-test.sh` | 0 | **17 PASS / 0 FAIL** (first attempt exit 1: "Binary not found" — the load-test run builds test bins, not the daemon binary; after `cargo build --release -p cerberus` → 17/17) |
| M1 | `edit api.rs:638` → `("POST","/api/reload") => Ok(not_found()),` (sanctioned TEMPORARY mutation) | — | 1-line mutation |
| M2 | `cargo test -p cerberus --bin cerberus every_daemon_backed_cli_command_maps_to_a_real_api_route` | **101** | **FAILED**: "parity: CLI 'reload' maps to POST /api/reload, which the ROUTER does not serve (bare 404 — the dispatch arm is missing)" |
| M3 | `cargo test -p cerberus-proxy --test f6b_api_surface route_table_matches_the_router` | **101** | **FAILED**: "route table claims POST /api/reload but the ROUTER does not serve it" |
| M3b | `git checkout -- crates/cerberus-proxy/src/api.rs` + `git status --porcelain` | 0 | 0 dirty files (mutation reverted; re-ran twice — second pass recorded with true exit codes) |
| M4 | re-run parity (1/1) + full f6b suite (10/10) after revert | 0 | green again |
| L1–L9 | LIVE battery vs real release daemon (`target/release/cerberus start --port 18947`, isolated HOME, 0600 config, random 64-hex token; serving binary identity verified via `lsof` txt path → the worktree build) | 0/1 as designed | see §2 |
| T7 | `git diff --check` (worktree, post-mutation-revert) + `git status --porcelain` | 0 | clean |
| H1 | `shasum -a 256` over the 9 changed files | 0 | all 9 == pack's frozen block (§6) |

Harness noise, disclosed: one `start` failed with "no upstreams configured" and two CLI probes printed an 11-command help / "unrecognized subcommand 'events'". Root cause was **reviewer error, not product**: those calls ran without a workdir and resolved `./target/release/cerberus` to the main repo's stale Aug-31 pre-F6.B binary (verified: main-repo binary hash `a61851a4…`, 14,462,624 B, Aug 31 vs worktree binary `b067496e…`, 14,966,064 B). Every decisive result was re-confirmed with the worktree binary (daemon identity proven by `lsof -p <pid> | grep txt` → `/…/f6b-attempt2-verify/target/release/cerberus`).

## 2. Per-item closure table

| Item | Attempt-1 finding | Reproduction outcome (this reviewer, independent) | Verdict |
|---|---|---|---|
| **F1** (P1) anti-lockout on `PUT /api/config` | `{"admin_token":null}` → 200, closes plane, persists null | **LIVE**: PUT `{"admin_token":null}` w/ valid token → **400** `config update would remove the admin token and CLOSE the control plane (fail-closed)…`; immediately: GET /api/config w/ old token → **200**; `/health` → **200**; disk still carries the original token (grep=1). Rotation: PUT `{"admin_token":"<new 64-hex>"}` → **200**, old → **401**, new → **200**; **restart** → old still 401 / new 200 (rotation persists). Sneaky variants: **omission** (PUT `{}`/`{"mode":"enforce"}`) → 200, token preserved (correct partial-patch semantics, does NOT clear); **`"Admin_Token": null`** → **400 unknown field** (`deny_unknown_fields` — cannot clear by case games); **null via /api/reload** → **400** (guard holds on the reload path). **BUT `{"admin_token":""}` → 200 — see Finding P1 below (hole, live-reproduced incl. restart persistence).** | Closed for null/omission/case-games; **invariant still violated via empty string → P1** |
| **P2-1** (security) unaudited control-plane mutations | `GET /api/events` showed only dataplane events after reload/config/allowlist/upstream swaps | **LIVE**: reload, config PUT, allowlist add+remove, upstream add+remove (all 200) → `/api/events?tool=control-plane` lists **config-reload, config-update, allowlist-add, allowlist-remove, upstream-add, upstream-remove**, all `tool=control-plane`, `provider=control`, `action_taken=audit`, empty `counts`/`hashed_values`. Secret-free: **0** payload hits for the admin token, the raw allowlist canary (`AuditCanaryRawValue-987654`), and `hmac:`. Visible via CLI `events --tool control-plane` (10 rows). Tee log carries the paired lines (10× "control-plane config mutation applied"). Filters discriminate: `?tool=proxy` → 0 control-plane rows; `?provider=openai` intact. Success-only verified (failed mutations emit nothing — guard/reject paths return before `audit_config_mutation`). | **CLOSED** |
| **F2** (P2) parity test checked a duplicated table, not the router | Mutation A: removed router arm left the parity test green | **Re-executed by this reviewer** (see §3): 1-line mutation `Ok(not_found())` on the reload dispatch arm → parity test **FAILED (exit 101)** AND `route_table_matches_the_router` **FAILED (exit 101)**; revert → parity 1/1 + f6b 10/10 green; worktree pristine. Both tests also assert the router's bare `404 {"error":"not found"}` canary first (no vacuous pass). | **CLOSED** (mutation-proven red→green) |
| **F3** (P2) no executing test for real packs enable/disable success path | `set_active`/worker arms never executed | `pack_enable_disable_worker_e2e` **1/1** on my run (~1.2 s): spawns the REAL `cerberus start` daemon (signed Pro license + trust root via env), drives install→`/api/scan` DETECTS pack marker→disable→scan does NOT detect→enable→DETECTS again, and asserts pack-enable/pack-disable audit events on the real daemon via `/api/events`. The composed path API→PackCommand→worker→`set_active`→engine rebase→live scan now executes in CI. | **CLOSED** |
| **P2-2** (security) flaky `login_verifies_and_installs_signed_license` | nanosecond-timestamp `temp_home()` collisions; sibling rmtree deleted a live home | 3 consecutive `cargo test -p cerberus login_verifies_and_installs_signed_license -- --test-threads=1` → **3× `ok. 1 passed`**; also green inside my full workspace run (862/0). Helper fix audited in source: all THREE `temp_home` copies (`cli_surface.rs:984`, `cli_api.rs:304`, `cli_pack.rs:204`) now use `tag-pid-nanos-SEQ` with a monotonic `AtomicU64` — unique per CALL. | **CLOSED** |
| **P3-1** (security) tee file 0644 | `~/.cerberus/logs/cerberus.log` created world-readable | **LIVE**: `stat` on the real daemon's tee → `-rw-------` (0600). Source: `open_log_file()` with `.mode(0o600)` at creation (append keeps existing mode), used by `TeeSink::open` and rotation. Unit test `tee_file_is_created_0600` in the 862. | **CLOSED** |
| P3-2 (informational) scan cap | shared 1 MiB control-plane limit vs plan's 100 KB budget shape | Documented at `api.rs:126-135` (`KNOWN LIMIT` comment); no behavior change — accepted as documentation-only per the finding. | Documented ✓ |

## 3. Mutation-test proof (F2 — reproduced by this reviewer)

Mutation (the one sanctioned temporary edit, applied twice for clean exit-code capture, reverted immediately both times):

```
crates/cerberus-proxy/src/api.rs:638
- ("POST", "/api/reload") => handle_reload(ctx).await,
+ ("POST", "/api/reload") => Ok(not_found()),
```

| Test | Under mutation | After revert |
|---|---|---|
| `every_daemon_backed_cli_command_maps_to_a_real_api_route` (crates/cerberus/src/main.rs) | **exit 101 — FAILED**: `assertion 'left != right' failed: parity: CLI 'reload' maps to POST /api/reload, which the ROUTER does not serve (bare 404 — the dispatch arm is missing)` | exit 0 — `ok. 1 passed` |
| `route_table_matches_the_router` (crates/cerberus-proxy/tests/f6b_api_surface.rs) | **exit 101 — FAILED**: `assertion 'left != right' failed: route table claims POST /api/reload but the ROUTER does not serve it` | exit 0 — f6b suite `ok. 10 passed` |

`git status --porcelain` after revert: **0 dirty files** (both times). The canary-first design is real: an authenticated `/api/not-a-route` request returns the bare router `404 {"error":"not found"}` (asserted in both tests), so a missing arm cannot hide behind "any non-404 status". A removed router arm is now caught by BOTH the CLI parity test and the table↔router cross-check.

## 4. New-hole hunt

**R2 — PUT transaction restructure (scoped lock block)**: reviewed `handle_put_config`, `handle_post_upstreams`, `handle_delete_upstream`. The write lock is now scoped in a lexical block; the guard/validation/persist/publish order is unchanged; the audit emission (`audit_config_mutation` → `record_event`) awaits only after the lock is released, so no lock is held across an await. `live_operation_mode` re-acquires the read lock separately (benign). No nested acquisition, no deadlock shape, no half-applied state on failure paths (exposure/persist failures return before `*live = candidate`). Workspace suites (862), smoke (17/17), and the f6b reload/config suites all green on the restructured code. **No hole found.**

**R1 — new audit events change the `/api/events` surface**: control-plane rows now sit next to dataplane rows. Verified live: `?tool=proxy` → 0 control-plane rows; `?tool=control-plane` → 10 rows, all control-plane; `?provider=openai` filter discriminates; smoke script's non-empty `/api/events` check still passes (smoke ran on this candidate: 17/17); the f6b event assertions are membership-based and passed. Secret-free verified (§2 P2-1). **No hole found** — reads as the intended feature.

**R3/R4** (worker-e2e deadline sensitivity; pack install/rollback not event-audited) — acknowledged in the pack; e2e passed in ~1.2 s locally; install/rollback events were outside the remediation list (two-line follow-up if the panel wants them). Not defects.

**NEW HOLE (found by this battery): `admin_token: ""` (empty string) reproduces the F1 failure mode on BOTH write paths — the anti-lockout invariant is not fully closed.** See Finding 1.

**Also checked, safe**: case games (`Admin_Token`, `admin_Token`) → 400 unknown field (`deny_unknown_fields` — the PUT cannot be tricked into clearing by casing); omission → token preserved; `admin_token_configured` stays read-only; GET→modify→PUT cycles are unaffected (GET omits the token value; PUT-back without the field keeps it). The `?provider`/`?tool` event filters, the smoke script's non-empty events check, and `stats --by flag` grouping (action names land in `flags`) all behave on the new event shape.

## 5. Findings

**No P0. One P1. No new P2/P3.**

### P1 — Anti-lockout invariant incomplete: `"admin_token": ""` closes the control plane on BOTH config write paths and persists the closure (live-reproduced end-to-end, incl. restart)

- **Repro (live, real release daemon, loopback listen, valid token)**: `PUT /api/config` with body `{"admin_token": ""}` → **HTTP 200** `{"status":"ok","requires_restart":false,"message":"config updated"}`. Immediately after, the **same previously-valid token** on `GET /api/config` → **401** (every data route now 401s — the auth layer's `expected_admin_token()` filters empty to None → fail-closed for everyone, operator included). On disk, line 18 becomes `admin_token: ''`. **Restart** → still 401 with the old token: the closure survives restart exactly like attempt-1's F1, and recovery requires a hand edit of the YAML (reproduced: hand-restore + restart → 200 again).
- **Same hole on the reload path**: a config file with `admin_token: ''` → `POST /api/reload` → **200** ("config reloaded… hot-reload applied") → valid token 401. The live config is overwritten; even after fixing the disk file the running daemon stays locked until restart (a reload with the fixed file cannot be issued — the caller is 401).
- **Mechanism**: the attempt-2 guard tests `live.admin_token.is_some() && candidate.admin_token.is_none()` (api.rs:1361, and the same shape in `apply_reload` api.rs:833), but the auth layer defines "no token" as `Some("")` **or** None — `expected_admin_token(cfg) = cfg.admin_token.as_deref().filter(|t| !t.is_empty())` (api.rs:384-385, doc: "`None`/empty = the control plane is CLOSED"). `Some("")` passes the `is_none()` guard, passes exposure validation on loopback (`validate_control_plane_exposure` returns Ok for loopback before the token is ever consulted), is persisted, and closes the plane.
- **Why this blocks a PASS**: the attempt-2 pack claims "the anti-lockout invariant now holds on BOTH config write paths (reload + PUT)". The invariant — "a running secured control plane never silently closes" — is still false via the empty-string encoding, on both paths, with the same persistent-closure and hand-edit-recovery profile that made attempt-1's F1 a P1. `config edit` + `cerberus reload` is a realistic operator path into it (emptying the token string in the editor parses as valid YAML and reloads clean).
- **Pre-existing, not a regression**: the filter and both paths behave identically at `cb36c8a` (`git show cb36c8a:…api.rs` → filter at line 377; 0 hits for the new PUT guard message). Attempt 2 closed the *null* encoding and left the *empty* encoding open. The fix is small: guard on `expected_admin_token(&candidate).is_none()` (instead of `candidate.admin_token.is_none()`) in both `handle_put_config` and `apply_reload`, or reject empty tokens at the DTO/deserialize layer.
- **What is NOT broken**: fail-closed posture (no data exposure — the closure 401s everyone including the operator); rotation to a non-empty token still applies immediately; non-loopback listens reject empty tokens through exposure validation; only a valid-token holder can trigger it.

**Residuals (informational, no action)**: R3/R4 as disclosed by the builder (worker-e2e deadline margin; install/rollback not event-audited, outside the remediation list).

## 6. No-regression sweep

| Surface | Result |
|---|---|
| F6.A 5-route auth spot-check (`/api/config`, `/api/events`, `/api/allowlist`, `/api/packs`, `/api/scan` × no/wrong token) | **401/401 everywhere**; valid token → 200 (proper methods; the 404s on GET-only routes under POST are dispatch after auth) |
| Anti-rebinding (one shape) | `Host: attacker.com` → **403 pre-auth** `host not allowed (anti-rebinding allowlist)`; with valid token also 403 |
| Unauthenticated bypass | `X-Cerberus-Bypass` without token → **401**, payload refused |
| F5 structural gate | `cargo test --release --test hotpath_sync_write_gate -- --test-threads=1` → **3/3** (`hot_path_has_no_synchronous_console_writes`, `logging_module_is_non_blocking_by_construction`, `cli_main_holds_the_log_guard_for_the_process_lifetime`) |
| F2 single-parse | `load_test_json_many_leaf_context_reuse … ok` inside my 14/14 load run |
| Smoke script | **17 PASS / 0 FAIL** (incl. R9-5 fail-closed 401/401/403/bypass and zero-leak steps) |
| redos frozen rule | 0-byte diff on `tests/redos_fuzz.rs`; 11/11 release |
| Worktree integrity | `git diff --check` clean; `git status --porcelain` empty after the sanctioned mutation was reverted |

## 7. Hash check (pack's attempt-2 frozen block vs my worktree, shasum -a 256)

| File | Pack frozen | Mine | Match |
|---|---|---|---|
| `crates/cerberus-proxy/src/api.rs` | `87b13acc…d2d633b` | `87b13acc46e27ea2e26b2d876ef1f9d8c3fb212807fecad2c06b0504ad2d633b` | ✓ |
| `crates/cerberus-store/src/event.rs` | `fa7ed2f6…7c315a` | `fa7ed2f67ef3599acdef99e9b1a4e282ed4de13578c4d4eb18f0d7c02c7c315a` | ✓ |
| `crates/cerberus-proxy/src/log.rs` | `91ca5af3…a95b167` | `91ca5af3f29f2b5a0b42ea822c09058b82aa2744ab25338391c7dd115a95b167` | ✓ |
| `crates/cerberus-proxy/tests/f6b_api_surface.rs` | `acde20ce…e24a2ae` | `acde20ce13770041257398db8fd424107e5a77a1e4b85128335f38b54e24a2ae` | ✓ |
| `crates/cerberus/src/main.rs` | `1a5135b5…5103cd` | `1a5135b5c40036c56404e64b0c10b85387597cda3c7bb2494233a14de5382bbc` | ✓ |
| `crates/cerberus/src/cli_surface.rs` | `3d53830f…5103cd` | `3d53830f58a7c8bb2c284e9e25b52d12e3e4723977c14a26e9137a7f1b5103cd` | ✓ |
| `crates/cerberus/src/cli_api.rs` | `526ca2c4…536f3` | `526ca2c4f7cb3e5cb840c836b238d1a6f5366b68071a57333f0cfc16271536f3` | ✓ |
| `crates/cerberus/src/cli_pack.rs` | `50a78de1…b1a6` | `50a78de18214f489e2efb1ceb1ba1d124f3c88f09b2bf19eb917bf935e1b71a6` | ✓ |
| `crates/cerberus/tests/pack_enable_disable_worker_e2e.rs` | `a4efee9c…a4f7f` | `a4efee9cd13c7c3d3c5af8d3197940673b303b536f77092f1d75e2ea2eda4f7f` | ✓ |

**9/9 byte-identical** to the pack's frozen block. (The 10th entry, the gitignored smoke-run log, is a run artifact whose hash is per-run by nature — not reproducible by design; noted, not scored.)

## 8. Final verdict

**FAIL** (returns to FIX — one P1).

Every attempt-1 item the fix targeted is closed and independently re-verified: F1's *null* encoding is now rejected 400 on `PUT /api/config` with rotation semantics intact (live, incl. restart persistence); P2-1's audit events are honest, secret-free, filter-clean, and visible via API and CLI; F2's parity test and the table↔router cross-check both dispatch through the REAL router and both fail under my own re-executed mutation (exit 101 → revert → green); the worker e2e runs the real daemon install→disable→enable round trip; the login flake's root cause is removed (stable ×3 + inside the 862); the tee file is created 0600 (live stat); and all gates reproduce the builder's numbers exactly (fmt clean, clippy clean, **862/0**, 19/19, 14/14 incl. the honest gate, 11/11 redos byte-untouched, 69/69, 10/10, 11/11, 1/1, 17/17 smoke, hash equality 9/9).

But the fix's central claim — "the anti-lockout invariant now holds on BOTH config write paths" — is falsified by the empty-string encoding: `PUT /api/config` with `{"admin_token": ""}` (and a reload of a file with `admin_token: ''`) answers 200, immediately closes every data route (401 for the previously-valid token), persists `admin_token: ''` to disk, and the closure survives restart, with recovery requiring a hand edit — reproduced live end-to-end. This is the same defect class as attempt-1's blocking P1 (pre-existing on both paths, not introduced by this commit), and the invariant the fix claims to enforce ("a running secured control plane never silently closes") remains false. One-line follow-up (guard on `expected_admin_token(&candidate)` instead of `is_none()`, both write paths, or reject empty tokens at the DTO layer) and this can return to VERIFY with everything else already green.

---

*All commands quoted above were executed by the reviewer in the detached worktree
`/var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/f6b-attempt2-verify`; live-harness
artifacts (daemon logs, tokens, events.json) live under
`/var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/f6b-a2-live` (throwaway). The serving
daemon was stopped and 0 listeners remained. The only file created in the main repo is this report;
the one sanctioned temporary edit (mutation M1) was reverted and the worktree verified clean before
removal.*