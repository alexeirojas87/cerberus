# F6.B — Independent Adversarial Verification — SECURITY lens (attempt 1)

- **Unit**: F6.B — R9-6: Appendix B CLI surface + API→CLI→dashboard parity matrix (~26 new CLI commands, new API endpoints: `packs enable/disable/update`, `POST /api/reload`, `POST /api/scan`, log tee, dashboard controls)
- **Candidate**: commit `079ebf8` on `r9-remediation` (parent `be6b6ff`) · 22 files, +4811/−327
- **Reviewer**: independent adversarial verifier, SECURITY lens (did not build; blind to the correctness-lens report)
- **Date**: 2026-09-02 · Host: macOS arm64 (darwin) · release build `target/release/cerberus`
- **Method**: §8B — all gates + a live adversarial battery against a real release daemon (isolated `$HOME`, port 18811, token-authenticated). Security core under protection: fail-closed auth, anti-rebinding pre-auth, token-gated bypass, HMAC-only allowlist, 0600 credential files. "Couldn't run" = FAIL respected.

---

## 1. Commands run (verbatim, exit codes)

| # | Command | Exit | Result |
|---|---|---|---|
| 1 | `git worktree add --detach …/opencode/f6b-attempt1-security 079ebf8` | 0 | worktree at `079ebf8` |
| 2 | `git diff --stat be6b6ff..079ebf8` | 0 | 22 files, +4811/−327 (matches pack) |
| 3 | `rtk cargo clippy --workspace --all-targets -- -D warnings` | 0 | **0 warnings** |
| 4 | `rtk cargo test --release --test redos_fuzz -- --test-threads=1 --nocapture` | 0 | **11/11** |
| 5 | `git diff be6b6ff..079ebf8 -- tests/redos_fuzz.rs \| wc -c` | 0 | **0 bytes** — frozen rule byte-untouched |
| 6 | `rtk cargo test -p cerberus-proxy` | 0 | **293 passed (4 suites)** |
| 7 | `rtk cargo test -p cerberus` | **101** | **1 FAILED**: `cli_surface::tests::login_verifies_and_installs_signed_license` (`assertion failed: dest.exists()`, cli_surface.rs:1200); 93 passed |
| 8 | `cargo test -p cerberus --bin cerberus cli_surface::tests::login_verifies_and_installs_signed_license -- --exact` | 0 | passes in isolation |
| 9 | `cargo test -p cerberus` (full re-run) | 0 | **118 passed (0 failed)** — 94+11+2+4+3+4 |
| 10 | `rtk cargo test -p cerberus-packs --test production_pack_pr` | 0 | **19/19** |
| 11 | `rtk cargo build --release -p cerberus` | 0 | release binary |
| 12 | `HOME=$SEC_HOME cerberus init` | 0 | config.yaml **100600**; 64-char token generated |
| 13 | `HOME=$SEC_HOME nohup cerberus start --port 18811` + `/health` | 0 | daemon healthy (enforce, 2 upstreams) |
| 14 | auth matrix: 22 routes × {no/wrong/valid token} via `curl -w %{http_code}` | 0 | see §3a |
| 15 | dashboard CSP/leak probes + `python3` sha256 recompute of served `<script>`/`<style>` | 0 | hashes match CSP exactly |
| 16 | anti-rebinding regression: `curl -H "Host: attacker.com" …` | 0 | **403** pre-auth, unchanged |
| 17 | logs-tee battery (dataplane detection, token/raw-canary greps, endpoint probing, CLI `logs`) | 0 | see §3b |
| 18 | `cerberus packs list` / `cerberus packs update` (live, Free tier) | 0 / 1 | update aborts via Pro gate (exit 1 = gate fired) |
| 19 | reload battery: token-removal / broken YAML / bad policy / token rotation / allowlist removal + `GET /api/events` audit check | 0 | see §3d |
| 20 | `cerberus login --file` (tampered license) | 1 | **rejected**, nothing installed |
| 21 | scan battery: 10 MB body, 954 KB body, malformed JSON, persistence check | 0 | see §3f |
| 22 | CLI token battery: unreachable-daemon error, `--help`, `version`, failing command, `config show` | 0 | token never printed; redaction live |
| 23 | `cargo test --release --test load_test -- --test-threads=1` | 0 | **14/14** incl. `load_test_f3_3_honest_http_round_trip_gate … ok` |
| 24 | `git status --porcelain` (worktree) | 0 | clean — zero reviewer modifications |
| 25 | `git worktree remove --force …/f6b-attempt1-security` | 0 | worktree removed; 0 listeners remained (`lsof :18811` = empty) |

## 2. Per-criterion verdicts

| Criterion | Verdict | Evidence |
|---|---|---|
| Gate 1 clippy `-D warnings` | **PASS** | exit 0, no output |
| Gate 2 redos 11/11, byte-untouched | **PASS** | 11 passed; 0-byte diff on `tests/redos_fuzz.rs` |
| Gate 3 `-p cerberus-proxy` / `-p cerberus` | **PASS w/ finding** | proxy 293/293; cerberus **flake** — run 1 failed (exit 101), run 2 passed 118/118, passes isolated → P2-2 |
| Gate 4 packs PR 19/19 | **PASS** | 19 passed |
| 5a new-endpoint auth funnel | **PASS** | all 20 data routes 401/401 (no/wrong token); funnel order anti-rebind → auth → dispatch read in `handle_api_request` (api.rs:560–640) |
| 5b logs tee | **PASS w/ P3** | token/raw canaries absent live; no `/api/logs*` route (401/404); CLI reads fixed local path, no params; 8 MiB cap + rotation unit-tested (`tee_sink_rotates_at_the_cap`); file mode **0644** → P3-1 |
| 5c updater SSRF/TOCTOU | **PASS** | `verify_installed`+`rebuild_active_set` local-only; the crate's lone reqwest dep (telemetry.rs) has **zero callers**; rebuild re-verifies signatures **from disk** before rules enter the engine → TOCTOU closed |
| 5d reload guard | **PASS w/ P2** | token-removal → 400 (live); broken YAML/bad policy → 400, live untouched; rotation applies immediately (old 401/new 200); host-origin policy boot-frozen (cannot be weakened); **no audit event/log for reload** → P2-1 |
| 5e login | **PASS** | no `/api/login` route; CLI login fails closed without trust root; tamper rejected, nothing installed; mints nothing (local verify+install 0600); no brute-force surface |
| 5f scan | **PASS** | 10 MB → **413 in 6 ms**; 954 KB → 200 in 38 ms; nothing persisted (events unchanged); raw never echoed (keyed `hmac:` only); oracle is admin-only (R9-7 residual, documented) |
| 5g CLI token handling | **PASS** | token only ever in a request header; unreachable-daemon error, `--help`, `version`, failing commands: 0 token occurrences (grep, live); `config show` → `***redacted***` |
| 5h dashboard legs | **PASS** | all new controls via `sendJson` (session token, same-origin); DOM built with `textContent`/`replaceChildren`; **0 `innerHTML` in file**; CSP recomputation: script sha256 `3c00816e…` = CSP `PACBbqUi…` byte-exact; no unsafe-inline |
| 5i honest gate | **PASS** | load_test 14/14 release-serial incl. honest HTTP round-trip gate |

## 3. Live attack battery (real daemon, release, token-authenticated, port 18811)

### a. New-endpoint auth matrix — FAIL-CLOSED INTACT

All 22 `known_api_routes()` entries probed live:

| Route class | no token | wrong token | valid token |
|---|---|---|---|
| 20 data routes (config, events, stats, allowlist×3, break-glass, policy×2, upstreams×2, packs×6, **reload**, **scan**) | **401** | **401** | 200 or 400 (body-validation only) |
| `GET /api/dashboard` | 200 (public shell by design — zero inline data: 0 `action_taken`/`hashed_values`/`hmac:` matches) | 200 | 200 |
| `GET /ui` | 302 (empty body, CSP `default-src 'none'`) | 302 | 302 |

Router order verified in source: `anti_rebinding_gate` runs **first** (403 before auth), then `auth_gate` on every `/api/*` except dashboard/`/ui`, then dispatch. Regression: `Host: attacker.com` + valid token → **403** `{"error":"forbidden","detail":"host not allowed (anti-rebinding allowlist)"}`. Bearer also accepted on new routes (constant-time compares). Malformed JSON on the new endpoints → 400 JSON, connection survives (P3-1 class not reintroduced).

### b. Logs tee — no secret leakage; bounded

- Drove a real dataplane detection (`OPENAI_API_KEY=sk-abc123…` → 403 block) and `POST /api/scan` with canaries.
- **Log grep: admin token = 0 hits; raw canaries = 0 hits.** The teed security event contains only `event_type / action_taken / finding_count / flags / categories / hashes` — hashes are `hmac:` keyed fingerprints. Console+file both verified via `cerberus logs`.
- **No HTTP logs surface**: `/api/logs`, `/api/logs/follow`, `/api/logs?path=../../etc/passwd` → 401 unauth / 404 with token. CLI `logs [-f]` reads the fixed path `~/.cerberus/logs/cerberus.log` (`log_file_path()`); no user-controlled path reaches the reader — no arbitrary-file-read vector.
- **Cap**: `LOG_FILE_MAX_BYTES = 8 MiB`, one-shot rotation to `cerberus.log.1` (overwrite), size resumed from metadata; total footprint bounded ≈16 MiB; rotation unit-tested; writes stay on the logging worker (R9-10 hot-path guarantees untouched — gate tests pass unmodified).
- **P3-1**: tee file is created 0644 (default umask via `OpenOptions::create(true).append(true)`) while the repo's discipline for `.cerberus` files is 0600. Content is designed secret-free (verified live), so this is defense-in-depth only.

### c. Updater (packs update) — no SSRF; TOCTOU closed

- Static: `PackManager::verify_installed` and `rebuild_active_set` perform local signature verification and manifest rebuild only. The sole reqwest dependency in `cerberus-packs` is `telemetry.rs`, which has **zero callers** in the workspace — unreachable from enable/disable/update. No URL parameter is accepted by any new route; registry fetch remains F7 (documented).
- Live: `cerberus packs update` (Free tier) → `400 pack update aborted via control plane: rule packs require a Pro license` — Pro gate fires through the API path.
- **TOCTOU (verify↔reload)**: `verify_installed` checks in-memory signatures, but the engine rebuild re-reads pack JSON **from disk and re-verifies each signature** (`extract_with_root(root)` → deactivate on failure, api/updater paths). Tampered disk content between verify and rebuild cannot enter the engine — the authoritative gate sits at load time. Closed structurally.

### d. Reload guard — anti-lockout holds; atomic on failure; audit gap found

- Token-removing file → **400** `reload would remove the admin token and CLOSE the control plane (fail-closed)`; control plane still authenticated after (200).
- Broken YAML and invalid policy → **400**, live config verified untouched after each failure (compile happens **before** the swap, inside the write lock — no half-applied state).
- Token **rotation** → 200; old token **401 immediately**, new token 200 (the auth gate reads the live config).
- Operator-power vector: a valid-token reload **can** remove allowlist entries and swap upstreams (applied on disk exactly). Per plan this is operator power — but it is **not audited**: `GET /api/events` after all mutations showed only dataplane `proxy` events; `apply_reload` emits no event and no log line → **P2-1**.
- Note (safe direction): reload does not rebuild the boot-frozen host-origin policy — anti-rebinding cannot be weakened via reload.

### e. Login — local issuer, fails closed, mints nothing

- No `/api/login` HTTP route exists (401 unauth → 404 with token; never dispatched).
- CLI `login --file`: tampered/fake license → `license rejected: … no trust root configured`, exit 1, **nothing installed** (no 0600 file written on failure; good-license-preserved behavior unit-tested). Nothing long-lived is minted by the command: it verifies an operator-supplied signed license with the daemon's trust root and installs it 0600. No credential-guessing surface exists (public-key verification of a local file) → rate limiting not applicable; no auth oracle.

### f. Scan — bounded dry-run, not a public oracle

- Auth-gated (401/401 in matrix). **10 MB body → 413 in 6 ms** (`CONTROL_PLANE_MAX_BYTES = 1 MiB`, `Limited` collector); 954 KB → 200 in 38 ms (no CPU pathology). Divergence vs the plan's "100 KB scan budget": the cap is the shared 1 MiB control-plane limit, not a scan-specific 100 KB budget (P3 note; empirically bounded either way).
- **Nothing persisted**: `/api/events` count unchanged after scans (shadow and enforce); response carries `flags/counts/action/hashed_values` only — raw input never echoed (verified with `SuperSecretCanaryXYZ-98765` → `hmac:f35aa539…`).
- **Fingerprint-oracle judgment (R9-7 residual)**: a valid-token holder can submit candidate text to `/api/scan`, receive its per-install keyed HMAC, and compare against allowlist fingerprints from `GET /api/allowlist` — i.e. an active allowlist-membership probe. This power is **admin-token-gated end-to-end** and is the same power the token-gated dataplane bypass already grants; it is NOT reachable unauthenticated (scan 401s; HMAC key is per-install, never served). Residual documented per R9-7 — no new exposure beyond the admin's existing powers.

### g. CLI token handling — no leak surface

Code: token resolved from env > config, attached only as `X-Cerberus-Admin-Token` header; error constructors (`unreachable_error`, `missing_token_error`, HTTP-error mapper) interpolate only base URL, status, and the daemon's `error` field — never the token; `ApiClient` has no `Debug` derive. Live: unreachable-daemon error, `--help`, `version`, failing commands — 0 token occurrences; `config show` prints `admin_token: ***redacted***`; allowlist display prints truncated fingerprints only (`hmac:76ccb9624728…`), raw value grep = 0 hits (R9-7 held).

### h. Dashboard legs — v6 XSS rule held

New Enable/Disable/Update/Test-Detection controls all call `sendJson` (same-origin relative paths, session token header, 401 → re-auth). All rendering via `el()/textContent/replaceChildren`; `setMsg` uses `textContent`; **`innerHTML` count in the whole served file: 0**. CSP recomputed from the served bytes: script `sha256-3c00816e…` and style `sha256-b4618a7f…` match the CSP header values byte-for-byte; no `unsafe-inline`; `no-store` + `X-Frame-Options: DENY` present. Scan result box renders counts only — user input is never reflected as HTML.

### i. Frozen surfaces

`tests/redos_fuzz.rs` 0-byte diff; honest-gate load test 14/14 release-serial; anti-rebinding/401/bypass core reproduced unchanged (§3a).

## 4. Findings

**No P0. No P1.**

- **P2-1 — control-plane mutations (reload) are unaudited.** `POST /api/reload` (new surface) swaps the entire live config — allowlist entries, upstreams, mode — with only a valid token required, and emits **no audit event** (event store shows only dataplane `proxy` events) and **no log line** (`apply_reload` has no tracing call; pack enable/disable/update and install do log to the tee). The same gap predates F6.B for `PUT /api/config` and allowlist CRUD, but reload concentrates the power and is new. Remediation: emit an audit event (e.g. `event_type: control_plane.reload`) + a tee log line on reload/config/pack mutations. Security core unaffected (fail-closed intact); plan-compliance gap — recommend closing before phase-gate.
- **P2-2 — flaky test: `login_verifies_and_installs_signed_license`.** Failed once in the full `-p cerberus` run (exit 101, `assertion failed: dest.exists()`), passed on full re-run (118/118) and in isolation. Builder's pack claims a crate-wide `ENV_LOCK`; every env-mutating test site audited does take it, so the likelier mechanism is `temp_home()`'s nanosecond-timestamp directory names (`cli_surface.rs:984`, `cli_api.rs`): two tests landing on the same clock tick share a directory, and a sibling's `remove_dir_all(&home)` deletes the login test's home mid-run — matching the observed signature exactly (login reported "installed", the file then vanished). Nondeterministic gates undermine the gauntlet; recommend unique temp dirs (`.random_suffix`) or per-test cwd. Not a product-code security defect.
- **P3-1 — log tee file created 0644** (`~/.cerberus/logs/cerberus.log`). Content verified secret-free (flags/categories/keyed hashes only; token and raw canaries absent live), but 0600 would match the repo's credential-file discipline. One-line hardening in `TeeSink::open`.
- **P3-2 — scan body cap is the shared 1 MiB control-plane limit**, not the plan's 100 KB scan-specific budget. Empirically bounded (10 MB → 413 in 6 ms; 954 KB → 38 ms; linear scan); no amplification. Document or add the scan-specific cap in a follow-up.
- **R9-7 residual (informational, by design)**: `/api/scan` + `GET /api/allowlist` compose into an admin-only allowlist-membership probe (§3f). Not reachable unauthenticated; per-install keyed HMAC; same power as the token-gated bypass. Documented, no action.

## 5. Final verdict

**PASS.** Every new surface added by F6.B sits behind the F6.A security core and the core itself shows zero semantic movement under live attack: all 22 routes fail closed (401 on missing and wrong token, verified against a real release daemon), the anti-rebinding gate still 403s a rebinding Host pre-auth, the reload endpoint refuses to remove the admin token (400, live), applies atomically on every failure path (broken YAML and bad policy left the live config untouched), applies token rotation immediately (old 401/new 200), and cannot weaken the boot-frozen host allowlist; `packs update` performs local signature verification with the rebuild re-verifying disk content before any rule reaches the engine (TOCTOU closed), the only HTTP client in the packs crate is unreachable dead code, and the Pro gate fired live; the log tee leaks neither the admin token nor raw values (flags/categories/keyed hashes only), exposes no HTTP path-trick surface, and is bounded at 8 MiB with unit-tested rotation; `login` fails closed without a trust root and mints nothing; `/api/scan` is auth-gated, bounded (413 at 10 MB in 6 ms), persists nothing, never echoes raw input, and its fingerprint-oracle residual is admin-only per R9-7; the CLI never prints the token anywhere I could make it; and the dashboard's new legs are CSP-hash-exact with zero `innerHTML`. Gates reproduce the builder's numbers (clippy clean, redos 11/11 byte-untouched, proxy 293, packs 19/19, load 14/14 incl. the honest gate) with one exception honestly recorded: a single nondeterministic test flake in the cerberus crate (failed once, passed on re-run and isolation — P2-2, test infrastructure, not product code). Two P2s (unaudited reload power; flaky test) and two P3s are registered as remediation items; none creates an attack path or weakens fail-closed auth, anti-rebinding, token-gated bypass, or the HMAC-only allowlist. **F6.B may proceed to phase-gate sign-off with P2-1/P2-2 scheduled for remediation.**

---

*Report by the independent security-lens verifier; all commands executed in detached worktree `/var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/f6b-attempt1-security` (removed after verification; reviewer daemons stopped, 0 listeners remained). The only file created in the main repo is this report.*
