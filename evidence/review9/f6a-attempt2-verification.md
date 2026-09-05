# F6.A — Independent Adversarial Re-Verification — FIX attempt 2 (P1 + P2 closures)

- **Unit**: F6.A — fix attempt 2 (closes attempt-1 P1 + P2s + security-lens P2-1/P3-1; fix-plan F6.1 session-scoped credential)
- **Candidate**: commit `2b59547` on `r9-remediation` (parent `40283eb`) · 6 files, +504/−42
- **Reviewer**: independent adversarial re-verifier (did not build; verifying the fix attempt, hunting regressions from the fix itself)
- **Date**: 2026-09-02 · Host: macOS arm64 (darwin) · rustc/clippy 1.97.1 · release build `target/release/cerberus`
- **Method**: §8B — all gates re-run in a detached worktree at `2b59547`; every closure reproduced **live** against the release binary (isolated `$HOME`s, ports 18801–18805, all reviewer daemons stopped afterwards). "Couldn't run" = FAIL respected: nothing was skipped.

---

## 1. Commands run (verbatim, exit codes)

| # | Command | Exit | Result |
|---|---|---|---|
| 1 | `git -C /Users/alexeirojas/Work/Personal/Cerberus worktree add --detach /var/folders/…/opencode/f6a-attempt2-verify 2b59547` | 0 | worktree created at `2b59547` |
| 2 | `git diff --stat 40283eb..2b59547` | 0 | 6 files, +504/−42 (matches pack) |
| 3 | `rtk cargo fmt --all -- --check` | 0 | clean |
| 4 | `rtk cargo clippy --workspace --all-targets -- -D warnings` | 0 | 0 warnings ("No issues found") |
| 5 | `rtk cargo test --workspace --all-targets` | 0 | **810 passed** (26 suites, 53.33 s) — matches builder claim exactly |
| 6 | `rtk cargo test -p cerberus-packs --test production_pack_pr` | 0 | **19/19** |
| 7 | `rtk cargo test -p cerberus-proxy --test smoke_harness` | 0 | **69/69** |
| 8 | `cargo test --release --test load_test -- --test-threads=1` | 0 | **14/14** incl. `load_test_f3_3_honest_http_round_trip_gate ... ok` (7.54 s) |
| 9 | `rtk cargo test --release --test redos_fuzz -- --test-threads=1` | 0 | **11/11**; `git diff 40283eb..2b59547 -- tests/redos_fuzz.rs \| wc -c` = **0 bytes** (rule untouched) |
| 10 | `rtk cargo build --release -p cerberus` | 0 | release binary for the live battery |
| 11 | `bash tests/smoke-test.sh --port 18977` then `--port 18978` (release binary, script-managed isolated HOME) | 0 | **17/17 PASS, Fail: 0**; second run for clean exit-code capture (`SMOKE_EXIT=0`; first run's exit was obscured by the script's own daemon-cleanup job notices — output identical both runs) |
| 12 | `git diff --check` and `git diff 40283eb..2b59547 --check` | 0 / 0 | clean (whitespace/conflict markers) |
| 13 | `shasum -a 256 <5 changed files>` | 0 | **5/5 match** the pack's attempt-2 frozen block (§6) |
| 14 | `HOME=$F6A2 …/cerberus init` (isolated HOME) | 0 | config.yaml **100600**; report "mode 0600, R9-5"; token not printed |
| 15 | live battery (curl against release daemons, ports 18801–18805) | 0 | see §2/§3 |
| 16 | `kill` of all reviewer daemons + port sweep `lsof -ti :1880x` | 0 | 0 listeners remain |

Process note (recorded honestly): the verification shell is zsh; the first gate pass used bash-style `${PIPESTATUS}` which silently degraded, so **every gate was re-run with output redirected to a file and `$?` captured directly** — the exit codes above are the second-pass values (counts identical between passes).

## 2. Per-item closure table

| Item (attempt-1 finding) | Closure claim | Reproduction outcome | Verdict |
|---|---|---|---|
| **P1** — `persist_config` regressed config.yaml 0600→0644 on control-plane writes (admin-token-carrying file world-readable) | shared helper `write_config_file_0600` + `write_tmp_0600` (api.rs:847/867), `create_new(true).mode(0o600)` at creation, atomic rename; `persist_config` delegates | **LIVE, decisive**: init → `100600`; `PUT /api/config` (token, 200) → `stat` = **`100600`** immediately (attempt 1: `100644`). Every other persist path: `POST /api/allowlist` 200 → `100600`; `POST /api/upstreams` 200 → `100600`; `DELETE /api/upstreams/test-up` 200 → `100600`; `PUT /api/policy` 200 → `100600`. Zero `<path>.tmp` residue in the tree after the battery. New tests green: `persist_config_keeps_0600_on_an_existing_file`, `persist_config_creates_the_file_at_0600`, live-flow `config_put_persists_yaml_at_0600` | **CLOSED** |
| **P2** — `atomic_write_config` (migration persist) wrote the tmp at umask default before chmod | delegates to the SAME shared helper (daemon.rs:216) | Code read confirms one-writer discipline; `atomic_write_config_enforces_0600_on_result` green; **LIVE migration**: 0644 legacy fixture → after migration boot **`100600`** (mode repaired by the persist), raw destroyed, fingerprints persisted | **CLOSED** |
| **P2-1** (security lens) — re-init over non-0600 config kept 0644 and the report falsely claimed "mode 0600" | init `write_config_0600` → shared tmp+rename helper (re-init REPLACES the file); report mode now stat-derived (`actual_mode_note`) | **LIVE**: `chmod 644 config.yaml` (→ `100644`) → `cerberus init` → **`100600`** and report prints "(mode 0600, R9-5)" — the file **IS** 0600, the claim is truthful. Token rotated (old ≠ new); after restart old → **401**, new → **200**. Running daemon kept the old in-memory token (200) = documented non-hot-reload, by design. `reinit_over_non_0600_config_enforces_0600_and_tells_the_truth` green | **CLOSED** |
| **P2** (fix-plan F6.1) — dashboard stored the admin token in `localStorage` | all four sites switched to `sessionStorage`; CSP self-adapts (derived from served HTML) | Served `/api/dashboard` (70,365 B): `localStorage.` API calls = **0**; `sessionStorage` = 5 hits; no `document.cookie`/`indexedDB` channels. **CSP re-verified by recomputation**: sha256 of the served `<script>` block = `sha256-bDSrSEcBaqJ9cZ+4en4PJd+zv/XynCnRAf5llZAijZk=` = CSP `script-src` value **exactly** (style hash also recomputed and matching) — the served page and the CSP authorize the *same* edited script. Token dies with the tab = the intended plan trade | **CLOSED** |
| **P3-1** (security lens) — malformed JSON on authenticated `POST /api/upstreams` dropped the connection (curl HTTP=000) | parse arm returns 400 via `invalid_config_response` | **LIVE**: `{invalid json here` → **400** `{"status":"error","error":"invalid upstream payload: key must be a string at line 1 column 2"}`; attempt-1 repro shape `{}` → **400** `…missing field 'name'…`; `not-json-at-all` → **400** JSON. Connection survives (three consecutive requests on the same daemon). Harness `upstream_post_malformed_json_answers_400_not_connection_drop` green | **CLOSED** |

## 3. New-hole hunt (attacks on the fix itself)

| Vector | Probe | Outcome |
|---|---|---|
| **umask window on the tmp** (is the tmp itself 0600 at creation?) | daemon rebooted under `umask 000` (`(umask 000; cerberus start …)`) — any plain `fs::write` would produce 0666 | `PUT /api/config` 200 → **`100600`**. Code read: `write_tmp_0600` = `OpenOptions::write(true).create_new(true).mode(0o600)` then `write_all` — creation-time mode is the *only* mechanism (no post-hoc chmod exists in the helper), so a plain write under any umask could not have produced 0600. **No umask window** — proven empirically and structurally |
| **TOCTOU on the tmp** (attacker plants a symlink at `<path>.tmp` between `remove_file` and `open`) | code analysis | `create_new(true)` = `O_CREAT\|O_EXCL`, which on unix **fails with EEXIST rather than following a symlink** — the race cannot yield a symlinked tmp. The tmp lives in the operator's own `.cerberus` dir, so an attacker who could win the race already has the privilege to replace `config.yaml` directly; no boundary is crossed. **No hole** |
| **Stale-tmp leak** (leftover tmp from a crash carrying token bytes) | planted `config.yaml.tmp` at 0644 containing canary `STALE-TMP-LEAK-CANARY-1234567890` → next PUT | tmp **removed** at the next write (exclusive re-create, never reused); canary grep over the tree = **0 hits**; config at `100600`. Removal is best-effort (`let _ = remove_file`) — see Finding N-1 (wording, not a hole) |
| **Symlinked config.yaml** (claimed semantic delta: "replaced rather than written through") | `config.yaml` → symlink → `target.yaml`; marker + sha256 snapshot of target; PUT | After PUT: `config.yaml` = **Regular File, 100600** (symlink destroyed by the rename); `target.yaml` sha256 **identical** before/after (`79bbb08f…` both) — zero write-through. **Judgment: strictly safer.** Attempt-1's in-place truncate followed the link, so a planted symlink would have received the credential write (classic symlink-attack primitive against e.g. `~/.ssh/authorized_keys`); rename semantics make that unreachable. Cost: a deliberately symlinked config is silently unlinked — operationally minor for a single-user pre-start credential file, noted as accepted in the pack (risk §2) |
| **Regression sweep** — attempt-1 security core | auth matrix 5 routes (`GET /api/events`, `GET /api/config`, `GET /api/policy`, `GET /api/stats`, `POST /api/upstreams`) × no/wrong/valid token | **15/15 correct**: no-token → 401, wrong-token → 401, valid → 200 on every route |
| **Regression sweep** — rebinding | `Host: attacker.com` + valid token → | **403** pre-auth, unchanged |
| **Regression sweep** — bypass (F4 vector) | data-plane `X-Cerberus-Bypass: 1` **unauthenticated** + detectable secret (`AKIA…` shape, non-allowlisted) | **403 BLOCK** (`{"error":"blocked","flag":"secret.aws_access_key_id"}`) — bypass refused, payload not forwarded; control without bypass header → 403 likewise; bypass + valid `X-Cerberus-Admin-Token` → honored (503 = egress-blocked sandbox, same shape attempt-1 recorded). Semantics unchanged |
| **Regression sweep** — frozen rules | `git diff 40283eb..2b59547 -- tests/redos_fuzz.rs` = 0 bytes; attempt-1 frozen hashes spot-checked on unchanged files (`engine.rs`, `proxy.rs`, `host_origin.rs`) | all match the attempt-1 frozen block; redos 11/11 |

## 4. Findings

**No P0. No P1. No P2.**

- **N-1 (P3, wording only)** — the pack says a stale tmp is "removed before the exclusive create (loudly, no silent reuse)". The removal is best-effort and **silent** (`let _ = std::fs::remove_file(&tmp)` — no log line); "no silent reuse" is accurate (the tmp is never reused — it is removed then exclusively re-created at 0600). The security property holds fully; only the word "loudly" overstates. No action required; fix the wording whenever the pack is next touched.
- **N-2 (P3, informational)** — a literal grep of the served dashboard HTML for `localStorage` finds **1 hit inside the explanatory comment** ("(localStorage survived browser restarts)"). Zero `localStorage.` API calls exist (the operative claim, which is true). No security impact; noted so future grep-based audits match on code, not prose.

## 5. Final verdict

**PASS.** All five fix items are closed and reproduced empirically, not just asserted: the decisive P1 check (init → start → PUT /api/config → stat) yields **100600**, and every persist path (config, policy, allowlist, upstream add/delete) plus a umask-000 adversarial boot keeps the credential file at 0600 with no tmp window and no residue; the migration persist repairs a regressed 0644 file through the same helper; re-init now repairs the mode and its report is truthful (file IS 0600) with rotation invalidating the old token after restart; the dashboard serves a sessionStorage-only credential whose CSP sha256 matches the served script byte-for-byte by independent recomputation; and malformed JSON now answers 400 JSON instead of dropping the connection. The new-hole hunt found no exploitable gap — the tmp is created 0600 (O_EXCL refuses symlink plants), stale tmps are removed without leaking their bytes, and the symlink semantic delta is strictly safer than attempt-1's write-through. The full gate matrix reproduces the builder's numbers exactly (fmt clean; clippy 0 warnings; workspace 810/810; pack 19/19; load 14/14 release-serial incl. the honest HTTP gate; smoke harness 69/69; smoke script 17/17; redos 11/11 byte-untouched; `git diff --check` clean) and the five changed files match the pack's frozen SHA-256 block exactly. Attempt-1's security core shows zero semantic movement (auth matrix, rebinding, bypass, frozen rules). Two P3 wording-level notes registered, neither blocking. **F6.A may proceed to phase-gate sign-off.**

---

*Report by the independent re-verifier; all commands executed in detached worktree `/var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/f6a-attempt2-verify` (removed after verification); the only file created in the main repo is this report.*
