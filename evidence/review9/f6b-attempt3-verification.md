# F6.B FIX attempt 3 — independent adversarial spot-verification

- **Candidate**: commit `44f278a` (branch `r9-remediation`, parent `ddf72c4`) — "F6.B attempt 3 — anti-lockout also rejects the empty-token encoding".
- **Claim under test**: both anti-lockout guards (`apply_reload`, `handle_put_config`) now reject the EMPTY-STRING token encoding (`Some("")`, filtered to `None` by `expected_admin_token`) in addition to `null`; closure live-reproducible on a real release daemon.
- **Method**: detached worktree at `/var/folders/…/opencode/f6b-attempt3-verify`; all gates and the live reproduction run from that worktree; throwaway daemon `HOME` under `/var/folders/…/opencode/f6b-live-home`; no code/test/threshold edits; nothing pushed; main repo touched only by this report file.
- **Toolchain**: rustc/cargo 1.97 (clippy 0.1.97 `8bab26f4f6 2026-07-14`), macOS (darwin).

## Commands run

| # | Command (verbatim) | Exit | Result |
|---|---|---|---|
| 1 | `git -C /Users/alexeirojas/Work/Personal/Cerberus worktree add --detach /var/folders/…/f6b-attempt3-verify 44f278a` | 0 | worktree at 44f278a |
| 2 | `git diff ddf72c4..44f278a --stat` | 0 | exactly 3 files: `api.rs` (+16/−6), `f6b_api_surface.rs` (+88), `evidence/f6/r9-cli-parity.md` (+38) |
| 3 | `git diff --check ddf72c4..44f278a` | 0 | no whitespace errors |
| 4 | `shasum -a 256 crates/cerberus-proxy/src/api.rs crates/cerberus-proxy/tests/f6b_api_surface.rs` | 0 | `177fedc1…c196b` / `7db05e4f…184856` — **both match the pack's attempt-3 frozen-hashes block** |
| 5 | `rtk cargo test -p cerberus-proxy --test f6b_api_surface -- --test-threads=1` | 0 | **11 passed** |
| 6 | `cargo test -p cerberus-proxy --test f6b_api_surface -- --test-threads=1 --list` | 0 | 11 tests incl. `put_config_rejects_admin_token_removal_anti_lockout` and new `reload_rejects_empty_token_file_anti_lockout` |
| 7 | `rtk cargo test --workspace --all-targets` | 0 | **863 passed** (29 suites, 57.07 s) — matches the claimed 863 (+1 vs attempt-2's 862) |
| 8 | `rtk cargo fmt --all --check` | 0 | clean |
| 9 | `cargo clippy -p cerberus-proxy --all-targets -- -D warnings` | **101** | **FAIL — 2 errors** (detail under Findings) |
| 10 | baseline at parent `ddf72c4` (own worktree): same clippy command | 0 | clean → both errors are **introduced by attempt 3** |
| 11 | `cargo clippy -p cerberus-proxy --lib -- -D warnings` | 0 | clean → failure is confined to the test target |
| 12 | `cargo build --release -p cerberus-proxy` / `-p cerberus` | 0 | release daemon binary built |
| 13 | `cargo test -p cerberus-proxy --test smoke_harness` | 0 | **69 passed** |
| 14 | `cargo test -p cerberus-hardening --test hotpath_sync_write_gate` | 0 | **3 passed** |
| 15 | `cargo test -p cerberus-packs --test production_pack_pr` | 0 | **19 passed** |
| 16 | live daemon: `HOME=<throwaway> ./target/release/cerberus start -p 18971` + curl checks (a)–(e) below | 0 | see next section |
| 17 | `git worktree remove --force …` (both verification worktrees) | 0 | cleaned up |

## Live closure results (real release daemon, isolated `$HOME`, port 18971, token `live-secret-token-0123456789abcdef`)

**(a) Empty-string PUT — CLOSED ✅**
- `PUT /api/config` body `{"admin_token":""}` with valid token → **HTTP 400**, body: `"config update would remove or clear the admin token and CLOSE the control plane (fail-closed)…"`.
- `GET /api/config` with old token immediately after → **200**; `/health` → **200**.
- On-disk `config.yaml` unchanged — still `admin_token: live-secret-token-0123456789abcdef`.

**(b) Null PUT (attempt-2 case) — still CLOSED ✅**
- `PUT /api/config` body `{"admin_token":null}` → **HTTP 400**, same "remove or clear" message; old token → **200**; disk unchanged.

**(c) Empty-token file + reload — CLOSED ✅**
- On-disk file rewritten to `admin_token: ''` (operator hand-edit class) → `POST /api/reload` → **HTTP 400**: `"reload would remove or clear the admin token and CLOSE the control plane…"`.
- Plane still authenticates with the OLD token: `GET /api/config` → **200**. Refused reload did not swap the live config.

**(d) Rotation — INTACT ✅**
- `PUT` with a NEW non-empty token → **200** (`"config updated"`); old token → **401**; new token → **200**; disk persisted `admin_token: rotated-live-token-fedcba9876543210`.

**(e) Whitespace edge (documented, not fixed) — NOT SAFE ⚠️**
- `PUT /api/config` body `{"admin_token":"   "}` (3 spaces) → **HTTP 200, accepted** — the guard passes it because `expected_admin_token` filters only `is_empty()` (api.rs:384-386), not whitespace.
- Consequences, live-proven: previous token → **401** (rotated away); whitespace token via `X-Cerberus-Admin-Token:    ` → **401**; via `Authorization: Bearer    ` → **401**; disk persisted `admin_token: '   '`. The control plane is **API-closed**: no credential works. Mechanism: `authorized()` (api.rs:392-402) trims the *header* value but compares against the *untrimmed expected* token, and hyper strips surrounding OWS anyway — a whitespace-only or whitespace-padded expected token is unmatchable by construction.
- Restart persistence: the whitespace token sits in `config.yaml`; recovery requires manual file edit + daemon restart (verified: after edit + restart, `GET /api/config` → **200**). Operator-recoverable, but the invariant "PUT/reload cannot close the plane" is violated by this encoding.
- Realistic variant also live-proven: `PUT {"admin_token":"abc "}` (trailing-space paste accident) → **200**, then header `abc` → **401** and header `abc ` → **401** — same lockout.

## Findings

**P1 — clippy `-D warnings` gate is RED on attempt-3-introduced test code, and the evidence pack's "clippy clean" claim is false.**
`cargo clippy -p cerberus-proxy --all-targets -- -D warnings` exits 101 with exactly two errors, both in code added by 44f278a:
1. `clippy::let_underscore_future` — `crates/cerberus-proxy/tests/f6b_api_surface.rs:696` (`let _ = handle;` in the new `reload_rejects_empty_token_file_anti_lockout` test; the only such occurrence in the file).
2. `clippy::too_many_lines` (117/100) — `crates/cerberus-proxy/tests/f6b_api_surface.rs:707`, `put_config_rejects_admin_token_removal_anti_lockout` grew past the 100-line pedantic limit with the added empty-string block (`clippy::pedantic` is denied at workspace level, root `Cargo.toml:44`).

Attribution is clean: the identical clippy command on parent `ddf72c4` exits 0 with the same toolchain (clippy 0.1.97), so this is a regression of the commit, not an environment artifact. The unit's own verification matrix (r9-cli-parity.md lines 114/345) declares `cargo clippy --workspace --all-targets -- -D warnings` a gate, and the attempt-3 addendum (line 437) claims "clippy `-D warnings` clean" — that claim does not hold. Product code is unaffected (`--lib` run is clean); the fix is confined to the new test code (await/drop the handle, split the test or add a scoped allow), plus an evidence correction.

**P2 — the anti-lockout invariant is still bypassable via whitespace-encoded tokens (live-proven, see (e)).**
Same invariant class as the null/empty-string P1 that attempt 3 closes, one encoding deeper: the guards consult `expected_admin_token`, which filters only the empty string, while `authorized()` trims header input — so a whitespace-only candidate is accepted (400-invariant violated) and any leading/trailing-whitespace candidate becomes live, persisted, and unusable from any header (plane API-closed until manual file edit + restart). Harder to trigger accidentally than the empty string but the trailing-space paste shape is plausible. Suggested direction for a future attempt (not applied): trim candidate tokens before storing/validating and reject whitespace-only values on both write paths. Per instructions this was judged and noted only.

**No other findings.** The diff is surgical (3 files; predicate change only in product code); both frozen hashes match; `git diff --check` clean; the test list is exactly 11 with both anti-lockout tests present; workspace count matches the claim (863).

## Final verdict

**FAIL** — with a precise scope:
- The **functional gap attempt 3 targets is genuinely closed**: empty-string and null are rejected on both write paths with the plane and disk left intact (a–d live-proven on a real release daemon), rotation intact, all 863 workspace tests / 11 f6b / 69 smoke / 3 hotpath / 19 pack green, hashes match, nothing else moved.
- But a **required gate of the unit's own declared verification matrix is red** (clippy `-D warnings`, 2 errors introduced by this commit) **and the evidence pack asserts it is clean** — under the Gauntlet ("no work closed without a PASS Evidence Pack"; evidence must be true) this blocks closure regardless of how trivial the repair is.
- Additionally, the whitespace encoding (e) leaves the same lockout invariant open — noted as P2 for the panel to schedule, not a blocker for *this* attempt's claim.

**Required to close**: fix the two lints in `f6b_api_surface.rs` (attempt-3-added test code only), re-run `cargo clippy --workspace --all-targets -- -D warnings` for a genuine clean, correct the attempt-3 evidence claim (or supersede with an attempt-4 block), and decide the disposition of the P2 whitespace class.
