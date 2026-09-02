# F6.A — Independent Adversarial Review — CORRECTNESS lens (attempt 1)

- Unit: **F6.A** — R9-5 fail-closed control-plane auth + anti-rebinding + token-gated bypass; R9-7 HMAC-only allowlist; F5 key-file hygiene follow-ups (F-1/F-2/F-3)
- Candidate: commit `40283eb` on `r9-remediation` (parent `f73928b`) · 19 files, +2610/−211
- Reviewer: independent correctness lens (did not build; blind to the security lens) · Date: 2026-09-02 · Host: macOS arm64
- Method: §8B — all five gates run locally in a detached worktree + live adversarial session (release binary, isolated `$HOME`s, curl/HTTP-level attacks). Every claim below was executed, not read.

---

## 1. Commands run (verbatim, exit codes)

| # | Command | Result | Exit |
|---|---|---|---|
| 1 | `git worktree add --detach /var/folders/…/opencode/f6a-attempt1-correctness2 40283eb` | worktree created (`…/f6a-attempt1-correctness` was taken) | 0 |
| 2 | `git diff --stat f73928b..40283eb` | 19 files, +2610/−211 (matches pack) | 0 |
| 3 | `rtk cargo fmt --all -- --check` | clean | 0 |
| 4 | `rtk cargo clippy --workspace --all-targets -- -D warnings` | 0 warnings | 0 |
| 5 | `rtk cargo test --workspace --all-targets` | **804 passed, 0 failed** (26 suites; matches builder claim) | 0 |
| 6 | `rtk cargo test -p cerberus-packs --test production_pack_pr` | **19/19** | 0 |
| 7 | `cargo test --release --test load_test -- --test-threads=1` | **14/14** incl. `load_test_f3_3_honest_http_round_trip_gate` (7.56 s) | 0 |
| 8 | `cargo test -p cerberus-proxy --test smoke_harness` | **67/67** | 0 |
| 9 | `cargo test -p cerberus-proxy --test smoke_harness r9_` | 4/4 (`r9_5_route_matrix_fail_closed`, `r9_5_rebinding_attack_shapes_are_rejected`, `r9_5_f4_injection_vector_bypass_without_token_is_refused`, `r9_7_allowlist_fingerprints_end_to_end`) | 0 |
| 10 | `cargo test --test hotpath_sync_write_gate` | 3/3 (F5 structural gate) | 0 |
| 11 | `cargo test -p cerberus-store --lib` | 27/27 (incl. `RejectedUnkeyed` write-gate tests) | 0 |
| 12 | `cargo test -p cerberus-proxy --test smoke_harness decoder_records_multipart_regions_for_single_parse_redaction` | 1/1 (F2 single-parse contract) | 0 |
| 13 | `git diff f73928b..40283eb -- tests/redos_fuzz.rs \| wc -c` | 0 bytes (R9-16 rule untouched) | 0 |
| 14 | `cargo build --release -p cerberus` | OK | 0 |
| 15 | `bash tests/smoke-test.sh --port 18955` (release binary) | **17/17 PASS, Fail: 0** (incl. R9-5 checks 401/401/403 + bypass-payload-never-reached-mock; token from init) | 0 |
| 16 | `cerberus init` (isolated HOME) + `stat` + 64-hex grep over stdout+stderr | config.yaml `100600`; token **not** printed; report names file + grep hint | 0 |
| 17 | live boot + curl matrices (dev-mode, token, rebinding, migration, env-override, rotation) | see §3 | 0 |

Environment notes (recorded honestly): port 8787 is occupied on this host by an unrelated `headroom-proxy` daemon; a **stale foreign `cerberus` daemon (PID 57333) on 18793 from a concurrent session** answered my first "valid token" matrix (all 401 — wrong daemon). All token matrices were re-run on verified-clean ports (`lsof` + health checked before every probe). Port semantics discovered: `resolve_config` applies the **CLI port always**; config `listen` only supplies the host (daemon.rs:289–313).

## 2. Per-criterion verdicts

| # | Criterion | Verdict | Evidence |
|---|---|---|---|
| 1 | All `/api/*` fail-closed 401 without valid token, loopback included; complete route matrix | **PASS** | Live: 8 GET routes + POST/PUT/DELETE mutations + unknown `/api/zzz` → 401 with no-token AND wrong-token; valid token → 200 (7 GET routes, Bearer also accepted on control plane); `/api/dashboard` and `/health` public (200); OPTIONS/HEAD → 401. Harness `r9_5_route_matrix_fail_closed` green. Router is a single hand-rolled hyper funnel (`proxy_handler` → `is_api_path` → `handle_api_request`); **no axum Router anywhere**; anti-rebinding gate runs BEFORE auth (api.rs:470–490); no route mounted outside the gate; unknown `/api/*` 401s before the 404 (no pre-auth oracle) |
| 2 | Host/Origin allowlist + rebinding attack shapes; dashboard works with token | **PASS** | 19 live shapes (§3c) — every rebinding shape 403 pre-auth; 7 unit tests in `host_origin.rs`; wildcard/blank config entries fail the build (unit-tested); dashboard 200 with token, no token in DOM, CSP hashed (`sha256-…`, no unsafe-inline), frame protections present |
| 3 | Bypass token-gated everywhere; F4 vector fails | **PASS** | Live dev-mode: `X-Cerberus-Bypass` with no token → normal scan path (no bypass); smoke TEST POINT 5a proves the payload never reached the mock; harness `r9_5_f4_injection_vector_bypass_without_token_is_refused` green; code path proxy.rs:635–671 refuses on `None` |
| 4 | Raw never persisted; fingerprints end-to-end; migration safe; write gates hold | **PASS** | Live migration: loud boot line, raw destroyed in place, fingerprints persisted at 0600, idempotent second boot, persist-failure → loud warn + raw remains (documented deviation — judged acceptable, §4); `PUT /api/policy` and `PUT /api/config` with raw → **400** (`RejectedUnkeyed`-class message); `POST /api/allowlist` converts (fingerprint only echoed); `GET /api/allowlist` returns fingerprints only; store gate 27/27 |
| 5 | Key-file hygiene F-1/F-2/F-3 | **PASS** (with adjacent P1) | `audit_key.rs:176–231` `create_new(true).mode(0o600)` at creation — verified in code; exclusive-create, stale-tmp, Regenerated-source and loud-warning tests green in the 804; dry-run ephemeral marker in init. **Adjacent P1 found in the config write path** (§5) — outside F-1's scope but same bug class |
| 6 | Full matrix green incl. honest HTTP gate | **PASS** | Gates 3–7 + smoke 17/17 + load 14/14 (release, serial) |

## 3. Attack vectors tried (live, release binary, curl)

**(a) Dev-mode semantics** — isolated HOME per scenario:
- `admin_token: None` boot → loud WARN: *"NO admin token configured — the control plane is CLOSED (every data /api/* route responds 401, loopback included; R9-5)…"* (daemon.rs:417 confirmed live).
- Tokenless matrix: 8 GET routes + POST `/api/upstreams` + POST `/api/break-glass` + DELETE `/api/upstreams/{n}` + PUT `/api/policy` → **all 401**; `/api/dashboard` and `/health` → 200; unknown `/api/zzz` → 401.
- init → 32 CSPRNG bytes (`getrandom`) → 64-hex token; config.yaml `100600` at creation; stdout+stderr greped for a 64-hex token: **no match**.
- Rotation: re-`init` rotates the token (old ≠ new); running daemon keeps the old in-memory token until restart (by design — token is not hot-reloadable); after restart NEW → 200, OLD → **401**. Verified.
- `CERBERUS_ADMIN_TOKEN` env override wins over config (env → 200, config token → 401). Verified.
- Dashboard: 70 KB HTML, token absent from DOM (grep 0), login/token card present, CSP `default-src 'none'` + script/style sha256 hashes + `connect-src 'self'`, frame protections on.

**(b) Auth matrix** — every route in the dispatch table exercised: `GET/PUT /api/config`, `GET /api/events`, `GET /api/stats`, `POST/GET/DELETE /api/allowlist`, `POST /api/break-glass`, `GET/PUT /api/policy`, `GET/POST /api/upstreams`, `DELETE /api/upstreams/{name}`, `GET /api/packs`, `POST /api/packs/install`, `POST /api/packs/rollback`, `/api/dashboard`, unknown `/api/*`. No-token → 401 everywhere data is served; wrong-token → 401; valid token → 200 (or 400/404 by validation/Pro-license, proving the handler was reached). Mutation sanity: upstream add/delete round-trip 200; break-glass issues a nonce with HMAC'd reason; allowlist add/remove round-trip echoes fingerprints only; `GET /api/config` does **not** echo the token. Edge: bare `/api` (no trailing slash) falls to the data plane (forward attempt) — not a control-plane route, not a gate bypass.

**(c) Anti-rebinding** — `host_origin.rs` attacked line-by-line, then live:
- 403 pre-auth (even WITH a valid token): `Host: attacker.com`, `Origin: http://evil.com`, `Origin: null`, POST mutations with `text/plain` / `x-www-form-urlencoded` / `multipart/form-data` + Origin.
- Pass (correct loopback semantics): `Host: LOCALHOST:18811` (case), `Host: [::1]:18811` (IPv6 literal), `Host: 127.0.0.1:9999` (port-stripped hostname-unit match), `Origin: http://127.0.0.1:18811` + JSON POST.
- Fail-closed (correctly rejected): `Host: localhost.` (trailing dot), `Host: sub.localhost`, `Host: localhost.evil.com`, `Host: 127.1` (shorthand), empty/missing Host; evil Origin on the dashboard route too.
- curl shape (no Origin) + valid token → 200 (CLI rule holds). `text/plain` POST **without** Origin + token → 200 (correct: form-gate is browser-shaped only).
- Parser reading: wildcard/`*`, blank, path, scheme entries fail `build`; multi-colon/bracket/port edge cases normalize safely; IDN/punycode config entries simply never match a browser Host (fail-closed, no spoofing vector — exact compare).

**(d) Allowlist migration** — live legacy fixture (`policy.allowlist: [sk-LEGACY-RAW-…, hmac:0123…]`):
- Boot 1 → `allowlist migration (R9-7): 1 raw entry converted to HMAC fingerprints (domain cerberus:allowlist:v1)…`; raw value grep → **0 hits**; fingerprint `hmac:6d9baeec…` persisted; pre-existing fingerprint untouched; file rewritten `100600` (atomic tmp+rename with chmod).
- Boot 2 → no migration line (idempotent), raw still gone.
- Persist-failure (read-only config dir): migration converts in memory, `warning: allowlist migration persist: tmp write: Permission denied (os error 13)` printed, **raw remains on disk** — the documented deviation, judged acceptable (§4).
- Injection: `PUT /api/policy` raw → 400 *"allowlist entries must be HMAC fingerprints… (R9-7)"*; `PUT /api/config` raw → 400; nothing raw ever lands on disk; `POST /api/allowlist` converts by design; `GET /api/allowlist` → fingerprints only.

**(e) Regression** — smoke 17/17 (token now sourced from init-generated config); F2 single-parse harness test green; F5 `hotpath_sync_write_gate` 3/3; honest HTTP gate inside load 14/14 (release, serial); `redos_fuzz.rs` byte-identical to base.

## 4. Deviation judgments

- **No raw backup on migration** (fix-plan F6.3 says "backup con permisos mínimos y destruirlo tras sign-off explícito"): **ACCEPTED**. A raw backup file would itself violate the R9-7 invariant ("the raw value is never persisted") — the deviation is the safer reading. Conversion is atomic, idempotent, loud; on persist failure the operator is warned and the raw stays where it always was (in `config.yaml` itself, no NEW artifact). Live-verified both paths.
- **Content-type rule** (fix-plan F6.1 says "exigir application/json"; implemented as rejection of the three form-submittable simple types, JSON routes already 400 on non-JSON): **ACCEPTED** — effective browser shape is still JSON, byte-upload pack route stays usable, live-verified.
- **Dev-mode semantics** — see §6: **ACCEPTED** (textually mandated by the fix-plan).

## 5. Findings

**P1 — `persist_config` regresses `config.yaml` from 0600 to 0644 after any control-plane write** (`crates/cerberus-proxy/src/api.rs:836–846`).
`persist_config` writes `config.yaml.tmp` with plain `std::fs::write` (umask → 0644) and renames it over `config.yaml` — no mode enforcement — so the first `PUT /api/config`, `PUT /api/policy`, or `POST /api/allowlist` **replaces the 0600 file with a 0644 one while it carries the admin token**. Empirically confirmed: fresh init → `100600`; one `PUT /api/config` (200) → `100644`; stays 0644 through further writes. The tmp file also briefly carries the token at umask perms (write→rename window). The function is pre-existing (identical at `f73928b`), but it is (a) the persistence path of the allowlist this unit reworked, (b) the exact umask/ignored-chmod class this unit's F-1 fixed in `audit_key.rs`, and (c) contradictory with the pack's "config.yaml 0600" story — while `daemon.rs::atomic_write_config` (new in this commit) does chmod-before-rename correctly, showing the pattern was known. Secondary effect: `write_config_0600` (init) applies mode only at creation, so re-init does **not** repair a regressed file (observed: stayed 0644 after re-init until manual chmod). Not a re-opening of R9-5 (the token still gates everything; exposure requires local same-host access), but it must be fixed (mode-at-creation tmp, like F-1) and followed up.

**P2 — `atomic_write_config` (daemon.rs:212–227) writes the tmp at umask default before chmod.** Same class as the P1 with a shorter window (chmod happens before rename, final file is 0600 — verified live). Fold into the same fix.

**P2 — Dashboard persists the admin token in `localStorage`** (`dashboard.html:1098,1121`). Fix-plan F6.1: *"credencial solo en memoria/session scope"*. localStorage survives browser restarts on the operator's disk. Pre-existing UI (file untouched in this diff; CSP's no-unsafe-inline mitigates XSS reading it), but it is a fix-plan non-compliance in F6's own section — track for F6.4/F8 or a follow-up finding.

**P2 (observation) — Data plane has no Host/Origin gate.** The rebinding allowlist covers `/api/*` only (correct per fix-plan scope). A rebound page can still relay provider calls through the data plane (`POST /v1/chat/completions` with `Host: attacker.com` — verified it takes the same path as a normal Host; 503 here only because egress is blocked). The provider key is never exfiltrated (it is injected, not returned), but the page can spend the operator's quota. Residual risk, out of F6.1's closed scope — register as known limitation.

**P2 (UX note) — Rotation by re-`init` wholesale-replaces `config.yaml`**: custom upstreams/policy/allowlist fingerprints are silently reset to defaults (pre-existing init behavior; the allowlist loss is fail-closed and matches the documented key-rotation semantics, but an operator should be told). Rotation also requires a restart to take effect (in-memory token).

No P0 findings.

## 6. Dev-mode semantics judgment (explicit, per the review charter)

**(i) Fix-plan text**: `evidence/review9/fix-plan.md` F6.1 states verbatim *"Si falta token, mutation/data API responde 401 aun en loopback"* — the CLOSED reading is not an interpretation, it is the literal mandate; the finding text also names the old "None = open" contract as the R9-5 vulnerability itself. **The builder's design call is textually and logically correct.** (ii) **Token generation verified live**: 32 `getrandom` CSPRNG bytes → 64-hex (≥ the 24-byte non-loopback minimum), persisted 0600 at creation, never printed to stdout/logs, init report names the file with a `grep` hint. (iii) **Dashboard flow verified end-to-end live**: public HTML (no token in DOM, hashed CSP), login card present, token pasted into it authenticates every data route via `X-Cerberus-Admin-Token` (200 across the matrix); the harness authenticates like the product (67/67). (iv) **First-run path is honest and has no chicken-and-egg**: the operator and the file owner are the same user, so reading the 0600 config and pasting into the login card works; the alternatives (`CERBERUS_ADMIN_TOKEN` env — verified to win over config — and non-loopback binds still requiring strong tokens) are intact; a hand-written tokenless config boots loudly CLOSED rather than silently open, which is exactly the mandated trade. (v) **Rotation verified**: re-init rotates the token, old token rejected / new accepted after restart (the running daemon keeping the old in-memory token until restart is correct, documented behavior — `admin_token` is deliberately not hot-reloadable). The residual UX cost (re-init also resets custom config; localStorage persistence — P2) is real but does not touch the security semantics. **Judgment: the dev-mode semantics decision is correct, safe, textually mandated, and live-verified; accepted without reservation.**

## 7. Final verdict

**PASS.** All five gates are green and reproduce the builder's numbers exactly (fmt clean; clippy 0 warnings; workspace 804/804; production pack 19/19; load 14/14 in release serial including the honest HTTP round-trip gate; plus smoke harness 67/67, F4 smoke script 17/17, F5 structural gates 3/3, store gates 27/27, F2 single-parse green, `redos_fuzz.rs` byte-untouched). The security semantics of R9-5/R9-7 are not just unit-tested but live-verified against the release binary: the control plane is fail-closed (401 everywhere without a valid token, loopback included, including unknown `/api/*` paths and all mutations), every route passes through a single funnel where the anti-rebinding gate precedes the auth gate and no route is mounted outside it, 19 rebinding attack shapes are rejected pre-auth while legitimate loopback/curl shapes still work, the bypass is refused without a token in all modes, the allowlist migration destroys raw values in place (loud, atomic at 0600, idempotent, persist-failure loudly warned) and the config-store write gates reject raw injection with fingerprints-only API echoes, and the dev-mode `None = CLOSED` semantics — the unit's decisive design call — is textually mandated by the fix-plan and verified end-to-end including rotation and env override. One P1 must be registered before phase-gate sign-off: `api.rs::persist_config` silently regresses `config.yaml` from 0600 to 0644 on the first control-plane write (admin-token-carrying file becomes world-readable; same umask/chmod class F-1 already fixed elsewhere, fix pattern known and applied inconsistently) — it does not reopen R9-5 and is fixable in a small follow-up, alongside the P2s (migration tmp window, dashboard localStorage token, ungated data-plane Host, re-init UX note).
