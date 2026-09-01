# Evidence Pack — review9 / F2.2+F2.3 attempt-1 panel — SECURITY lens

- Unit: F2.2 (vault zeroization) + F2.3 (live break-glass) — R9-8 remediation
- Candidate: `d1a0322` (branch `r9-remediation`), parent/base `1df53a0`
- Reviewer: independent adversarial panel, **security** lens (did not build; blind to the correctness lens)
- Date: 2026-09-01
- Host: `Darwin 25.5.0 arm64` (M-series)
- Toolchain: `rustc/cargo 1.97.1`
- Worktree: `/var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/f23-attempt1-security` (detached HEAD at `d1a0322`; main repo untouched except this report file)
- Live e2e: release daemon on `127.0.0.1:18791` (admin token configured, `CERBERUS_MODE=enforce`), isolated `$HOME`, python3 echo upstream on `127.0.0.1:19999`; second isolated-HOME daemon (dev mode, no token) on `:18892` for the R9-5 interaction probe.

## Commands run (verbatim)

| # | Command (worktree cwd unless noted) | Result | Exit |
|---|---|---|---|
| 1 | `git worktree add --detach …/f23-attempt1-security d1a0322` | worktree created at d1a0322 | 0 |
| 2 | `rtk cargo clippy --workspace --all-targets -- -D warnings` | No issues found | 0 |
| 3 | `rtk cargo test --release --test redos_fuzz -- --test-threads=1 --nocapture` | 11 passed | 0 |
| 4 | `rtk cargo test -p cerberus-engine` | 246 passed | 0 |
| 5 | `rtk cargo test -p cerberus-proxy` | 182 passed | 0 |
| 6 | `rtk cargo test -p cerberus-packs --test production_pack_pr` | 19 passed | 0 |
| 7 | `cargo test -p cerberus-engine --lib -- --list` (raw; rtk suppressed listing) | 9 break-glass + 16 vault tests located | 0 |
| 8 | `rtk cargo test -p cerberus-engine --lib <each of 25 test names> -- --exact` (individually) | 1 passed, 225 filtered — every run | 0 ×25 |
| 9 | `rtk cargo build --release -p cerberus` | release binary built | 0 |
| 10 | e2e battery: ~30 curl/python3 probes A0–A14, B1–B5, C1–C8, D1–D5, E0–E8, F1–F4, G1–G4 (below) | all assertions observed as expected | 0 |

The 25 individually-run tests (all exit 0): break-glass — `valid_redemption_returns_grant_with_reason_hash`, `absent_nonce_rejected`, `expired_nonce_rejected`, `replay_rejected_one_shot`, `nonce_is_cryptographic_and_unique`, `two_concurrent_requests_exactly_one_wins`, `wrong_provider_rejected_and_token_survives_for_right_scope`, `reason_truncated_and_hashed_never_raw`, `ttl_clamped_to_max`; vault — `capacity_evicts_oldest_and_zeroizes`, `clear_and_zeroize_all`, `debug_output_never_contains_secret`, `expiry_purges_and_zeroizes`, `request_scoped_isolation_between_vaults`, `resolve_nonexistent_token`, `resolve_str_with_wrapper_and_bare_id`, `reversible_options_default_disabled`, `reversible_redaction_blocks_like_irreversible`, `reversible_redaction_splices_vault_tokens`, `store_and_resolve_round_trip`, `token_display_has_no_secret`, `tokens_are_non_guessable`, `unredact_replaces_tokens_and_consumes`, `unredact_without_tokens_is_noop`, `wipe_before_drop_clears_value`.

## Per-criterion verdicts

| Criterion (security lens) | Verdict | Evidence |
|---|---|---|
| Gates: clippy / ReDoS 11 / engine 246 / proxy 182 / packs 19 | **PASS** | commands 2–6, all exit 0 |
| Gate 5: 9 break-glass + 16 vault tests individually | **PASS** | command 8, 25×exit 0 |
| (a) Bypass unreachable without valid admin token (API + data plane) | **PASS** | A1–A4 (401 on none/empty/wrong/query-token), A7/A8 (data-plane redeem w/o `X-Cerberus-Admin-Token` → 403; Bearer-only → 403); nonce NOT burned by failed auth attempts (A7b redeems the same nonce after two unauth attempts) |
| (b) Nonce: CSPRNG source, no restart-resurrection, one-shot | **PASS** | `random_nonce_256` = `getrandom` (vault.rs:126); 20/20 unique 64-hex nonces (G4); ledger is in-memory `Mutex<HashMap>` — after daemon restart, both an unspent (B4) and a spent (B5) pre-restart nonce → 403; replay always 403 (A9, A10b, C4) |
| (b2) One-shot atomic under concurrency | **PASS** | unit test `two_concurrent_requests_exactly_one_wins` + live 8-parallel curl race → exactly one 200, seven 403 (D4) |
| (c) Scope escape | **PASS** | wrong provider → 403 and token survives (C2→C3); case forgery `OPENAI` ≠ `openai` → 403, not consumed (C5); empty-string scope never redeems against a real provider (C6/C7); global scope works (C8) |
| (d) Raw reason never persisted | **PASS** | canary `SECCANARY-9x7-RAW sk-CANARYdeadbeef999` → **0 hits** in daemon.log, daemon2.log, `/api/events` JSON, and `strings home/.cerberus/cerberus.db` (D3–D5); events carry only `bypass-hash:<sha256>` equal to the issuance `reason_hash` |
| (d2) Truncation happens BEFORE hashing | **PASS** | reason A = 200×`X` and reason B = 200×`X`+suffix → identical `reason_hash`, and hash(A) == local `sha256(200×X)` (D2) |
| (e) Bypass cannot skip redaction (block-only semantics) | **PASS** | rule hot-set to `redact`; secret + valid break-glass bypass → upstream received `[REDACTED:secret.openai_api_key]`, i.e. redaction still applied; bypass only un-blocks (E2) — matches plan §4.7 |
| (f) Timing/DoS on redeem | **PASS** (reasoned) | lock held only over in-process `HashMap` remove/insert (µs, no I/O, no attacker-controlled wait) — no hostage possible; nonce lookup is a single HashMap probe on both hit and miss paths over a 256-bit space — no enumeration channel; `#[allow(clippy::significant_drop_tightening)]` is justified in-code (releasing between remove and scope-mismatch re-insert would break exactly-once) |
| (g) Zeroization guarantees | **PASS** | `VaultSecret` = `Zeroizing<String>`; no `Clone`/`Serialize` derive (compile-enforced — tree builds); `Debug`/`Display` redact (2 tests); wipe on consume/expiry/eviction/clear/Drop (`VaultEntry::drop`, `VaultInner::drop`); ids/nonce via `getrandom` (vault.rs:119–130); TTL 5 min + capacity 1024 enforced in `store()` eviction; `wipe_before_drop_clears_value` proves observable overwrite |
| 7. No-secret-logging sweep | **PASS** | `vault.rs`/`break_glass.rs` contain **zero** log/print calls; proxy logs only `break-glass redemption refused: {e}` (error Display, no nonce/reason) and issuance logs scope+ttl only; bypass/admin-token headers stripped before upstream (proxy.rs:777–784) and confirmed by the echo upstream (A7b: neither header present in received_headers) |

## Attack vectors tried (payload → observed result)

**A — auth bypass surface**
- A1 `POST /api/break-glass` no token → `401 {"error":"unauthorized"}`
- A2 empty `X-Cerberus-Admin-Token;` header → 401
- A3 wrong token → 401
- A4 token in query `?token=…` → 401 (query tokens are not an auth channel)
- A5/A6 valid token via `X-Cerberus-Admin-Token` and via `Authorization: Bearer` → 200 + 64-hex nonce (API accepts both, per pre-existing `authorized()`)
- A0 baseline: secret in body, no bypass → `403 {"error":"blocked","flag":"secret.openai_api_key"}`
- A7 data-plane redeem with **no** admin token → 403 blocked; **nonce survives** (A7b same nonce + proper token → 200 from upstream)
- A8 Bearer-only redeem → 403 (data plane requires `X-Cerberus-Admin-Token` specifically — review-v4 rule preserved)
- A9 replay of spent nonce → 403; A10 header-case variant (`X-CERBERUS-BYPASS`, spaces after colon) redeemed an unspent nonce → 200, then replay → 403
- A11 `break-glass:` empty nonce → 403; A12 forged 64-hex nonce → 403
- A13 legacy reason bypass without token → 403 (ignored); A14 legacy with token → 200 (findings-preserving, unchanged)
- Upstream echo in A7b/A10/A14: **no** `x-cerberus-bypass`, **no** `x-cerberus-admin-token` forwarded

**B — restart replay**
- B1 issue nonce → kill daemon → restart with same token: B4 redeem unspent pre-restart nonce → 403; B5 redeem spent pre-restart nonce → 403. In-memory ledger ⇒ no resurrection, no restart-replay. Fail-closed; the plan does not require persistence, so documented restart-invalidation is acceptable.

**C — scope escape**
- C1 issue `provider:"openai"` → C2 redeem on `/anthropic/…` → 403 (blocked) → C3 same nonce on `/openai/…` → 200 (not consumed by C2) → C4 replay → 403
- C5 issue `provider:"OPENAI"`, redeem against `openai` route → 403 (scope compare is case-sensitive; fail-closed)
- C6/C7 `provider:""` issuable but never redeems against a real provider → 403
- C8 global scope (no provider) → 200

**D — reason leakage**
- Canary reason issued + redeemed; grep of daemon.log, daemon2.log, events JSON, `strings cerberus.db` → **0 raw hits** in all four; events show `flags:[finding,"bypass","break-glass"]` + `bypass-hash:<sha256>` == issuance `reason_hash`
- D2 truncation-before-hash proven (A/B identical hash; matches local sha256 of the exact 200-byte prefix)
- Feedback header on one-shot redeem carries no nonce/reason

**E — bypass abuse shape**
- E0/E1 rule → `redact`; E2 secret + valid one-shot bypass → upstream still received `[REDACTED:…]` — **bypass does not skip redaction**
- E7 nonce redeemed on a redact-path request **is consumed** (replay under block → 403); E8 nonce redeemed on a clean request (no findings) **is also consumed** (redeem happens at header-parse, before scan). Fail-closed direction; see P2-2.
- E5/E6 confirmed state restore; no state confusion.

**F — R9-5 interaction probe (dev mode, `admin_token: None`, isolated HOME)**
- F2 `POST /api/break-glass` with no token → **200 + nonce**; F3 data-plane redeem with no token → **200 (block bypassed)**. Pre-existing dev-mode openness (R9-5 already documents the legacy bypass being open in dev mode); the new endpoint does not weaken the token-configured gate (A1–A8), but extends the dev-mode unauthenticated surface to *minting*. See P2-1.

**G — hygiene**
- No `println!`/`dbg!`/logging in vault.rs/break_glass.rs; single proxy warn logs the error `Display` only
- 20 nonces → 20 unique, all 64-hex
- TLS/redirect/upstream behavior untouched by the diff

## Findings

**P0 — none.**

**P1 — none.**

**P2 (advisory, none block this unit):**

1. **R9-5 interaction — dev-mode open mint (inherited, not introduced).** With `admin_token: None`, `POST /api/break-glass` mints scoped one-shot tokens unauthenticated and the data plane redeems them token-free (F2/F3 → 200 bypass). The token-configured gate is intact on both endpoints (A1–A8) — this commit does **not** weaken what R9-5 targets — but the R9-5 fix must explicitly cover `/api/break-glass` (e.g. default-on auth on loopback or Origin/Host validation), and reviewers of that fix should include this route in the gate tests.
2. **One-shot = one request, spent regardless of outcome.** The nonce is consumed at header-parse time even when the request is clean (E8) or its action is `redact` (E7), where the bypass grants nothing. Additionally, a bypass request that is actually **redacted** is audited as `action_taken:"bypass"` (inherited from the legacy path). Not a security hole (fail-closed; a stolen nonce is burned by any request), but it can waste an operator token and slightly overstates the audit trail.
3. **`ttl_secs: 0` accepted by the API.** The handler doc says clamped to `[1, 3600]`; only the max (1 h) is enforced (`ttl_secs:999999 → 3600`, D1). `ttl_secs:0` yields an instantly-expired token — fails closed, so cosmetic/doc mismatch only.
4. **Empty-string provider scope issuable** (`{"provider":""}` → `scope:"provider:"`). It cannot redeem against any real upstream name (C7), so fail-closed; a non-empty validation at issue time would tidy the API surface.
5. **`reason_hash` is unsalted SHA-256** (shared `hash_value` helper; same class as the already-open R9-16). Operator-chosen reasons are typically low-risk, but a guessable reason could be confirmed offline from the audit DB. Consider folding the reason-hash into the R9-16 HMAC fix.

## Final verdict

**PASS.** All six gates ran clean with exit 0 (clippy `-D warnings`; ReDoS 11/11; engine 246; proxy 182; packs 19/19; and all 9 break-glass + 16 vault tests re-run individually). The live adversarial battery could not break the new bypass surface: every unauthenticated variant (missing/empty/wrong token, query-token, Bearer-on-data-plane) is refused with 401/403 and — critically — never burns the nonce; one-shot holds under an 8-way concurrent race and across daemon restarts (in-memory ledger, fail-closed); provider scoping rejects wrong-provider, case-forged, and empty-scope redemptions without consumption; the raw reason is absent from logs, events, and the SQLite audit store while truncation-before-hash (200 bytes) was proven against a local SHA-256; bypass semantics remain block-only (redaction is never skipped); and the zeroization surface holds by construction (`Zeroizing<String>` container, no Clone/Serialize, redacting Debug, getrandom identifiers, bounded capacity/TTL, wipe on every removal path). The five P2 notes are advisory (dev-mode inheritance covered by the pending R9-5 fix, audit-accuracy and validation cosmetics, unsalted reason hash in the R9-16 class); none contradicts R9-8's requirements, moves a threshold, or weakens the admin-token gate.
