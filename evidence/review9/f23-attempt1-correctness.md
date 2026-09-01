# F2.2+F2.3 (R9-8) — Attempt 1, CORRECTNESS lens — independent adversarial verification

- **Candidate:** `d1a0322` on branch `r9-remediation` (parent `1df53a0`, base of the unit)
- **Unit:** F2.2 (reversible vault, real memory hygiene) + F2.3 (live authenticated one-shot break-glass) — R9-8
- **Spec:** `evidence/review9/gauntlet-findings.md` R9-8 (full text read) + `evidence/f2/r9-vault-zeroization.md` (builder pack, incl. e2e transcript)
- **Worktree:** `/var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/f23-attempt1-correctness2` (detached HEAD at `d1a0322`, removed after the round)
- **Date:** 2026-09-01 (15:34–16:10 UTC)
- **Host:** `Darwin Alexei-MacBook-Pro.local 25.5.0` arm64 (M-series), quiet during serial runs
- **Toolchain:** `rustc 1.97.1 (8bab26f4f 2026-07-14)`, `cargo 1.97.1`
- **Blindness:** sibling security-lens report (`f23-attempt1-security.md`) was never opened. No code/test/threshold edits; only file created in the main repo is this report.

Integrity: all 10 frozen SHA-256 hashes in builder STEP 7 recomputed at `d1a0322` and matched exactly (10/10).

## Commands run (verbatim, worktree cwd unless noted)

| # | Command | Result | Exit |
|---|---|---|---|
| 1 | `git -C /Users/alexeirojas/Work/Personal/Cerberus worktree add --detach /var/folders/.../f23-attempt1-correctness2 d1a0322` | worktree created | 0 |
| 2 | `rtk cargo fmt --all -- --check` | clean | 0 |
| 3 | `rtk cargo clippy --workspace --all-targets -- -D warnings` | 0 issues | 0 |
| 4 | `rtk cargo test --workspace --all-targets` | **680 passed** (25 suites, 48.08 s), 0 failed | 0 |
| 5 | `rtk cargo test -p cerberus-engine` | 246 passed | 0 |
| 6 | `rtk cargo test -p cerberus-proxy` | 182 passed | 0 |
| 7 | `rtk cargo test -p cerberus-packs --test production_pack_pr` | 19/19 passed | 0 |
| 8 | `rtk cargo test -p cerberus-proxy --test smoke_harness reversible` | 2 passed (`test_reversible_vault_round_trip_request_scoped`, `test_reversible_redaction_is_opt_in_default_irreversible`) | 0 |
| 9 | `rtk cargo test -p cerberus-proxy reversible_redaction_is_opt_in` | 2 passed (config `reversible_redaction_is_opt_in_and_defaults_off` + harness opt-in) | 0 |
| 10 | `rtk cargo test -p cerberus-proxy --test smoke_harness break_glass` | 3 passed (one-shot e2e, wrong-scope, legacy header) | 0 |
| 11 | `rtk cargo test -p cerberus-engine --lib break_glass` | 9 passed (incl. `two_concurrent_requests_exactly_one_wins`, `wrong_provider_rejected_and_token_survives_for_right_scope`, `expired_nonce_rejected`, `replay_rejected_one_shot`) | 0 |
| 12 | `rtk cargo test -p cerberus-engine --lib vault` | 16 passed (zeroization counts, Debug-leak, eviction, TTL, consume-once, wipe-before-drop) | 0 |
| 13 | `rtk cargo build --release -p cerberus` | release binary built | 0 |
| 14 | live e2e: release daemon (port 18791, isolated `$HOME`, `reversible_redaction: true`, admin token, enforce) + raw-socket python mock upstream (port 19999) + `framing_driver.py` (25 checks) | 25/25 after driver-side typo fix (driver bug only, see Attack vectors #7) | 0 |
| 15 | `rtk cargo test --release --test load_test -- --test-threads=1 --nocapture` | **13/13**, 5.62 s, no contention flake | 0 |
| 16 | `rtk cargo test -p cerberus-proxy --test smoke_harness bypass` / `--lib bypass` | 3 / 1 passed (legacy reason path intact) | 0 |
| 17 | `git diff 1df53a0..d1a0322 -- tests/load_test.rs` | exactly one line: `redact_body(..., None)` — signature-only, no gate/threshold/payload change | 0 |
| 18 | leak grep on live e2e artifacts (`grep -c "sk-E2EframingX" daemon.log mock.log`; events API JSON; SQLite `cerberus.db`) | **0 hits in all four**; events carry `sha256:` hashes only, no `[VAULT:` ids persisted | 0 |
| 19 | `shasum -a 256` over the 10 touched files | 10/10 match builder STEP 7 | 0 |

## Per-criterion verdicts

| Criterion | Verdict | Evidence (mine, not the builder's) |
|---|---|---|
| G1 fmt | **PASS** | exit 0 |
| G2 clippy `-D warnings` | **PASS** | exit 0 |
| G3 workspace tests | **PASS** | my count **680/0** (= builder claim; baseline 666 + 14 new) |
| G4 engine 246 / proxy 182 | **PASS** | both match |
| G5 production pack P/R | **PASS** | 19/19 |
| 6a reversible redaction is OPT-IN (default irreversible) | **PASS** | config test `reversible_redaction_is_opt_in_and_defaults_off` asserts default-off, YAML-absent-off, `true` parses, `false` parses (ran, exit 0); harness `test_reversible_redaction_is_opt_in_default_irreversible` proves the wire behavior (`[REDACTED:…]`, no vault round trip); `#[serde(default)]` at config.rs:74-75; `PUT /api/config` patch preserves the flag (api.rs:596), so it cannot be hot-enabled |
| 6a vault is REQUEST-SCOPED (no cross-request state) | **PASS** | only prod creation point is `proxy.rs:675` (`reversible_redaction.then(Vault::new)`) inside the request handler; zero `static`/`Lazy`/`OnceLock` vaults (grep); `Vault` is not `Clone`, so it cannot be shared by accident; harness round-trip test (req 2 restores only secret B, 0 hits of secret A) ran green; live e2e confirmed back-to-back requests independently restored |
| 6a un-redact restores ORIGINAL response bytes | **PASS** | `vault.rs:308-350` 3-pass scheme: pass 1 resolves all token ids under the lock (dedup, fixed-width hex ids → no prefix ambiguity); pass 2 splices every occurrence (`String::replace` = all occurrences); pass 3 consumes+zeroizes used entries; unknown/expired tokens left untouched (never guessed into a value — asserted by `unredact_replaces_tokens_and_consumes`); live e2e: echo upstream returned the exact original secret with `[VAULT:` fully gone |
| 6b content-length framing after un-redaction | **PASS** (1 P2 metadata note) | recompute at `proxy.rs:852-856` is unconditional under `request_vault.is_some()` and `HeaderMap::insert` replaces any stale upstream value. Live matrix: JSON echo (shrink case, CL 49 == actual 49); chunked upstream (`transfer-encoding` stripped by `RESPONSE_HOP_BY_HOP`, restored body, CL == actual); gzip passthrough (non-UTF8 → untouched, gzip intact, no secret injected into compressed bytes); 204/304 (no body; client observes **no** content-length — hyper strips the inserted header for bodyless statuses, spec-correct); HEAD (no framing break, connection reusable). One metadata deviation logged as P2 below |
| 6c one-shot exactly-once (no TOCTOU) | **PASS** | `redeem` (break_glass.rs:243-265) holds the Mutex across remove→expiry→scope→grant; because re-insert on scope-mismatch happens **before** the lock is released, no concurrent observer can ever see the removed state — the hypothesized "scope-mismatch window" is closed by construction, not by discipline. Barrier race test asserts exactly one winner (ran); wrong-scope → token survives (`ledger.len()==1` asserted in harness + engine test, both ran); scope-mismatch replay cannot burn (re-insert) nor resurrect (successful redeem removes permanently and the grant path never re-inserts); expired → consumed+purged, reported `Expired`; provider-scoped token + redemption without provider → `ScopeMismatch` (fails closed) |
| 6d wipe completeness (every exit path) | **PASS** (1 P2 advisory) | Enumerated: consume (resolve → entry returned, `VaultEntry::drop` wipes; unredact pass 3 wipes), TTL expiry (`purge_expired_locked` wipes), capacity eviction (`store` wipes evicted), `clear()`/`zeroize_all` (drain+wipe), `Vault` Drop (`VaultInner::drop` drains+wipes every remaining entry), Drop of any handle (same Drop; `Vault` non-Clone), failed/partial un-redact (entries simply remain → request-end Drop wipes). No `Clone`/`Serialize` on `VaultSecret`/`VaultEntry`/`Vault` (compile-enforced surface); `Debug`/`Display` redacted and asserted secret-free by 3 tests (ran); `BreakGlassLedger` Debug hides the nonce map; audit trail carries `sha256:` + flags only — live grep: 0 raw-secret hits in daemon log, upstream-side log, events JSON, SQLite |
| 6e legacy compat | **PASS** | `BypassKind::Legacy` semantics unchanged (dev-mode open / admin-gated via `X-Cerberus-Admin-Token` only; reason hashed into `bypass-hash:`, echoed via feedback header); `test_break_glass_header_bypasses_block` pre-exists at parent `1df53a0` and passes; `git diff` deletes no test functions; `redact_body` signature change has exactly the builder's non-test call sites — proxy.rs:679 (`request_vault.as_ref()`) and tests/load_test.rs:495 (`None`), no stale caller (grep over crates+tests); `apply_redaction` (irreversible) untouched |
| 7 fingerprints / regressors | **PASS** | load suite 13/13 release serial (5.62 s, quiet host, no re-run needed); `load_test.rs` diff is exactly the `+None` signature change |

## Attack vectors tried

1. **Cross-request vault leak via shared state** — hunted for any global/static vault, `Arc`-shared vault in `ProxyContext`/`ApiContext`, or a vault created outside the handler. None exists; the type system helps (`Vault` not `Clone`). Closed.
2. **Cross-request token guessing** — 128-bit CSPRNG ids (`getrandom`), 32-hex; old `v1` counter ids deleted. Closed.
3. **Token-injection cross-replacement in un-redact** — a secret whose value contains `[VAULT:<live-id>]` of another entry in the same vault would be double-expanded in pass 2 (replacements applied sequentially). Exploiting it requires predicting a CSPRNG id generated after the request body is fixed (2⁻¹²⁸ per entry, and the vault is request-scoped). Unknown ids are provably left untouched. Closed (theoretical).
4. **TOCTOU on the redeem path** — looked for a window between `remove` and `re-insert` visible to concurrent redeemers. None: the whole sequence is one critical section (the targeted `clippy::significant_drop_tightening` allow documents the deliberate guard hold). A wrong-scope redeem in flight cannot make a right-scope redeemer observe `UnknownNonce`, cannot burn the token, and cannot let a replayed grant through. Closed.
5. **Chunked/streaming framing** — upstream `Transfer-Encoding: chunked` is stripped from the response headers; the body is fully buffered (no streaming passthrough exists to bypass the vault lifecycle), un-redacted, and `content-length` is recomputed. Verified live with a raw-socket chunked mock. Closed.
6. **Compressed bodies** — non-UTF8 response → `unredact` returns bytes untouched (gzip stays valid, verified live); a compressed stream coincidentally containing a literal `[VAULT:<32hex>]` token is astronomically improbable and cannot be constructed via the echo path. Closed.
7. **Response shapes: HEAD / 204 / 304 / empty** — exercised live. No framing error in any shape (connections reusable, hyper accepted all responses). HEAD metadata rewrite observed (→ P2-2). One initial "failure" during this round was a Python f-string walrus bug in **my throwaway driver** (list literal inside an `in` expression), not in the product; fixed and re-run to 25/25.
8. **Secret escape surfaces** — grep-audited for `Clone`/`Serialize` on secret holders (none), `Debug`/`Display` paths (redacted; tests ran), owned-`String` returns (only the documented response-splice copy + P2-1 intermediate below), persistence into SQLite/events JSON (0 raw hits, live). Closed.
9. **Stale `content-length` from the upstream** — would break framing; `HeaderMap::insert` replaces it wholesale whenever the vault path is active. Verified live (49-byte restored body vs larger tokenized upstream body). Closed.

## Findings

**P0: none. P1: none.**

- **P2-1 (advisory — zeroization footprint):** `Vault::unredact` pass 1 collects `replacements: Vec<(String, String)>` (vault.rs:320-332) whose second element is a **plain `String` copy of the secret**, dropped at function end without zeroization. The same bytes already land in the plain response body (the feature's purpose, documented), so the incremental exposure is marginal and `unsafe` is forbidden — but wrapping the replacement values in `Zeroizing<String>` would shrink the non-zeroized footprint to exactly the response buffer. No functional impact.
- **P2-2 (advisory — HEAD metadata):** with `reversible_redaction` enabled, the content-length recompute (proxy.rs:852-856) runs for **every** response, including bodiless ones. Observed live: a HEAD response whose upstream declared `content-length: 1234` is rewritten to `content-length: 0` (RFC 9110 says HEAD SHOULD mirror the GET's length). Framing stays valid (verified: empty body, connection reusable) and the flag is opt-in, so impact is metadata-only. Suggest skipping the rewrite for bodiless methods/statuses or gating it on an actual length change.
- **P2-3 (advisory — latent, no current caller):** `BreakGlassToken` derives `Debug` and contains the **bearer nonce** (break_glass.rs:95-107). The ledger's `Debug` carefully hides the pending map, but a future prod path that Debug-logs an issued token would print the bearer credential. Verified today: no caller formats `BreakGlassToken` with `{:?}` in prod code (issuance logs scope+ttl only). Hardening note for F6.4 (CLI).

None of the findings blocks the unit; none moves a threshold or gate.

## Final verdict

**PASS.** Every gate was executed on a clean detached worktree at `d1a0322`: fmt and clippy clean; my own counts reproduce the builder's exactly (680/0 workspace, 246 engine, 182 proxy, 19/19 production pack, 13/13 release-serial load); the four new harness tests and the 25 new engine unit tests all pass and assert the right invariants (opt-in default-off, request-scoping, restore-original, consume-once, exactly-one-winner under a barrier race, scope-mismatch survival, expiry burn, Debug redaction, counted zeroization). The key adversarial probes were closed by evidence rather than argument: request-scoping is structural (single per-request creation point, no shared/static vault, non-Clone type, CSPRNG ids); the redeem path's exactly-once guarantee holds because remove→check→re-insert is a single critical section, so neither a scope-mismatch replay nor a concurrent race can burn, resurrect, or double-spend a nonce; un-redaction restores the original bytes through the 3-pass scheme and the framing recompute survived every response shape I could construct against a raw-socket mock (chunked, gzip, HEAD, 204, 304, keep-alive reuse, shrink/grow), with the only observed deviations being two opt-in, non-blocking metadata/footprint advisories (P2-1, P2-2) and one latent Debug-derive note (P2-3). Live leak greps over daemon log, upstream-side log, events JSON and the SQLite audit store found zero raw-secret hits, and the 10 frozen SHAs match the builder's pack byte-for-byte. The R9-8 correctness criteria are met; the unit may proceed to sign-off from the correctness lens.
