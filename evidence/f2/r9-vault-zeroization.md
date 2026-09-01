# Evidence Pack — F2.2+F2.3 / R9-8 vault zeroization + live break-glass

- Unit: F2.2 (reversible vault, real memory hygiene) + F2.3 (allow-once/break-glass primitive) — R9-8
- Builder status: **FIX executed — returns to VERIFY** (unit NOT closed)
- Base HEAD: `1df53a0` (branch `r9-remediation`, clean tree)
- Attempt: 1 (branch `r9-f2-attempt2`, isolated worktree)
- Date: 2026-09-01 (14:47 UTC)
- Host: `Darwin 25.5.0 arm64` (M-series)
- Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, `cargo 1.97.1`
- Worktree: `/var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/f2-attempt2-builder`

## Finding under repair (R9-8, ALTO, VERIFIED — review9/gauntlet-findings.md)

> Zeroization nunca implementada y vault reversible (decisión cerrada §9 #4, Phase 2) es
> código muerto. `zeroize`/`secrecy` en ningún Cargo.toml; workspace `unsafe_code = "forbid"`.
> `Vault` sin ningún caller fuera de `vault.rs`/`lib.rs`; `Vault::clear` no limpia memoria.
> `evidence/f2/reversible-vault.md` lo marca BUILT — evidencia falsa vs código.
> Mismo patrón break-glass CLI: `BreakGlass` (break_glass.rs) sin callers fuera de sus tests;
> `allow-once` no existe en CLI.

Spec sources used (verbatim requirements): `evidence/review9/fix-plan.md` F2.2/F2.3 +
`CERBERUS_PRODUCT_BUILD_PLAN.md` §4.4 (reversible opt-in), §4.7 (break-glass semantics),
§5 (memory hygiene row), §9 #4 (irreversible default / reversible opt-in closed decision),
§8B.5. NO threshold moved, NO scope invented, nothing from the OUT-of-MVP list
(streaming stays out; no CLI command added — `allow-once` CLI is F6.4 scope).

## STEP 1 — Reconciliation: R9-8 text vs code at 1df53a0

| R9-8 / fix-plan F2.2+F2.3 requirement | State at 1df53a0 | Built in this fix |
|---|---|---|
| `zeroize`/`secrecy` in no Cargo.toml | CONFIRMED (transitive only) | `zeroize = "1"` + `getrandom = "0.2"` added as direct deps of `cerberus-engine` (both already resolved in Cargo.lock 1.9.0 / 0.2.17 → zero new crates) |
| `Vault` dead code, `String` storage, no zeroization | CONFIRMED (`vault.rs` plain `String`, `#[derive(Debug)]` printed secrets, `Clone` duplicated them) | Full rewrite: `Zeroizing<String>` container, zeroization on consume/expiry/eviction/clear/Drop (file:line below) |
| Predictable `v1` token ids (`next_id` counter) | CONFIRMED (`vault.rs:81` old `format!("v{}", n)`) | 128-bit CSPRNG hex ids (`vault.rs:119` `random_id`, `getrandom`) |
| No capacity / no TTL, global-lifetime vault | CONFIRMED (global semantics implied by API; no limits) | Request-scoped vault: created per request by the proxy (`proxy.rs:674`), capacity=1024 + TTL=5 min defaults, configurable (`vault.rs:48,52,228`) |
| `Vault::clear` doesn't wipe memory | CONFIRMED | `clear()` → `zeroize_all()` wipes every buffer (`vault.rs:413,425`); `Drop` of `VaultInner` drains+wipes (`vault.rs:201`) |
| `BreakGlass` dead code (no caller outside its tests) | CONFIRMED (old `apply()` helper, no server-side state, no auth, no one-shot) | Replaced by `BreakGlassLedger`: authenticated issuance, 256-bit CSPRNG nonce, TTL, explicit provider scope, atomic exactly-once redeem (`break_glass.rs:157,201,243`) |
| Break-glass NOT reachable from the running product | CONFIRMED for the primitive | Wired end-to-end: `POST /api/break-glass` (control plane, behind the existing admin-token gate, `api.rs:358,1172,1195`) → data-plane redemption via `X-Cerberus-Bypass: break-glass:<nonce>` (`proxy.rs:559-599`) → audited bypass event (`proxy.rs:728-748`) |
| Bypass audited; reason hashed, never raw | Already true for the legacy header path (kept findings-preserving) | Kept + extended: one-shot redemption shares the same audit; flags add `break-glass` marker; `bypass-hash:<sha256>` carries the reason hash from issuance (`break_glass.rs:201`, `proxy.rs:737-744`) |
| Irreversible redaction is the DEFAULT (§9 #4) | Vault was never wired (so default held trivially) | Preserved explicitly: `reversible_redaction: bool` config, `#[serde(default)]` = `false` (`config.rs:66-75`), parse test `reversible_redaction_is_opt_in_and_defaults_off`, harness test `test_reversible_redaction_is_opt_in_default_irreversible` |
| Un-redaction only for non-streaming MVP responses | N/A (proxy buffers whole response) | Documented + enforced by construction: `vault.unredact` runs on the fully-buffered response (`proxy.rs:836-841`); no streaming path exists to bypass the lifecycle |
| Nothing from the vault persisted or logged | N/A | No `Serialize` on any vault/break-glass type; `Debug` redacts (`vault.rs:96-103,179-188`); nonce map hidden from `BreakGlassLedger` Debug (`break_glass.rs:163-172`); e2e grep proves 0 raw hits in logs/events/SQLite |

What was kept findings-preserving: the legacy `X-Cerberus-Bypass: <reason>` path is unchanged
(dev-mode open, admin-token-gated when configured, reason hashed into `bypass-hash:`, echoed
back only to the same caller via the feedback header). All pre-existing tests pass unchanged
except the old dead-`BreakGlass`/clone-`Vault` unit tests, which were replaced by tests of the
new behavior (R9-8 explicitly invalidates the old claims).

## STEP 2 — Implementation evidence (file:line)

**F2.2 — request-scoped reversible vault with real zeroization** (`crates/cerberus-engine/src/vault.rs`, rewritten):

- `VaultSecret` (`vault.rs:65`) — wraps `zeroize::Zeroizing<String>`; no `Clone`, no
  `Serialize`; `Debug`/`Display` print `<redacted>`; explicit `wipe()` (`:88`).
- `VaultEntry::drop` (`:167`) — zeroize before free on EVERY removal path (consume, expiry,
  eviction, clear, vault drop).
- `VaultInner::drop` (`:201`) — last-resort drain+wipe of every remaining entry.
- `Vault::store` (`:244`) — CSPRNG token id, capacity FIFO eviction (wipes evicted), lazy TTL purge.
- `Vault::resolve` / `resolve_str` (`:276,284`) — CONSUME semantics: entry removed (zeroized)
  and moved to the caller; second resolve returns `None`.
- `Vault::unredact` (`:308`) — non-streaming response restoration: resolves replacements under
  the lock, splices, then consumes+zeroizes used entries; unknown tokens untouched.
- `Vault::purge_expired` (`:373`), `zeroize_all` (`:413`), `clear` (`:425`).
- `apply_redaction_reversible` (`:440`) — span splicing with the same overlap resolution as
  `apply_redaction`; unique vault token per span; `Block` contract identical.
- Module docs (`vault.rs:1-45`) document **where the bytes live and when they die**
  (vault buffer / request-body decode copy / response splice copy).

**F2.2 wiring** (`crates/cerberus-proxy/src/`): config opt-in flag `reversible_redaction`
(`config.rs:66-75`); vault threaded through `redact_body`/`redact_json`/`redact_value`/
`fallback_text` (`json_redact.rs:33-120`); request-scoped vault created per request
(`proxy.rs:674-675`), used for redaction (`proxy.rs:690`), response un-redaction
(`proxy.rs:836-841`) and dropped at request end; `content-length` recomputed after un-redaction
(`proxy.rs:847-854`) — a stale header would break HTTP framing (found and fixed during e2e).

**F2.3 — live authenticated one-shot break-glass** (`crates/cerberus-engine/src/break_glass.rs`, rewritten):

- `BreakGlassScope` (`:55`) — explicit scope: `for_provider(name)` or `global()`; `covers` (`:78`).
- `BreakGlassToken` (`:96`) — 256-bit CSPRNG nonce (`vault.rs:126` `random_nonce_256`),
  `reason_hash` (SHA-256 of the 200-byte-truncated reason, `:41`), TTL clamped to `MAX_TTL` 1 h
  (`:33`), default 60 s (`:36`).
- `BreakGlassLedger` (`:157`) — `issue` (`:201`) and atomic `redeem` (`:243`): remove-under-lock
  → expiry check → scope check (mismatch does NOT consume) → grant; concurrent redeemers race on
  a single map removal so exactly one wins. Guard-hold is deliberate (one-shot guarantee; the
  targeted `clippy::significant_drop_tightening` allow documents it).

**F2.3 wiring** (`crates/cerberus-proxy/src/`): ledger owned by `ApiContext`
(`api.rs:136`, shared control-plane↔data-plane, consistent with the existing shared-state
pattern); `POST /api/break-glass` route (`api.rs:358`) + handler (`api.rs:1172,1195`) — data
route ⇒ requires the admin token when configured (existing control-plane gate, `route_serves_data`);
data plane parses `X-Cerberus-Bypass: break-glass:<nonce>` (`proxy.rs:86,559-599`), redeems with
the request's provider, refuses on `UnknownNonce`/`Expired`/`ScopeMismatch` (request proceeds to
normal scan → blocked), and the audit event gains the `break-glass` flag (`proxy.rs:89,737-738`).

## STEP 3 — Observable zeroization (what a test can prove without `unsafe`)

The workspace forbids `unsafe_code` (closed), so "memory is wiped" is proven by composition:

1. **Type-level containment**: the only owned home of secret bytes in the vault is
   `Zeroizing<String>` (zeroize crate contract: overwritten before free).
2. **Explicit wipe call sites**: `VaultEntry::drop`, `VaultInner::drop`, eviction in `store`,
   `purge_expired_locked`, `zeroize_all`, `unredact` pass 3 all call `wipe()`/`zeroize()`
   before the buffer is freed.
3. **Counted, asserted paths**: `zeroize_all() -> usize` and `purge_expired() -> usize` return
   the number of wiped entries; tests assert the counts and that a subsequent resolve is `None`
   (`vault.rs` tests: `clear_and_zeroize_all`, `expiry_purges_and_zeroizes`,
   `capacity_evicts_oldest_and_zeroizes`, `store_and_resolve_round_trip`,
   `unredact_replaces_tokens_and_consumes`).
4. **Direct overwrite proof**: `wipe_before_drop_clears_value` asserts `expose() == ""` after
   `wipe()` — the buffer content is observably zeroed.
5. **No-leak surface**: no `Clone`/`Serialize` on secret holders; `Debug`/`Display` asserted
   secret-free (`debug_output_never_contains_secret`, `token_display_has_no_secret`,
   `reason_truncated_and_hashed_never_raw`).

## STEP 4 — Verification matrix (all commands verbatim, worktree cwd)

| # | Gate | Command | Result | Exit |
|---|---|---|---|---|
| 1 | fmt | `rtk cargo fmt --all -- --check` | clean (after `cargo fmt --all`) | 0 |
| 2 | clippy | `cargo clippy --workspace --all-targets -- -D warnings` | 0 errors, 0 warnings (fixed 12 pedantic/nursery lints introduced by the new code; 1 documented allow) | 0 |
| 3 | workspace tests | `rtk cargo test --workspace --all-targets` | **680 passed, 0 failed** (baseline 666 + 14 new) | 0 |
| 4a | engine full | `rtk cargo test -p cerberus-engine --all-targets` | 246 passed | 0 |
| 4b | proxy full | `rtk cargo test -p cerberus-proxy --all-targets` | 182 passed | 0 |
| 5 | production pack P/R | `rtk cargo test -p cerberus-packs --test production_pack_pr` | **19/19** | 0 |
| 6 | ReDoS fuzz | `rtk cargo test --release --test redos_fuzz -- --test-threads=1` | **11/11** | 0 |
| 7 | load test | `rtk cargo test --release --test load_test -- --test-threads=1 --nocapture` | **13/13** (no contention flake; 5.63 s) | 0 |
| 8 | e2e break-glass + vault (live daemon) | see STEP 5 transcript | all assertions pass | 0 |
| 9 | whitespace | `rtk git diff --check` | clean | 0 |

New tests (14 net): `vault.rs` 16 (replacing 11 dead-API tests), `break_glass.rs` 9 (replacing
5), `smoke_harness.rs` +4 (`test_break_glass_one_shot_end_to_end` :2126,
`test_break_glass_wrong_provider_scope_rejected` :2238,
`test_reversible_vault_round_trip_request_scoped` :2287,
`test_reversible_redaction_is_opt_in_default_irreversible` :2346), `config.rs` +1
(`reversible_redaction_is_opt_in_and_defaults_off`). One-shot enforcement (second use fails),
unauthenticated issue (401), audit-event emission and zeroization-on-drop/removal are all
directly asserted.

## STEP 5 — e2e transcript (live daemon, release binary, isolated HOME, port 18787)

Environment: release build (`rtk cargo build --release -p cerberus`); mock upstream
(python3 HTTP echo server on 127.0.0.1:19999); isolated `$HOME` (`f2-e2e/home`, untouched user
config); daemon started with `CERBERUS_ADMIN_TOKEN='e2e-admin-token-r9-0123456789abcdef'
CERBERUS_UPSTREAM_URL='http://127.0.0.1:19999' CERBERUS_MODE=enforce ./target/release/cerberus
start --port 18787`; `/health` → 200; daemon log confirms `engine with 15 rules (15 base)`.

| # | Command (abridged) | Result |
|---|---|---|
| 1 | `curl -X POST /api/break-glass -d '{"reason":"unauthenticated attempt"}'` (no token) | **401** — no admin token, no break-glass |
| 2 | `curl -X POST /openai/v1/chat -d '{"…my key is sk-E2Edeadbeefcafebabe12345"}'` | **403** `{"error":"blocked","flag":"secret.openai_api_key"}` (default pack, enforce) |
| 3 | `curl -X POST /api/break-glass -H 'X-Cerberus-Admin-Token: …' -d '{"reason":"e2e emergency: …","provider":"openai","ttl_secs":60}'` | **200** `{"status":"ok","nonce":"106c18ef43ff372d…fa5b6","reason_hash":"sha256:5abdf7d7…","scope":"provider:openai","ttl_secs":60,"expires_at_nanos":1788273874636091000}` — 64-hex nonce; raw reason NOT in the response |
| 4 | data plane: `curl -X POST /openai/v1/chat -H 'X-Cerberus-Bypass: break-glass:<nonce>' -H 'X-Cerberus-Admin-Token: …'` (same secret) | **200** from the mock upstream `{"ok": true, "received_bytes": 80}` — block bypassed; request actually reached the upstream |
| 5 | replay of the SAME nonce (identical command) | **403** `{"error":"blocked","flag":"secret.openai_api_key"}` — one-shot enforced |
| 6 | `curl /api/events -H 'X-Cerberus-Admin-Token: …'` | event with `action_taken: "bypass"`, `flags: ["secret.openai_api_key","bypass","break-glass"]`, `hashed_values` contains `bypass-hash:5abdf7d72d80312e…` = the issuance `reason_hash`; raw reason → **0 hits** |
| 7 | issue `provider:"anthropic"` → redeem against `/openai/…` route | **403** (scope mismatch refuses the bypass; daemon log: `break-glass redemption refused: break-glass token is scoped to another provider (anthropic)`) |
| 7b | SAME token against the RIGHT provider `/anthropic/…` | **200** — scope mismatch did NOT consume the token |
| 7c | replay after that success | **403** — one-shot again |
| 8 | `PUT /api/policy {"rules":{"secret.openai_api_key":"redact"}}` (hot) + request with `sk-E2EROUNDTRIPabc111222333`, echo upstream | **200**; response = upstream echo with the ORIGINAL value restored (un-redaction ran); audit event `action_taken: "redact"` with `hashed_values: sha256:d871c79d…` proves redaction executed (rules out "never redacted") |
| 9 | second request with a different secret | restored correctly; **0 hits** of the first secret — request-scoped vault, no cross-request reuse |
| 10 | leak grep: `grep -rc "sk-E2E…" daemon.log daemon2.log events.json` + `strings cerberus.db \| grep -c sk-E2E` | **0 hits in all four** — no raw secret in logs, event API or the SQLite audit store |

Full raw transcript archived by the builder in `f2-e2e/` (worktree-external temp dir; commands
and outputs quoted verbatim above; the harness tests re-run the same flow hermetically).

## STEP 6 — Acceptance criteria (R9-8 + fix-plan F2.2/F2.3)

| Criterion | Result | Evidence |
|---|---|---|
| Vault secret material zeroized in memory (`Zeroizing`), incl. Drop/removal/expiry; documented lifecycle | **PASS** | `VaultSecret` = `Zeroizing<String>` (vault.rs:65); wipe on consume `:276`, expiry `:373`, eviction `:244`, clear `:413,425`, Drop `:167,201`; lifecycle table vault.rs:38-45; counted assertions in 16 unit tests |
| Vault request-scoped (no cross-request reuse; capacity/TTL per fix-plan) | **PASS** | per-request creation proxy.rs:674; e2e STEP 5 #9; harness `test_reversible_vault_round_trip_request_scoped`; defaults 1024 entries / 5 min TTL |
| Irreversible redaction remains the DEFAULT; vault opt-in (§9 #4) | **PASS** | `reversible_redaction: bool` default `false` (config.rs:66-75); parse + harness tests; e2e STEP 5 #2 (block) and harness opt-in test |
| Break-glass authenticated (admin token per existing control-plane auth) | **PASS** | issuance behind `route_serves_data` gate (api.rs:358,1172); e2e #1 401 without token; data plane additionally requires `X-Cerberus-Admin-Token` (unchanged review-v4 rule) |
| Break-glass one-shot (consumed on use; reuse rejected), atomic under concurrency | **PASS** | `redeem` remove-under-lock (break_glass.rs:243); tests: `replay_rejected_one_shot`, `two_concurrent_requests_exactly_one_wins`, `absent_nonce_rejected`, `expired_nonce_rejected`; e2e #5/#7c |
| Break-glass wired end-to-end (reachable from the live daemon) | **PASS** | e2e STEP 5 with the release daemon: issue → redeem → 200 from upstream → replay 403; nonce never forwarded upstream (bypass header stripped, pre-existing) |
| Break-glass audited (event recorded per plan; reason hashed, never raw) | **PASS** | e2e #6: `action_taken=bypass`, flags `bypass`+`break-glass`, `bypass-hash:<sha256>` = issuance hash; raw reason 0 hits; both mechanisms share the audit path |
| Scope explicit; wrong provider rejected, token not consumed | **PASS** | `BreakGlassScope` (break_glass.rs:55); test `wrong_provider_rejected_and_token_survives_for_right_scope`; e2e #7/7b/7c |
| No secret bytes in logs/errors/Debug/serialized config | **PASS** | no `Serialize` on secret holders; `Debug` redaction tests; e2e leak grep #10 (daemon logs + events + SQLite: 0 hits); `reason_hash`-only issuance |
| Non-guessable tokens (no predictable `v1`) | **PASS** | 128-bit CSPRNG vault ids (`tokens_are_non_guessable`), 256-bit CSPRNG nonce (`nonce_is_cryptographic_and_unique`); e2e nonce 64 hex |
| All existing tests still pass; new tests cover zeroization/one-shot/unauth/audit | **PASS** | matrix #3: 680/680 (baseline 666); coverage listed in STEP 4 |

## STEP 7 — Frozen SHA-256 (touched files, at commit time)

```
fffd67f8f4b91e31cd980bdb3694d850914c833498d0c568ce9e70e4913b08c1  Cargo.lock
803b11327b21c7bcfe5515e03943ffe31470af1a4bdcd55d1243df6cd945776e  crates/cerberus-engine/Cargo.toml
d8f60fa1126ef649c5579abdfcc5877bc004731a2787e4220d701bdcd1a8e2c1  crates/cerberus-engine/src/break_glass.rs
e806d7d072580c2dbfbc26b1f3b3c5242ee15288d5262d2265a6e26c2a64c9a5  crates/cerberus-engine/src/vault.rs
4e0875c6aa2721bc24340c4f3c63e7f6539787a016cd79786feb18b33b8058f9  crates/cerberus-proxy/src/api.rs
58a956a421b4193ad15d71f6d1482a4f31ba0cef5772fdc8ddd17fa870339e1d  crates/cerberus-proxy/src/config.rs
d91957925b06079b5374e85369a8e47f68d413e605ae6319a2e30967a17495fb  crates/cerberus-proxy/src/json_redact.rs
20aa3c43f1de4ec6e6c5281355f80d000ca1d3f5a4726be2ed6e498097bd205b  crates/cerberus-proxy/src/proxy.rs
322cbbd10e12c4493d330311c4530625a386883612d9a74a76eed1de16ec1cb2  crates/cerberus-proxy/tests/smoke_harness.rs
ab443c579712401d64d889c6b4ef301d48b30e7247fa9644bbb791d706943bc4  tests/load_test.rs
```

(`tests/load_test.rs` is a signature-only change: `redact_body` gained the `vault` argument,
call passes `None` — no gate, threshold or payload touched.)

## STEP 8 — Known limits (honest, none threshold-related)

1. **Request-body decode copy**: the proxy's `DecodedBody` still holds the request text in a
   plain buffer (same as the irreversible path). R9-8's text targets vault-owned material; the
   scan-pipeline buffer lifecycle is engine-wide scope (F1/§5 zeroization row), not vault
   zeroization. Documented in `vault.rs:38-45`.
2. **Response splice copy**: un-redaction necessarily writes the original value into the
   response bytes (that is the feature). Those bytes travel the TLS-protected response and are
   never persisted/logged; the vault's own copy is consumed+zeroized right after.
3. **Sub-second TTL allowed at `issue`**: the ledger clamps only the MAX (1 h); sub-second TTLs
   exist for tests. Production issuance via the API clamps to `[1, 3600]` seconds at the
   handler level (`ttl_secs: u64`).
4. **`reversible_redaction` not hot-toggleable** via `PUT /api/config` (preserved on patch,
   like `policy`'s own door); it changes via YAML/startup. API/CLI exposure is F6 parity scope.
5. **`allow-once` CLI command** remains out of F2 (fix-plan F6.4 unit 1); the F2.3 primitive is
   the server-side contract the CLI will call.
6. **No streaming un-redaction**: out of MVP per §9 #5; the proxy buffers responses, so no
   streaming path can bypass the vault lifecycle (fails closed by absence).
7. **Zeroization observability**: the workspace forbids `unsafe`, so memory-wipe is proven by
   the zeroize crate contract + explicit wipe call sites + counted/consumed assertions
   (STEP 3), not by raw memory inspection.

## Builder verdict

**FIX executed — returns to VERIFY.** All nine builder-matrix gates pass with the counts in
STEP 4; the R9-8 finding is addressed without moving any threshold and without inventing scope.
The unit is NOT closed; VERIFY/panel must reproduce STEP 4/STEP 5 from a clean checkout.
