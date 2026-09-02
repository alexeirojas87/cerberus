# F5 Verification — attempt 1 — SECURITY lens (independent adversarial review)

- Unit: **F5** — R9-10 (non-blocking hot-path logging) + R9-16 (HMAC keyed default)
- Candidate: commit `77d6be7` on `r9-remediation` (parent `fa61084`) · Worktree: `/var/folders/.../opencode/f5-attempt1-security`
- Reviewer: independent security lens (did not build; blind to the correctness lens)
- Date: 2026-09-01/02 · Host: macOS arm64 (darwin), quiet
- Method: every criterion verified by RUNNING tests or live product attacks (release binary, isolated `$HOME` labs, local dummy upstreams). "Couldn't run" = FAIL — nothing in the verdict table below is unrun.

---

## Commands run (verbatim, with exit codes)

| # | Command | Exit | Result |
|---|---|---|---|
| 1 | `git -C /Users/alexeirojas/Work/Personal/Cerberus worktree add --detach /var/folders/.../opencode/f5-attempt1-security 77d6be7` | 0 | worktree created at 77d6be7 |
| 2 | `rtk cargo clippy --workspace --all-targets -- -D warnings` | 0 | 0 warnings (GATE 1 PASS) |
| 3 | `rtk cargo test --release --test redos_fuzz -- --test-threads=1 --nocapture` | 0 | **11/11 PASS** (GATE 2) |
| 4 | `git diff fa61084..77d6be7 -- tests/redos_fuzz.rs` → `wc -c` | 0 | **0 bytes — file untouched** (R9-16 rule) |
| 5 | `rtk cargo test -p cerberus-engine` | 0 | **253 passed** (4 suites) (GATE 3a) |
| 6 | `rtk cargo test -p cerberus-proxy` | 0 | **260 passed** (3 suites) (GATE 3b) |
| 7 | `rtk cargo test -p cerberus-packs --test production_pack_pr` | 0 | **19/19** (GATE 4; note: requires `-p cerberus-packs`, bare `--test production_pack_pr` errors with exit 101 — command in builder matrix omitted the flag) |
| 8 | `cargo build --release -p cerberus` | 0 | release binary for live attacks |
| 9 | `rtk cargo test -p cerberus-engine --lib -- hmac_sha256_rfc_vectors keyed_hash domain_hash entropy_and_pattern` | 0 | 5/5 keyed-semantics tests |
| 10 | `rtk cargo test -p cerberus-engine --lib keyed_ledger` / `different_installation_keys` / `keyed_reason` (3 runs) | 0 | 1/1 each |
| 11 | `rtk cargo test -p cerberus-proxy --lib legacy_bypass` / `strip_hash` | 0 | 1/1 each |
| 12 | `rtk cargo test -p cerberus --bin cerberus product_engine_wiring` | 0 | 1/1 (daemon wiring emits only `hmac:`) |
| 13 | `rtk cargo test -p cerberus --bin cerberus audit_key::` | 0 | 5/5 (env precedence, 0600+reuse, repair, dry-run, hex) |
| 14 | `rtk cargo test -p cerberus-proxy --lib log::` | 0 | 7/7 (off-thread, no-loss shutdown, saturated drop, blocked sink) |
| 15 | `rtk cargo test -p cerberus-store --lib legacy_unsalted` | 0 | 1/1 (coexistence test) |
| 16 | `rtk cargo test --test hotpath_sync_write_gate` | 0 | 3/3 (structural no-sync-write gate) |
| 17 | throwaway crate `/var/folders/.../opencode/rfc-probe` (`cargo run --release`) calling `hmac_sha256`/`domain_hash` from the candidate engine | 0 | **RFC 4231 TC1/TC2/TC3/TC6/TC7 all match** (incl. key>block-size cases); NUL-ambiguity check passes |
| 18 | `python3` cross-check: `HMAC-SHA256(key, domain‖0x00‖msg)` | 0 | byte-exact match of `domain_hash` construction |
| 19 | `HOME=$LAB/home1 ./target/release/cerberus scan $LAB/leak.txt` (PEM + AWS + openai key) | 0 | findings hashed `hmac:` (incl. multiline PEM); **no key file written** |
| 20 | env-override scans ×3 (same key ×2, different key ×1) + `diff` | 0 | deterministic per key, divergent across keys, no file writes |
| 21 | daemon boot matrix (isolated `$HOME`s): boot1 generate / boot2 reuse / corrupt-file / env / read-only-dir | 0 | boot labels observed (see §Attack vectors AV-2…AV-5) |
| 22 | `stat -f "%Sp …/.cerberus/audit-hmac-key"` (homes 3/8/9/10) | 0 | `-rw-------` (0600) at rest on every boot |
| 23 | full E2E: dummy local upstream + `cerberus start` + POST with secrets + `sqlite3` store dump | 0 | store row `hmac:…`; 0 raw secrets in DB; 0 in log; WARN line content-free |
| 24 | python: recompute store digest from persisted key file | 0 | `hmac:c5a286c1…` **byte-exact** = `HMAC(key, "cerberus:audit-event:v1\0sk-abcDEF…")` |
| 25 | E2E legacy bypass: `x-cerberus-bypass: emergency release ticket-88` (local upstream) | 0 | `bypass-hash:0f287bcf…` **byte-exact** = break-glass-domain HMAC; event-domain of same reason differs |
| 26 | saturation AV-7a: fifo sink stalled (~50 lines/s), 2000 sequential finding-bearing requests | 0 | 2000/2000 HTTP 200 in 15 s; queue absorbed all; 0 drops; 0 secret bytes in drained log |
| 27 | saturation AV-7b: 25 000 parallel requests (-P 24), stalled sink | 0 | all served (392 s, ~64 ev/s vs 50 lines/s drain); **24 164 events persisted in SQLite, 100 % `hmac:`, 0 `sha256:`**; no backlog overflow at this rate |
| 28 | umask probe (throwaway `rustc` program replicating `generate_and_persist` byte-sequence, umasks 022/077/000) | 0 | **0644 (umask 022) / 0666 (umask 000) window between `fs::write` and chmod** — see F-1 |
| 29 | `CERBERUS_HMAC_SECRET=doctor-leak-probe-secret ./cerberus doctor | grep -c <secret>` | 0 | **0 occurrences** — env secret never echoed by CLI |
| 30 | `ps -E` / `ps eww` against a process carrying the env override | 0 | env var not shown on this macOS build (documented limitation remains for Linux `/proc`/`ps eww`, same-uid) |
| 31 | `git status --short` (worktree) / `git diff --check fa61084..77d6be7` | 0 | clean / clean — no repo edits by reviewer |

---

## Per-criterion verdicts

| Criterion (security lens) | Verdict | Evidence |
|---|---|---|
| GATE 1 clippy `-D warnings` | **PASS** | cmd 2 |
| GATE 2 redos_fuzz 11/11, file untouched | **PASS** | cmds 3–4 (diff = 0 bytes; last touch predates F5) |
| GATE 3 engine 253 / proxy 260 | **PASS** | cmds 5–6 |
| GATE 4 production_pack_pr 19/19 | **PASS** | cmd 7 |
| (a-i) 32-byte CSPRNG + 0600 persistence | **PASS with finding F-1** | final mode 0600 verified on 4 live boots; creation has an umask race window (0644/0666) + ignored chmod error — F-1 |
| (a-ii) ephemeral fallback cannot occur silently on a normal boot | **PASS with finding F-3** | normal boot (file present) always takes File path (boot2 test); degraded boots print the source label unconditionally, but it is a `println!`, not a WARN, and `scan` output discloses nothing — F-3 |
| (a-iii) env override never leaks into logs/ps | **PASS** | grep over code: only `key_from_env` reads it, never printed/Debug; `doctor` output clean (cmd 29); `ps -E`/`eww` negative on macOS (cmd 30); Linux same-uid visibility documented as inherent limitation |
| (a-iv) corrupt file repaired, never accepted, repair visible | **PASS with finding F-2** | tampered file (`garbage!!not-hex-key…`) rejected + regenerated + rewritten 0600 (live); length+hex validation in `key_from_file` is strict (64 hex); **repair is NOT explicitly logged** — F-2 |
| (b) real HMAC-SHA256, no home-rolled crypto beyond documented wrapper | **PASS** | RFC 2104 construction over `sha2` crate; **5 independent RFC 4231 vectors match** (cmd 17); python cross-check of `domain_hash` byte-exact (cmd 18) |
| (b) domain strings exactly as documented + cross-domain confusion impossible | **PASS** | `cerberus:audit-event:v1` / `cerberus:break-glass:v1` / `cerberus:allowlist:v1` (reserved, unimplemented) — constant grep; domains differ at byte 10 so `domain‖0x00‖msg` preimages can never collide; NUL-ambiguity test; **live**: event-domain vs break-glass-domain digests of the same value differ in the store (cmds 24–25) |
| (c) no production path emits unkeyed `sha256:` on secret material | **PASS with note N-1** | all product wirings keyed (daemon `build_base_engine`/`snapshot_engine`/`build_engine`/`EngineControl`/`ApiContext::with_audit_hash_key`/pack worker/CLI `scan_text` — grep + wiring test + **live**: 24 164/24 164 store rows `hmac:` under flood, CLI scan `hmac:` incl. multiline PEM). Library unkeyed builder unreachable from the daemon binary today (all binary-crate `EngineBuilder::new` call sites pass the key; `packs.rs` uses are `#[cfg(test)]`), but the guard is wiring discipline, not the type system — N-1 |
| (d) legacy rows kept; no new unsalted writes possible | **PASS with finding F-4** | coexistence test passes; live store shows 0 `sha256:` across 24 k events; **but the gate is producer-side only — the store has zero write-time prefix validation** (any regressed/future writer could inject legacy rows) — F-4 |
| (e) no secret bytes in any log path; drop notice content-free | **PASS** | live WARN line = `event_type/action_taken/finding_count/flags/categories/hashes` only (hashes are keyed digests); 0 hits for 3 planted secrets in DB and log (cmds 23, 26); drop-notice format string carries counts only; queue worker never touches payload content (structural) |
| (e) no new at-rest file leaking event content | **PASS** | writer sinks to `io::stdout()` only; live homes contain no log files (find, cmd set 28/30) |
| (e) DoS saturation judgment | **PASS with note N-2** | producer never blocks (2000/2000 and 25 000-parallel floods served with stalled sink); drops counted + rate-limited content-free notice (unit-tested); decisive: **console drops ≠ audit loss — the durable SQLite store kept 24 164 security events during the stalled-sink flood**. Residual: notice defers under continuous saturation (fires on idle tick) and in-memory counter dies with SIGKILL — acceptable per R9-10's lossy text, documented as N-2 |
| (f) redos_fuzz.rs byte-untouched | **PASS** | cmd 4 |

---

## Attack vectors tried (each with observed result)

- **AV-1 — Rainbow/dictionary recovery of low-entropy secrets (the R9-16 core).** Planted `sk-abcDEFghijklmnopqrstuvwxyz1234`, `AKIAIOSFODNN7EXAMPLE`, a fake PEM key. Observed: every digest in CLI output, WARN log lines, and the SQLite store is `hmac:<32B>`; recomputing `sha256(secret)` matches nothing; python recomputation from the *persisted key file* reproduces the store digest byte-exactly. Recovery requires the installation key. **Blocked.**
- **AV-2 — First-boot key substitution.** Booted with empty `$HOME/.cerberus`: label `generated + persisted this boot`; file 0600; second boot reuses (`persisted key file`). An attacker who deletes the file forces regeneration (correlation loss, loud label) but cannot force an unkeyed state — there is no unkeyed fallback anywhere. **Blocked.**
- **AV-3 — Tampered key file.** Overwrote with `garbage!!not-hex-key-at-all-just-junk`: rejected (strict 64-hex check), regenerated, file repaired at 0600, next boot reuses repaired key. Tamper is detected, never accepted. **Blocked** (repair logging gap → F-2).
- **AV-4 — Env-override abuse.** `CERBERUS_HMAC_SECRET` short/low-entropy is accepted by design (explicit operator override); verified it never lands in logs, doctor output, or ps on macOS. Rotation via env works and diverges digests. **Accepted risk, correctly surfaced.**
- **AV-5 — Silent ephemeral daemon.** Read-only `$HOME/.cerberus` → boot continues with ephemeral key, label `ephemeral (per-process, not persisted)`. It cannot happen on a normal boot and it is printed, but it is not a WARN and `scan` output discloses nothing (F-3). **Partially loud.**
- **AV-6 — Key-file permission race (pre-rename window).** Replicated `generate_and_persist`'s exact sequence standalone: with macOS default umask 022 the key hex sits at mode **0644** between `fs::write` and `set_permissions`; umask 000 → **0666**; chmod result is ignored (`let _ =`), so a failed chmod or a crash in the window leaves a world-readable key file. Final state is 0600 (4 live boots). **Window real → F-1.**
- **AV-7 — Sink-starvation DoS on the hot path / silent security-event loss.** Stall the console sink via fifo (~50 lines/s) while flooding finding-bearing requests. Observed: (a) 2000 sequential requests all 200 in 15 s — hot path never blocked (R9-10 core guarantee, live); (b) 25 000-parallel flood: all served, queue backlog absorbed (no overflow at ~64 ev/s vs 50 lines/s), **24 164 security events durably persisted in the audit store, 100 % keyed** — console loss cannot silently destroy the security record; (c) drop counter + rate-limited content-free notice exist (unit-proven; live flood never crossed 8 192-chunk capacity so no notice fired — sustained saturation defers the notice to the next idle tick, N-2). **Acceptable per R9-10; residual documented.**
- **AV-8 — Cross-domain hash transplant.** Tried to correlate a break-glass reason hash with an event hash under the same key: domain strings differ at byte 10 and NUL-delimiting makes `(domain,message)` splits unambiguous; live store bypass-hash matched only the break-glass-domain HMAC, not the event-domain. **Blocked.**
- **AV-9 — Unkeyed-row injection post-migration.** Looked for any store-level rejection of `sha256:` writes: **none exists** — the migration coexistence test itself injects a legacy row through the ordinary writer. Today no production producer can emit one (proven live), so the attack needs a code regression, not a runtime input. **Not exploitable at runtime; gate is not enforced at the store layer → F-4.**
- **AV-10 — Secret leakage via CLI surfaces.** `cerberus doctor`, boot lines, drop notices, and the WARN event schema were grepped for planted secrets and for the raw key: zero occurrences. `KeySource` labels are static strings; `BreakGlassLedger` Debug omits nonces; `ApiContext` (holding the key) has no `Debug` derive. **Blocked.**

---

## Findings

### P0 — none

### P1 — none

### P2

- **F-1 (key-management, P2): creation-time umask race + ignored chmod failure in `generate_and_persist` (`crates/cerberus/src/audit_key.rs`).** `fs::write` creates `audit-hmac-key.tmp-<pid>` with umask-derived mode (0644 under the macOS default umask; 0666 under umask 000 — empirically reproduced, cmd 28) and only afterwards `set_permissions(0o600)`, whose `Result` is discarded. A local same-host attacker winning the window (µs), a crash between write and chmod, or a failed chmod leaves the installation key world-readable. Fix is mechanical: on unix create with `OpenOptions::new().write(true).create_new(true).mode(0o600)` (mode applied atomically at creation) and handle/propagate the chmod error. Final-state 0600 is verified correct on every live boot, hence P2, not P1.
- **F-2 (observability/evidence honesty, P2): corrupt-key repair is not explicitly logged.** The builder pack states "Malformed/corrupt key file → **warn** + regenerate + repair". The code regenerates and repairs correctly (verified live), but `audit_key.rs` has no tracing call and the daemon boot prints only the generic label `generated + persisted this boot` — indistinguishable from a first boot. Operators lose the signal that dedup correlation broke at the corruption boundary. Add a distinct warn (e.g. "audit key file was corrupt — regenerated; correlation with prior hashes lost").
- **F-3 (observability, P2): ephemeral fallback is under-signalled.** A daemon that cannot persist the key boots with an ephemeral key; the only signal is the boot-line label (a `println!`, same visual weight as every other boot line, not captured by tracing into persistent logs), and `cerberus scan/test` dry-run output does not disclose at all that its hashes are per-process and non-comparable. A normal boot (file present) never reaches this state (verified), so this is loudness, not silence — recommend `tracing::warn!` on `Generated`/`Ephemeral` sources plus a marker line in dry-run output.
- **F-4 (hardening, P2): the legacy-row "prefix-gate" is producer-discipline only; the store does not enforce it at write time.** `cerberus-store` has zero validation of `hashed_values` schemes (the coexistence test itself writes a `sha256:` row through the ordinary writer). No runtime input can inject one today (all producers keyed — proven across 24 k live events), but any future/regressed writer reintroduces R9-16 silently. Cheap fix: reject/rewrite `sha256:`-prefixed entries in `write_event` (or log-warn) with an explicit `allow_legacy` flag for migration tooling.
- **N-1 (note, no action required for this gate): the unkeyed engine builder is a library affordance guarded by wiring discipline, not by the type system.** It is unreachable from the daemon binary today (verified: every binary-crate construction passes the installation key; remaining unkeyed constructions are `#[cfg(test)]` or validate-only compile checks), and the daemon wiring test plus the live 24 k-row flood prove the product path. Also: `multiline.rs::detect_multiline` is dead code (own tests only) that still hashes with unkeyed `hash_value` — a latent trap if ever wired; delete it or key it. A cheap permanent guard would be a warn (or debug_assert) inside `payload_hash` when `payload_secret` is `None` in release builds.
- **N-2 (note): drop-notice deferral under sustained saturation.** The notice fires from the worker's idle tick (≥30 s apart); under continuous saturation it is deferred until the backlog drains, and the in-memory dropped counter is lost on SIGKILL. Console drops never endanger the durable audit record (separate SQLite writer held 24 164/24 164 events during the stalled-sink flood). Judged acceptable under R9-10's lossy, counted, content-free design.

---

## Final verdict

**PASS.** All four §8B gates pass exactly as specified (clippy clean; redos_fuzz 11/11 release with the file byte-untouched per `git diff` = 0 bytes; engine 253 / proxy 260; production_pack_pr 19/19 — noting the bare command in the builder matrix misses `-p cerberus-packs` and exits 101, a documentation nit only). The R9-16 security core is genuinely fixed and I could not break it: the HMAC is real RFC 2104 HMAC-SHA256 over the `sha2` crate (5 independent RFC 4231 vectors including >block-size keys match; the `domain‖0x00‖msg` wrapper matches an external python computation byte-for-byte); the installation key is 32-byte CSPRNG, persisted 0600 (verified on four live boots), repaired when corrupt (never accepted), overridable via env without leaking into logs, doctor output, or process listings; and the live end-to-end chain — CLI scan, daemon engine, entropy detector, break-glass ledger, legacy bypass — produced **zero unkeyed hashes across ~24 200 audited events**, with store digests reproducible externally only with the persisted key, and event vs break-glass domains provably non-interchangeable. The R9-10 core guarantee held under direct attack: with the console sink starved at ~50 lines/s, 25 000 parallel finding-bearing requests were all served without blocking, drops are counted with a content-free rate-limited notice, and — decisively — every security event still reached the durable audit store, so lossy console logging cannot silently destroy the security record. The five P2 findings (umask race on key-file creation with ignored chmod error; unlogged corrupt-key repair; under-signalled ephemeral mode; store-level absence of the legacy prefix-gate; plus the dead unkeyed `detect_multiline` path) are real but none weakens the keyed-default property that R9-16 mandates, none blocks release, and each has a mechanical fix; I recommend they be queued as follow-up hardening, with F-1 (atomic 0600 creation) prioritized.

*Reviewer hygiene: no code, test, or threshold was modified; the only repo write is this report; the worktree was used read-only for builds/tests; live labs ran under throwaway `$HOME`s with local dummy upstreams — one early bypass probe reached api.openai.com with a dummy bearer and a made-up test string before the upstream was corrected to localhost (disclosed for honesty; no real secret was transmitted).*
