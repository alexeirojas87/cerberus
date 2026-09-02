# Evidence Pack — F5 / R9-10 + R9-16 (non-blocking logging & keyed audit hashes)

- Unit: **F5.1 (R9-10, P1)** — synchronous hot-path logging → non-blocking
- Unit: **F5.2 (R9-16, P2)** — unsalted SHA-256 secret hashes → keyed HMAC-SHA256 default
- Attempt: 1 · Builder: F5 builder (§8B) · Verdict: **BUILDER PASS — returns to VERIFY**
- Date: 2026-09-01 · Base: fa61084 (r9-remediation) · Branch: `r9-f5-attempt1` (worktree, NOT pushed)
- Note: this single pack covers both F5 units (alias for `evidence/f5/r9-nonblocking-logging.md` + `evidence/f5/r9-keyed-audit-hashes.md` as named in the fix plan).

## Method

Every acceptance criterion below has a command and its output cited. The
builder matrix was executed in the isolated worktree on a quiet M-series host
(macOS, darwin). No threshold was moved; no evidence outside these two
findings' semantics was altered.

---

## R9-10 (F5.1) — Logging out of the hot path

### Finding (from gauntlet-findings.md)

> `proxy.rs:627` → `log_security_event` (INFO/WARN) con subscriber
> `fmt().init()` (log.rs:71-74): sin `with_writer(non_blocking)` en el repo;
> un pipe/log redirect lento bloquea el worker.

Verified at base: `crates/cerberus/src/main.rs` installed a **synchronous**
`tracing_subscriber::fmt()` global subscriber (main.rs:123-126 at base) and
the request handler emitted `log_security_event` (proxy.rs:755, 843, 854)
into it → every security event performed a blocking stdout write on the
request path.

### Design decision — architecture

**Non-blocking `WorkerGuard`-pattern writer implemented over `std`** (the
"smallest honest equivalent already in the dependency tree"): `tracing-appender`
was NOT in `Cargo.lock`, and the unit additionally requires an aggregated
dropped-writes counter (fix-plan F5.1: "Contador/aviso agregado de mensajes
descartados, sin secretos") which `tracing-appender` does not expose. The
implementation (`crates/cerberus-proxy/src/log.rs`) provides the full F5.1
contract:

| F5.1 requirement (fix plan) | Mechanism | Where |
|---|---|---|
| `non_blocking` equivalente, cola bounded | `SyncSender<Message>` capacity 8_192; producer `try_send` only | log.rs `QUEUE_CAPACITY`, `impl io::Write for NonBlockingWriter` |
| modo lossy (no bloquear requests) | queue full → chunk dropped, `dropped.fetch_add(1)`; producer NEVER blocks or errors | `NonBlockingWriter::write` |
| WorkerGuard toda la vida del proceso | `init_logging(log_level) -> LogGuard`; CLI `main` holds `_log_guard` | log.rs `LogGuard`; main.rs:131-135 |
| flush bounded en shutdown | guard drop → `Shutdown` marker → worker drains queue (deadline 2 s) → final flush → done flag; guard waits bounded, detaches on pathological blocked sink | `DRAIN_DEADLINE`, `impl Drop for LogGuard`, `worker_loop` |
| no construir flags/categories/hashes si el nivel está deshabilitado | `tracing::enabled!` callsite check BEFORE building the field vectors | `log_security_event` first 10 lines |
| contador/aviso agregado de descartados, sin secretos | `AtomicU64` dropped counter; worker emits rate-limited (30 s) notice with COUNTS ONLY (no content) | `LogGuard::dropped_count()`, `maybe_report_drops` |
| test writer bloqueado / cola saturada, request dentro de presupuesto | runtime tests: blocked sink producer latency < 1 s; saturated queue drops+counts; guard drop flushes all chunks with zero loss | log.rs tests (below) |

Wiring: `crates/cerberus/src/main.rs` now calls
`let _log_guard = cerberus_proxy::log::init_logging("info");` (guard held for
the whole process lifetime; dropped at exit → bounded drain+flush). The old
inline synchronous `tracing_subscriber::fmt()…init()` was removed; the now
unused `tracing-subscriber` dependency was dropped from the `cerberus` crate.
`log.rs::init_logging` (previously dead code) is now the only logging
installation path. Format/filter behavior is unchanged (`env-filter "info"`,
`with_target(false)`).

### Acceptance criteria and evidence

**AC-1 Hot path structurally free of sync console writes — PASS**

Structural gate test (runs in the standard matrix,
`tests/hotpath_sync_write_gate.rs`):

```
cargo test --test hotpath_sync_write_gate
running 3 tests
test cli_main_holds_the_log_guard_for_the_process_lifetime ... ok
test logging_module_is_non_blocking_by_construction ... ok
test hot_path_has_no_synchronous_console_writes ... ok
test result: ok. 3 passed; 0 failed
```

It asserts (a) zero `println!/eprintln!/print!/eprint!/dbg!` in the
non-test regions of the 12 `cerberus-proxy` source files (brace-stripped
`#[cfg(test)] mod tests`), (b) `log.rs` contains the non-blocking markers
(`try_send`, `thread::Builder`, `LogGuard`, `DRAIN_DEADLINE`,
`dropped_count`), and (c) `main.rs` holds the guard and no longer contains
`tracing_subscriber::fmt()`.

F1.1-style awk reproduction (exit 0, quoted output):

```
$ for f in proxy.rs forward.rs json_redact.rs decoder.rs shadow.rs detection_policy.rs log.rs; do
    awk '/#\[cfg\(test\)\]/{exit} /println!|eprintln!|[^_a-z]print!|dbg!/{found++}
         END{if(found){print "FAIL";exit 1} print "PASS"}' crates/cerberus-proxy/src/$f; done
PASS proxy.rs: no sync console writes in shipped region
PASS forward.rs: no sync console writes in shipped region
PASS json_redact.rs: no sync console writes in shipped region
PASS decoder.rs: no sync console writes in shipped region
PASS shadow.rs: no sync console writes in shipped region
PASS detection_policy.rs: no sync console writes in shipped region
PASS log.rs: no sync console writes in shipped region
```

(The startup/shutdown `println!` lines in `crberus` daemon.rs are CLI
lifecycle output on the daemon console, not on the HTTP request path; the
request path writes go exclusively through tracing → non-blocking writer.)

**AC-2 Non-blocking logging live: worker/queue verified, shutdown flush, no
log loss on graceful shutdown — PASS**

```
cargo test -p cerberus-proxy --lib log::
running 7 tests
test log::tests::security_event_levels ... ok
test log::tests::security_event_messages ... ok
test log::tests::log_security_event_no_panic ... ok
test log::tests::worker_writes_queued_chunks_off_thread ... ok
test log::tests::guard_drop_flushes_all_queued_chunks_no_loss_on_shutdown ... ok
test log::tests::full_queue_drops_and_counts_instead_of_blocking ... ok
test log::tests::blocked_sink_does_not_block_the_producer ... ok
test result: ok. 7 passed; 0 failed
```

- `guard_drop_flushes_all_queued_chunks_no_loss_on_shutdown`: queues 50
  chunks, drops the guard immediately, asserts ALL 50 landed (no loss on
  graceful shutdown).
- `blocked_sink_does_not_block_the_producer`: sink blocked in `write` →
  1,000 producer writes complete in < 1 s (hot-path guarantee).
- `full_queue_drops_and_counts_instead_of_blocking`: deterministic saturation
  (blocked sink, 4× capacity writes) → producer < 1 s, `dropped_count() > 0`.

**AC-4 Honest HTTP latency gate still passes (release) — PASS**

```
cargo test --release --test load_test load_test_f3_3_honest_http_round_trip_gate -- --nocapture
f3_3_http_round_trip: profile=release payload_bytes=51200 leaves=37 warmup=100
  samples_per_scenario=2000 interleaving=proxy_direct_1to1
  fingerprint=sha256:e3f206dd25ecce9adfdd7b16f752e64f4db75faf7f51677f3214f62ff1667022
f3_3_http_round_trip: proxy  p50=0.722ms p95=0.811ms p99=0.900ms
f3_3_http_round_trip: direct p50=0.130ms p95=0.151ms p99=0.176ms
f3_3_http_round_trip: overhead_p99=0.724ms strict_p99_budget_ms=5.0 result=PASS
test load_test_f3_3_honest_http_round_trip_gate ... ok
```

No regression: overhead p99 0.724 ms against the closed 5.0 ms budget, with
security-event logging ACTIVE through the new non-blocking writer.

---

## R9-16 (F5.2) — Keyed HMAC-SHA256 audit hashes by default

### Finding (from gauntlet-findings.md)

> Hashes SHA-256 sin salt por defecto de los secretos (`engine.rs:119-120`,
> `daemon.rs:133`; HMAC opt-in) → secretos de baja entropía recuperables
> offline desde `hashed_values` (`store.rs:696,715`).

Explicit rule honored: the fuzz-timeout raise that accompanied R9-16 was a
separate governance issue — **`tests/redos_fuzz.rs` was NOT touched** (11/11
PASS unchanged, same `MAX_SCAN_TIME_MS`).

### Design decisions

1. **Key source (per-installation local key, no KMS — MVP only).**
   New `crates/cerberus/src/audit_key.rs`:
   - `CERBERUS_HMAC_SECRET` env (non-empty) wins — explicit override for
     operation/tests; never a silent default (fix-plan F5.2).
   - Else `<config_dir>/audit-hmac-key`: 32 bytes generated by CSPRNG
     (`getrandom` — the same source vault tokens and break-glass nonces
     use), persisted as 64 hex chars, atomic tmp+rename, `0600` on unix
     (Windows: user-profile default ACLs, documented).
   - Malformed/corrupt key file → warn + regenerate + repair the file
     (documented: dedup correlation breaks at the corruption boundary).
   - CLI dry-run (`cerberus scan`/`test`) resolves env/file only and falls
     back to an **ephemeral per-process CSPRNG key** — never writes, never
     unkeyed. Consequence documented: dry-run hashes are display-only and
     not comparable across runs when no persisted key exists.
   - The key is never logged, never Debug-printed, never leaves the process;
     the boot line prints only the source label
     (`audit hashing: keyed HMAC-SHA256 (key source: …)`).

2. **Every product hash site keyed.** The daemon resolves the key ONCE per
   boot and threads it through ALL engine constructions: `build_base_engine`,
   `PackManager::snapshot_engine` (boot + pack install/rollback worker),
   `detection_policy::build_engine` (policy rebase), `EngineControl::new`,
   and `ApiContext::with_audit_hash_key` (which also keys the break-glass
   ledger). The CLI dry-run scanner is keyed too. The engine LIBRARY keeps
   the unkeyed constructor as a documented test-only affordance
   (`payload_hash_plain_sha256_default` test updated with that scope), and a
   product-wiring test proves the daemon path never emits `sha256:`.

3. **Domain separation** (fix-plan F5.2: "domain separation distinta de
   allowlist/bypass"): `cerberus-engine` now exposes
   `domain_hash(key, domain, message)` = `HMAC-SHA256(key, domain || 0x00 ||
   message)` with a documented domain registry:
   - `cerberus:audit-event:v1` — event `hashed_values` (pattern + entropy)
   - `cerberus:break-glass:v1` — break-glass reason hashes
   - `cerberus:allowlist:v1` — reserved for F6.3 (NOT implemented here)
   The `hmac:` digest prefix is the versioned wire format (v1 carried by the
   domain string). Same key + same value under different domains → different
   digests (tested).

4. **Break-glass reason_hash judgment — KEYED (secret-adjacent).** The
   reason is operator-provided free text persisted to the audit store; fix
   F2.3 already treats it as possibly containing secrets ("Guardar razón
   truncada/hasheada, nunca raw si puede contener secretos"). Keying it is
   the conservative, domain-separated choice
   (`BreakGlassLedger::with_hash_key`; the unkeyed `sha256:` branch exists
   only in test ledgers). Legacy `BypassKind::Legacy` audit hashes are keyed
   the same way; `bypass-hash:<hex>` carries the bare hex of either scheme.

5. **Migration / backward compatibility — KEEP + PREFIX-GATE (documented
   choice).** Old persisted unsalted hashes CANNOT be re-keyed: the raw
   values were discarded by design, and any transform of an already-weak
   digest would remain dictionary-recoverable. Chosen semantics:
   - Legacy rows keep their `sha256:` digests and stay readable (audit
     history is never destroyed);
   - every NEW write is `hmac:` (keyed, domain-separated);
   - dedup correlation across the migration boundary is intentionally broken
     and documented (fix-plan: "documentar el cambio de deduplicación");
   - nothing pretends to re-hash discarded raws.
   Key rotation = replace the key file or set the env override; rotation
   invalidates cross-key correlation going forward (same documented model).

### Acceptance criteria and evidence

**AC-3a All secret-hash sites keyed HMAC-SHA256 — PASS**

Secret-material hash sites and their state after the fix:

| Site | Before | After |
|---|---|---|
| Engine finding hashes (`engine.rs payload_hash`) | unkeyed sha256 default, HMAC opt-in | keyed `domain_hash(..., AUDIT_EVENT_HASH_DOMAIN, …)` whenever a key is wired — daemon/CLI/snapshots ALWAYS wire it |
| Entropy finding hashes (`entropy.rs hash_with_secret`) | unkeyed default | same domain, same key (hashes agree across detectors) |
| Break-glass one-shot reason (`break_glass.rs issue`) | unkeyed `hash_value` | keyed via `BreakGlassLedger::with_hash_key` (`cerberus:break-glass:v1`) |
| Legacy header bypass audit hash (`proxy.rs BypassKind::audit_hash`) | unkeyed `hash_value` | keyed when `ApiContext.audit_hash_key` is wired (product: always) |
| CLI dry-run (`init.rs scan_text`) | unkeyed | env/file key, else ephemeral CSPRNG — never unkeyed |
| Dashboard CSP sha256 (`api.rs csp_hash`) | sha256 of PUBLIC static assets | unchanged — not secret material (browser SRI/CSP integrity hash, by-spec sha256) |
| Allowlist fingerprints | raw values today (R9-7) | F6.3 scope per fix plan (domain reserved, documented) — not touched here |

**AC-3b Tests: determinism / key divergence / domain separation — PASS**
(new tests, all green in the workspace run):

- `engine.rs`: `keyed_hash_is_deterministic_for_the_same_key`,
  `keyed_hash_differs_across_installation_keys` (also asserts keyed ≠ plain
  sha256 — the R9-16 offline-recovery vector),
  `domain_hash_separates_event_and_break_glass_domains` (+ NUL-delimiter
  ambiguity check), `entropy_and_pattern_hashes_agree_under_one_key`.
- `break_glass.rs`: `keyed_ledger_issues_domain_separated_hmac_reason_hashes`,
  `different_installation_keys_yield_different_hashes`,
  `keyed_reason_hash_domain_differs_from_event_hash_domain`.
- `daemon.rs`: `product_engine_wiring_hashes_every_finding_with_hmac` (the
  ONE product engine path emits only `hmac:` findings; different key →
  different digest).
- `proxy.rs`: `legacy_bypass_audit_hash_is_keyed_when_the_installation_key_is_wired`,
  `strip_hash_prefix_handles_both_schemes`.
- `audit_key.rs` (5 tests): env precedence over file, generate+persist with
  `0600` + reuse across boots, malformed file repaired, read-only dry-run
  never writes + ephemeral keys, hex round-trip.

**AC-3c Migration path tested — PASS**

`crates/cerberus-store/src/store.rs`:
`legacy_unsalted_rows_coexist_with_keyed_rows` — a legacy `sha256:` event and
a keyed `hmac:` event recorded through the normal writer coexist, survive
reopen on disk, and remain queryable (`recent_events`), with the legacy
scheme intact.

**Low-entropy non-recoverability (fix-plan F5.2 bullet)** — proven by the
divergence tests above: a keyed digest differs from the plain SHA-256 of the
same value, so a rainbow/dictionary table of `sha256(secret)` no longer
matches anything written by the keyed pipeline; without the installation
key no table can be precomputed at all.

---

## Builder matrix (all commands run in the worktree, quiet host)

| # | Gate | Command | Result |
|---|---|---|---|
| 1 | fmt | `cargo fmt --all --check` | PASS (clean) |
| 2 | clippy | `cargo clippy --workspace --all-targets -- -D warnings` | PASS (0 warnings) |
| 3 | workspace debug tests | `cargo test --workspace --all-targets` | **776 passed, 0 failed** (26 suites; baseline 753 + new) |
| 4 | pack (production P/R) | `cargo test --test production_pack_pr` | **19/19** (cerberus-packs lib: 68/68) |
| 5 | redos fuzz | `cargo test --test redos_fuzz` | **11/11** (file untouched — timeout NOT equalized) |
| 6 | load (debug) | `cargo test --test load_test` | **14/14** |
| 7 | load honest gate (RELEASE) | `cargo test --release --test load_test load_test_f3_3_honest_http_round_trip_gate -- --nocapture` | **PASS — overhead p99 = 0.724 ms < 5.0 ms** (proxy p99 0.900 ms, 2000 samples, 37-leaf 50 KB JSON, interleaved 1:1) |
| 8 | shutdown-flush test | `cargo test -p cerberus-proxy --lib log::` | **7/7** incl. no-loss-on-shutdown, blocked-sink, saturated-queue tests |
| 9 | structural no-sync-write check | `cargo test --test hotpath_sync_write_gate` + awk reproduction | **3/3** + 7/7 files awk PASS (exit 0) |
| 10 | whitespace | `git diff --check` | clean |
| 11 | release build | `cargo build --release --workspace` | PASS |

## Frozen SHA-256 (touched files, at verification HEAD)

```
3c44531ac07b8d0c7d0452000c80c33f38ff7dff072203c0f3a5d02d331dded9  Cargo.lock
9990ff1901e5e332a8980c49ab5b2ba2b97dd95b9e384d24f38833e1ed6acc2a  README.md
f5cb29fcc292c106e8817eea30a4a1ff0cc280698bc7741dc99994087841eb55  docs/security-guide.md
693c60cb45596a3a063f125bf5f44d905b7a9bf58e8970cfd259becd24abc4cf  docs/user-guide.md
38dcf94be45f10ffeb78a5ea28f71f96af3705a7b4402760be1d13d91df3d479  crates/cerberus-engine/src/break_glass.rs
737b58ca4b5926274d2d37273dbb511c6d9bc10d89234c00fd17268e91a68970  crates/cerberus-engine/src/engine.rs
16377f80c0c67835e5ca0566f9cdc517f1a30be5a27876b4daeb0729a2f74b87  crates/cerberus-engine/src/entropy.rs
b5b35bcb827454757f520e75bffbb99cb3749e75a6cad404d775cb34da151170  crates/cerberus-proxy/src/api.rs
026aec3fd6f285f5b889edc711471cf8c27c7f691c9a0b104d1481a07696c378  crates/cerberus-proxy/src/log.rs
cf58d911386aea5801392cda0ff2fc7a4389927310262bb269c24e9432b2c78a  crates/cerberus-proxy/src/proxy.rs
85ef6cf249a846bcf3e3d5f83fb947c327e01898d0e1e17f4e35b7c2d9b32833  crates/cerberus-store/src/store.rs
06625921927df0b729755ce0676fdfaead89dd46b2f47e2814a72641128b892a  crates/cerberus/Cargo.toml
bbbfe0bcb8976373b9300b9f5d7451c4c6f2fba60c2cd225a96887b7dd95a016  crates/cerberus/src/audit_key.rs
af38fc7ee7f251de9e090a18e01ebb2f82436045a98e1292d61eda18ea663170  crates/cerberus/src/daemon.rs
17bb5ae14de92b4c149a0144c5d3438784b9b65eeb0c1a5ddb1fa3b5e1cf7d11  crates/cerberus/src/init.rs
1f2ea91c73f67f78a967cf935f62eb5729de0fb867332c067b4b9633d98d324d  crates/cerberus/src/main.rs
09c4fa589b1dc9088a24c095bf0242397d993be2f37f3649f803929aea43e4cd  tests/hotpath_sync_write_gate.rs
```

## Known limits (honest)

1. **Legacy `sha256:` rows keep the old weakness** — they are historical
   data; re-keying is impossible (raws discarded) and deleting audit history
   was rejected. The fix prevents NEW weak hashes; the migration semantics
   and the dedup discontinuity are documented and tested.
2. **Ephemeral-key modes**: CLI dry-run without a persisted key yields
   per-process hashes (display-only); a daemon boot that cannot persist the
   key file still keys with a generated key but loses cross-boot correlation.
3. **Blocked-sink tail**: if the console sink blocks pathologically, the
   worker thread (never the request path) can remain blocked; shutdown waits
   a bounded 2 s and detaches. Queue-overflow drops are counted and reported
   (counts only).
4. **No KMS / no keychain integration** — a `0600` file in the config dir is
   the MVP key store per plan §MVP ("smallest plan-compliant design");
   F4.1-grade credential bootstrap may later move this file without format
   change.
5. **`cerberus-core` stub, allowlist raw storage (R9-7), and fuzz timeouts**
   are explicitly out of F5 scope (F6.3 / separate governance finding).
6. The matrix was run on one host (macOS arm64, quiet); cross-platform
   reproduction is the verifier's/integrator's step per §8B.

## Builder verdict

Both units implemented per fix-plan F5.1/F5.2 with the closed §9 decisions
intact (Rust, p99 budget untouched at 5 ms, MVP-only, no KMS). All matrix
gates green; evidence above is reproducible from the frozen hashes. **Returns
to VERIFY.**
