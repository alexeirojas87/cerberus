# F5 Verification — Attempt 1 — CORRECTNESS lens (independent adversarial review)

- **Candidate**: commit `77d6be7` on `r9-remediation` (parent `fa61084`) — R9-10 non-blocking hot-path logging + R9-16 HMAC keyed default
- **Reviewer**: independent correctness lens (did not build; blind to the security lens)
- **Method**: every criterion verified by RUNNING tests in an isolated detached worktree (`/var/folders/.../opencode/f5-attempt1-correctness`), plus two purpose-built runtime probes against the real product code and a live concurrent-boot race. "Couldn't run" did not occur.
- **Date**: 2026-09-01 · Host: macOS darwin (arm64), M-series

---

## 1. Commands run (verbatim, with exit codes)

| # | Command (worktree unless noted) | Result | Exit |
|---|---|---|---|
| 1 | `git -C /Users/alexeirojas/Work/Personal/Cerberus worktree add --detach …/f5-attempt1-correctness 77d6be7` | worktree created | 0 |
| 2 | `rtk cargo fmt --all -- --check` | clean | 0 |
| 3 | `rtk cargo clippy --workspace --all-targets -- -D warnings` | "No issues found" | 0 |
| 4 | `rtk cargo test --workspace --all-targets` (run 1) | **1 FAILED**: `load_test_100kb_phone_list` (p99=675.488 ms > 240 ms debug ceiling) | 101 |
| 5 | `rtk cargo test -p cerberus-hardening --test load_test load_test_100kb_phone_list` ×5 | 5/5 PASS (~3.5 s each) | 0 |
| 6 | same, `--nocapture` ×3 (candidate) | p99 = 71.744 / 71.888 / 72.295 ms | 0 |
| 7 | `git checkout fa61084` (base, in my worktree) + same test ×3 | p99 = 77.719 / 75.226 / 72.122 ms — **statistically identical to candidate** | 0 |
| 8 | `git checkout 77d6be7` (restore candidate) | tree restored, clean | 0 |
| 9 | `rtk cargo test --workspace --all-targets` (retry, machine quiet) | **776 passed, 26 suites, 0 failed** — matches builder claim | 0 |
| 10 | `rtk cargo test -p cerberus-packs --test production_pack_pr` | **19/19** | 0 |
| 11 | `cargo test --release -p cerberus-hardening --test load_test -- --test-threads=1` (attempt 1 — run while my own probes hammered the CPU) | 12 passed, **2 FAILED** (attempt6/7 plan budgets) | 101 |
| 12 | same, clean serial retry | **14/14 PASS** | 0 |
| 13 | `cargo test --release … load_test_f3_3_honest_http_round_trip_gate -- --nocapture` | fingerprint `sha256:e3f206dd…7022` **unchanged**; proxy p99=0.861 ms, direct p99=0.205 ms, **overhead_p99=0.656 ms < 5.0 ms → PASS** | 0 |
| 14 | `rtk cargo test -p cerberus-proxy --lib log::` | **7/7** (incl. no-loss-on-shutdown, blocked-sink, saturated-queue) | 0 |
| 15 | `rtk cargo test -p cerberus --bin cerberus audit_key::` | **5/5** (env precedence, 0600+reuse, corrupt repair, dry-run read-only, hex round-trip) | 0 |
| 16 | `rtk cargo test -p cerberus-store --lib legacy_unsalted_rows_coexist` | 1/1 (coexistence + reopen-on-disk) | 0 |
| 17 | `rtk cargo test -p cerberus --bin cerberus product_engine_wiring` | 1/1 (product path emits only `hmac:`) | 0 |
| 18 | `rtk cargo test --test redos_fuzz` | **11/11** | 0 |
| 19 | `rtk cargo test -p cerberus-hardening --test hotpath_sync_write_gate` | **3/3** | 0 |
| 20 | `for f in proxy.rs forward.rs json_redact.rs decoder.rs shadow.rs detection_policy.rs log.rs; do awk '/#\[cfg\(test\)\]/{exit} /println!|eprintln!|[^_a-z]print!|dbg!/{found++} END{if(found){print "FAIL";exit 1} print "PASS"}' crates/cerberus-proxy/src/$f; done` | **7× PASS** | 0 |
| 21 | external probe `f5-logprobe` (path-dep on candidate's `cerberus-proxy`): `cargo build --release` | built | 0 |
| 22 | `./f5-logprobe fifo` (4 producers × 5 000 events, real product pipeline) | 20 000 emitted / 11 045 landed; **0 out-of-order, 0 duplicates, 0 malformed lines** | 0 |
| 23 | `./f5-logprobe race` ×3 (producers emitting THROUGH `LogGuard::drop`) | ~10.5 M emitted / ~1.4 M landed; FIFO still 0/0 | 0 |
| 24 | two concurrent `HOME=<tmp> cerberus start` boots (fresh config dir) | **both printed `key source: generated + persisted this boot`**; key file intact (0600, 65 B) | 0 |
| 25 | `git diff fa61084..77d6be7 -- tests/redos_fuzz.rs tests/load_test.rs` | **EMPTY** (both files byte-untouched); `MAX_SCAN_TIME_MS=250` still present | 0 |
| 26 | `shasum -a 256` on log.rs / audit_key.rs / store.rs / engine.rs | match the pack's frozen hashes (`026aec3f…`, `bbbfe0bc…`, `85ef6cf2…`, `737b58ca…`) | 0 |
| 27 | `git diff --check fa61084..77d6be7` | clean | 0 |

**On the two first-run failures (row 4 and row 11)**: both occurred under load I caused (row 4: full workspace run on a warm machine; row 11: release suite launched in background while my probes pushed ~10 M events/s through the logging worker). Evidence this is interference, not regression: (a) isolated candidate p99 ≈ 72 ms vs the 240 ms ceiling (3.3× margin); (b) **base commit `fa61084` shows statistically identical p99 (72–78 ms)**, so the debug pathology guard is equally flaky there; (c) clean serial re-runs give **776/776 (exit 0)** and **14/14 (exit 0)**, exactly the builder's numbers. No threshold was moved and no test was touched.

---

## 2. Per-criterion verdicts

| Criterion | Verdict | Evidence |
|---|---|---|
| Gate 1 — `cargo fmt --all -- --check` | **PASS** | exit 0, clean |
| Gate 2 — clippy `-D warnings` | **PASS** | exit 0, 0 warnings |
| Gate 3 — workspace debug tests (builder: 776) | **PASS** (with documented load flake on run 1) | 776 passed / 26 suites / 0 failed on clean retry; base-comparison shows identical flake exposure |
| Gate 4 — `production_pack_pr` (19/19) | **PASS** | 19 passed, exit 0 |
| Gate 5 — full load suite, release, serial, honest HTTP gate (14/14) | **PASS** | 14/14 exit 0 clean serial; honest gate: fingerprint `e3f206dd…` unchanged, overhead p99 **0.656 ms** < 5.0 ms budget with logging active |
| (a) Logging correctness — bounded queue 8 192, try_send lossy, worker flush tick, rate-limited notice, LogGuard shutdown | **PASS with P2s** | 7/7 log tests; structural gate 3/3 + awk 7/7 reproduced (exit 0); probes prove per-producer FIFO, no duplication, no reordering, whole-line atomicity; P2-1/P2-2 below |
| (b) Migration semantics — legacy `sha256:` coexists with keyed `hmac:` | **PASS** | coexistence test 1/1 incl. reopen-on-disk; no cross-scheme comparison path exists (see §4 judgment) |
| (c) HMAC wiring completeness — key reaches EVERY production construction site | **PASS** | call-graph audit: `build_base_engine` (unconditional), `snapshot_engine` boot+worker ×2, policy `build_engine`, `EngineControl::new` (compile+rebase both use it), pack-install/list/rollback, `ApiContext::with_audit_hash_key` (keys break-glass ledger AND bypass hash), CLI dry-run (env→file→ephemeral, never unkeyed). Wiring test 1/1. Every remaining unkeyed `hash_value` site is test-only or unreachable (P2-5 latent note) |
| (d) Key file lifecycle — 5 audit_key tests + concurrency/corruption attacks | **PASS with P2s** | 5/5; atomicity held under concurrent boots (empirical); corrupt repair regenerates but silently (P2-3/P2-4) |
| (e) REDOS-timeout rule — fuzz untouched, NOT equalized | **PASS** | `tests/redos_fuzz.rs` byte-untouched in diff; `MAX_SCAN_TIME_MS=250` intact; 11/11 pass |
| (f) Honest-gate fingerprint / workload untouched | **PASS** | fingerprint `e3f206dd…` reproduced unchanged; `tests/load_test.rs` byte-untouched (empty diff) |

---

## 3. Attack vectors tried (all empirical, against real product code)

1. **Multi-producer FIFO / duplication / reordering** (probe, 4 threads × 5 000 events): 0 out-of-order, 0 duplicated seqs, 0 malformed/interleaved lines across 11 045 delivered lines. Grounded mechanically: tracing-subscriber 0.3.23 (verified in the vendored source, `fmt_layer.rs:1018`) formats each event into a thread-local buffer and issues exactly **one `write_all` per event** → one atomic `try_send` chunk → lines cannot split or interleave; the single worker preserves queue FIFO.
2. **Shutdown race** (probe, producers emitting THROUGH `LogGuard::drop`, 3 runs): the tested claim holds — everything queued before the marker is drained and flushed. But ~10.5 M events emitted *while shutdown was in progress* mostly did not land; the post-disconnect portion is lost **silently and uncounted** (the `TrySendError::Disconnected` arm returns `Ok(len)` without incrementing `dropped`). FIFO still perfect (0/0) during the race. In production `main` holds the guard until return, so the window covers only shutdown-time emissions — same caveat class as `tracing-appender`'s `WorkerGuard`, but partially uncounted (P2-2).
3. **Runtime drops vs old synchronous semantics**: the old path guaranteed every security event reached the console before exit. The new path is lossy by design (fix-plan F5.1 demands it): under saturation an individual `Blocked` event can vanish, leaving only the aggregate count. Additionally the **first drop notice is suppressed for the first 30 s of process life** (`last_notice` initialized at worker start) — empirically ~9 k drops produced **zero notices** in a 2.4 s probe lifecycle (P2-1). Nothing in `main.rs` ever prints `dropped_count()` either, so in a short-lived process drops are effectively invisible.
4. **Cross-scheme dedup confusion** (task b): grepped every consumer of `hashed_values`. The only comparison is intra-event (`event.rs:57`), where all hashes come from one engine → one key → one scheme. Prefixes (`sha256:` vs `hmac:`) make string collision impossible; cross-scheme hash equality is cryptographically impossible. No false match exists; the discontinuity is a documented false-UNIQUE for operator correlation only.
5. **Same-secret double-count across detectors** (task b): pattern findings hash via `payload_hash` (engine.rs:695→736) and entropy findings via `hash_with_secret` (entropy.rs:278) — both with the same key + `AUDIT_EVENT_HASH_DOMAIN` (engine.rs:653 passes `payload_secret`), so the same value found by both detectors produces the same digest and is collapsed by `seen`/`contains` dedup. No double-count.
6. **"Never destroyed / never re-hashed"** (task b): grep found **no UPDATE/migration path touching `hashed_values`** — the store is append-only; legacy rows keep their `sha256:` digests verbatim (coexistence test asserts on-disk survival after reopen). Implemented exactly as documented.
7. **Wiring gaps** (task c): enumerated every `EngineBuilder::new` (production sites all keyed), every `snapshot_engine` caller (daemon boot + pack worker both pass `Some`; the `None` calls are test-module-only, verified against `#[cfg(test)]` line numbers), every `ApiContext` construction (only production site is daemon.rs:529, which chains `with_audit_hash_key`), every `BreakGlassLedger::new` (product ledger is replaced keyed via `with_audit_hash_key` before the server starts), every `EngineControl::new` (daemon passes `Some`; `compile`/`rebase` reuse it). Remaining unkeyed `hash_value` sites: all inside `#[cfg(test)]` or in the unkeyed library fallbacks behind `Option::None` that no production wiring reaches. One latent exception: P2-5.
8. **Concurrent key-file creation** (task d, live): two `cerberus start` on a fresh `$HOME` → **both** printed `generated + persisted this boot`. The tmp+rename held: exactly one complete 0600 / 65-byte file (pid-suffixed tmp names cannot collide; POSIX rename is atomic; readers cannot see torn content). Consequence: last-rename-wins; the loser runs its whole life with an orphaned key — silent cross-boot dedup break for that boot's hashes (P2-3). Reachable on first boot because `pack_install` resolves the key outside the pidfile gate.
9. **Corrupt-file repair** (task d): repair replaces the file with a fresh key. The old content is destroyed — but it was undecodable (no recoverable key material existed), so no *usable* audit key is lost; the documented dedup break applies. However the pack claims "warn + regenerate" and the code has **no warning** (P2-4).
10. **REDOS rule** (task e): diff of `tests/redos_fuzz.rs` is empty; `MAX_SCAN_TIME_MS = 250` untouched; 11/11 pass. The R9-16 rule (do not equalize the fuzz timeout) is honored.

---

## 4. Judgment: migration semantics (the decisive design call)

The chosen semantics — **keep legacy `sha256:` rows readable, write every new row keyed `hmac:`, never re-hash, accept a documented dedup discontinuity** — is the only correct option given that raw values were discarded by design (any transform of an already-weak digest remains dictionary-recoverable, and deleting audit history was rightly rejected). I verified the implementation matches the claim *exactly*: the coexistence test passes (both schemes in one store, legacy scheme intact on disk after reopen), and there is **no code path that compares an old hash against a new hash** — the store treats `hashed_values` as an opaque JSON blob with no index, no UNIQUE constraint, and no UPDATE path. The single comparison (`event.rs:57`) is intra-event and same-scheme by construction. Therefore: a **false match is impossible** (different prefixes; cross-scheme equality would require an HMAC collision), and the only artifact is the documented **false unique** — the same secret seen before and after the migration (or across a key rotation) correlates as two different values. That is precisely the discontinuity the fix plan told the builder to document, and it is documented in the pack, in `audit_key.rs` module docs, and in the store test's rationale. I also confirmed the subtler double-count vector is closed: pattern and entropy detectors share one key and one domain, so a secret caught by both detectors collapses to a single digest inside one event. Verdict: the migration design call is sound and implemented exactly as specified.

## 5. Findings

| ID | Severity | Finding |
|---|---|---|
| P2-1 | P2 | **First dropped-writes notice suppressed for the first 30 s of process life.** `worker_loop` initializes `last_notice = Instant::now()`, so `maybe_report_drops` returns early until 30 s after boot — empirically ~9 k drops, zero notices in a 2.4 s process. Long-lived daemons only lose visibility in their first 30 s; short-lived processes never see a notice, and nothing reads `dropped_count()` at exit. Spec still met (counter exists, notice rate-limited as the plan says), but the notice's practical reach is narrower than the pack implies. |
| P2-2 | P2 | **Shutdown-race emissions can be lost silently and uncounted.** The `Disconnected` arm of `NonBlockingWriter::write` returns `Ok` without incrementing `dropped`. The no-loss guarantee holds exactly for messages queued before the guard drop (the tested and probed scenario); messages emitted while shutdown is in progress are outside it and partially invisible to the counter. Matches the standard `WorkerGuard` caveat; product impact bounded because `main` holds the guard until return. |
| P2-3 | P2 | **Concurrent first-boot key generation race.** Both racing boots generated distinct keys (empirically reproduced); last rename wins, so the loser hashes its entire boot with an orphaned key — silent dedup-correlation break. No corruption/torn file (atomicity verified). Probability low (sub-ms window on fresh install; e.g. `cerberus start` + `cerberus pack install` racing). |
| P2-4 | P2 | **Evidence-pack overstatement on corrupt-key repair**: pack says "warn + regenerate"; `audit_key.rs` emits no warning (indistinguishable from first boot on the boot line). Behavior itself is sound (undecodable file → fresh key; no recoverable key material destroyed). |
| P2-5 | P2 (latent) | **`multiline.rs::detect_multiline` still emits unkeyed `hash_value`** — verified zero production callers (the engine's real multiline path goes through keyed `payload_hash`), so AC-3a holds today, but this is a latent unkeyed hash site if ever wired. |

No P0 or P1 findings. The two first-run gate flakes are environmental (base commit flakes identically; clean re-runs reproduce the builder's numbers exactly) and are not charged against the candidate.

## 6. Final verdict: **PASS**

All five gates pass on clean runs with the builder's exact numbers (fmt clean; clippy 0 warnings; **776/776** workspace tests; **19/19** production pack; **14/14** release load suite with the honest HTTP gate at overhead p99 **0.656 ms** against the untouched 5.0 ms budget and fingerprint `e3f206dd…` unchanged). The two intermittent first-run failures were reproduced, isolated, and traced to machine load — the base commit flakes identically and the candidate shows a 3.3× margin on the affected pathology guard — so they are not regressions, and no threshold was moved by anyone. The adversarial campaign found no correctness violation: the non-blocking writer preserves per-producer FIFO with zero duplication, zero reordering and perfect line atomicity even under saturation and even while shutdown races producers (verified with ~10.5 M-event probes against the real code); the lossy drop behavior is the semantics the fix plan itself mandates; HMAC wiring reaches every production-reachable construction site (verified by call-graph audit, the wiring test, and a grep showing every remaining unkeyed site is test-only or unreachable); the key-file lifecycle is atomic, 0600, and repairs corruption without ever falling back to unkeyed hashing; and the R9-16 governance rule (fuzz timeout not equalized) is honored byte-for-byte. The five P2 findings are quality/robustness notes on the margins of the contract (first-30 s notice suppression, uncounted post-disconnect shutdown emissions, first-boot generation race, a missing warning, one latent dead unkeyed hash site) — none violates an acceptance criterion as written; recording them for the fix-plan backlog is recommended, and none blocks the gate.

---

*Reviewer independence note: this review ran in an isolated detached worktree; the main repository was not modified except this report file. The sibling security-lens report was never read. Report generated 2026-09-01.*
