# Evidence — F5 integration review (R9-10 + R9-16 candidate)

- Candidate: `099c470` @ `origin/r9-remediation` (clean clone)
- Date: 2026-09-01 · Host: macOS arm64 (Apple M4 Pro) · `rustc/cargo 1.97.1`
- Provenance: battery executed inline by the orchestrator gatekeeper
  (established pattern after the session's sub-agent transport failures);
  outputs captured verbatim in the transcript.

## Remote state

- Clone HEAD = `099c4703216bf61c7f4069b53459eb07d62aff71`; clean tree.
- Containment intact: `release.yml` / `notify-tap.yml` inert.

## Frozen-hash verification

- Panel reports verified the attempt-1 frozen hashes for all 18 touched files
  (builder pack `evidence/f5/r9-logging-and-hmac.md`); the integration clone
  matches the pushed candidate by construction (clean clone at HEAD).
- `tests/redos_fuzz.rs` byte-untouched (R9-16's explicit rule) — verified by
  both lenses via git diff.

## Full battery (clean clone, sequential)

| Command | Exit | Result |
|---|---|---|
| `cargo fmt --all -- --check` | 0 | clean |
| `rtk cargo clippy --workspace --all-targets -- -D warnings` | 0 | 0 issues |
| `rtk cargo test --workspace --all-targets` (debug) | 0 | **776 passed / 0 failed** (26 suites) |
| `rtk cargo test --release -p cerberus-packs --test production_pack_pr -- --test-threads=1` | 0 | **19/19** |
| `rtk cargo test --release --test redos_fuzz -- --test-threads=1` | 0 | **11/11** |
| `rtk cargo test --release --test load_test -- --test-threads=1` | 0 | **14/14** |
| `rtk proxy cargo test --release --test load_test load_test_f3_3_honest_http_round_trip_gate -- --nocapture --test-threads=1` | 0 | honest HTTP gate **PASS**: p99 **0.839 ms** vs strict 5.0 ms |
| `rtk proxy cargo test --release -p cerberus-proxy --test smoke_harness -- --test-threads=1` | 0 | **63/63** |
| `rtk proxy cargo test --release --test hotpath_sync_write_gate -- --test-threads=1` | 0 | **3/3** (no-sync-write structural gate) |
| `git diff --check` | 0 | clean |

## Verdict: PASS

R9-10 (non-blocking hot-path logging: bounded queue, single worker,
WorkerGuard-pattern shutdown with bounded drain, dropped-writes counter with
rate-limited content-free notice) and R9-16 (HMAC-SHA256 keyed default with
domain separation, persisted 0600 key file, legacy rows kept readable +
prefix-gated, break-glass reason keyed) are independently verified:
panels 2/2 PASS (no P0/P1; 9×P2 follow-ups registered), structural no-sync
gate green, shutdown-flush suite green, security lens confirmed real
RFC-4231-conformant HMAC with key reach into every production construction
site and durable persistence of 24,164 security events under console-sink
flood. All prior-phase guarantees re-confirmed.

## Follow-ups registered (P2, non-blocking)

- Key-file creation race window: `fs::write` umask-dependent mode before
  chmod (fix: `OpenOptions::create_new(true).mode(0o600)`); chmod Result
  ignored — folded into F6 builder scope as an authorized hygiene item.
- First 30 s drop-notice suppression (~9k drops, zero notices observed);
  shutdown-race emissions lost silently and uncounted; concurrent-boot key
  race (last rename wins); corrupt-key repair not logged (pack overstates
  "warn + regenerate"); ephemeral fallback not WARN-labeled; store-level
  write gate on `sha256:` rows missing (producer discipline only); latent
  unkeyed hash in dead `multiline.rs::detect_multiline`.
