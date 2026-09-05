# Evidence — F3 integration review (F3.3 + F3.1/F3.2 candidate)

- Candidate: `5ac2564` @ `origin/r9-remediation`
- Clone path: `/var/folders/.../opencode/f3-integrator-clone` (clean clone from origin)
- Date: 2026-09-01
- Host: macOS (Darwin), arm64, Apple M4 Pro
- Toolchain: `rustc 1.97.1`, `cargo 1.97.1`

## Provenance note (transport failures)

As in the F2 integration review, the integration-reviewer sub-agent role was
executed inline by the orchestrator gatekeeper after the session's repeated
long-task sub-agent transport failures. Every command below ran on the clean
clone with output captured verbatim in the session transcript; the owner signs
the gate with the raw outputs plus the panel reports visible.

## Remote state

- Clone `HEAD = 5ac25640560eb88360b8c571742c42f9d895d385`; `git status` clean
  throughout.
- **Containment intact**: `release.yml:14` and `notify-tap.yml:7` both
  `"on": []`; single jobs guarded by `if: ${{ false }}`.

## Frozen-hash verification

- `evidence/f3/r9-mode-failpolicy-multipart-wirename.md` attempt-2 block
  (decoder.rs, forward.rs, json_redact.rs, log.rs, proxy.rs, smoke_harness.rs,
  daemon.rs): **7/7 OK**.
- Whole-pack check (18 lines = attempt-1 + attempt-2 blocks): 12 OK; the 6
  FAILED lines are exactly the attempt-1 hashes of the 6 files re-frozen by
  attempt 2 — every mismatch explained by the re-freeze chain (attempt-2 lines
  of the same files all OK).
- Earlier-phase files verified in the F2 integration review remain untouched
  where this phase did not modify them (F3 attempt-1 re-froze config.rs/api.rs
  — their new hashes were verified OK in the whole-pack check above).

## Full battery (clean clone, sequential, quiet-host discipline)

| Command | Exit | Result |
|---|---|---|
| `cargo fmt --all -- --check` | 0 | clean |
| `rtk cargo clippy --workspace --all-targets -- -D warnings` | 0 | 0 issues |
| `rtk cargo test --workspace --all-targets` (debug) | 0 | **753 passed / 0 failed** |
| `rtk cargo test --release -p cerberus-packs --test production_pack_pr -- --test-threads=1` | 0 | **19/19** |
| `rtk cargo test --release --test redos_fuzz -- --test-threads=1` | 0 | **11/11** |
| `rtk cargo test --release --test load_test -- --test-threads=1` | 0 | **14/14** |
| `rtk proxy cargo test --release --test load_test load_test_json_many_leaf_context_reuse -- --nocapture --test-threads=1` | 0 | 64-leaf p99 **0.265 ms**, 512-leaf p99 **0.420 ms** (budget 5 ms) |
| `rtk proxy cargo test --release --test load_test load_test_f3_3_honest_http_round_trip_gate -- --nocapture --test-threads=1` | 0 | honest HTTP gate **PASS**: p99 **0.871 ms** vs strict 5.0 ms (overhead p99 0.699 ms) |
| `rtk cargo test --release --workspace --all-targets` | 0 | **753 passed / 0 failed** |
| `rtk proxy cargo test --release -p cerberus-proxy --test smoke_harness -- --test-threads=1` | 0 | **63/63** (multipart pipeline e2e, MITM mode, break-glass, vault round-trip) |
| `git diff --check` | 0 | clean |

## Verdict: PASS

F3's repair units — F3.3 (R9-2 honest HTTP latency gate; panel 2/2 PASS + owner
governance decision keeping the absolute strict assert) and F3.1/F3.2 (R9-11/
12/13/20; attempt-1 rejected 4×P1 by the panel, attempt-2 closed every P1 and
passed re-verification 2/2) — are reproduced end-to-end on the clean clone of
the pushed candidate. Containment remains intact.

## Notes / registered follow-ups

- **New pre-existing finding surfaced by the re-verification panel (register as
  R9-21)**: JSON key-name context asymmetry — a contextKeyword placed in a JSON
  key name can fire in the leaf re-scan while the decision path misses it (the
  multipart analog of F-1, which this phase fixed for multipart only; the JSON
  code predates R9-13 and was unchanged in this diff). Must be repaired and
  re-verified before GA; not a blocker for F3 (pre-existing, parity-documented
  in both panel reports).
- Carry-over follow-ups from earlier panels remain tracked: R9-5 must cover
  break-glass dev-mode; `reason_hash` unsalted (R9-16 class); un-redact
  pass-1 plain-String copies; HEAD content-length metadata; MITM TOCTOU
  residual; trailing-dot upstream host mapping.
- Honest-gate quiet-host requirement (owner decision 2026-09-01) applies to CI
  when the Windows load-test gap (R9-2 residual) is addressed.
