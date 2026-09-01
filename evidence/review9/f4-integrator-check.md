# Evidence — F4 integration review (F4.3 / R9-17 candidate)

- Candidate: `3b59407` @ `origin/r9-remediation` (clean clone)
- Date: 2026-09-01 · Host: macOS arm64 (Apple M4 Pro) · `rustc/cargo 1.97.1`
- Provenance: battery executed inline by the orchestrator gatekeeper
  (established after the session's sub-agent transport failures; same pattern
  as F2/F3 integrations), outputs captured verbatim in the transcript.

## Remote state

- Clone HEAD = `3b59407006c87fc54742ef59f3120cf6bdda9859`; clean tree.
- Containment intact: `release.yml` / `notify-tap.yml` inert (`"on": []`,
  `if: ${{ false }}` guards) — verified on the clone.

## Frozen hashes

- `tests/smoke-test.sh` = `4be41c0c4eac759a7fea4efb3de43a7b19af1b78810dbf3011e410f09b07691c` — **MATCH** (frozen in `evidence/f4/r9-smoke-test-hygiene.md`).
- Product code untouched by F4.3 (only the smoke script + evidence moved) —
  consistent with the F3 integration review's hash state.

## Full battery (clean clone)

| Command | Exit | Result |
|---|---|---|
| `cargo fmt --all -- --check` | 0 | clean |
| `rtk cargo clippy --workspace --all-targets -- -D warnings` | 0 | 0 issues |
| `rtk cargo test --workspace --all-targets` (debug) | 0 | **753 passed / 0 failed** |
| `rtk cargo test --release -p cerberus-packs --test production_pack_pr -- --test-threads=1` | 0 | **19/19** |
| `rtk cargo test --release --test load_test -- --test-threads=1` | 0 | **14/14** (honest HTTP gate inside) |
| `rtk proxy cargo test --release -p cerberus-proxy --test smoke_harness -- --test-threads=1` | 0 | **63/63** |
| `git diff --check` | 0 | clean |

## Verdict: PASS

F4's sole R9 repair unit (R9-17, smoke-test hygiene) is independently
verified: the repaired checks defeat every vacuity vector the reviewer
attempted (403-misread, stale/missing artifacts, swallowed init), and the
decisive negative test was reproduced — the OLD test passed vacuously on an
injected real leak while the repaired test failed it (exit 1, raw-secret hit
named). No product code changed in this phase; all prior-phase guarantees
re-confirmed on the clean clone.

## Notes

- Panel P2 nits (non-blocking): two temp-fixture SHA-256s not byte-reproducible
  from Appendix A's recipe (behavior reproduced regardless); AC1-neg cites a
  historical log filename that does not exist (the defect it evidences was
  independently proven anyway).
- The negative test demonstrates R9-5 (unauthenticated dev-mode bypass)
  end-to-end — already tracked for F6.2.
