# Evidence — F2 integration review (F2.1 + F2.2/F2.3 candidate)

- Candidate: `975be15` @ `origin/r9-remediation`
- Clone path: `/var/folders/.../opencode/f2-integrator-clone` (clean clone from origin)
- Date: 2026-09-01
- Host: macOS (Darwin), arm64, Apple M4 Pro
- Toolchain: `rustc 1.97.1`, `cargo 1.97.1`

## Provenance note (transport failures)

Two integration-reviewer sub-agent attempts failed before producing a verdict
(one died after cloning; the second died mid-battery and returned corrupted
output). The battery below was therefore executed inline by the orchestrator
gatekeeper against the same clean clone, with every command's output captured
verbatim in this session transcript. The F2 phase gate stands on these raw
outputs plus the two independent panel reports; the owner signs the gate with
all of them visible.

## Remote state

- Clone `HEAD = 975be155acaee9382c9a4f2490ab70b2092a2db6` (matches pushed
  candidate); `git status` clean throughout.
- Log head: `975be15` (panel reports) ← `d1a0322` (R9-8 fix) ← `1df53a0`
  (F2.1 panel reports) ← `e8c1eb5` (F2.1 fix) ← `74e9c9a` (F1 evidence).
- **Containment intact**: `.github/workflows/release.yml:14` and
  `.github/workflows/notify-tap.yml:7` both `"on": []`; single jobs guarded by
  `if: ${{ false }}` (release.yml:22, notify-tap.yml:15) with fail-closed
  `review9_*_freeze` exit-1 guards.

## Frozen-hash verification

| Group | Pack | Result |
|---|---|---|
| F2.2 block (Cargo.lock, engine/Cargo.toml, vault.rs, break_glass.rs, api.rs, config.rs, json_redact.rs, proxy.rs, smoke_harness.rs, load_test.rs) | evidence/f2/r9-vault-zeroization.md | **10/10 OK** |
| F2.1 (decoder.rs, json_redact.rs) | evidence/f2/r9-json-redaction.md | decoder.rs OK; json_redact.rs differs — **expected** (re-frozen by F2.2, matches F2.2 pack) |
| F1.2 (constraints.rs, validator.rs, default_pack.rs, production_pack_pr.rs, raw/production_pack_pr.json, root Cargo.toml) | evidence/f1/r9-pii-regression-repair.md | 6/6 relevant OK (engine.rs/json_redact.rs/load_test.rs differ — **expected**: re-frozen by F1.3-attempt6 and F2.2 respectively, both verified against their newer packs) |
| F1.3 attempt-6 (engine.rs, entropy.rs) | evidence/f1/r9-engine-throughput.md | **OK / OK** (hardcoded authoritative attempt-6 hashes) |

Zero unexplained mismatches.

## Full battery (clean clone, sequential, quiet host)

| Command | Exit | Result |
|---|---|---|
| `cargo fmt --all -- --check` | 0 | clean |
| `rtk cargo clippy --workspace --all-targets -- -D warnings` | 0 | 0 issues |
| `rtk cargo test --workspace --all-targets` (debug) | 0 | **680 passed / 0 failed** (25 suites) |
| `rtk cargo test --release -p cerberus-packs --test production_pack_pr -- --test-threads=1 --nocapture` | 0 | **19/19** |
| `rtk cargo test --release --test redos_fuzz -- --test-threads=1 --nocapture` | 0 | **11/11** |
| `rtk cargo test --release --test load_test -- --test-threads=1 --nocapture` | 0 | **13/13** (5.64 s) |
| `rtk proxy cargo test --release --test load_test load_test_json_many_leaf_context_reuse -- --nocapture --test-threads=1` | 0 | 64-leaf p99 **0.298 ms**, 512-leaf p99 **0.361 ms** (budget 5 ms) |
| `rtk cargo test --release --workspace --all-targets` | 0 | **680 passed / 0 failed** |
| `rtk proxy cargo test --release -p cerberus-proxy --test smoke_harness -- --test-threads=1` | 0 | **42/42** — e2e `test_break_glass_one_shot_end_to_end`, `test_break_glass_wrong_provider_scope_rejected`, `test_break_glass_header_bypasses_block`, `test_reversible_vault_round_trip_request_scoped` all pass |
| `git diff --check` | 0 | clean |

## e2e break-glass reproduction

Reproduced on the clean clone through the smoke harness (real release daemon +
admin API + dataplane): issuance → one-shot redeem → replay rejected →
wrong-provider scope rejected without consumption → reversible vault
request-scoped round trip. The security lens additionally ran ~30 live
adversarial probes at the panel stage (auth, nonce, scope, reason-leakage,
bypass-shape) with zero successful attacks
(`evidence/review9/f23-attempt1-security.md`).

## Verdict: PASS

All acceptance evidence for F2.1 (R9-1) and F2.2+F2.3 (R9-8) was independently
reproduced from a clean clone of the pushed candidate: unit panels 2/2 PASS
each, frozen-hash integrity explained end-to-end, full debug+release battery
green (680/0 both profiles), product gate 19/19, ReDoS 11/11, JSON leaf gate
~16× under budget, and the live break-glass/vault e2e suite green. Containment
remains intact on the pushed branch.

## Notes

- Carry-over performance notes: the official HTTP end-to-end proxy gate with
  ≥2,000 samples is F3.3 scope; F2's builder HTTP probe (p99 ~1.8 ms vs the
  38.9 ms Review-9 claim, non-reproducing) is recorded in
  `evidence/f2/r9-json-redaction.md`.
- Panel P2 advisories carried as follow-ups: R9-5 must cover
  `POST /api/break-glass` in dev-mode; `reason_hash` unsalted (R9-16 class);
  un-redact pass-1 plain-String copies; HEAD content-length metadata note.
