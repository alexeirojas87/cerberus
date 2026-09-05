# Evidence Pack — F9 final gauntlet integration gate (R9 remediation closure)

- Candidate: `b7c56df` @ `origin/r9-remediation` (cumulative remediation:
  base `fccd9e4` → 40 commits)
- Date: 2026-09-05 · Host: macOS arm64 (Apple M4 Pro) · `rustc/cargo 1.97.1`
- Provenance: F9's verification batteries were executed by the orchestrator
  gatekeeper (inline, after the session's repeated sub-agent transport
  failures and one reviewer fabrication incident — both preserved as audit
  records). Final gates re-confirmed on the tip this session.

## F9 units — coverage summary

| Unit (§8B.6) | Evidence | Status |
|---|---|---|
| security-review | `evidence/f9/security-review-r9.md` — 133 live cross-phase attacks (break-glass scope, allowlist 3-surface consistency, vault×bypass, 120-request adversarial flood), zero raw secrets across upstream/logs/SQLite/events API; R9-5/R9-7/R9-16 triangulated live; 7 residuals confirmed documented | **PASS** |
| redos-fuzz | release suite 11/11 on every round (multiple sessions, real shipped pack) | **PASS** |
| load-test | honest HTTP gate (2,000 individual round-trips, interleaved direct baseline) p99 0.84–1.73 ms across rounds vs strict 5.0 ms; JSON leaf gate ~0.25/0.40 ms; fingerprint `e3f206dd…` unchanged throughout | **PASS** |
| failsafe | fail-policy matrix (Closed/ClosedOnCritical/Open) re-semantized + verified; decode-failure closed posture; upstream-failure 503; fail-open/fail-closed honestly audited (`redact-failed` flag) | **PASS** |
| docs | user-guide + security-guide synced through F5/F6 (fail-closed control plane, init token, anti-rebinding, CLI surface); F8 workflows self-document; pack caveats documented in-unit | **PASS** |
| R9-21 (registered finding) | `evidence/f9/r9-json-key-context.md` + r2 verification | **CLOSED** |

## Final confirmation on the tip (this session)

- `cargo fmt --all -- --check` → 0
- `cargo clippy --workspace --all-targets -- -D warnings` (un-piped) → 0
- `rtk cargo test --workspace --all-targets` (debug) → **868 passed / 0 failed**
- `rtk git status` → clean; worktree = pushed tip

## Register closure request

With F1–F8 closed (owner sign-offs 2026-08-31/09-01/02/03) and F9's units
PASS above, the Review 9 invalidation register is fully re-verified: every
R9 finding R9-1..R9-20 repaired and re-verified under §8B, plus the
registered R9-21. Prior PASS claims stand SUPERSEDED by this new evidence
chain; the containment G0 lift (flipping `release-v2.yml` /
`version-bump-v2.yml` / `notify-tap-v2.yml` live, merging `r9-remediation`
to main, and the first tag release through the new PR-based flow) is an
OWNER action gated on the F9 sign-off.
