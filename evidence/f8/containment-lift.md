# Evidence Pack — F8 containment lift (`review9_f8_pending` → live)

- Date: 2026-09-05
- Actor: owner (alexeirojas), explicit authorization in the orchestrator session ("vamos a hacer las tres")
- Branch: `ci/lift-review9-f8-containment` (based on `main` @ `0759a9a`)
- Change: the 6 `if: ${{ false }} # review9_f8_pending` job guards are removed from
  `release-v2.yml` (4), `version-bump-v2.yml` (1) and `notify-tap-v2.yml` (1); the three
  G0/F8 CONTAINMENT header blocks now document the lift.

## Conditions required by the guard contract — all met

| Condition (per the guard comment + evidence/f8/r9-release-and-tap.md) | Evidence | Status |
|---|---|---|
| F8 gate has an independently reviewed PASS Evidence Pack | `evidence/f8/r9-release-and-tap.md` — attempt-2 re-verification by an independent adversarial reviewer: **PASS** (F8-V-1 P0 closed; 36-command battery) | ✅ |
| F8 phase gate closed | commit `0ee508a` — "gate(f8): F8 phase gate CLOSED - owner sign-off 2026-09-03" | ✅ |
| F9 phase gate closed (the lift was sequenced after F9) | commit `7ccfc81` — "gate(f9): F9 CLOSED - owner sign-off 2026-09-05 - REVIEW 9 REMEDIATION GA-READY" | ✅ |
| Owner removes the guard lines | this commit, authorized by the owner in-session | ✅ |
| External-review workflow defects fixed before lift | PRs #9–#12 merged to `main` (multipart bypass F1, vault JSON F4, reload brick F6, dedup F7, CLI header F2, route F5, dry-run restore F3, packaging checkout F8-review, ARM runner F9-review, bump permissions F10, offline lockfile F11) — CI green on every merge | ✅ |
| Frozen legacy workflows untouched | `release.yml` / `notify-tap.yml` keep `review9_*_freeze` guards + `"on": []` (no diff in this change) | ✅ |

## What is now live (and what the first real run must prove)

- `release-v2.yml`: triggers on `v*` tags — verify-tag (fail-closed), 4-target build matrix
  (incl. native `ubuntu-24.04-arm`), mandatory per-OS signing (fail-closed on missing
  credentials), real deb/rpm packaging, canonical SHA256SUMS with a both-directions gate,
  `gh release create`.
- `version-bump-v2.yml`: `workflow_dispatch` → bump branch → PR (human merges).
- `notify-tap-v2.yml`: on release published → tap PR with real sha256 (fail-closed on
  missing `TAP_PR_TOKEN`).

Known honest limits carried over from `evidence/f8/r9-release-and-tap.md`: the real
GitHub Actions execution (secrets, runners, cross-compiles, real signatures, real
release) is proven only by the first live run — that run is the post-lift release gate
and doubles as the planned release rehearsal.

## Verification performed on this change

- `actionlint -no-color .github/workflows/*.yml`: the only remaining findings are the two
  documented intentional containment patterns of the FROZEN legacy workflows
  (`review9_*_freeze` guards ×2, `"on": []` ×2); the three v2 workflows are clean.
- The PR also carries CI-conformance fixes for the load-test battery discovered during
  the lift's CI runs (all pre-existing register tests, never CI-exposed before PR #8):
  the F1.3 throughput micro-gate and the empty-engine ceiling now use the documented
  `CI_CONTENTION_TOLERANCE` bound on CI, like every other timing gate. Local strict
  budgets unchanged.
