# PR-3 Evidence Pack — release tooling & CI (F3, F8-F11)

Change: review-findings-remediation | Slice: PR-3 | Attempt rf-remed-pr3-attempt1 (token sha256:420df6e9...3427ce) | STRICT TDD.
Commits: 2b54478 (F3, tasks 3.1-3.2) → c3f1dc9 (F11, tasks 3.3-3.4) → 1cda155 (F8/F9/F10, tasks 3.5-3.7) → this pack (3.8).

## TDD evidence — harness: NEW tools/release/bump_version_test.sh (temp git repo fixtures, per design obs #465 testing row)

| Task | Case | RED (watched) | GREEN |
|---|---|---|---|
| 3.1/3.2 | f3-success + f3-failure (staged+dirty mix) | 10 checks FAILED — old `git checkout --` restore destroyed the unstaged TOML delta + Cargo.lock edit on BOTH success and failure paths (the staged edit survived only because checkout restores from the index) | 16 passed / 0 failed |
| 3.3/3.4 | f11-error (missing path dep) + f11-cold (empty CARGO_HOME + uncached `serde`) | 2 checks FAILED — cargo's real error text swallowed by `>/dev/null 2>&1` (missing on stderr: `zz-r9f11-missing`, `no matching package named`) | 24 passed / 0 failed |

Final: `bash tools/release/bump_version_test.sh` → **24 passed, 0 failed, exit 0**. f3: TOML+lock byte-identical after restore (pre-existing staged+unstaged edits intact), script's own bump reverted, porcelain `MM crates/cerberus/Cargo.toml` + ` M Cargo.lock` preserved; f11: exit nonzero, cargo error text ON stderr, snapshot restore still ran (triangulated across manifest-load and registry-resolve failure paths).

## Design mapping (obs #465 → obs #447 sites)

- **F3**: bump_version.sh :45-60 — mktemp snapshot of Cargo.toml + Cargo.lock BEFORE any rewrite; `trap restore EXIT INT TERM`; plain file copies (git-state independent, works with staged+dirty mix); `git checkout --` REMOVED. Defect was bump_version.sh:45-46.
- **F11**: bump_version.sh :66-69 — `>/dev/null` kept, `2>&1` dropped (cargo stderr visible; defect :61). version-bump-v2.yml gains `cargo fetch` step BEFORE the bump_version.sh call (cold registry, Req C5).
- **F8/F9/F10**: release-v2.yml — linux-packages FIRST step is checkout@v4 pinned to `github.ref_name` (job previously had NO checkout; defect :239-265); aarch64 matrix entry `ubuntu-24.04-arm` (native ARM, no cross toolchain; defect :87). version-bump-v2.yml — job-scope `permissions: {contents: write, pull-requests: write}` with inline justification; workflow level narrowed to `contents: read` (defect :34-76).

## Structural verification (tasks 3.5-3.7) — structural, gated-by-F8, if:false inert

All edited jobs remain guarded by the 5 `if: ${{ false }}` lines — **byte-identical vs 88657d0 (diff-verified)** — so the workflows stay INERT until the F8 gate lifts (latent blockers per obs #447).

- **pyyaml asserts: 14/14 PASS** — F8: linux-packages steps[0] is actions/checkout@v4 with ref `${{ github.ref_name }}`. F9: aarch64 entry runner == ubuntu-24.04-arm (x86_64 entry unchanged). F10: workflow-level == {contents: read} only; job-scope == {contents: write, pull-requests: write}; exactly one `git push`, refspec `release/bump-v*`, no default-branch push; `gh pr create --base "$CERBERUS_DEFAULT_BRANCH" --head "$BRANCH"` args unchanged. F11: cargo fetch precedes bump_version.sh.
- **actionlint**: 5 findings — the byte-identical pre-existing `if-cond` notices on the containment guards; normalized diff vs base = IDENTICAL → zero new findings.

## Gate (task 3.9, final tree)

`cargo test --workspace && make lint && cargo fmt --check` → **38 suites ok / 0 FAILED; clippy (-D warnings) clean; fmt clean.** Workflows + shell script only — proves no Rust regression.

## Rollback boundary

Revert 2b54478 / c3f1dc9 / 1cda155 + this pack: tools/release/bump_version.sh + bump_version_test.sh + the two workflows + evidence only. No Rust source touched (slice boundary held; if:false guards untouched).

## Size note

Net tree diff vs 88657d0: ~176 ins + 5 del = **181 lines before this pack (~208 total) vs 180 cap → size:exception recommended**. The design-mandated NEW harness (111 lines) is the F3/F11 runtime-evidence host; §8B pack + design-mandated inline F-justification comments add the rest. No golfing performed (no comments/tests/docs deleted to fit).
