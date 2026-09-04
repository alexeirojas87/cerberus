# Evidence Pack — F8 / R9-3 release workflow integrity, R9-4 Homebrew tap, R9-15 packaging gaps

- Attempt: 1    Reviewer: Builder (returns to VERIFY — independent review pending)    Verdict: BUILT (not claimed PASS until VERIFY)
- Date: 2026-09-04
- Worktree: `/var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/f8-attempt1-builder`, branch `r9-f8-attempt1`, base commit `5d0a23b` (r9-remediation, clean tree)
- Frozen workflows `.github/workflows/release.yml` + `notify-tap.yml`: **untouched** (verified `git diff --stat` empty; both still have `"on": []` + `review9_*_freeze` guards)

## Acceptance criteria (one row each)

| Criterion | Command run | Output (quoted) | Result |
|---|---|---|---|
| **R9-3**: version bump via PR, never a push to protected main | `version-bump-v2.yml` (new): bump job commits on `release/bump-v<ver>` branch and opens a PR; `tools/release/bump_version.sh --dry-run 0.2.0` locally | dry-run diff: `crates/cerberus/Cargo.toml: -version = "0.1.2" +version = "0.2.0"` + Cargo.lock `name = "cerberus"` 0.1.2→0.2.0; originals restored (`git status` clean) | ✅ |
| **R9-3**: publish triggered ONLY on tags `v*` over MERGED commits, fail-closed | `tools/release/verify_tag_merge.sh v0.1.2` with tag on 5d0a23b (unmerged) | `FAIL: tag commit 5d0a23bd… is NOT reachable from main merged history; refusing to release (R9-3)`; script exit 1 | ✅ |
| **R9-3**: positive merged-tag case | `verify_tag_merge.sh v0.1.2` with tag on 753f9a9 (a real origin/main commit, version 0.1.2) | semver OK / Cargo.toml OK / Cargo.lock OK / `tag commit … is an ancestor of origin/main (merged) — OK`; `PASS`, exit 0 | ✅ |
| **R9-3**: negative cases (malformed tag, version mismatch) | `verify_tag_merge.sh release-0.1.2` / `verify_tag_merge.sh v9.9.9` | `FAIL: tag 'release-0.1.2' does not match…`; `FAIL: tag v9.9.9 != crates/cerberus/Cargo.toml version 0.1.2`; exit 1 both | ✅ |
| **R9-3**: no workflow writes to main | read of release-v2.yml / version-bump-v2.yml / notify-tap-v2.yml | no `git push` to the default branch anywhere; release job writes only `gh release create`; bump flow uses `gh pr create` against `main` | ✅ |
| **R9-4**: tap update flow automated, sha-sourced, cannot silently lag | `notify-tap-v2.yml` (release published → opens tap PR); `tools/release/publish_tap_pr.sh --version 0.1.2 --sums <real v0.1.2 SHA256SUMS> --dry-run` | generated formula with REAL shas (macos-aarch64 `d48d142b…`, linux-x86_64 `696491f8…`, linux-aarch64 `0065a661…`), diff vs broken contrib formula (0000… placeholders @ 0.1.0) shown; `DRY-RUN OK`; `TAP_PR_TOKEN` missing ⇒ job FAILS (fail-closed) | ✅ |
| **R9-4**: REAL clean-install `brew install` gate with real artifact + real sha256 | `brew uninstall cerberus` (pre-state 0.1.1 recorded) → `brew install --build-from-source cerberusf8/local/cerberus` (local tap formula, real sha `a98e55d487c64372…` from the real build, `file://` URL) | `🍺  /opt/homebrew/Cellar/cerberus/0.1.2: 4 files, 15.0MB` | ✅ |
| **R9-4**: post-install verification of the brew-installed binary | `/opt/homebrew/bin/cerberus --version`; `brew test cerberusf8/local/cerberus`; `/opt/homebrew/bin/cerberus test "my api key is sk-abc123"` | `cerberus 0.1.2`; brew test exit 0 (`==> …/cerberus --version`); smoke: `✓ No sensitive data detected.` (test-string non-detection is expected default-pack behavior) | ✅ |
| **R9-4**: formula sha fail-closed (no zero placeholders can reach a tap) | `fill_brew_formula.sh --platforms dist/SHA256SUMS` (single-platform local sums) | `error: no sha256 for 'cerberus-0.1.2-linux-x86_64.tar.gz' … (R9-4: refusing to emit a placeholder)` — the old zero-placeholder path is gone | ✅ |
| **R9-15a**: deb really built by release-v2.yml | workflow job `linux-packages` (`build_deb.sh` + `dpkg-deb --info` on ubuntu-latest) | workflow implements the build; locally validated with dpkg-deb installed via brew (see transcript below) | ✅ (build in CI) |
| **R9-15a**: rpm really built by release-v2.yml | workflow `rpmbuild -ba` from the real linux tar.gz | spec made portable (`install -D` → `mkdir -p` + `install -m`); real rpmbuild validation locally (see transcript) | ✅ (build in CI) |
| **R9-15b**: winget zip flow current, real InstallerSha256 injection | `tools/release/fill_winget_manifest.sh --version 0.1.2 --sums <real SHA256SUMS> --dry-run` | `PackageVersion: 0.1.2`, `InstallerSha256: 12ab923d1c64e4f5…` (REAL sha of the published v0.1.2 zip), fail-closed on zero/missing sha | ✅ |
| **R9-15c**: SHA256SUMS mandatory, no unsigned fallback | release-v2.yml `release` job: expected-artifact list + zero-sha refusal + per-file recomputation; signing prechecks `: "${SECRET:?FAIL …no unsigned fallback}"` for macOS/Windows/Linux+packages | missing credential = hard FAIL; merged SHA256SUMS re-verified before `gh release create` | ✅ (logic; live run post-lift) |
| **R9-15d**: Intel macOS per closed decision | matrix = 4 targets (linux x86_64/aarch64, macos-aarch64, windows-x86_64); `brew.rb` template documents + `odie`s on Intel macOS | plan §4 requires macOS (not Intel); owner decision recorded in commit 161387a ("drop macOS Intel (x86_64) from release matrix" — chronic macos-13 runner stalls) | ✅ documented |
| Replacement workflows exist, inert, NEW guard | grep guards in new files | 3 new workflows; every job `if: ${{ false }} # review9_f8_pending — remove after F8 gate PASS + owner sign-off`; triggers present so the owner flip is a minimal diff | ✅ |
| actionlint on ALL workflow files | `actionlint -no-color .github/workflows/*.yml` (actionlint 1.7.12, brew-installed — G0 residual closed) | 10 findings, ALL of them the two intentional containment patterns (`if:false` guards × 8; frozen `"on":[]` × 2). With those two known patterns excluded: **exit 0, zero findings**. One real finding (SC2046) was found and FIXED during the round | ✅ |

## Architecture of the replacement workflows (R9-3)

```
                      ┌──────────────────────────────────────────────┐
                      │ version-bump-v2.yml   (workflow_dispatch)    │
                      │  human triggers → bump Cargo.toml+lock →     │
                      │  branch release/bump-v<V> → gh pr create     │
                      │  (HUMAN merges the PR — never pushes to main)│
                      └───────────────┬──────────────────────────────┘
                                      │ merge (human)
                                      ▼
                              tag v<V> on merged commit
                                      │ (push tags v*)
                                      ▼
  release-v2.yml ── verify-tag job: verify_tag_merge.sh —
  │  1. strict semver tag          2. tag == Cargo.toml == Cargo.lock
  │  3. git merge-base --is-ancestor tag origin/main  (fail-closed)
  ▼
  build (matrix: linux x86_64, linux aarch64, macos aarch64, windows x86_64)
  │   build_release.sh → artifact + SHA256SUMS
  │   mandatory signing, per-OS, fail-closed precheck (R9-15):
  │   - macos: codesign+notarize, codesign --verify, spctl
  │   - windows: Authenticode (signtool sign/verify)
  │   - linux: detached GPG signature (.sig) + gpg --verify
  ▼
  linux-packages: real .deb (build_deb.sh + dpkg-deb) + real .rpm
  │   (rpmbuild from the spec against the real linux artifact) + GPG sigs
  ▼
  release: merge SHA256SUMS → verify every expected entry (fail-closed list)
  │   → generate cerberus.rb (real shas, zero-placeholder = FAIL)
  │   → generate winget manifests (real InstallerSha256)
  │   → gh release create (contents:write — the ONLY write in the whole flow)
  ▼
  notify-tap-v2.yml (trigger: release published)
      download SHA256SUMS from the release → publish_tap_pr.sh →
      clone tap → branch tap-v<V> → formula with real shas → PR (idempotent)
      TAP_PR_TOKEN missing ⇒ FAIL (tap lag always visible, never skipped)
```

Guard / inertia contract:
- Old `release.yml` / `notify-tap.yml`: UNTOUCHED, still inert (`review9_release_freeze` / `review9_tap_freeze`, `"on": []`).
- New `release-v2.yml` / `version-bump-v2.yml` / `notify-tap-v2.yml`: real triggers, but EVERY job guarded `if: ${{ false }}` with the NEW guard comment `review9_f8_pending`. Owner flip = remove guard lines after gate PASS + sign-off.
- All checkouts pin the tag/SHA of the event; no job uses a mutable ref.

## Local packaging transcript (real artifacts, host macos/aarch64)

```
$ ./tools/release/build_release.sh
    Compiling cerberus v0.1.2 … Finished `release` profile in 41.38s
==> Packaged dist/cerberus-0.1.2-macos-aarch64.tar.gz
a98e55d487c64372d3f9574c05422dd8dfef88940e26dee1544f1b751a92d121  cerberus-0.1.2-macos-aarch64.tar.gz

$ cd dist && shasum -a 256 -c SHA256SUMS
cerberus-0.1.2-macos-aarch64.tar.gz: OK

$ tar tzf cerberus-0.1.2-macos-aarch64.tar.gz
cerberus
```

install.sh gate (local HTTP server 127.0.0.1:8813, isolated HOME, `CERBERUS_RELEASE_URL` override — a new documented env so the gate does not hit GitHub):

```
✓ SHA-256 checksum verified        (CERBERUS_SHA256 = a98e55d4…)
✓ Cerberus installed to …/f8-install-gate/bin/cerberus
$ …/bin/cerberus --version
cerberus 0.1.2
NEGATIVE: CERBERUS_SHA256=deadbeef… →
Error: checksum mismatch. Expected deadbeef…, got a98e55d4…   (exit 1)  PASS
```

brew clean-install gate (R9-4):

```
pre-state:  cerberus 0.1.1 installed from tap alexeirojas87/cerberus
            (real shas, formula still at 0.1.1 → tap lag CONFIRMED LIVE, fix-plan §0.2)
$ brew uninstall --force cerberus
Uninstalling cerberus... (4 files, 11.4MB)
$ brew install --build-from-source cerberusf8/local/cerberus
   (formula: version 0.1.2, url file://…/dist/cerberus-0.1.2-macos-aarch64.tar.gz,
    sha256 a98e55d487c64372… — the REAL sha from the real build)
✔︎ Formula cerberus (0.1.2)
🍺  /opt/homebrew/Cellar/cerberus/0.1.2: 4 files, 15.0MB
$ /opt/homebrew/bin/cerberus --version
cerberus 0.1.2
$ brew test cerberusf8/local/cerberus
==> Testing cerberusf8/local/cerberus
==> /opt/homebrew/Cellar/cerberus/0.1.2/bin/cerberus --version        (exit 0)
$ /opt/homebrew/bin/cerberus test "my api key is sk-abc123"
✓ No sensitive data detected.
post-state: gate install + tap removed; 0.1.1 reinstalled from the real tap
            (`brew install alexeirojas87/cerberus/cerberus` → cerberus 0.1.1 OK)
```

First `brew test` attempt FAILED (`Failed to execute: #{bin}/cerberus`) because the gate
formula was generated with an over-escaped heredoc (`\#{bin}`) — caught by the gate,
fixed, re-run PASS. The gate is real: it rejects broken formulas.

deb local validation (mechanics; real deb built in CI on ubuntu):

```
$ brew install dpkg   (dpkg-deb 1.22.x, not configured for installs — build only)
$ ./packaging/deb/build_deb.sh dist/cerberus-0.1.2-macos-aarch64.tar.gz 0.1.2 --arch aarch64
  (BUG FIXED: script advertised `--arch` but only accepted a positional arg)
  (BUG FIXED: packaging/deb/control had no final newline →
   dpkg-deb: error: … 'Description' (missing final newline) — would also have
   failed in CI; trailing newline added)
✔  .deb generated: ./dist/cerberus_0.1.2_arm64.deb
$ dpkg-deb --contents dist/cerberus_0.1.2_arm64.deb
-rwxr-xr-x root/root  14969760 … ./usr/bin/cerberus
$ dpkg-deb --info …   → Package: cerberus  Version: 0.1.2  Architecture: arm64
NOTE: the payload here is the host (macos) binary — this run validates the
PACKAGING MECHANICS against a real dist/ artifact; the distributable deb is
built by release-v2.yml from the real linux/x86_64 artifact on ubuntu-latest.
```

rpm local validation (rpmbuild 6.1.0 installed via brew):

```
$ sed spec {{VERSION}}→0.1.2 {{ARCH}}→aarch64 (+ BuildArch aarch64 for the fixture)
  (SPEC FIXED: %install `install -D` (GNU-only) → `mkdir -p` + `install -m 0755`
   (portable BSD/GNU); bogus %changelog date Thu→Fri Aug 21 2026 fixed)
$ rpmbuild -ba … /tmp/cerberus.spec
  → RPMS/aarch64/cerberus-0.1.2-1.aarch64.rpm (4.3 MB) + SRPM
$ rpm -qpl cerberus-0.1.2-1.aarch64.rpm
/usr/bin/cerberus
Version: 0.1.2  Arch: aarch64      (with --define _prefix /usr)
NOTE: Source0 fixture = host tar.gz renamed; the real linux artifact is used
by release-v2.yml in CI. Fixture run validates spec syntax + %prep/%install/
%files against a real dist/ artifact.
```

## Builder matrix (all gates)

| Gate | Command | Result |
|---|---|---|
| fmt | `cargo fmt --check` | exit 0 |
| clippy | `cargo clippy --workspace --all-targets -- -D warnings` (un-piped rc checked) | exit 0, Finished dev profile |
| workspace tests | `rtk cargo test --workspace --all-targets` | 865 passed (29 suites, 54.25s), 0 failed |
| pack | `rtk cargo test -p cerberus-packs --test production_pack_pr` | 19 passed |
| redos | `rtk cargo test --test redos_fuzz` | 11 passed |
| load (incl. honest gate) | `rtk cargo test --test load_test` | 14 passed |
| precision/recall gate | `rtk cargo test -p cerberus-engine --test precision_recall_test` | 5 passed |
| local packaging run | `./tools/release/build_release.sh` + `shasum -c SHA256SUMS` | artifacts OK, sums match |
| install.sh gate | isolated HOME + local server + real/wrong sha | PASS / negative PASS |
| brew clean-install gate | uninstall → `brew install --build-from-source` → `--version` → `brew test` → smoke | PASS (transcript above) |
| bump-PR dry-run | `bump_version.sh 0.2.0 --dry-run` | exact diff of Cargo.toml + Cargo.lock, restored clean |
| tap-PR dry-run | `publish_tap_pr.sh --dry-run` (real v0.1.2 sums) | valid formula, real shas, no network |
| winget dry-run | `fill_winget_manifest.sh --dry-run` | real InstallerSha256 injected |
| verify-tag gate | 3 negative + 1 positive cases above | all fail-closed / PASS as designed |
| actionlint | see acceptance table | 0 real findings |
| `git diff --check` | both staged and unstaged | clean |
| frozen workflows | `git diff --stat` on release.yml/notify-tap.yml | untouched; `"on": []` present |

## Bugs found and fixed during this round (all packaging/workflow, no product code)

1. `publish_tap_pr.sh --dry-run` infinite loop (`--dry-run` case lacked `shift`) — caught by running the gate itself.
2. `fill_winget_manifest.sh`: same `--dry-run` loop + template path missing `$TPL_ROOT` prefix — both fixed, gate re-run green.
3. `bump_version.sh`: GNU-only `sed 0,/re/` fails on BSD sed (macOS) — replaced with portable awk; dry-run diff gate green.
4. `tools/release/brew.rb` header comments still listed `{{SHA256_MACOS_X86_64}}` after the Intel branch was removed — the R9-4 fail-closed grep caught it; comments corrected.
5. `fill_brew_formula.sh`: zero-placeholder path removed — a missing required sha is now a hard error (R9-4).
6. `packaging/deb/build_deb.sh`: usage advertised `--arch` flag but only accepted a positional — implemented.
7. `packaging/deb/control`: missing final newline → dpkg-deb hard error (would have failed in CI too) — fixed.
8. `packaging/rpm/cerberus.spec`: GNU-only `install -D` → portable `mkdir -p` + `install -m`; bogus changelog date fixed.
9. `release-v2.yml` SC2046 (unquoted command substitution in `gh release create`) — fixed with a bash array (found by actionlint).

## What can only be proven post-containment-lift (honest limits)

- The real GitHub Actions run of release-v2.yml / version-bump-v2.yml / notify-tap-v2.yml (secrets, runners, cross-compiles, real `gh release create`).
- Real codesign+notarization (APPLE_* secrets), Authenticode (WINDOWS_SIGN_*), Linux GPG detached signatures (GPG_* secrets) — logic is fail-closed locally-proven, real signatures need credentials.
- The real deb/rpm from the real linux/x86_64 artifact (local runs validate mechanics with host-artifact fixtures, documented).
- The real tap PR + `brew install alexeirojas87/cerberus/cerberus` resolving to the NEW version (the live tap was verified working but at the lagged 0.1.1; automation opens the PR post-lift).
- winget-pkgs PR + validation bots; MSI remains out of MVP scope (zip flow is the closed v6.1 path, README documents MSI as future note).

## Applicable NFRs

- Supply-chain integrity: SHA256SUMS mandatory + recomputed in-workflow; install.sh checksum verify (negative case proven); formula/winget real shas → ✅ (as far as locally provable).
- No direct writes to the protected default branch from any workflow → ✅ (static review + bump flow uses PR).
- Scope: MVP only; docker/helm, licensing/entitlements, telemetry are separate F8 units (untouched here); no threshold moved.

## If FAIL: what fails and how to reproduce it

- `actionlint -no-color .github/workflows/*.yml` exits 1 while the containment guards exist — that is the INTENTIONAL inert pattern (same as the frozen workflows). Exclude the two known intentional patterns (documented above) for the real result; after the owner lift, the full run must be exit 0.
- Everything else in this pack was reproduced with the exact commands above in the worktree at the commit below.

## Files touched (frozen SHA-256)

| File | SHA-256 |
|---|---|
| `.github/workflows/release-v2.yml` | see `git hash-object` table in commit |
| `.github/workflows/version-bump-v2.yml` | (same) |
| `.github/workflows/notify-tap-v2.yml` | (same) |
| `tools/release/verify_tag_merge.sh` | (same) |
| `tools/release/bump_version.sh` | (same) |
| `tools/release/publish_tap_pr.sh` | (same) |
| `tools/release/fill_winget_manifest.sh` | (same) |
| `tools/release/brew.rb` (Intel branch removed per 161387a) | (same) |
| `tools/release/fill_brew_formula.sh` (fail-closed shas) | (same) |
| `install.sh` (CERBERUS_RELEASE_URL override + live latest resolution) | (same) |
| `packaging/deb/build_deb.sh` (--arch flag) | (same) |
| `packaging/deb/control` (final newline) | (same) |
| `packaging/rpm/cerberus.spec` (portable %install, date) | (same) |
| `evidence/f8/r9-release-and-tap.md` | (same) |

(Hashes frozen at commit time — see the commit message body for the exact table.)

## Builder verdict

BUILT — returns to VERIFY (independent reviewer). The containment lift itself is NOT part of this attempt: the owner flips the new workflows live only after this phase gate has an independently reviewed PASS Evidence Pack and sign-off, per §8B.
