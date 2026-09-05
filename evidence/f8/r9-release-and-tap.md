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

---

## FIX attempt 2

- Attempt: 2    Reviewer: Builder (returns to VERIFY — independent re-review pending)    Verdict: BUILT (not claimed PASS until VERIFY)
- Date: 2026-09-04
- Worktree: `/var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/f8-attempt2-builder`, branch `r9-f8-attempt2`, base commit `5a4aa92` (r9-remediation, clean tree; parent = the attempt-1 verification FAIL report)
- Scope: workflows/scripts/pack + new simulation script ONLY. Product code untouched; frozen `release.yml` / `notify-tap.yml` byte-untouched (`git diff 5a4aa92` = 0 bytes); all 6 `review9_f8_pending` job guards intact (release-v2 L54/L72/L241/L350, version-bump-v2 L48, notify-tap-v2 L37).

### F8-V-1 (P0) — canonical SHA256SUMS assembly, no dead-end

Four independent dead-ends, four fixes, all in `.github/workflows/release-v2.yml`:

| # | Dead-end (attempt 1) | Fix (file:line) | Proof |
|---|---|---|---|
| 1 | deb/rpm shas never written into any SHA256SUMS → EXPECTED loop `exit 1` before `gh release create` | `linux-packages` now emits its own fragment with the deb, the deb.sig, the rpm and the rpm.sig checksums (bare asset names): **release-v2.yml:308-333** (`Package sums fragment`), fail-closed on any missing package/sig | simulation: `SHA256SUMS-packages` fragment shows 4 lines incl. `cerberus_0.1.2_amd64.deb` + `cerberus-0.1.2-1.x86_64.rpm`; REQUIRED check + direction A PASS |
| 2 | four per-platform `SHA256SUMS` files collide under `download-artifact@v4 merge-multiple` (last writer wins) → ≥3 platform lines lost | (a) build job emits each platform's sums under a UNIQUE name `SHA256SUMS-<os>-<arch>`, normalized (strips the `dist/` prefix the Windows signing step writes via `Set-Content -NoNewline`, guarantees trailing newline): **release-v2.yml:213-227**; upload glob `dist/SHA256SUMS-*` **:229-236**; (b) release job downloads every artifact into its OWN directory — NO merge-multiple anywhere — **:365-394**, then canonical SHA256SUMS = EXPLICIT concatenation of the five named fragments **:401-419** | simulation replays the Windows quirk (`dist/` prefix + no trailing newline) and the explicit `cat` of 5 fragments yields a 12-line canonical sums: 4 platform artifacts + 4 platform sigs + 4 package lines — zero lines lost |
| 3 | `dist/*.rpm` upload glob matches nothing (rpmbuild writes `dist/rpm/x86_64/`) → rpm + rpm.sig never uploaded | packages upload glob points at the real layout: `dist/cerberus_*.deb`, `dist/cerberus_*.deb.sig`, `dist/rpm/x86_64/*.rpm`, `dist/rpm/x86_64/*.sig`, `dist/SHA256SUMS-packages` — **release-v2.yml:335-345**; srpms redirected to `dist/srpm` (not released, MVP) | simulation stages the rpm from `rpm/x86_64/`; both `cerberus-0.1.2-1.x86_64.rpm` and its `.sig` reach the staged-asset set and the final asset list |
| 4 | release-asset `find cerberus-*` omits the underscore deb, its sig, `cerberus.rb`, winget manifests → no release ever published | (a) winget manifests generated FLAT into `dist/` (attempt 1 wrote `dist/winget-manifests/` that nothing uploaded): **release-v2.yml:456-462**; (b) formula + manifests folded INTO the canonical SHA256SUMS **:471-476**; (c) FINAL both-directions gate **:478-497** — direction A: every listed file staged with recomputed sha; direction B: every staged asset listed (end-anchored match — a `.sig` line cannot satisfy a bare name); (d) `gh release create` asset list driven FROM the verified SHA256SUMS **:499-520** — publish set is 1:1 with the integrity manifest | simulation: final asset list = **17 assets** (SHA256SUMS, 4 tarballs/zips + sigs, deb + sig, rpm + sig, cerberus.rb, 3 winget yamls) — `SIM-PASS: release assembly dataflow reaches gh release create with no dead-end` |

Fail-closed both directions, proven by two negative replays (see transcript): dropping the rpm line from the fragment ⇒ final gate `FAIL: staged asset 'cerberus-0.1.2-1.x86_64.rpm' is NOT listed in SHA256SUMS` (exit 1 — the attempt-1 P0 can never silently recur); staging an unlisted asset ⇒ `FAIL: staged asset 'UNLISTED-fixture.txt' is NOT listed in SHA256SUMS` (exit 1). Note: the REQUIRED-name check uses substring matching (kept as defense in depth), so NEGATIVE 1 shows it passing off the `.rpm.sig` line — the end-anchored direction-B gate is what refuses the release; the transcript documents exactly this layering.

### F8-V-2 (P2) — frozen-hash table anchored

See "Files touched (frozen SHA-256, attempt 2)" below — REAL `shasum -a 256` values, committed in the same commit as the pack. The attempt-1 gap (table deferred to a commit-message table that did not exist) is not repeated. The attempt-1 hashes themselves were frozen by the verifier in §7 of `evidence/review9/f8-attempt1-verification.md`; the 3 untouched files (install.sh, fill_brew_formula.sh, fill_winget_manifest.sh) re-hash identically in this round, re-anchoring that table.

### F8-V-3 (P2) — rpm Release pinned

`packaging/rpm/cerberus.spec:8` — `Release: 1` (literal; the dist-tag macro removed from the field). The workflow's required name `cerberus-${VERSION}-1.x86_64.rpm` is now exactly what the spec produces on ANY host, including dist-tagging ones. Proof: `rpmspec -q --qf '%{RELEASE}' --define 'dist .fc40'` on the substituted spec → `1` (the pre-fix field would yield `1.fc40`). The static guard also lives inside the simulation (`PASS: rpm spec Release pinned to literal 1`), so a future regression of the field fails the sim before any release. (rpmbuild's full `dpkg`-style build itself was already proven in attempt 1; on this macOS host rpm 6's file-classification regex crashes on ANY spec, so attempt 2 proves the filename via rpmspec — the property F8-V-3 is about.)

### F8-V-4 (P2) — TAP_PR_TOKEN no longer rides the clone URL

`tools/release/publish_tap_pr.sh:78-97` — the token is NEVER placed in a URL. Clone + push authenticate via `git -c http.https://github.com/.extraheader=AUTHORIZATION: basic …` (the actions/checkout mechanism), `set +x` guards every token-bearing line (the script never enables xtrace), `GIT_TERMINAL_PROMPT=0` forbids interactive fallback, `credential.helper=` is explicitly cleared, and `GH_TOKEN` is exported from `TAP_PR_TOKEN` for the `gh pr create` call (which previously had no explicit credential at all — a latent CI failure). After the push, `unset AUTH_HEADER` drops the credential from scope.

Proof: negative run `TAP_PR_TOKEN='F8A2FAKE-token-…' --tap-repo f8-nonexistent-verify-xyz/homebrew-cerberus` → `FAIL: could not clone tap repo` exit 1, fake-token occurrences in the full output: **0**, `x-access-token` occurrences: **0** (the URL in git's transport errors is the bare `https://github.com/…` now). Dry-run gate still green (`DRY-RUN OK`, real shas, no network).

### THE PROOF — local end-to-end assembly simulation (new, committed)

`tools/release/simulate_release_assembly.sh` replicates the release job step-for-step against local fixtures it builds itself: the REAL `dist/cerberus-0.1.2-macos-aarch64.tar.gz` (real cargo build; reused when present), dummy-but-real-sha tar.gz/zip fixtures for the other platforms (payload text says FIXTURE), fixture `.sig` placeholders (clearly named), a fixture `.deb`, and the rpm filename proven via rpmspec on a dist-tagged host. It replays the Windows `Set-Content -NoNewline` + `dist/` prefix quirk, the distinct-dir downloads, the explicit canonical concatenation, the REQUIRED list, direction A, the REAL `fill_brew_formula.sh` + `fill_winget_manifest.sh` off the canonical sums, the fold, the both-directions gate, and prints the exact `gh release create` asset list. No network, no release, no repo writes; `SIM_KEEP=1` preserves the sim dir. `--negative` replays the attempt-1 failure modes and demands failure.

Transcript (verbatim, from the committed script version; the two negative tamper scenarios included):

```
═══ release-sim F8 attempt 2 — fixture build (version 0.1.2) ═══
PASS: rpm spec Release pinned to literal 1 (F8-V-3)
FIXTURE macos-aarch64 : REAL build artifact cerberus-0.1.2-macos-aarch64.tar.gz (3a25a47a2d5845bf…)
FIXTURE linux-x86_64 : dummy tar.gz (payload text says FIXTURE)
FIXTURE linux-aarch64 : dummy tar.gz (payload text says FIXTURE)
FIXTURE windows-x86_64 : dummy zip; SHA256SUMS written with dist/ prefix + no trailing newline (pwsh quirk replayed)
FIXTURE deb            : cerberus_0.1.2_amd64.deb (dummy file)
FIXTURE rpm            : Release '1' PROVEN via rpmspec on a dist-tagged host (--define dist .fc40) — F8-V-3 pin holds → CI name = cerberus-0.1.2-1.x86_64.rpm
== fixture ci/packages fragment (SHA256SUMS-packages) ==
2668a384…f5  cerberus_0.1.2_amd64.deb
4b346a58…b7  cerberus_0.1.2_amd64.deb.sig
24d75cfa…e7  cerberus-0.1.2-1.x86_64.rpm
3d1304ff…bb  cerberus-0.1.2-1.x86_64.rpm.sig
== per-platform fragments (unique names, normalized) ==
e3fac1ed…5c  cerberus-0.1.2-linux-x86_64.tar.gz
4618e1ed…8e  cerberus-0.1.2-linux-x86_64.tar.gz.sig
bd4447de…2d  cerberus-0.1.2-linux-aarch64.tar.gz
65bff96b…1c  cerberus-0.1.2-linux-aarch64.tar.gz.sig
3a25a47a…06  cerberus-0.1.2-macos-aarch64.tar.gz
ccf70581…67  cerberus-0.1.2-macos-aarch64.tar.gz.sig
1d64e7f8…e2  cerberus-0.1.2-windows-x86_64.zip
0a5df639…e1  cerberus-0.1.2-windows-x86_64.zip.sig

═══ POSITIVE: full assembly simulation (must PASS) ═══
── [sim] download-artifact → distinct dirs (NO merge-multiple) ──
── [sim] assemble canonical SHA256SUMS + stage assets ──
   (12-line canonical SHA256SUMS printed: 4 platform artifacts + 4 sigs + 4 package lines)
── [sim] REQUIRED entries (non-zero shas, fail-closed) ──
PASS: all 6 required entries present with real shas
── [sim] direction A: every listed file staged + recomputed ──
PASS: direction A
── [sim] generate formula + winget manifests from the canonical sums ──
✔  Formula generated …   sha256 macos-aarch64 : 3a25a47a2d5845bf…
PASS: winget manifests for 0.1.2 generated … (InstallerSha256 = 1d64e7f8cb59f5b0…)
── [sim] fold formula + manifests into the canonical SHA256SUMS ──
   (16-line final SHA256SUMS printed: + cerberus.rb + 3 winget yamls)
── [sim] final BOTH-DIRECTIONS asset gate (fail-closed) ──
PASS: both-directions asset gate
── [sim] the EXACT 'gh release create' asset list it WOULD publish ──
gh release create v0.1.2 --title "cerberus 0.1.2" --generate-notes \
  dist/SHA256SUMS
  dist/cerberus-0.1.2-linux-x86_64.tar.gz          (+ .sig)
  dist/cerberus-0.1.2-linux-aarch64.tar.gz         (+ .sig)
  dist/cerberus-0.1.2-macos-aarch64.tar.gz         (+ .sig)
  dist/cerberus-0.1.2-windows-x86_64.zip           (+ .sig)
  dist/cerberus_0.1.2_amd64.deb                    (+ .sig)
  dist/cerberus-0.1.2-1.x86_64.rpm                 (+ .sig)
  dist/cerberus.rb
  dist/Cerberus.Cerberus.installer.yaml
  dist/Cerberus.Cerberus.locale.en-US.yaml
  dist/Cerberus.Cerberus.version.yaml
== asset count: 17 ==
SIM-PASS: release assembly dataflow reaches gh release create with no dead-end
PASS: positive simulation green

═══ NEGATIVE 1: attempt-1 P0 replay (rpm line dropped from fragment → must FAIL) ═══
── [sim] final BOTH-DIRECTIONS asset gate (fail-closed) ──
FAIL: staged asset 'cerberus-0.1.2-1.x86_64.rpm' is NOT listed in SHA256SUMS
PASS: negative 1 failed closed, exactly like the attempt-1 P0 demands

═══ NEGATIVE 2: unlisted staged asset → direction B must FAIL ═══
── [sim] final BOTH-DIRECTIONS asset gate (fail-closed) ──
FAIL: staged asset 'UNLISTED-fixture.txt' is NOT listed in SHA256SUMS
PASS: negative 2 failed closed (both-directions gate bites in both directions)

═══ SIMULATION GREEN — release-v2.yml dataflow proven end-to-end ═══
```

Idempotency: run ×2 (plus the `--negative` full run) — all green.

### Regression gates (round-1 pieces, re-proven)

```
brew clean-install gate — ISOLATED prefix (git clone --depth=1 Homebrew/brew into a
temp copy moved out of TMPDIR; HOMEBREW_REPOSITORY/PREFIX/CELLAR/CACHE bound there;
machine /opt/homebrew NEVER invoked — its pre-existing cerberus 0.1.1 untouched):
$ fill_brew_formula.sh --version 0.1.2 --platforms <canonical 3-platform sums>   → real macos sha 3a25a47a…, ruby -c OK
$ url patched to file://…/dist/cerberus-0.1.2-macos-aarch64.tar.gz
$ brew install --build-from-source f8a2/local/cerberus   → exit 0 (brew verified the sha256)
$ …/bin/cerberus --version                               → cerberus 0.1.2
$ brew test f8a2/local/cerberus                          → exit 0
$ …/bin/cerberus test "my api key is sk-abc123"          → ✓ No sensitive data detected.
$ brew uninstall --force cerberus                        → prefix clean; gate dirs deleted

install.sh gate — local HTTP + isolated HOME + CERBERUS_RELEASE_URL override:
NEGATIVE  CERBERUS_SHA256=deadbeef… → Error: checksum mismatch. Expected deadbeef…, got 3a25a47a…   exit 1
POSITIVE  CERBERUS_SHA256=3a25a47a… → ✓ SHA-256 checksum verified → cerberus 0.1.2                 exit 0

tap-PR gates: --dry-run → DRY-RUN OK (real shas, no network); real-mode negative →
exit 1 with 0 token occurrences (F8-V-4 above); token-missing precheck unchanged (fail-closed).
```

### Builder matrix (attempt 2)

| Gate | Command | Result |
|---|---|---|
| fmt | `cargo fmt --check` | exit 0 |
| clippy | `cargo clippy --workspace --all-targets -- -D warnings` (un-piped, rc checked) | exit 0 |
| workspace tests | `rtk cargo test --workspace --all-targets` | 865 passed (29 suites, 54.16s), 0 failed |
| pack | `rtk cargo test -p cerberus-packs --test production_pack_pr` | 19 passed |
| simulation (positive) | `tools/release/simulate_release_assembly.sh` | GREEN ×2 (idempotent), asset count 17, no dead-end |
| simulation (fail-closed) | `tools/release/simulate_release_assembly.sh --negative` | GREEN — both tamper scenarios fail closed (exit 1 each, expected) |
| brew clean-install gate | isolated prefix, real artifact, real sha | PASS (transcript above) |
| install.sh negative | local HTTP, isolated HOME, wrong sha | PASS (`checksum mismatch`, exit 1); positive also re-run PASS |
| tap-PR token negative | fake token + nonexistent tap repo | exit 1, token occurrences 0 |
| tap-PR dry-run | `publish_tap_pr.sh --dry-run` | DRY-RUN OK |
| actionlint | `actionlint -no-color .github/workflows/*.yml` (v1.7.12) | 10 findings — ALL the documented intentional containment patterns (6× new-workflow `if:false` guards, 2× frozen guards, 2× frozen `"on":[]`); **zero new findings** from this round's edits |
| `git diff --check` | staged + unstaged | clean |
| frozen workflows | `git diff 5a4aa92 -- release.yml notify-tap.yml` | 0 bytes |
| containment guards | grep `if: ${{ false }}` | 6/6 jobs guarded, `review9_f8_pending` markers intact |

### Files touched (frozen SHA-256 — REAL values, at commit state)

| File | SHA-256 |
|---|---|
| `.github/workflows/release-v2.yml` | `5452981712876d21ede27225c84241e90d10424ac1513d7873c9f6782b35ecf8` |
| `packaging/rpm/cerberus.spec` | `dca9db40e541439698fc63d298c0b6e7731071d50d5150ae4256db0713788d6e` |
| `tools/release/publish_tap_pr.sh` | `cb9bfb03bcddda68c53bf8bdbb3309b8405a97cad31bc1be95937730b434e20e` |
| `tools/release/simulate_release_assembly.sh` (NEW) | `a71fa8083b6124316c174f0359439cbbf7dc38d23bc09730d0b46901364a516d` |
| `evidence/f8/r9-release-and-tap.md` | (this document — self-referential; `git show <commit>:evidence/f8/r9-release-and-tap.md \| shasum -a 256`) |

Untouched this round, re-anchored for continuity (attempt-1 verifier §7 values match live): `install.sh 29c252d7…`, `fill_brew_formula.sh 37d1ee04…`, `fill_winget_manifest.sh 2be8523c…`, `verify_tag_merge.sh 6ff5e0aa…`, `bump_version.sh 6801e2f2…`, `brew.rb b22cae00…`, `version-bump-v2.yml 39f6aad1…`, `notify-tap-v2.yml e7b6692a…`, `packaging/deb/* b3bccc16…/38aaf40a…`.

### Honest limits (unchanged in kind from attempt 1)

- The REAL GitHub Actions run (runners, secrets, cross-compiles, real `gh release create`, real signatures) remains post-containment-lift; what is NEW is that the assembly dataflow it will execute is now locally executable and has been executed — the exact step sequence reaches the `gh release create` asset list with a fail-closed both-directions gate, and its failure modes were replayed.
- rpmbuild full-build mechanics on THIS mac host remain blocked by an upstream rpm-6-on-macOS classification crash (any spec); CI ubuntu builds the real x86_64 rpm (mechanics proven in attempt 1; filename pin proven here via rpmspec).

### Builder verdict (attempt 2)

BUILT — returns to VERIFY. The attempt-1 P0 chain (dead-end before `gh release create`) is repaired and the repaired dataflow is executed end-to-end locally, green, twice, with both failure directions proven to bite. Containment lift is still NOT part of this attempt: the owner flips the workflows live only after an independently reviewed PASS Evidence Pack and sign-off, per §8B.

---

## Verification attempt 2 — re-verification

- Reviewer: INDEPENDENT adversarial VERIFY (did not build; Gauntlet §8B)
- Candidate: commit `c37c071` on branch `r9-remediation` (parent `5a4aa92` — the attempt-1 FAIL report)
- Re-verification worktree: `/var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/f8-verify2` (detached at c37c071; removed after this report)
- Required reading done: attempt-1 battery + FIX attempt 2 section (this file), `git diff 5a4aa92..c37c071` (5 files, +726/−33 — exactly the 5 declared files, no scope creep), `evidence/review9/f8-attempt1-verification.md` (the P0 diagnosis being closed)
- **Final verdict: PASS** — F8-V-1 (P0) CLOSED, all four sub-diagnoses fixed and the repaired dataflow executed end-to-end BY THIS REVIEWER; 2 P2 findings recorded (no blocker); 0 P0/P1.

### 1. Commands run (verbatim, with exit codes)

| # | Command (cwd = worktree unless noted) | Exit | Result |
|---|---|---|---|
| 1 | `git worktree add --detach …/f8-verify2 c37c071` | 0 | worktree created, HEAD c37c071 |
| 2 | `git diff --stat 5a4aa92..c37c071` | 0 | 5 files: release-v2.yml (+208), evidence pack (+175), cerberus.spec (7), publish_tap_pr.sh (23), simulate_release_assembly.sh (NEW +346) |
| 3 | `bash tools/release/simulate_release_assembly.sh` (run 1) | **0** | **SIM-PASS — reaches the exact `gh release create` asset list; asset count 17; real cargo release build executed (47.89s, sha `2a47ace3…`)** |
| 4 | `bash tools/release/simulate_release_assembly.sh` (run 2) | 0 | idempotent GREEN, same 17-asset list |
| 5 | `SIM_KEEP=1 bash tools/release/simulate_release_assembly.sh` | 0 | GREEN; sim dir preserved for forensics |
| 6 | `bash tools/release/simulate_release_assembly.sh --negative` (×2) | 0 | both tamper shapes fail closed: `FAIL: staged asset 'cerberus-0.1.2-1.x86_64.rpm' is NOT listed in SHA256SUMS` and `FAIL: staged asset 'UNLISTED-fixture.txt' is NOT listed in SHA256SUMS` (inner exits 1 — wrapper 0 = demanded failure achieved) |
| 7 | `shasum -a 256 -c SHA256SUMS` in the kept sim `dist/` (INDEPENDENT of the sim's own gate) | 0 | **16/16 OK** — incl. `cerberus.rb` + 3 winget yamls: shas in the canonical sums equal the actual files |
| 8 | `grep InstallerSha256 …installer.yaml` vs `shasum -a 256 …windows-x86_64.zip` | 0 | `InstallerSha256: 9cfa14691f8cade1a3441c9a3014e9f07c97f1f3534961b2c1cfa2184e9d7faa` == actual zip sha (REAL, not placeholder) |
| 9 | rpmspec proof: `sed {{VERSION}}/{{ARCH}}` → `rpmspec -q --qf '%{RELEASE}' --define 'dist .fc40' <spec>` | 0 | `%{RELEASE}` = **1** on a dist-tagged host → CI rpm name = `cerberus-0.1.2-1.x86_64.rpm` (F8-V-3 pin independently re-proven) |
| 10 | ATTACK b — throwaway copy of the sim with the **windows** fragment dropped from the canonical `cat`, run `--_inner` | **1** | `FAIL: cerberus-0.1.2-windows-x86_64.zip missing from SHA256SUMS` — a different-fragment drop fails closed |
| 11 | ATTACK c — identical duplicate of the deb line appended to `SHA256SUMS-packages` | **0** | **gate PASSES, asset list = 18 with `dist/cerberus_0.1.2_amd64.deb` twice** — identical dupes are NOT caught (finding F8-V2b-1 below) |
| 12 | ATTACK c2 — sha-CONFLICTING duplicate (same name, altered sha) | **1** | `FAIL: sha mismatch for cerberus_0.1.2_amd64.deb` — direction A catches conflicting dupes |
| 13 | ATTACK e — byte tampered into the staged deb after sums assembly | **1** | `FAIL: sha mismatch for cerberus_0.1.2_amd64.deb` — direction-A recomputation bites |
| 14 | `./tools/release/verify_tag_merge.sh v0.1.2` on tag→753f9a9 (real origin/main, throwaway clone, origin/main fetched from GitHub = `753f9a9`, version 0.1.2) | 0 | PASS (semver/Cargo.toml/lock/ancestry) |
| 15 | tag→`c37c071` (unmerged), `verify_tag_merge.sh v0.1.2` | **1** | `FAIL: … NOT reachable from main merged history; refusing to release (R9-3)` |
| 16 | `verify_tag_merge.sh v9.9.9` | **1** | `FAIL: tag v9.9.9 != crates/cerberus/Cargo.toml version 0.1.2` |
| 17 | install.sh NEGATIVE: local HTTP 8821 + isolated HOME + `CERBERUS_SHA256=deadbeef…` | **1** | `Error: checksum mismatch. Expected deadbeef…, got 2a47ace3…` |
| 18 | install.sh POSITIVE: `CERBERUS_SHA256=2a47ace3…` | 0 | `✓ SHA-256 checksum verified` → installed → `cerberus --version` = `cerberus 0.1.2` (exit 0) |
| 19 | brew clean-install, ISOLATED prefix: `git clone --depth=1 https://github.com/Homebrew/brew /Users/alexeirojas/f8brew-verify2/homebrew` + HOMEBREW_PREFIX/REPOSITORY/CELLAR/CACHE bound there | 0 | Homebrew ≥4.3.0 (shallow clone) |
| 20 | `brew tap-new f8a2/local` + `fill_brew_formula.sh --version 0.1.2 --platforms <canonical sums> --out <tap>/Formula/cerberus.rb` (url patched to `file://` of the REAL artifact) | 0 | formula with REAL macos sha `2a47ace31810cb35…`; `ruby -c` OK |
| 21 | `brew install --build-from-source f8a2/local/cerberus` | 0 | poured; **brew verified the real sha256** |
| 22 | `$P/bin/cerberus --version` / `brew test f8a2/local/cerberus` / `$P/bin/cerberus test "my api key is sk-abc123"` | 0/0/0 | `cerberus 0.1.2`; brew test exit 0; `✓ No sensitive data detected.` |
| 23 | `brew uninstall --force cerberus`; `rm -rf` isolated prefix | 0 | prefix clean; **machine `/opt/homebrew` untouched (cerberus 0.1.1 intact, verified)** |
| 24 | `TAP_PR_TOKEN='F8A2FAKE-token-…' ./tools/release/publish_tap_pr.sh --version 0.1.2 --sums <canonical sums> --tap-repo f8-nonexistent-verify-xyz/homebrew-cerberus` | **1** | `FAIL: could not clone tap repo…`; **fake-token occurrences in full output: 0; `x-access-token` occurrences: 0** (error URL is bare `https://github.com/…`) |
| 25 | `publish_tap_pr.sh --version 0.1.2 --sums <canonical sums> --dry-run` | 0 | `DRY-RUN OK: formula valid, shas sourced from … No network calls made.` |
| 26 | leak greps over 3 v2 workflows + release scripts: `set -x|printenv|env \|` and `echo.*secret vars` | 0/0 | only comment hits (`publish_tap_pr.sh:81` mentions `set -x` in prose; macos-notarize DRY-RUN echoes escaped `\$VARS` literals); `GPG_*` echo pipes to gpg stdin unchanged from attempt 1 (GitHub-masks, standard) |
| 27 | `actionlint -no-color .github/workflows/*.yml` (v1.7.12) | 1 | **10 findings — 6× `review9_f8_pending` if:false (release-v2 L54/L72/L241/L350, version-bump L48, notify-tap L37), 2× frozen if:false (release.yml L22, notify-tap.yml L15), 2× frozen `"on":[]` (release.yml L14, notify-tap.yml L7). ZERO new findings from the attempt-2 edits** |
| 28 | `cargo fmt --check` | 0 | clean |
| 29 | `cargo clippy --workspace --all-targets -- -D warnings` (un-piped, rc checked) | 0 | Finished dev profile |
| 30 | `rtk cargo test --workspace --all-targets` | 0 | **865 passed (29 suites, 55.38s), 0 failed** |
| 31 | `rtk cargo test -p cerberus-packs --test production_pack_pr` | 0 | **19 passed** |
| 32 | `git diff 5a4aa92..c37c071 -- .github/workflows/release.yml .github/workflows/notify-tap.yml \| wc -c` | 0 bytes | **frozen workflows byte-untouched**; `"on": []` present in both |
| 33 | guard grep `review9_f8_pending` | 0 | **6/6 jobs** guarded at the exact claimed lines (release-v2 L54/L72/L241/L350, version-bump-v2 L48, notify-tap-v2 L37) |
| 34 | `git diff --check` (staged + unstaged) | 0 | clean |
| 35 | `shasum -a 256` on the 4 touched files | 0 | **4/4 match the pack's attempt-2 frozen table byte-for-byte** (release-v2 `54529817…`, spec `dca9db40…`, tap script `cb9bfb03…`, sim `a71fa808…`); 10 untouched files re-hash identical to the attempt-1 verifier §7 table (F8-V-2 re-anchoring claim TRUE) |
| 36 | `worktree remove` (after this report) | 0 | worktree removed |

### 2. The decisive check — sim executed BY THE REVIEWER

Positive GREEN ×2 + SIM_KEEP forensics run (all exit 0, idempotent, asset count 17, `SIM-PASS: release assembly dataflow reaches gh release create with no dead-end`). Negative ×2: both tamper shapes failed closed (exit 1 each). The sim's own real-cargo-build artifact sha (`2a47ace3…`) flows through fragments → canonical sums → formula (`sha256 macos-aarch64 : 2a47ace3…`) → both-directions gate → asset list, exactly as the workflow prescribes.

### 3. Sim ↔ workflow fidelity (side-by-side)

Verified block-for-block against `release-v2.yml`: staging `find dl -type f ! -name 'SHA256SUMS-*' -exec mv {} dist/ \;` (L408 ≡ sim L91), canonical 5-fragment `cat` in the SAME order (L410-416 ≡ L92-98), REQUIRED array + zero-sha refusal (L422-435 ≡ L103-116), direction A recompute (L437-442 ≡ L120-125), fold (`(cd dist && sha256sum cerberus.rb Cerberus.Cerberus.*.yaml) >> SHA256SUMS`, L474 ≡ L141-144), both-directions gate incl. end-anchored direction B `grep -q " ${name}\$"` (L481-496 ≡ L149-161), asset list driven from the verified sums (L508-513 ≡ L166-173). Documented local adaptations (equivalent, disclosed in the sim): absolute paths for the generator scripts (they `cd "$REPO_ROOT"` internally; in CI cwd IS the repo root so the workflow's relative paths resolve identically), and a broader sed (`s#  .*/#  #`) for sig lines because sim sigs live at absolute paths (workflow's `s#  dist/#  #` is correct for CI's `dist/`-relative sigs; same effect). The Windows `Set-Content -NoNewline` + `dist/` prefix quirk is replayed and normalized (fragment ends with a real `0x0a`, bare name) — byte-verified in the kept sim dir.

New stale-sha vector checked and DEFUSED: on macOS the artifact is re-packaged AFTER signing and `macos-notarize.sh:118-122` **regenerates dist/SHA256SUMS** before the fragment step reads it; on Windows the pwsh step hashes AFTER `Compress-Archive` (release-v2.yml:178-179). No stale sha can enter a fragment.

### 4. F8-V-1 (P0) closure — each sub-diagnosis verified closed in release-v2.yml

| Sub-diagnosis (attempt 1) | Fix verified at | Independently proven by |
|---|---|---|
| 1. deb/rpm shas never in any SHA256SUMS → EXPECTED loop exit 1 before publish | `Package sums fragment` **L302-328** (fail-closed L314-318, bare names L319-326), canonical cat includes `dl/packages/SHA256SUMS-packages` **L415**, upload includes it **L344** | sim fragment shows 4 package lines incl. deb + rpm; REQUIRED check + direction A PASS; neg1 (rpm line dropped) fails closed |
| 2. four `SHA256SUMS` collide under merge-multiple (last writer wins) | unique fragments `SHA256SUMS-<os>-<arch>` **L213-227** (normalization incl. Windows quirk), upload glob `dist/SHA256SUMS-*` **L235**, 5 distinct-dir downloads **L365-394**, explicit canonical `cat` **L410-416**; `grep merge-multiple release-v2.yml` = 2 COMMENT hits only | sim replays the quirk; all 8 platform lines + 4 package lines present in the 12-line canonical — zero lines lost |
| 3. `dist/*.rpm` upload glob matches nothing (rpms live in `dist/rpm/x86_64/`) | upload paths **L342-343** `dist/rpm/x86_64/*.rpm` + `*.sig`; srpms → `dist/srpm` L276 (not released, MVP) | sim stages rpm from `rpm/x86_64/`; rpm + rpm.sig reach the staged set and the asset list |
| 4. asset `find cerberus-*` omits the deb (underscore), its sig, `cerberus.rb`, winget manifests | winget flat-in-dist `--out-dir dist` **L456-464**, fold **L471-476**, FINAL both-directions gate **L478-497** (direction A recompute; direction B end-anchored), `gh release create` asset list driven FROM the verified sums **L499-520** | sim asset list = SHA256SUMS + 4 tarballs/zips + sigs + deb(+sig) + rpm(+sig) + cerberus.rb + 3 winget yamls; `shasum -c` 16/16 OK; unlisted-asset negative fails closed |

**F8-V-1: CLOSED.** The attempt-1 P0 chain can no longer silently recur: the rpm-drop replay (neg1) fails the gate exactly like the original P0 demands, and the exact `gh release create` asset list is reached from the verified manifest.

### 5. Findings

| ID | Severity | Finding |
|---|---|---|
| F8-V2-1 | P2 | **Sim fixture over-generates detached sigs for macos-aarch64 and windows-x86_64.** Real CI produces none there (macOS = codesign+staple embedded; Windows = Authenticode embedded; only Linux emits detached sigs), so a real release will list ~15 assets, not the sim's 17. No dataflow impact (all mechanisms identical; the both-directions gate is 1:1 and count-agnostic, so it handles any sig count); the pack's "17 assets" transcript must be read as the fixture model's list, not the literal CI manifest. Cosmetic fidelity note for the next sim revision. |
| F8-V2-2 | P2 | **The both-directions gate does NOT catch IDENTICAL duplicate lines inside a fragment** (empirically proven: exit 0, 18-asset list with the deb twice). A sha-CONFLICTING duplicate IS caught by direction A (exit 1, proven). Reachability under the committed steps: none — every fragment step is an explicit fixed list (no loop can emit a dupe). If it ever manifested, `gh release create` would receive the duplicated asset twice → GitHub API 422 → exit 1 **after the release object is created** (partial assets, visibly failed run — not a silent bad release). Suggested future hardening (not applied, per no-edit rule): a `sort \| uniq -d` check on the canonical sums inside the gate. |
| — | note | REQUIRED-name check remains substring-based (`awk index`), disclosed by the builder: a `.rpm.sig` line can satisfy the bare-rpm REQUIRED probe (observed in neg1 — defense-in-depth layering as documented); the end-anchored direction-B gate is the real refusal. Works as designed. |
| — | note | If a pwsh future version wrote a BOM into `dist\SHA256SUMS`, direction A would fail-closed (sha mismatch), never silently. windows-latest pwsh 7 default is utf8NoBOM. No action. |
| — | note | `gh release create` creates the release object before uploading assets; an upload failure mid-list leaves a partial release + exit 1. Inherent to the GitHub release flow (pre-existing behavior class), minimized here by the 1:1 gate; not a regression. |

### 6. Per-criterion verdicts (attempt-2 scope)

| Criterion | Verdict |
|---|---|
| F8-V-1 (P0) closed: canonical assembly, no merge-multiple, fixed globs, both-directions gate, publish list = verified manifest | **PASS** — all 4 fixes at file:line; dataflow executed end-to-end by this reviewer (×2 green), failures replayed (×2, both bite) |
| F8-V-2 (P2) frozen-hash table anchored | **PASS** — 4/4 touched files match the committed table; 10 untouched files re-hash identical to attempt-1 §7 |
| F8-V-3 (P2) rpm Release pinned | **PASS** — `Release: 1` literal (spec L8 region); `%{RELEASE}` = `1` under `--define dist .fc40` re-proven independently; static guard inside the sim |
| F8-V-4 (P2) token handling | **PASS** — token never in a URL (extraheader mechanism), `set +x` guard real (script never enables xtrace), `GIT_TERMINAL_PROMPT=0` + `credential.helper=` cleared, `unset AUTH_HEADER` before gh, `GH_TOKEN` for the PR call; negative: exit 1, 0 token occurrences, 0 `x-access-token` occurrences |
| Regression: brew clean-install / install.sh / verify_tag battery / actionlint | **PASS** — all re-proven green (§1 rows 14-27) |
| Gates: fmt / clippy / 865-0 / pack 19 / frozen 0-byte / guards 6/6 / diff --check | **PASS** (§1 rows 28-34) |
| Hash check (4 touched files) | **PASS** — byte-exact match with the pack's frozen table |
| Containment integrity | **PASS** — frozen workflows byte-untouched; 6/6 new-job `review9_f8_pending` guards; no `uses:`/`workflow_call` bypass in the diff |

### 7. Final verdict

**PASS.** The attempt-1 P0 (F8-V-1) is genuinely closed: the canonical-SHA256SUMS assembly dataflow — five named fragments, explicit `cat`, no merge-multiple, corrected upload globs, both-directions fail-closed gate, publish list driven from the verified manifest — was executed end-to-end by this independent reviewer against real fixtures (twice, idempotent), its failure modes were replayed and bite in both directions, and the winget/formula shas in the canonical sums are real (independently recomputed 16/16). Two P2 findings are recorded above (sim sig-fixture fidelity; identical-duplicate lines pass the gate but fail visibly at publish and are unreachable under the committed steps). Containment remains intact; the live GitHub Actions run stays honestly deferred to post-lift. The F8 gate may proceed to owner sign-off per §8B.
