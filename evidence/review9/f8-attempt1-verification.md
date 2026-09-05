# F8 Independent Verification — R9-3 release architecture / R9-4 tap + clean-install gate / R9-15 packaging

- Reviewer: Independent adversarial VERIFY (did not build; Gauntlet §8B, combined correctness + security, proportionate to workflows + shell scope)
- Candidate: commit `848f28e` on branch `r9-remediation` (parent `5d0a23b`)
- Verification worktree: `/var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/f8-verify` (detached at 848f28e; removed after this report)
- Date: 2026-09-04
- Builder pack under review: `evidence/f8/r9-release-and-tap.md` (attempt 1, verdict BUILT — not claimed PASS)
- **Final verdict: FAIL** (one P0: the `release-v2.yml` publish chain deterministically hard-fails — no GitHub release can ever be created, so the tap-PR trigger never fires; the original R9-3 harm "pipeline broken → distribution dead" is structurally reproduced inside the replacement workflow). R9-3's tag gate itself and all local R9-4/R9-15 gates verified genuine.

---

## 1. Commands run (verbatim, with exit codes)

| # | Command (cwd = verification worktree unless noted) | Exit | Result |
|---|---|---|---|
| 1 | `git worktree add --detach …/f8-verify 848f28e` | 0 | worktree created |
| 2 | `git diff 5d0a23b..848f28e --stat` | 0 | 14 files, +1178/−27 |
| 3 | `git diff 5d0a23b..848f28e -- .github/workflows/release.yml .github/workflows/notify-tap.yml` | 0 | **empty (0 bytes) — frozen workflows byte-untouched** |
| 4 | `git diff 5d0a23b..848f28e --check` | 0 | clean |
| 5 | `cargo fmt --check` | 0 | clean |
| 6 | `cargo clippy --workspace --all-targets -- -D warnings` (un-piped, rc checked) | 0 | Finished dev profile |
| 7 | `rtk cargo test --workspace --all-targets` | 0 | **865 passed (29 suites, 55.02s), 0 failed** |
| 8 | `rtk cargo test -p cerberus-packs --test production_pack_pr` | 0 | **19 passed** |
| 9 | guard grep (see §2) | 0 | 6/6 jobs guarded |
| 10 | static write-path grep (push/merge/checkout) over 3 v2 workflows + scripts | 0 | see §4a |
| 11 | secret-leak grep over workflows + scripts | 0 | see §4d |
| 12–19 | `verify_tag_merge.sh` attack battery T1–T7 in throwaway clone `…/f8tags` (tags created ONLY there) | 0/1 as designed | see §4b/c |
| 20 | release-job simulation `…/f8relsim` (verbatim shell logic of `release-v2.yml`) | 1 (job) | **P0 reproduced** — see §5 |
| 21 | `./tools/release/build_release.sh` | 0 | real `dist/cerberus-0.1.2-macos-aarch64.tar.gz`, sha `1b9f81a5…`; `shasum -c SHA256SUMS` → OK |
| 22 | isolated brew: `git clone --depth=1 https://github.com/Homebrew/brew …/f8brew/homebrew` | 0 | temp prefix, machine `/opt/homebrew` never touched |
| 23 | `fill_brew_formula.sh --version 0.1.2 --platforms <sums w/ missing linux-aarch64 line>` | **1** | `error: no sha256 for 'cerberus-0.1.2-linux-aarch64.tar.gz' … (R9-4: refusing to emit a placeholder)` — fail-closed proven |
| 24 | `fill_brew_formula.sh --version 0.1.2 --platforms /tmp/f8-full-sums --out /tmp/f8-formula.rb` + `ruby -c` | 0 | valid Ruby, real macos sha, 0 zero-placeholders |
| 25 | `brew tap-new f8/local` (inside temp prefix) + formula installed into tap | 0 | tap constructed from builder's recipe + real artifact |
| 26 | `brew install --build-from-source f8/local/cerberus` | 0 | poured, **brew verified the real sha256** |
| 27 | `$PREFIX/bin/cerberus --version` | 0 | `cerberus 0.1.2` |
| 28 | `brew test f8/local/cerberus` | 0 | `==> Testing f8/local/cerberus` → exit 0 |
| 29 | `$PREFIX/bin/cerberus test "my api key is sk-abc123"` | 0 | `✓ No sensitive data detected.` |
| 30 | `brew uninstall --force cerberus` (temp prefix) | 0 | isolated prefix clean; real `/opt/homebrew/Cellar/cerberus/0.1.1` (Aug 22, pre-existing) untouched |
| 31 | `publish_tap_pr.sh --version 0.1.2 --sums <REAL v0.1.2 SHA256SUMS> --dry-run` | 0 | real shas, `DRY-RUN OK`, no network |
| 32 | `env -u TAP_PR_TOKEN ./tools/release/publish_tap_pr.sh …` (real mode) | **1** | `FAIL: TAP_PR_TOKEN is not set … Refusing (fail-closed).` |
| 33 | `TAP_PR_TOKEN='F8FAKE-…' publish_tap_pr.sh --tap-repo f8-nonexistent-verify-xyz/…` | **1** | clone fails; **fake token appears 0× in output** (git redacts) |
| 34 | `actionlint -no-color .github/workflows/*.yml` (actionlint 1.7.12) | 1 | **10 findings — all intentional containment patterns; zero real** (see §6) |
| 35–38 | `fill_winget_manifest.sh` negatives: missing sums file / entry missing / zero sha / 4-hex sha | 1,1,1,1 | all hard-fail-closed |
| 39 | `fill_winget_manifest.sh --version 0.1.2 --sums <REAL v0.1.2 sums> --out-dir /tmp/f8-winget-out` | 0 | `InstallerSha256: 12ab923d1c64e4f5…` (real published sha), `PackageVersion: 0.1.2` |
| 40 | `install.sh` negative (wrong sha) via local HTTP 8814 + isolated HOME | **1** | `Error: checksum mismatch. Expected deadbeef…, got 1b9f81a5…` |
| 41 | `install.sh` positive (real sha) | 0 | `✓ SHA-256 checksum verified` → installed → `cerberus 0.1.2` |
| 42 | `bump_version.sh 0.2.0 --dry-run` | 0 | exact Cargo.toml+lock diff; tree clean after (0 dirty files) |
| 43 | `bump_version.sh 0.2` | **1** | `FAIL: '0.2' is not strict MAJOR.MINOR.PATCH semver` |
| 44 | commit-message + file-list hash audit | 0 | see §7 |
| 45 | containment escape-hatch grep (job-level `uses:`, `workflow_call`) | 0 | none — see §8 |

## 2. Gate results

| Gate | Expected | Observed | Verdict |
|---|---|---|---|
| `cargo fmt --check` | exit 0 | exit 0 | PASS |
| clippy un-piped `-D warnings` | exit 0 | exit 0 | PASS |
| workspace debug tests | 865/0 | 865 passed / 0 failed (29 suites, 55.02s) | PASS |
| pack | 19/19 | 19 passed / 0 failed | PASS |
| `git diff --check` | clean | clean | PASS |
| frozen workflows untouched | empty diff | empty diff (`release.yml`, `notify-tap.yml`); `"on": []` + `review9_release_freeze` / `review9_tap_freeze` still present | PASS |
| new-workflow guard | every job | **6/6 jobs** carry `if: ${{ false }} # review9_f8_pending` (release-v2: verify-tag L54, build L72, linux-packages L217, release L291; version-bump-v2: L48; notify-tap-v2: L37) | PASS |

## 3. Per-criterion verdicts

| Criterion | Verdict | Note |
|---|---|---|
| R9-3: version bump via PR, never a push to protected main | **PASS** | static proof + local dry-run; see §4a |
| R9-3: publish only on `v*` tags over merged commits, fail-closed | **PASS (gate) / FAIL (publish chain)** | verify_tag_merge.sh gate solid (§4b/c); the publish job after it **cannot succeed** (§5, P0) |
| R9-3: no workflow writes to main | **PASS** | §4a |
| R9-3: maintainer cannot trick the tag gate (cherry-picked sha) | **PASS** | §4c |
| R9-3: secrets hygiene | **PASS** | §4d |
| R9-4: tap flow automated, sha-sourced, fail-closed on missing token | **PASS** | §4d + §9 |
| R9-4: REAL clean-install brew gate | **PASS** | reproduced independently in an isolated prefix; §9 |
| R9-4: formula sha fail-closed (no zero placeholders) | **PASS** | §9 |
| R9-15a: deb really built by release-v2.yml | **PARTIAL** | build step exists (build_deb.sh + dpkg-deb --info), but the deb **never reaches the release assets and its sha never enters SHA256SUMS** → publish job dies (§5) |
| R9-15a: rpm really built by release-v2.yml | **FAIL** | rpm is never uploaded at all (`dist/*.rpm` glob misses `dist/rpm/`), sha never in SHA256SUMS (§5) |
| R9-15b: winget zip flow current, real InstallerSha256 | **PASS** | real published sha `12ab923d…` injected; 4 negative cases fail-closed |
| R9-15c: SHA256SUMS mandatory, no unsigned fallback | **PASS (logic, in-workflow)** | zero-sha refusal + recompute loop verified by simulation; signing prechecks present (`: "${SECRET:?FAIL …}"`) — but see §5 for the merge/EXPECTED break |
| R9-15d: Intel macOS per closed decision | **PASS** | matrix 4 targets; brew.rb `odie` + documented decision 161387a |
| actionlint on all workflows | **PASS** | 10 findings, all intentional containment patterns; 0 real (§6) |
| Containment integrity | **PASS** | §8 |
| Hash check of 13 files vs pack's frozen block | **PARTIAL (evidence gap)** | §7 — the pack's frozen-hash table does not exist in the commit message; file list verified 1:1 instead |

## 4. R9-3 architecture attack results (the P0 — attacked from every vector)

### (a) No workflow writes to main — static audit
Grep over all 3 v2 workflows + all release scripts for `git push|gh pr merge|git merge|gh pr |gh release|checkout|ref:`:

- `version-bump-v2.yml`: the only push is `git push origin "$BRANCH"` with `BRANCH="release/bump-v${VERSION}"` — a **new** branch; then `gh pr create --base "$CERBERUS_DEFAULT_BRANCH"`. **No `gh pr merge` anywhere in the repo's workflows.** A human merges. Checkouts pin `ref: main` (default branch, read).
- `release-v2.yml`: triggers only on `push: tags: v*`; all checkouts pin `ref: ${{ github.ref_name }}` (the event tag, never a mutable ref); the only privileged write is `gh release create` under `permissions: contents: write` (job-scoped). No push/merge of any ref.
- `notify-tap-v2.yml`: checkout pins `github.event.release.tag_name`; downloads SHA256SUMS from the release; all writes go to the **tap repo** (different repository) via `publish_tap_pr.sh` → branch `tap-v<V>` + `gh pr create --repo <tap>`. No write to this repo.
- Scripts: `bump_version.sh` only `git checkout --` (restore); `verify_tag_merge.sh` read-only; `publish_tap_pr.sh` pushes only to the tap repo.

**Outcome: PASS** — nothing in the v2 architecture can write to or merge into `main`.

### (b) verify_tag_merge.sh — reproduced + extended negative battery
Run in throwaway clone `…/f8tags` (checkout 848f28e; `refs/remotes/origin/main` pinned to the real GitHub main `753f9a9` — note: a local clone mapped the main repo's *stale local* `main` (54f88c4), which I corrected to mirror what CI's `fetch-depth: 0` sees). All test tags created only in the throwaway clone.

| Vector | Setup | Result |
|---|---|---|
| T1 (reproduce builder's negative) | tag `v0.1.2` on unmerged `5d0a23b` | `FAIL: tag commit 5d0a23bd… is NOT reachable from main merged history; refusing to release (R9-3)`, exit 1 — **reproduced exactly** |
| T2 (new shape) | strict-semver `v0.1.2` on a commit existing **only on a feature branch** (`1b26724`, never merged) | `FAIL: … NOT reachable … (R9-3)`, exit 1 |
| T3 (malformed semver ×3) | `release-0.1.2`, `v0.1.2-rc1`, `v0.1.2.1` | each `FAIL` (pattern / strict-semver), exit 1 |
| T4 (version mismatch) | `v9.9.9` on HEAD | `FAIL: tag v9.9.9 != crates/cerberus/Cargo.toml version 0.1.2`, exit 1 |
| T5 (cherry-pick trick) | cherry-picked a real merged main commit onto an unmerged branch, tagged `v0.1.2` | `git merge-base --is-ancestor <cherry> origin/main` → rc 1; script `FAIL: … NOT reachable …`, exit 1 |
| T6a (positive) | lightweight `v0.1.2` on real merged `origin/main` commit `753f9a9` | semver OK / Cargo.toml OK / lock OK / `is an ancestor of origin/main (merged) — OK` → `PASS`, exit 0 |
| T6b (annotated positive) | annotated tag object (type `tag`) on `753f9a9` | `PASS`, exit 0 (`git rev-list -n 1` resolves annotated tags) |
| T7 (missing origin) | clone with `origin` removed and no `refs/heads/main` | `FAIL: default branch 'main' not found (need fetch-depth: 0 checkout in CI)`, exit 1 — **fail-closed** |

**Outcome: PASS — 8/8 vectors behave exactly as designed.** The merge-base check is the correct answer to the cherry-pick trick: ancestry is over object identity, so an identical-diff cherry-pick (different sha) is refused.

Caveat recorded for the owner: the script reads versions from the **working tree** Cargo.toml/lock; in CI this equals the tag tree because `release-v2.yml` checks out `ref: ${{ github.ref_name }}` before invoking it. This invariant is satisfied by every call site today.

### (c) Can a maintainer trick the tag gate?
- **Cherry-picked sha:** refused (T5). A commit not reachable from `origin/main` fails regardless of content identity.
- **Force-moved tag:** re-pointing the tag still re-runs the ancestry check at runtime; only commits genuinely on main pass.
- **Old-commit re-release:** tagging an old *merged* commit whose Cargo.toml matches the tag is possible — but that commit went through review/merge, and the release would ship exactly the artifact that commit's tree produced. Acceptable; noted, not a violation.

### (d) Secrets
- No `set -x`, no `printenv`/`env |` pipes, no echo of secret **values** in any v2 workflow or release script. The `echo "$GPG_PRIVATE_KEY" | gpg --import` pattern pipes to gpg's stdin (standard, not logged; GitHub also masks secret values in logs).
- `TAP_PR_TOKEN`: env-injected (notify-tap-v2 L41), **fail-closed precheck** (`: "${TAP_PR_TOKEN:?FAIL …}"`), used only in the clone URL. **Empirical leak test:** with a fake token and a nonexistent tap repo, the clone fails, the script exits 1, and `grep` for the token over the full output = **0 hits** (git redacts userinfo in transport errors).
- Minor note (P2-3): token-in-URL clone is one `set -x` away from leaking; recommend `GIT_TERMINAL_PROMPT=0` + credential-helper or `gh auth`-based flow in a future round. Not a blocker.

## 5. P0 FINDING — the release-v2.yml publish chain deterministically fails (release can never be created; tap PR can never fire)

This was found by static analysis and **reproduced by executing the release job's exact shell logic** against a reconstructed artifact layout in `…/f8relsim` (dummy files with correct names/paths; the EXPECTED loop and find run verbatim; the most charitable assumption — all 4 platform SHA256SUMS lines merged — was granted).

Chain of failures (all independent of each other; any one kills the release):

1. **deb/rpm shas are never computed into SHA256SUMS.** The 4 build jobs each write `dist/SHA256SUMS` (one platform line, from `build_release.sh:132`). `build_deb.sh` never touches SHA256SUMS; the `linux-packages` job's steps contain no `sha256sum` of the .deb/.rpm and its `upload-artifact` path list (`dist/*.deb`, `dist/*.rpm`, `dist/*.sig`) does not include any SHA256SUMS. The `release` job's EXPECTED list demands `cerberus_${VERSION}_amd64.deb` and `cerberus-${VERSION}-1.x86_64.rpm` entries → the loop emits:
   ```
   FAIL: cerberus_0.1.2_amd64.deb missing from SHA256SUMS
   FAIL: cerberus-0.1.2-1.x86_64.rpm missing from SHA256SUMS
   ```
   → `exit 1` **before `gh release create`**. (Simulation output verbatim; exit status would be 1.)
2. **The per-platform SHA256SUMS collide on download.** All four `dist-*` artifacts contain a file literally named `SHA256SUMS`; `actions/download-artifact@v4` with `merge-multiple: true` merges into one dir and — per the official README/MIGRATION docs — *"If files within merged artifacts have the same name, the last writer wins."* So at most **1 of 4** platform lines survives; the EXPECTED loop then fails on the other 3 platforms too. The charitable 4-line simulation above already fails; the real runner fails earlier.
3. **The rpm never leaves the linux-packages job.** rpmbuild writes to `dist/rpm/` (`--define "_rpmdir $(pwd)/dist/rpm"`, and the job's own signing loop finds it there), but the upload glob is `dist/*.rpm` (non-recursive) → **0 matches** (simulated: `find dist -maxdepth 1 -name '*.rpm'` → 0). `if-no-files-found: error` does not fire only because the .deb/.deb.sig match; the artifact silently ships without the rpm and without the rpm .sig.
4. **The release-asset find omits the packages it demands.** `find dist -maxdepth 1 -type f \( -name "cerberus-*" -o -name "SHA256SUMS" \)` (simulated verbatim on the exact CI layout) matches the 4 tarballs/zips + sigs + SHA256SUMS, but **NOT**: `cerberus_0.1.2_amd64.deb` (underscore ≠ dash), its `.sig`, `dist/cerberus.rb` (the formula the job itself just generated), and `dist/winget-manifests/` (never uploaded anywhere).

**Impact:** with the containment guard flipped live (the documented owner flip), every `v*` tag run builds everything, then dies at "Merge SHA256SUMS and verify every expected entry" — **no GitHub release is ever created**, therefore `notify-tap-v2.yml` (trigger: release published) **never runs**, and the tap stays stale. That is precisely the R9-3 harm class ("release pipeline broken on main; distribution stopped") reproduced one layer deeper. The builder's pack describes the intended flow ("release: merge SHA256SUMS → … → gh release create") but no evidence exists that this step sequence can succeed, and it provably cannot as committed.

This also fails the pack's R9-15a criterion as stated ("deb/rpm really built **by release-v2.yml**" — built, yes; **released**, never).

**Why the local gates could not catch it:** all local dry-runs (fill_brew/fill_winget/publish_tap) operate on a **supplied** SHA256SUMS; nothing locally exercises the in-workflow merge+EXPECTED step. The pack's honest-limits section defers "the real GitHub Actions run" — but this failure is provable statically and by simulation, and per §8B ("couldn't run = FAIL") the release chain must count as unverified-and-broken, not pending.

**Minimal remediation sketch (for the builder, not applied here):** per-platform sums files with distinct names (or upload them under distinct artifact keys), a step in `linux-packages` that computes and uploads a `packages-SHA256SUMS` (deb+rpm), `dist/rpm/*` upload globs, and an asset pattern that covers the deb (underscore), the formula and the winget manifests.

## 6. actionlint (R9-15 / G0 residual)

`actionlint -no-color .github/workflows/*.yml` (v1.7.12) → exit 1 with **10 findings**, classified:

- 6 × `if-cond` constant-false — the `review9_f8_pending` job guards in the 3 new workflows (one per job) → **intentional containment**
- 2 × `if-cond` constant-false — the frozen `release.yml:22` / `notify-tap.yml:15` guards → **intentional containment**
- 2 × `"on" section should not be empty` — the frozen `release.yml:14` / `notify-tap.yml:7` → **intentional containment**

Excluding the two documented intentional patterns: **zero real findings** (the pack's count of "if:false × 8 + frozen on:[] × 2 = 10" matches exactly). PASS.

## 7. Hash check (criterion 6)

- The pack's "Files touched (frozen SHA-256)" table defers every row to "see `git hash-object` table in commit" and states "(Hashes frozen at commit time — see the commit message body for the exact table.)" — **the commit message of 848f28e contains no hash table**. The claim is therefore unverifiable as written (P2-1).
- What *is* verifiable: the diff's 14 files match the pack's 14-row table **1:1 by path** (13 code/config files + the evidence pack).
- This report freezes the actual SHA-256 of the 13 code files at 848f28e for future re-verification:
  ```
  a60afff095ec7c6c8366a0d62269a2623665347420d0e42a59e100c027dd261a  .github/workflows/release-v2.yml
  39f6aad11103fb76964f0eea7869a533852b1c089251d39a4245edae1457c4cb  .github/workflows/version-bump-v2.yml
  e7b6692a0fa5da3426a53c54552458caedf41aa56c32c463509ffc50232505e0  .github/workflows/notify-tap-v2.yml
  6ff5e0aa0600f4d26f3147cce6f421734cb18f4596889bb079e2e6a4b618d239  tools/release/verify_tag_merge.sh
  6801e2f200a9fbd7c2f6c294b9246e9bc690f46cb0534d2d23aca4529e0656be  tools/release/bump_version.sh
  717d8234fa4399cabe322250ff385c16b5ac783e4df1f20ad45a53b9a29eaa00  tools/release/publish_tap_pr.sh
  2be8523c9eb051a0247d09edb431dae6b078d38a82d99a8b27e20c5ba9ae2e2f  tools/release/fill_winget_manifest.sh
  b22cae001da7cce83285430b158259ee20f0c6936aebc92d0f8099facda52b13  tools/release/brew.rb
  37d1ee04a3c2870bf262445f3fca4ec62b768b074b9baba4ec5e94bb78f30f4c  tools/release/fill_brew_formula.sh
  29c252d7f0ac10e733d0abcfe0840c04adf43f06ddd411cfdd077bdc8c9c16c5  install.sh
  b3bccc166ec7068395ea1c632a890e20be1d1b370d248c9272dcd5251e70ab19  packaging/deb/build_deb.sh
  38aaf40abcb255338f178acdc04ad433e21fb713505c15c18c27d08dbaaf6f02  packaging/deb/control
  a96690bd0f29fbecf84c1d6630c85a528c43ec3f5b577b5831ceb7e4a0cbfa69  packaging/rpm/cerberus.spec
  ```

## 8. Containment integrity

- Frozen workflows: byte-identical to base (empty diff), still `"on": []` + old guards → **inert**.
- New workflows: real triggers present (so the owner flip is a minimal diff), but **all 6 jobs** are guarded `if: ${{ false }}` with the new `review9_f8_pending` marker (one guard per job — verified per-file; the flip procedure is documented in each workflow's header comment: "remove after F8 gate PASS + owner sign-off").
- No job-level `uses:` (no reusable-workflow invocation) and no `workflow_call` trigger in any v2 file → **no bypass path**; with every job's `if` constant-false, no job can run while the guard is present.

## 9. R9-4 brew + negative-test transcripts (condensed)

**Clean-install gate — fully isolated Homebrew prefix** (`git clone --depth=1 Homebrew/brew` into temp; `HOMEBREW_REPOSITORY/CELLAR/PREFIX` bound to the temp clone; the machine's `/opt/homebrew` was never invoked and its pre-existing `cerberus 0.1.1` (Aug 22, builder's restore) is untouched):

```
$ brew tap-new f8/local                       # inside temp prefix
$ fill_brew_formula.sh --version 0.1.2 --platforms /tmp/f8-full-sums
  sha256 macos-aarch64 : 1b9f81a525f39c1e…    # REAL sha of the real build (this round)
  → ruby -c OK, zero zero-placeholders
  (formula URL patched to file://…/dist/cerberus-0.1.2-macos-aarch64.tar.gz)
$ brew install --build-from-source f8/local/cerberus      → exit 0 (brew verified the sha256)
$ $PREFIX/bin/cerberus --version               → cerberus 0.1.2
$ brew test f8/local/cerberus                  → ==> Testing f8/local/cerberus … exit 0
$ $PREFIX/bin/cerberus test "my api key is sk-abc123"  → ✓ No sensitive data detected.
$ brew uninstall --force cerberus              → Uninstalling cerberus... (4 files, 15.0MB); isolated prefix clean
```

Note: modern Homebrew 6 refuses bare formula paths ("requires formulae to be in a tap") — the tap route (`brew tap-new` + formula copy) was required; the builder's flow used the equivalent local-tap form.

**Formula fail-closed (R9-4):** a sums file missing the `linux-aarch64` entry → `error: no sha256 for 'cerberus-0.1.2-linux-aarch64.tar.gz' in … (R9-4: refusing to emit a placeholder)`, exit 1. The zero-placeholder path is gone.

**tap-PR script:**
```
$ publish_tap_pr.sh --version 0.1.2 --sums <REAL v0.1.2 SHA256SUMS> --dry-run
  real shas (d48d142b…/696491f8…/0065a661…) injected; diff vs broken 0.1.0 placeholder formula shown;
  DRY-RUN OK … No network calls made.                                  exit 0
$ env -u TAP_PR_TOKEN … (real mode)   → FAIL: TAP_PR_TOKEN is not set … Refusing (fail-closed).   exit 1
$ TAP_PR_TOKEN=F8FAKE-… --tap-repo f8-nonexistent-verify-xyz/…
  → remote: Invalid username or token … fatal: Authentication failed …
  → FAIL: could not clone tap repo …  exit 1; fake token occurrences in output: 0 (git redacts)
```

**Winget (R9-15):** negatives — missing sums file / missing zip entry / zero sha / 4-hex sha → all `FAIL …` exit 1. Positive with the **real published v0.1.2 SHA256SUMS** (fetched from the live GitHub release; shas match the pack's: `d48d142b…`, `696491f8…`, `0065a661…`, `12ab923d…`) → `PackageVersion: 0.1.2`, `InstallerSha256: 12ab923d1c64e4f5…` (real), URL correct, exit 0.

**install.sh:** local HTTP 8814 + isolated HOME + `CERBERUS_RELEASE_URL` override —
```
NEGATIVE  CERBERUS_SHA256=deadbeef… → Error: checksum mismatch. Expected deadbeef…, got 1b9f81a5…  exit 1
POSITIVE  CERBERUS_SHA256=<real>    → ✓ SHA-256 checksum verified → ✓ installed → cerberus 0.1.2   exit 0
```

**bump gate (R9-3 mechanics):** `bump_version.sh 0.2.0 --dry-run` → exact `-version = "0.1.2" +version = "0.2.0"` in Cargo.toml and lock, tree clean after; `0.2` → `FAIL … not strict MAJOR.MINOR.PATCH semver`, exit 1.

## 10. Findings

| ID | Severity | Finding |
|---|---|---|
| **F8-V-1** | **P0** | `release-v2.yml` publish chain deterministically fails: (1) deb/rpm shas are never written into any SHA256SUMS → the EXPECTED-list loop `exit 1`s **before `gh release create`**; (2) the four per-platform `SHA256SUMS` collide under `download-artifact@v4 merge-multiple` ("last writer wins" per official docs) → ≥3 platform lines lost; (3) `dist/*.rpm` upload glob matches nothing (rpms live in `dist/rpm/`) → rpm + rpm.sig never uploaded; (4) the release-asset `find` (`cerberus-*`) omits the deb (underscore), its sig, `cerberus.rb`, and the winget manifests. Net effect when live: every tag run builds everything and publishes **nothing**; `notify-tap-v2.yml` never triggers; tap stays stale — the R9-3 harm class reproduced inside the replacement. Proven by static audit + verbatim-logic simulation (§5). |
| F8-V-2 | P2 | The pack's frozen-hash block is unanchored: it defers to "the commit message body for the exact table" / "`git hash-object` table in commit", but commit 848f28e contains no such table; no hashes are comparable anywhere. File list verified 1:1 instead; actual hashes frozen in §7 of this report. |
| F8-V-3 | P2 | `packaging/rpm/cerberus.spec` has `Release: 1%{?dist}` — on a dist-tagging rpm installation the artifact name becomes `cerberus-0.1.2-1.<disttag>.x86_64.rpm`, which the EXPECTED-list's `cerberus-${VERSION}-1.x86_64.rpm` would not match. Fragility on top of F8-V-1; pin `Release: 1` or derive the name from the built file. |
| F8-V-4 | P2 | `publish_tap_pr.sh` embeds `TAP_PR_TOKEN` in the clone URL. Empirically redacted by git in failure output (0 leaks), but any future `set -x`/verbose transport logging would expose it; prefer a credential helper or `gh`-mediated auth. |
| F8-V-5 | P2 (note, pre-existing) | `install.sh` proceeds with only a warning when `CERBERUS_SHA256` is unset (documented P1-14 behavior, unchanged by this phase; the R9-15 scope here was the resolution override, which works and fails loud on latest-resolution failure). |

## 11. Final verdict

**FAIL.**

- R9-3's **core invariant** (no workflow writes to main; publish only on tags over merged history; tag gate fail-closed against unmerged, feature-only, cherry-picked, malformed, mismatched, and missing-origin vectors) is genuinely solid — all 8 attack vectors behave as designed, reproduced and extended beyond the builder's evidence.
- R9-4's local gates are genuine (independently reproduced clean-install with a real artifact and real sha in an isolated Homebrew prefix; fail-closed tap/formula/winget/install behavior all proven, including the token-leak negative).
- But the phase's product — the replacement release workflow — **cannot publish a release**: the `release` job's mandatory-integrity step requires entries (deb/rpm shas) and files (rpm) that no step ever produces, under the pack's own fail-closed design. Per §8B, "the real GitHub Actions run" is not an acceptable unknown when the failure is deterministic and provable statically; the pack's R9-15a criterion ("deb/rpm really built by release-v2.yml" → released) is unmet.
- Containment is intact (frozen workflows untouched; 6/6 new-job guards; no bypass), so there is **no live breakage** — but the gate must not be lifted on this attempt. Return to the builder with F8-V-1 (P0) and re-verify the release chain end-to-end (a dry-run harness for the release job's merge/EXPECTED/find steps would have caught this locally and should be part of the fix's evidence).

*Verification artifacts (all in `/var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/`, throwaway): `f8-verify/` (worktree), `f8tags/` + `f8-noorigin/` (tag-gate clones), `f8relsim/` (release-job simulation), `f8brew/` (isolated Homebrew), `f8-www/` (install-gate server fixture). Main repo touched only by this report file.*
