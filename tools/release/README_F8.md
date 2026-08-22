# F8 — Cross-platform release pipeline (vending)

This directory contains ONLY the installers/packaging for macOS, Linux and
Windows. Helm and pack signing are covered by another agent (not touched in
this directory).

## 1. What each thing produces

| Platform | Installation method | Artifact | Where it is produced |
|---|---|---|---|
| macOS / Linux | `curl … \| sh` | `install.sh` (with `CERBERUS_SHA256` checksum) | `install.sh` repo |
| macOS | Homebrew | formula `tools/release/brew.rb` (+ `contrib/homebrew/cerberus.rb` for the tap) | release CI + tap |
| Linux | `.deb` (Debian/Ubuntu) | `packaging/deb/*` + `build_deb.sh` | release CI (ubuntu) |
| Linux | `.rpm` (Fedora/RHEL) | `packaging/rpm/cerberus.spec` | release CI (optional) |
| Windows | winget/MSI | `packaging/winget/manifests/…` + publish README | winget-pkgs PR |
| All | GitHub Release | `.tar.gz`/`.zip` + `SHA256SUMS` | `.github/workflows/release.yml` |

The naming scheme is canonical and shared by `install.sh`, the formula and the
winget manifest:

```
cerberus-<VERSION>-<OS>-<ARCH>.tar.gz      OS: macos|linux
cerberus-<VERSION>-<OS>-<ARCH>.zip         OS: windows     (contiene cerberus.exe)
SHA256SUMS
```

## 2. Release flow (local, without credentials — reproducible)

```bash
# 0) prerequisites: rustup stable + target(s) for cross
rustup target add aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu \
                 aarch64-apple-darwin x86_64-apple-darwin

# 1) host artifacts → dist/
./tools/release/build_release.sh                 # detects OS/arch
CERBERUS_OS=linux CERBERUS_ARCH=aarch64 TARGET=aarch64-unknown-linux-gnu \
  ./tools/release/build_release.sh

# 2) signatures (transparent if no credentials: DRY-RUN that does not fail)
./tools/release/macos-notarize.sh dist/cerberus-0.1.0-macos-aarch64.tar.gz
./tools/release/windows-sign.sh dist/exe/cerberus.exe          # only on Windows/signtool

# 3) brew: fill the formula with real hashes and validate
./tools/release/fill_brew_formula.sh --version 0.1.0 --platforms dist/SHA256SUMS --out dist/cerberus.rb
ruby -c dist/cerberus.rb
brew audit --strict --new dist/cerberus.rb      # with a published tag and real sha

# 4) .deb (requires dpkg-deb, optional in CI)
./packaging/deb/build_deb.sh dist/cerberus-0.1.0-linux-x86_64.tar.gz 0.1.0 --arch amd64

# 5) .rpm (requires rpmbuild; see cerberus.spec)
rpmbuild -ba packaging/rpm/cerberus.spec
```

## 3. Signing and notarization — what happens in CI (with secrets)

The secrets do NOT live in the repo. They are injected into `.github/workflows/release.yml`:

- **macOS**: `APPLE_ID`, `APPLE_APP_SPECIFIC_PASSWORD`, `APPLE_TEAM_ID`,
  `APPLE_IDENTITY` → the `macos-sign` job runs:
  `codesign --options runtime --timestamp` → `notarytool submit --wait` →
  `stapler staple` → `spctl --assess` → re-packages + regenerates SHA256SUMS.
  Without credentials: the step is skipped (unsigned binary, not notarized).
- **Windows**: `WINDOWS_SIGN_CERT` (pfx in base64) + `WINDOWS_SIGN_PASSWORD`
  → `signtool sign /fd SHA256 /tr …` on `cerberus.exe`, re-zip + sums.
  Without credentials: step skipped.

> Since locally there are no credentials, the scripts enter **DRY-RUN**: they
> show the exact sequence and exit with code 0 (they never break the pipeline).

## 4. Publish the release

1. Commit with a semver tag: `git tag v0.1.0 && git push origin v0.1.0`.
2. `.github/workflows/release.yml` builds the 5 targets, uploads the artifacts
   as GitHub Actions artifacts, performs signing if there are secrets and
   creates the GitHub Release with the global `SHA256SUMS`.
3. Homebrew: `tools/release/fill_brew_formula.sh --version 0.1.0
   --platforms <release SHA256SUMS> --install` (writes
   `contrib/homebrew/cerberus.rb`) and a PR is made to the Homebrew tap
   (or a local `brew tap`).
4. winget: follow `packaging/winget/README.md` (PR to `microsoft/winget-pkgs`).
5. verify: `install.sh`, `brew install`, `apt install ./cerberus_*.deb`,
   `rpm -i`, `winget install Cerberus.Cerberus`.

## 5. How they become real artifacts

- **`build_release.sh`** → `dist/` with the tarballs/zip + `SHA256SUMS`. Names
  exactly the same as those used by `install.sh` (`.tar.gz` with `cerberus` at
  the root; `.zip` with `cerberus.exe`).
- **CI `release.yml`** → per target: the script, sanity, artifact upload;
  then the `release` job: download merge, global `SHA256SUMS`,
  `gh release create`.
- **brew**: the fill transforms the placeholders with the real sha → a valid
  formula → `brew install`.

## 6. Pipeline verification (integrity, F8)

```bash
bash -n tools/release/build_release.sh
bash -n tools/release/macos-notarize.sh
bash -n tools/release/windows-sign.sh
bash -n tools/release/fill_brew_formula.sh
ruby -c tools/release/brew.rb
python3 -c "import yaml,glob;[yaml.safe_load(open(f)) for f in glob.glob('.github/workflows/*.yml')+glob.glob('packaging/winget/manifests/**/*.yaml',recursive=True)]"
cargo build --release          # the workspace stays green
```

The steps that require credentials (real signing/notarization) ONLY happen
in CI with secrets; the current CI matrix (`ci.yml`) stays intact
(build/test/lint).

## 7. Operational notes

- Without real signing credentials the release is functional but the binaries
  do not carry a notarization/Authenticode stamp: documented in the release
  notes. Prerequisite for GA: credentials + CI steps enabled.
- The winget MSI is produced with WiX (`dotnet tool install --global wix`);
  until the toolchain is pinned it is uploaded manually to the release with
  the same name `cerberus-<v>-windows-x86_64.msi` and `InstallerSha256` is
  filled in.
- Not touched: `src/`, daemon, proxy, packs, store, ceremony, current CI.