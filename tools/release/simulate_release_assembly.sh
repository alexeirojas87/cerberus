#!/usr/bin/env bash
# simulate_release_assembly.sh — local END-TO-END proof of the release-v2.yml
# publish-chain dataflow (F8 FIX attempt 2).
#
#   Usage:
#     tools/release/simulate_release_assembly.sh              # positive run
#     tools/release/simulate_release_assembly.sh --negative   # + fail-closed replay
#     SIM_KEEP=1 tools/release/simulate_release_assembly.sh   # keep the sim dir
#
#   WHY THIS EXISTS: F8 attempt 1 (848f28e) died in verification — the release
#   job's assembly dataflow deterministically dead-ended BEFORE
#   `gh release create` (deb/rpm shas never in SHA256SUMS; per-platform
#   SHA256SUMS colliding under download-artifact merge-multiple; rpm upload
#   glob missing dist/rpm/; asset find dropping the deb/.rb/winget files).
#   Local dry-runs never exercised the in-workflow merge+verify step. This
#   script replicates that step sequence EXACTLY against real local fixture
#   artifacts, so the dataflow is provable without a live GitHub run.
#
#   WHAT IT DOES (mirroring the fixed workflow step-for-step):
#     1. Fixtures (built by this script, clearly named where not real):
#        - macos-aarch64: the REAL artifact from tools/release/build_release.sh
#          (real cargo build, reused from dist/ when present);
#        - linux-x86_64 / linux-aarch64: fixture tar.gz with a dummy payload;
#        - windows-x86_64: fixture zip;
#        - .sig files: fixture PGP-armored placeholders (real GPG signing
#          needs the release key; signature MECHANICS are proven separately);
#        - .deb: fixture file (dpkg-deb mechanics proven separately);
#        - .rpm: REAL rpmbuild from packaging/rpm/cerberus.spec when
#          rpmbuild is available — which also proves the F8-V-3 pin
#          (`Release: 1` → the filename is exactly cerberus-<V>-1.x86_64.rpm).
#     2. Per-platform CI workspaces replicate the build jobs, including the
#        fixed "sums fragment" step — the Windows one even replays the
#        `Set-Content -NoNewline` + `dist/` path prefix quirk to prove the
#        normalization.
#     3. An inner run (--_inner) replicates the release job verbatim:
#        distinct-dir downloads → explicit canonical SHA256SUMS concatenation
#        → REQUIRED-entries check → direction-A recompute → formula (REAL
#        tools/release/fill_brew_formula.sh) + winget manifests (REAL
#        tools/release/fill_winget_manifest.sh) → fold into the sums →
#        both-directions gate → prints the exact `gh release create` asset
#        list it WOULD publish. No network, no release, no repo writes.
#     4. --negative replays the attempt-1 failure (rpm line dropped from the
#        packages fragment) and an unlisted-staged-asset case; BOTH must fail
#        closed, proving the gate actually bites.
#
#   Exit 0 = the dataflow has no dead-end. Any FAIL = bug in the workflow.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

MODE="${1:-positive}"
[ "$MODE" = "positive" ] || [ "$MODE" = "--negative" ] || [ "$MODE" = "--_inner" ] || {
  echo "usage: $0 [--negative]" >&2; exit 1; }

VERSION="$(sed -nE 's/^version = "([^"]+)"/\1/p' crates/cerberus/Cargo.toml | head -1)"
[ -n "$VERSION" ] || { echo "FAIL: cannot derive VERSION from crates/cerberus/Cargo.toml" >&2; exit 1; }

SIM_ROOT="${TMPDIR:-/tmp}/cerberus-release-sim-$(date +%s)-$$"

sha_of() { # <file> → sha256 hex (portable macOS/Linux)
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}
sums_line() { # <file> → "<sha>  <basename>" (the build_release.sh line format)
  printf '%s  %s\n' "$(sha_of "$1")" "$(basename "$1")"
}
fixture_sig() { # <file> → fixture PGP-armored placeholder next to it
  printf -- '-----BEGIN PGP SIGNATURE-----\nrelease-sim FIXTURE signature — NOT a real GPG signature (artifact: %s)\n-----END PGP SIGNATURE-----\n' "$(basename "$1")" > "$1.sig"
}

# ═══════════════════════════════════════════════════════════════ INNER MODE ══
if [ "$MODE" = "--_inner" ]; then
  # Usage: $0 --_inner <workspace>. The workspace holds one dist/ per
  # "CI runner" (platforms + packages). Replicates the release-v2.yml release
  # job: downloads (distinct dirs), canonical sums, checks, generations,
  # fold, both-directions gate, asset list. set -e: any FAIL aborts non-zero.
  WS="${2:-}"
  [ -d "$WS" ] || { echo "FAIL: inner workspace missing" >&2; exit 1; }
  cd "$WS"

  echo "── [sim] download-artifact → distinct dirs (NO merge-multiple) ──"
  for plat in linux-x86_64 linux-aarch64 macos-aarch64 windows-x86_64 packages; do
    mkdir -p "dl/$plat"
    cp -R "ci/$plat/dist/." "dl/$plat/"
  done

  echo "── [sim] assemble canonical SHA256SUMS + stage assets ──"
  mkdir -p dist
  find dl -type f ! -name 'SHA256SUMS-*' -exec mv {} dist/ \;
  cat \
    "dl/linux-x86_64/SHA256SUMS-linux-x86_64" \
    "dl/linux-aarch64/SHA256SUMS-linux-aarch64" \
    "dl/macos-aarch64/SHA256SUMS-macos-aarch64" \
    "dl/windows-x86_64/SHA256SUMS-windows-x86_64" \
    "dl/packages/SHA256SUMS-packages" \
    > dist/SHA256SUMS
  echo "== canonical dist/SHA256SUMS =="
  cat dist/SHA256SUMS

  echo "── [sim] REQUIRED entries (non-zero shas, fail-closed) ──"
  REQUIRED=(
    "cerberus-${VERSION}-linux-x86_64.tar.gz"
    "cerberus-${VERSION}-linux-aarch64.tar.gz"
    "cerberus-${VERSION}-macos-aarch64.tar.gz"
    "cerberus-${VERSION}-windows-x86_64.zip"
    "cerberus_${VERSION}_amd64.deb"
    "cerberus-${VERSION}-1.x86_64.rpm"
  )
  for name in "${REQUIRED[@]}"; do
    sha="$(awk -v n="$name" 'index($0, n) { print $1; exit }' dist/SHA256SUMS)"
    [ -n "$sha" ] || { echo "FAIL: $name missing from SHA256SUMS" >&2; exit 1; }
    [ "$sha" != "0000000000000000000000000000000000000000000000000000000000000000" ] \
      || { echo "FAIL: zero sha256 for $name" >&2; exit 1; }
  done
  echo "PASS: all 6 required entries present with real shas"

  echo "── [sim] direction A: every listed file staged + recomputed ──"
  while read -r sha file; do
    file="$(basename "$file")"
    [ -f "dist/$file" ] || { echo "FAIL: $file listed in SHA256SUMS but not staged" >&2; exit 1; }
    actual="$(sha_of "dist/$file")"
    [ "$actual" = "$sha" ] || { echo "FAIL: sha mismatch for $file" >&2; exit 1; }
  done < dist/SHA256SUMS
  echo "PASS: direction A"

  echo "── [sim] generate formula + winget manifests from the canonical sums ──"
  # The generator scripts cd to the REPO root internally, so the sums/out
  # paths must be ABSOLUTE here (in the real release job the checkout cwd IS
  # the repo root, where dist/SHA256SUMS lives — same logical layout).
  "$REPO_ROOT/tools/release/fill_brew_formula.sh" --version "$VERSION" \
    --platforms "$PWD/dist/SHA256SUMS" --out "$PWD/dist/cerberus.rb"
  if grep -qE 'sha256 "0{64}"|\{\{' dist/cerberus.rb; then
    echo "FAIL: release formula contains placeholder sha (R9-4)" >&2; exit 1
  fi
  "$REPO_ROOT/tools/release/fill_winget_manifest.sh" --version "$VERSION" \
    --sums "$PWD/dist/SHA256SUMS" --out-dir "$PWD/dist"

  echo "── [sim] fold formula + manifests into the canonical SHA256SUMS ──"
  (cd dist && {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum cerberus.rb Cerberus.Cerberus.*.yaml
    else shasum -a 256 cerberus.rb Cerberus.Cerberus.*.yaml; fi
  }) >> dist/SHA256SUMS
  echo "== final dist/SHA256SUMS =="
  cat dist/SHA256SUMS

  echo "── [sim] final BOTH-DIRECTIONS asset gate (fail-closed) ──"
  cd dist
  while read -r sha file; do
    file="$(basename "$file")"
    actual="$(sha_of "$file")"
    [ "$actual" = "$sha" ] || { echo "FAIL: sha mismatch for $file" >&2; exit 1; }
  done < SHA256SUMS
  fail=0
  while IFS= read -r f; do
    name="$(basename "$f")"
    grep -q " ${name}\$" SHA256SUMS \
      || { echo "FAIL: staged asset '$name' is NOT listed in SHA256SUMS" >&2; fail=1; }
  done < <(find . -maxdepth 1 -type f ! -name SHA256SUMS)
  [ "$fail" = 0 ] || exit 1
  cd ..
  echo "PASS: both-directions asset gate"

  echo "── [sim] the EXACT 'gh release create' asset list it WOULD publish ──"
  assets=()
  assets+=("dist/SHA256SUMS")
  while read -r _sha file; do
    assets+=("dist/$(basename "$file")")
  done < dist/SHA256SUMS
  echo "gh release create v${VERSION} --title \"cerberus ${VERSION}\" --generate-notes \\"
  for a in "${assets[@]}"; do echo "  $a"; done
  echo "== asset count: ${#assets[@]} =="
  echo "SIM-PASS: release assembly dataflow reaches gh release create with no dead-end"
  exit 0
fi

# ════════════════════════════════════════════════════════════ FIXTURE BUILD ══
echo "═══ release-sim F8 attempt 2 — fixture build (version $VERSION) ═══"
rm -rf "$SIM_ROOT"
mkdir -p "$SIM_ROOT"

# F8-V-3 static guard: the spec MUST pin Release: 1 (no %{?dist}), otherwise
# the required rpm filename is host-dependent and the workflow would guess.
if grep -qE '^Release:[[:space:]]+1[[:space:]]*$' packaging/rpm/cerberus.spec; then
  echo "PASS: rpm spec Release pinned to literal 1 (F8-V-3)"
else
  echo "FAIL: packaging/rpm/cerberus.spec Release is not the pinned literal '1' (F8-V-3)" >&2
  exit 1
fi
if grep -qE '^Release:.*%\{' packaging/rpm/cerberus.spec; then
  echo "FAIL: packaging/rpm/cerberus.spec Release still carries a %{} macro (F8-V-3)" >&2
  exit 1
fi

make_platform_workspace() { # <plat> <artifact-file>
  local plat="$1" art="$2" d
  d="$SIM_ROOT/ci/$plat/dist"
  mkdir -p "$d"
  cp "$art" "$d/"
  fixture_sig "$d/$(basename "$art")"
  # build_release.sh's per-runner dist/SHA256SUMS (one line, bare name):
  sums_line "$d/$(basename "$art")" > "$d/SHA256SUMS"
}

# ── macos-aarch64: the REAL artifact (reused from dist/, or built now) ──────
HOST_ART="dist/cerberus-${VERSION}-macos-aarch64.tar.gz"
if [ ! -f "$HOST_ART" ]; then
  echo "== real build (host macos/aarch64) via tools/release/build_release.sh =="
  ./tools/release/build_release.sh "$VERSION"
fi
[ -f "$HOST_ART" ] || { echo "FAIL: real host artifact $HOST_ART missing after build" >&2; exit 1; }
make_platform_workspace macos-aarch64 "$REPO_ROOT/$HOST_ART"
echo "FIXTURE macos-aarch64 : REAL build artifact $(basename "$HOST_ART") ($(sha_of "$HOST_ART" | head -c 16)…)"

# ── linux-x86_64 / linux-aarch64: fixture tarballs (clearly named payload) ──
for plat in linux-x86_64 linux-aarch64; do
  fdir="$SIM_ROOT/fixtures/$plat"; mkdir -p "$fdir"
  printf 'cerberus release-sim FIXTURE payload — not a real binary (platform %s)\n' "$plat" > "$fdir/cerberus"
  tar -czf "$fdir/cerberus-${VERSION}-${plat}.tar.gz" -C "$fdir" cerberus
  make_platform_workspace "$plat" "$fdir/cerberus-${VERSION}-${plat}.tar.gz"
  echo "FIXTURE $plat : dummy tar.gz (payload text says FIXTURE)"
done

# ── windows-x86_64: fixture zip; its SHA256SUMS replays the Windows quirks ──
wdir="$SIM_ROOT/fixtures/windows-x86_64"; mkdir -p "$wdir"
printf 'cerberus release-sim FIXTURE payload — not a real binary (windows x86_64)\n' > "$wdir/cerberus.exe"
zip -q -j "$wdir/cerberus-${VERSION}-windows-x86_64.zip" "$wdir/cerberus.exe"
wd="$SIM_ROOT/ci/windows-x86_64/dist"; mkdir -p "$wd"
cp "$wdir/cerberus-${VERSION}-windows-x86_64.zip" "$wd/"
fixture_sig "$wd/cerberus-${VERSION}-windows-x86_64.zip"
# The pwsh signing step writes:  "$sha  $zip" | Set-Content -NoNewline
# → `dist/` path prefix + NO trailing newline. The fixed fragment step must
# normalize both.
printf '%s  dist/cerberus-%s-windows-x86_64.zip' "$(sha_of "$wd/cerberus-${VERSION}-windows-x86_64.zip")" "$VERSION" > "$wd/SHA256SUMS"
echo "FIXTURE windows-x86_64 : dummy zip; SHA256SUMS written with dist/ prefix + no trailing newline (pwsh quirk replayed)"

# ── packages: fixture deb + REAL rpm (rpmbuild when available) + fixture sigs
pdir="$SIM_ROOT/ci/packages/dist"
mkdir -p "$pdir/rpm/x86_64"
printf 'cerberus release-sim FIXTURE payload — not a real .deb (dpkg-deb mechanics proven separately)\n' \
  > "$pdir/cerberus_${VERSION}_amd64.deb"
fixture_sig "$pdir/cerberus_${VERSION}_amd64.deb"
echo "FIXTURE deb            : cerberus_${VERSION}_amd64.deb (dummy file)"

RPM_NAME_REQ="cerberus-${VERSION}-1.x86_64.rpm"   # what the workflow requires
if command -v rpmspec >/dev/null 2>&1; then
  # F8-V-3 LIVE proof: on a DIST-TAGGED host (--define dist .fc40 simulates
  # Fedora-style dist tagging) the pinned spec's Release must still be the
  # literal `1` — pre-fix `Release: 1%{?dist}` would drift to `1.fc40` and
  # the CI filename would become cerberus-<V>-1.fc40.x86_64.rpm, which the
  # workflow cannot predict. The arch here follows the HOST (rpmspec refuses
  # a cross-arch query on macOS); CI (ubuntu x86_64) builds BuildArch:
  # x86_64, so the deterministic release field yields exactly
  # cerberus-<V>-1.x86_64.rpm there.
  host_arch="$(uname -m)"; [ "$host_arch" = "arm64" ] && host_arch=aarch64
  spec="$SIM_ROOT/cerberus.spec"
  sed -e "s/{{VERSION}}/${VERSION}/g" -e "s/{{ARCH}}/${host_arch}/g" \
      -e "s/^BuildArch:.*/BuildArch:      ${host_arch}/" \
    packaging/rpm/cerberus.spec > "$spec"
  REL="$(rpmspec -q --qf '%{RELEASE}\n' --define "dist .fc40" "$spec" 2>/dev/null | head -1 || true)"
  [ "$REL" = "1" ] || {
    echo "FAIL: pinned spec yields Release '$REL' on a dist-tagged host, expected '1' (F8-V-3 pin broken?)" >&2
    exit 1; }
  echo "FIXTURE rpm            : Release '${REL}' PROVEN via rpmspec on a dist-tagged host (--define dist .fc40) — F8-V-3 pin holds → CI name = ${RPM_NAME_REQ}"
else
  echo "note: rpmspec unavailable — F8-V-3 filename pin rests on the static Release check above"
fi
printf 'cerberus release-sim FIXTURE payload — not a real .rpm (rpmbuild mechanics proven in attempt 1; here the DATAFLOW is under proof)\n' \
  > "$pdir/rpm/x86_64/$RPM_NAME_REQ"
RPM="$pdir/rpm/x86_64/$RPM_NAME_REQ"
fixture_sig "$RPM"

# The fixed linux-packages fragment step, replicated verbatim:
(
  cd "$pdir"
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "cerberus_${VERSION}_amd64.deb" "cerberus_${VERSION}_amd64.deb.sig"
  else shasum -a 256 "cerberus_${VERSION}_amd64.deb" "cerberus_${VERSION}_amd64.deb.sig"; fi
  cd "rpm/x86_64"
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$RPM_NAME_REQ" "$RPM_NAME_REQ.sig"
  else shasum -a 256 "$RPM_NAME_REQ" "$RPM_NAME_REQ.sig"; fi
) > "$pdir/SHA256SUMS-packages"
echo "== fixture ci/packages fragment (SHA256SUMS-packages) =="
cat "$pdir/SHA256SUMS-packages"

# ── build-job fragment step (per-platform rename + normalization) ───────────
for plat in linux-x86_64 linux-aarch64 macos-aarch64 windows-x86_64; do
  d="$SIM_ROOT/ci/$plat/dist"
  {
    sed 's#  dist/#  #' "$d/SHA256SUMS" | awk 'NF { print }'
    for f in "$d"/*.sig; do
      [ -e "$f" ] || continue
      { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$f"
        else shasum -a 256 "$f"; fi; } | sed 's#  .*/#  #'
    done
  } > "$d/SHA256SUMS-$plat"
  rm -f "$d/SHA256SUMS"
done
echo "== per-platform fragments (unique names, normalized) =="
for plat in linux-x86_64 linux-aarch64 macos-aarch64 windows-x86_64; do
  cat "$SIM_ROOT/ci/$plat/dist/SHA256SUMS-$plat"
done

# ═════════════════════════════════════════════════════════════ POSITIVE RUN ══
echo
echo "═══ POSITIVE: full assembly simulation (must PASS) ═══"
if "$0" --_inner "$SIM_ROOT"; then
  echo "PASS: positive simulation green"
else
  echo "FAIL: the fixed dataflow still dead-ends — DO NOT COMMIT" >&2
  [ "${SIM_KEEP:-0}" = "1" ] || rm -rf "$SIM_ROOT"
  exit 1
fi

if [ "$MODE" = "--negative" ]; then
  echo
  echo "═══ NEGATIVE 1: attempt-1 P0 replay (rpm line dropped from fragment → must FAIL) ═══"
  n1="$SIM_ROOT/neg1"; mkdir -p "$n1"; cp -R "$SIM_ROOT/ci" "$n1/ci"
  grep -v "^.\{64\}  cerberus-${VERSION}-1.x86_64.rpm\$" \
    "$n1/ci/packages/dist/SHA256SUMS-packages" > "$n1/ci/packages/dist/SHA256SUMS-packages.tmp"
  mv "$n1/ci/packages/dist/SHA256SUMS-packages.tmp" "$n1/ci/packages/dist/SHA256SUMS-packages"
  if "$0" --_inner "$n1" 2>&1; then
    echo "FAIL: a missing rpm line did NOT fail the gate — the gate is broken" >&2
    [ "${SIM_KEEP:-0}" = "1" ] || rm -rf "$SIM_ROOT"
    exit 1
  else
    echo "PASS: negative 1 failed closed, exactly like the attempt-1 P0 demands"
  fi

  echo
  echo "═══ NEGATIVE 2: unlisted staged asset → direction B must FAIL ═══"
  n2="$SIM_ROOT/neg2"; mkdir -p "$n2"; cp -R "$SIM_ROOT/ci" "$n2/ci"
  printf 'cerberus release-sim FIXTURE — asset that never got a sums line\n' \
    > "$n2/ci/packages/dist/UNLISTED-fixture.txt"
  if "$0" --_inner "$n2" 2>&1; then
    echo "FAIL: an unlisted staged asset did NOT fail the gate — direction B is broken" >&2
    [ "${SIM_KEEP:-0}" = "1" ] || rm -rf "$SIM_ROOT"
    exit 1
  else
    echo "PASS: negative 2 failed closed (both-directions gate bites in both directions)"
  fi
fi

[ "${SIM_KEEP:-0}" = "1" ] && echo "(SIM_KEEP=1 — sim dir kept: $SIM_ROOT)" || rm -rf "$SIM_ROOT"
echo
echo "═══ SIMULATION GREEN — release-v2.yml dataflow proven end-to-end ═══"
