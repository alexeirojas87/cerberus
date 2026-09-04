#!/usr/bin/env bash
# fill_winget_manifest.sh — R9-15: winget manifest currency with REAL sha.
#
#   Usage:
#     tools/release/fill_winget_manifest.sh --version <V> --sums <SHA256SUMS> [--out-dir DIR] [--dry-run]
#
#   Copies the manifest template (packaging/winget/manifests/c/Cerberus/<template-version>/)
#   to the new version directory and injects:
#     - PackageVersion: <V>
#     - InstallerUrl:   .../download/v<V>/cerberus-<V>-windows-x86_64.zip
#     - InstallerSha256: the REAL sha256 of that zip, read from the release
#       SHA256SUMS. Fail-closed: a zero/missing sha aborts (no fake GUID/sha
#       may reach a winget-pkgs PR — R9-15).
#
#   --dry-run prints the would-be manifest diff without writing anything.

set -euo pipefail

VERSION=""
SUMS=""
OUT_DIR=""
DRY_RUN=0
TPL_VERSION="0.1.0"
TPL_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/packaging/winget/manifests/c/Cerberus"

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --sums)    SUMS="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    --template-version) TPL_VERSION="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
  esac
done

[ -n "$VERSION" ] || { echo "missing --version" >&2; exit 1; }
[ -n "$SUMS" ] || { echo "missing --sums" >&2; exit 1; }
[ -f "$SUMS" ] || { echo "error: $SUMS does not exist" >&2; exit 1; }

TPL="${TPL_ROOT}/${TPL_VERSION}"
[ -d "$TPL" ] || { echo "error: template dir $TPL does not exist" >&2; exit 1; }

ZIP_NAME="cerberus-${VERSION}-windows-x86_64.zip"
SHA="$(awk -v n="$ZIP_NAME" 'index($0, n) { print $1; exit }' "$SUMS")"
[ -n "$SHA" ] || { echo "FAIL: no sha256 for '$ZIP_NAME' in $SUMS — winget manifest cannot be generated (fail-closed)" >&2; exit 1; }
case "$SHA" in
  *[!0-9a-fA-F]*|"" ) echo "FAIL: malformed sha256 for $ZIP_NAME" >&2; exit 1 ;;
esac
[ "${#SHA}" = "64" ] || { echo "FAIL: sha256 for $ZIP_NAME is not 64 hex chars" >&2; exit 1; }
[ "$SHA" != "0000000000000000000000000000000000000000000000000000000000000000" ] \
  || { echo "FAIL: zero sha256 for $ZIP_NAME — refusing (R9-15: real sha injection mandatory)" >&2; exit 1; }

if [ -z "$OUT_DIR" ]; then
  OUT_DIR="$(cd "$TPL/.." && pwd)/$VERSION"
fi
URL="https://github.com/alexeirojas87/cerberus/releases/download/v${VERSION}/${ZIP_NAME}"

TMP_OUT="$(mktemp -d)"
cp -R "$TPL/." "$TMP_OUT/"

for f in "$TMP_OUT"/*.yaml; do
  sed -i.bak \
    -e "s|^PackageVersion: .*|PackageVersion: ${VERSION}|" \
    "$f"
  rm -f "$f.bak"
done

INSTALLER="$TMP_OUT/Cerberus.Cerberus.installer.yaml"
sed -i.bak \
  -e "s|/download/v[^/]*/cerberus-[^\"]*windows-x86_64.zip|/download/v${VERSION}/${ZIP_NAME}|" \
  -e "s|InstallerSha256: .*|InstallerSha256: ${SHA}|" \
  "$INSTALLER"
rm -f "$INSTALLER.bak"

# Fail-closed self-check: no stale version, no zero sha anywhere in the tree.
if grep -R -E "PackageVersion: 0\.1\.0$|InstallerSha256: 0{64}" "$TMP_OUT" >/dev/null 2>&1; then
  echo "FAIL: generated manifests still contain stale version or zero sha" >&2
  exit 1
fi

if [ "$DRY_RUN" = "1" ]; then
  echo "== DRY-RUN: manifests that would be generated in $OUT_DIR =="
  find "$TMP_OUT" -type f | sort
  for f in "$TMP_OUT"/*.yaml; do
    echo "--- $(basename "$f") ---"
    cat "$f"
  done
  echo "DRY-RUN OK: InstallerSha256 = $SHA (real, from $SUMS)"
  exit 0
fi

mkdir -p "$OUT_DIR"
cp -R "$TMP_OUT/." "$OUT_DIR/"
echo "PASS: winget manifests for ${VERSION} generated in $OUT_DIR (InstallerSha256 = ${SHA:0:16}…)"
