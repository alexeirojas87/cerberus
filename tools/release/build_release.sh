#!/usr/bin/env bash
# build_release.sh — packages the single `cerberus` binary into release artifacts.
#
#   Produces (with exactly these names, which are the ones expected by install.sh,
#   the Homebrew formula and the winget manifest):
#     dist/cerberus-<VERSION>-<OS>-<ARCH>.tar.gz   (macos / linux)
#     dist/cerberus-<VERSION>-<OS>-<ARCH>.zip       (windows)
#     dist/SHA256SUMS
#
#   Supported OS: linux | macos | windows
#   Supported ARCH: x86_64 | aarch64
#
#   Local usage:
#     ./tools/release/build_release.sh [VERSION]              # detects native OS/arch
#   Cross / CI usage:
#     CERBERUS_OS=linux   CERBERUS_ARCH=aarch64 TARGET=aarch64-unknown-linux-gnu \
#       ./tools/release/build_release.sh 0.1.0
#
#   The internal name of the binary inside the tar/zip is `cerberus` (`.exe` on Windows);
#   install.sh extracts it at the root and copies it to /usr/local/bin.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

# ── Configuration ─────────────────────────────────────────────────────────────
PKG="cerberus"
BIN_NAME="cerberus"
VERSION="${1:-}"

if [ -z "$VERSION" ]; then
  VERSION="$(sed -nE 's/^version = "([^"]+)"/\1/p' "crates/${PKG}/Cargo.toml" | head -1)"
  [ -n "$VERSION" ] || { echo "Could not derive VERSION from crates/${PKG}/Cargo.toml" >&2; exit 1; }
fi

# OS detection. Can be overridden with CERBERUS_OS (used in CI cross).
detect_os() {
  local raw
  raw="$(uname -s | tr '[:upper:]' '[:lower:]')"
  case "$raw" in
    linux)  echo "linux" ;;
    darwin) echo "macos" ;;
    mingw*|msys*|cygwin|windows|windowsnt|microsoft) echo "windows" ;;
    *) echo "$raw" ;;
  esac
}

# ARCH detection. Override with CERBERUS_ARCH.
detect_arch() {
  local raw
  raw="$(uname -m)"
  case "$raw" in
    x86_64|amd64)  echo "x86_64" ;;
    aarch64|arm64) echo "aarch64" ;;
    *) echo "$raw" ;;
  esac
}

OS="${CERBERUS_OS:-$(detect_os)}"
ARCH="${CERBERUS_ARCH:-$(detect_arch)}"

case "$OS" in
  linux|macos|windows) : ;;
  *) echo "error: unsupported OS '$OS' (use CERBERUS_OS=linux|macos|windows)" >&2; exit 1 ;;
esac
case "$ARCH" in
  x86_64|aarch64) : ;;
  *) echo "error: unsupported ARCH '$ARCH' (use CERBERUS_ARCH=x86_64|aarch64)" >&2; exit 1 ;;
esac

TARGET="${TARGET:-}"            # Rust target triple for cross-compile, e.g. x86_64-pc-windows-msvc

DIST="dist"
STAGE="$DIST/stage/$OS/$ARCH"
EXT="tar.gz"
[ "$OS" = "windows" ] && EXT="zip"
ARTIFACT="$DIST/${BIN_NAME}-${VERSION}-${OS}-${ARCH}.${EXT}"
EXPECTED_BIN="${BIN_NAME}"
[ "$OS" = "windows" ] && EXPECTED_BIN="${BIN_NAME}.exe"

# ── Build ──────────────────────────────────────────────────────────────────────
echo "==> Compiling $PKG v$VERSION (${OS}/${ARCH})${TARGET:+ target=$TARGET}"

BUILD_ARGS=(build --release --package "$PKG" --bin "$BIN_NAME")
[ -n "$TARGET" ] && BUILD_ARGS+=(--target "$TARGET")
cargo "${BUILD_ARGS[@]}"

if [ -n "$TARGET" ]; then
  BIN_PATH="target/$TARGET/release/$EXPECTED_BIN"
else
  BIN_PATH="target/release/$EXPECTED_BIN"
fi
[ -f "$BIN_PATH" ] || { echo "error: binary $BIN_PATH not found" >&2; exit 1; }

# ── Staging ────────────────────────────────────────────────────────────────────
rm -rf "$STAGE"
mkdir -p "$DIST" "$STAGE"
cp "$BIN_PATH" "$STAGE/$EXPECTED_BIN"

if [ "${CERBERUS_STRIP:-0}" = "1" ]; then
  strip_="$(command -v strip || true)"
  if [ -n "$strip_" ] && [ "$OS" != "windows" ]; then
    "$strip_" --strip-unneeded "$STAGE/$EXPECTED_BIN"
  fi
fi

# ── Packaging (the binary ends up at the root of the artifact: install.sh & brew expect it) ─
rm -f "$ARTIFACT"
if [ "$OS" = "windows" ]; then
  if command -v zip >/dev/null 2>&1; then
    (cd "$STAGE" && zip -q -j "$REPO_ROOT/$ARTIFACT" "$EXPECTED_BIN")
  else
    python3 - "$ARTIFACT" "$STAGE/$EXPECTED_BIN" <<'PY'
import sys, zipfile
zipfile.ZipFile(sys.argv[1], "w", zipfile.ZIP_DEFLATED).write(sys.argv[2], "cerberus.exe")
PY
  fi
else
  (cd "$STAGE" && tar -czf "$REPO_ROOT/$ARTIFACT" "$EXPECTED_BIN")
fi
echo "==> Packaged $ARTIFACT"

# ── Checksums ──────────────────────────────────────────────────────────────────
SHA_CMD="sha256sum"
command -v "$SHA_CMD" >/dev/null 2>&1 || SHA_CMD="shasum -a 256"
(cd "$DIST" && $SHA_CMD "$(basename "$ARTIFACT")" > SHA256SUMS)
SUMS="$DIST/SHA256SUMS"
cat "$SUMS"

echo
echo "✔  Release artifacts for ${OS}/${ARCH} at ./${ARTIFACT}"
echo "   SHA256SUMS -> ./${SUMS}"
echo
echo "   Next steps (see tools/release/README_F8.md):"
echo "   - macos  : tools/release/macos-notarize.sh   (signing + notarization)"
echo "   - windows: tools/release/windows-sign.sh     (Authenticode signing)"
echo "   - brew   : tools/release/fill_brew_formula.sh --version $VERSION --out dist/cerberus.rb"