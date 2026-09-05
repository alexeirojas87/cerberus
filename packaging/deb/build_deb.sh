#!/usr/bin/env bash
# build_deb.sh — reproducible build of a .deb from the single binary.
#
#   Usage:
#     CERBERUS_OS=linux CERBERUS_ARCH=x86_64 ./tools/release/build_release.sh 0.1.0
#     ./packaging/deb/build_deb.sh dist/cerberus-0.1.0-linux-x86_64.tar.gz [0.1.0] [--arch amd64]
#
#   Produces: dist/cerberus_<version>_<arch>.deb   (dpkg-deb, does not require debhelper).
#   Layout: <root>/DEBIAN/{control,postinst,prerm} + <root>/usr/bin/cerberus.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

ART="${1:-}"
VERSION="${2:-}"
ARCH="${3:-}"
# Accept the documented `--arch amd64|arm64` flag as the 3rd argument too
# (the usage string advertised it but the script only took a positional arg).
if [ "${2:-}" = "--arch" ]; then ARCH="${3:-}"; VERSION=""; fi
if [ "${3:-}" = "--arch" ] && [ -n "$4" ]; then ARCH="${4}"; fi
[ -n "$ARCH" ] || ARCH="amd64"
[ -n "$ART" ] && [ -f "$ART" ] || { echo "usage: $0 <cerberus-*.tar.gz> [VERSION] [--arch amd64|arm64]" >&2; exit 1; }
[ -n "$VERSION" ] || VERSION="$(sed -nE 's/^version = "([^"]+)"/\1/p' crates/cerberus/Cargo.toml | head -1)"

case "$ARCH" in
  amd64|x86_64) DPKG_ARCH="amd64" ;;
  arm64|aarch64) DPKG_ARCH="arm64" ;;
  *) echo "unsupported ARCH: $ARCH (amd64|arm64)" >&2; exit 1 ;;
esac

ROOT="dist/deb-root"
OUT="dist/cerberus_${VERSION}_${DPKG_ARCH}.deb"
rm -rf "$ROOT"
mkdir -p "$ROOT/DEBIAN" "$ROOT/usr/bin"

tar xzf "$ART" -C "$ROOT/usr/bin"
chmod 755 "$ROOT/usr/bin/cerberus"

# Control with resolved placeholders.
sed -e "s/{{VERSION}}/$VERSION/g" -e "s/{{ARCH}}/$DPKG_ARCH/g" \
    packaging/deb/control > "$ROOT/DEBIAN/control"
cp packaging/deb/postinst "$ROOT/DEBIAN/postinst"
cp packaging/deb/prerm   "$ROOT/DEBIAN/prerm"
chmod 755 "$ROOT/DEBIAN/postinst" "$ROOT/DEBIAN/prerm"

dpkg-deb --build --root-owner-group "$ROOT" "$OUT"

echo "✔  .deb generated: ./$OUT"
dpkg-deb --info "$OUT" | head -20