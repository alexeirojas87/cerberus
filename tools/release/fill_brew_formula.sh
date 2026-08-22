#!/usr/bin/env bash
# fill_brew_formula.sh — sustituye los placeholders del template de la formula
# Homebrew (tools/release/brew.rb) con los VALORES REALES del release.
#
#   Uso:
#     tools/release/fill_brew_formula.sh [--version 0.1.0] [--platforms dist/SHA256SUMS] [--out dist/cerberus.rb]
#
#   Si --platforms apunta al SHA256SUMS generado por build_release.sh, las cuatro
#   sumas se toman de ahí automáticamente (macos-x86_64, macos-aarch64,
#   linux-x86_64, linux-aarch64). Así la formula queda "lista para tap".
#
#   En la práctica, en CI se corre para cada plataforma antes del release:
#     ./tools/release/build_release.sh 0.1.0                     # por cada os/arch
#     ./tools/release/fill_brew_formula.sh --version 0.1.0 --out dist/cerberus.rb

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

TPL="tools/release/brew.rb"
VERSION=""
PLATFORMS=""
OUT="dist/cerberus.rb"

while [ $# -gt 0 ]; do
  case "$1" in
    --version)    VERSION="$2"; shift 2 ;;
    --platforms)  PLATFORMS="$2"; shift 2 ;;
    --out)        OUT="$2"; shift 2 ;;
    --install)    OUT="contrib/homebrew/cerberus.rb"; shift ;;
    *) echo "opcion desconocida: $1" >&2; exit 1 ;;
  esac
done

[ -n "$VERSION" ] || { echo "falta --version" >&2; exit 1; }
[ -f "$TPL" ] || { echo "no existe template: $TPL" >&2; exit 1; }

# Extrae sha256 de SHA256SUMS por substring exacto del nombre del artefacto.
# Si la plataforma aún no se construyó en dist/, usa placeholder cero y avisa
# (no falla: los 4 sha llegan en el release real agregado desde CI).
sha_for() {
  local needle="$1" h
  [ -n "$PLATFORMS" ] || { echo "warning: sin --platforms; sha en cero" >&2; echo "0000000000000000000000000000000000000000000000000000000000000000"; return; }
  [ -f "$PLATFORMS" ] || { echo "error: no existe $PLATFORMS" >&2; exit 1; }
  h="$(awk -v n="$needle" 'index($0, n) { print $1; exit }' "$PLATFORMS")"
  if [ -z "$h" ]; then
    echo "warning: no hay sha256 para '$needle' en $PLATFORMS (placeholder cero)" >&2
    echo "0000000000000000000000000000000000000000000000000000000000000000"
    return
  fi
  printf '%s\n' "$h"
}

MAC_X64="$(sha_for "cerberus-${VERSION}-macos-x86_64.tar.gz")"
MAC_ARM="$(sha_for "cerberus-${VERSION}-macos-aarch64.tar.gz")"
LIN_X64="$(sha_for "cerberus-${VERSION}-linux-x86_64.tar.gz")"
LIN_ARM="$(sha_for "cerberus-${VERSION}-linux-aarch64.tar.gz")"

mkdir -p "$(dirname "$OUT")"
sed -e "s/{{VERSION}}/$VERSION/g" \
    -e "s/{{SHA256_MACOS_X86_64}}/$MAC_X64/g" \
    -e "s/{{SHA256_MACOS_AARCH64}}/$MAC_ARM/g" \
    -e "s/{{SHA256_LINUX_X86_64}}/$LIN_X64/g" \
    -e "s/{{SHA256_LINUX_AARCH64}}/$LIN_ARM/g" \
    "$TPL" > "$OUT"

echo "✔  Formula generada en $OUT"
echo "   version                  : $VERSION"
echo "   sha256 macos-x86_64      : ${MAC_X64:0:16}…"
echo "   sha256 macos-aarch64     : ${MAC_ARM:0:16}…"
echo "   sha256 linux-x86_64      : ${LIN_X64:0:16}…"
echo "   sha256 linux-aarch64     : ${LIN_ARM:0:16}…"
echo "   Siguientes pasos:"
echo "   - ruby -c $OUT"
echo "   - brew audit --strict --new $OUT   (con sha256 reales y tag publicado)"
echo "   - publicar via brew tap (o GitHub release: gh release upload <tag> $OUT)"