#!/usr/bin/env bash
# macos-notarize.sh — firma (codesign) y notarización macOS del binario `cerberus`.
#
#   Uso:
#     tools/release/macos-notarize.sh <ruta-al-artefacto>   # cerberus-*.tar.gz o binario desnudo
#
#   Con credenciales (en CI, inyectadas como secrets) ejecuta la FIRMA REAL:
#     APPLE_IDENTITY="Developer ID Application: Your Name"   # nombre del certificado instalado
#     APPLE_ID="dev@cerberus.dev"
#     APPLE_APP_SPECIFIC_PASSWORD="xxxx-xxxx-xxxx-xxxx"
#     APPLE_TEAM_ID="TT12345678"
#   Sin credenciales entra en DRY-RUN: imprime la secuencia exacta que ejecutaría
#   CI y sale 0 (no falla). Es el modo por defecto en local.
#
#   Para un artefacto cerberus-*.tar.gz: extrae, firma el binario del interior,
#   re-empaqueta con el MISMO nombre (raíz plana) y regenera su entrada en
#   SHA256SUMS.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

ART="${1:-}"
[ -n "$ART" ] || { echo "uso: $0 <artefacto.tar.gz|binario>" >&2; exit 1; }
[ -f "$ART" ] || { echo "error: no existe $ART" >&2; exit 1; }

IDENTITY="${APPLE_IDENTITY:-Developer ID Application: Your Name}"

DRY_RUN=0
if [ -z "${APPLE_ID:-}" ] || [ -z "${APPLE_APP_SPECIFIC_PASSWORD:-}" ] || [ -z "${APPLE_TEAM_ID:-}" ]; then
  DRY_RUN=1
fi

sha_cmd() {
  if command -v sha256sum >/dev/null 2>&1; then printf '%s\n' "sha256sum"; else printf '%s\n' "shasum -a 256"; fi
}

# Regenera la línea del artefacto en su SHA256SUMS (override del checksum anterior).
regen_sha256() {
  local art shop sums_dir file
  art="$1"
  sums_dir="$(cd "$(dirname "$art")" && pwd)"
  file="$(basename "$art")"
  sums="$sums_dir/SHA256SUMS"
  (cd "$sums_dir" && "$(sha_cmd)" "$file" > "$sums")
  echo "==> SHA256SUMS regenerado ($file)"
}

dry_run_print() {
  echo "[DRY-RUN] Sin APPLE_ID / APPLE_APP_SPECIFIC_PASSWORD / APPLE_TEAM_ID;"
  echo "          CI importará estas credenciales y ejecutará literalmente:"
  echo
  echo "  codesign --force --options runtime --timestamp --sign \"$IDENTITY\" <cerberus>"
  echo "  ditto -c -k --keepParent <cerberus> cerberus-notarize.zip"
  echo "  xcrun notarytool submit cerberus-notarize.zip \\"
  echo "        --apple-id \$APPLE_ID --password \$APPLE_APP_SPECIFIC_PASSWORD \\"
  echo "        --team-id \$APPLE_TEAM_ID --wait"
  echo "  xcrun stapler staple cerberus-<version>-macos-<arch>.tar.gz"
  echo "  codesign --verify --deep --strict --verbose=2 <cerberus>"
  echo "  spctl --assess --type execute --verbose=4 <cerberus>"
  echo
  echo "[dry-run] OK — no se modificó ninguna credencial ni ningún artefacto."
}

notarize() {
  local bin_path="$1"
  local out_art="$2"

  echo "==> codesign ($IDENTITY)"
  codesign --force --options runtime --timestamp --sign "$IDENTITY" --verbose=4 "$bin_path"

  echo "==> notarytool submit --wait"
  local zip_path
  zip_path="$(mktemp -d)/cerberus-notarize.zip"
  ditto -c -k --keepParent "$bin_path" "$zip_path" 2>/dev/null \
    || zip -q -j "$zip_path" "$bin_path"
  xcrun notarytool submit "$zip_path" \
    --apple-id "$APPLE_ID" \
    --password "$APPLE_APP_SPECIFIC_PASSWORD" \
    --team-id "$APPLE_TEAM_ID" \
    --wait

  echo "==> stapler staple"
  xcrun stapler staple "$out_art" 2>/dev/null || true

  echo "==> verificación"
  codesign --verify --deep --strict --verbose=2 "$bin_path"
  spctl --assess --type execute --verbose=4 "$bin_path"
}

main() {
  local tmp bin_path out_art
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  case "$ART" in
    *.tar.gz)
      mkdir -p "$tmp/src"
      tar xzf "$ART" -C "$tmp/src"
      bin_path="$tmp/src/cerberus"
      [ -f "$bin_path" ] || { echo "error: el tar no contiene 'cerberus' en la raiza" >&2; exit 1; }
      out_art="$ART"
      ;;
    *)
      bin_path="$ART"
      out_art="$ART-codesigned"
      ;;
  esac

  if [ "$DRY_RUN" = "1" ]; then
    dry_run_print
    exit 0
  fi

  notarize "$bin_path" "$out_art"

  if [ "$out_art" = "$ART" ]; then
    # Re-empaqueta el tar con el binario firmaa (misma raiz plana) y refresca sumas.
    tar -czf "$REPO_ROOT/$ART" -C "$tmp/src" "cerberus"
    regen_sha256 "$REPO_ROOT/$ART"
  fi

  echo "✔  Firmado + notarizado: $out_art"
}

main "$@"