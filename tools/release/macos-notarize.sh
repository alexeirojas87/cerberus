#!/usr/bin/env bash
# macos-notarize.sh — codesign and macOS notarization of the `cerberus` binary.
#
#   Usage:
#     tools/release/macos-notarize.sh <path-to-artifact>   # cerberus-*.tar.gz or bare binary
#
#   With credentials (in CI, injected as secrets) it runs the REAL signing:
#     APPLE_IDENTITY="Developer ID Application: Your Name"   # name of the installed certificate
#     APPLE_ID="dev@cerberus.dev"
#     APPLE_APP_SPECIFIC_PASSWORD="xxxx-xxxx-xxxx-xxxx"
#     APPLE_TEAM_ID="TT12345678"
#   Without credentials it enters DRY-RUN: prints the exact sequence that CI
#   would run and exits 0 (does not fail). This is the default mode locally.
#
#   For a cerberus-*.tar.gz artifact: extracts it, signs the binary inside,
#   re-packages it with the SAME name (flat root) and regenerates its entry in
#   SHA256SUMS.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

ART="${1:-}"
[ -n "$ART" ] || { echo "usage: $0 <artifact.tar.gz|binary>" >&2; exit 1; }
[ -f "$ART" ] || { echo "error: $ART does not exist" >&2; exit 1; }

IDENTITY="${APPLE_IDENTITY:-Developer ID Application: Your Name}"

DRY_RUN=0
if [ -z "${APPLE_ID:-}" ] || [ -z "${APPLE_APP_SPECIFIC_PASSWORD:-}" ] || [ -z "${APPLE_TEAM_ID:-}" ]; then
  DRY_RUN=1
fi

sha_cmd() {
  if command -v sha256sum >/dev/null 2>&1; then printf '%s\n' "sha256sum"; else printf '%s\n' "shasum -a 256"; fi
}

# Regenerates the artifact's line in its SHA256SUMS (overrides the previous checksum).
regen_sha256() {
  local art shop sums_dir file
  art="$1"
  sums_dir="$(cd "$(dirname "$art")" && pwd)"
  file="$(basename "$art")"
  sums="$sums_dir/SHA256SUMS"
  (cd "$sums_dir" && "$(sha_cmd)" "$file" > "$sums")
  echo "==> SHA256SUMS regenerated ($file)"
}

dry_run_print() {
  echo "[DRY-RUN] No APPLE_ID / APPLE_APP_SPECIFIC_PASSWORD / APPLE_TEAM_ID;"
  echo "          CI will import these credentials and run literally:"
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
  echo "[dry-run] OK — no credentials and no artifacts were modified."
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

  echo "==> verification"
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
      [ -f "$bin_path" ] || { echo "error: the tar does not contain 'cerberus' at its root" >&2; exit 1; }
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
    # Re-packages the tar with the signed binary (same flat root) and refreshes the sums.
    tar -czf "$REPO_ROOT/$ART" -C "$tmp/src" "cerberus"
    regen_sha256 "$REPO_ROOT/$ART"
  fi

  echo "✔  Signed + notarized: $out_art"
}

main "$@"