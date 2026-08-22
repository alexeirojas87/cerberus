#!/usr/bin/env bash
# windows-sign.sh — Authenticode signing of cerberus.exe (signtool).
#
#   Usage:
#     tools/release/windows-sign.sh <cerberus.exe>
#
#   With credentials (CI) it runs the REAL signing:
#     WINDOWS_SIGN_CERT="/path/to/cert.pfx"          # path to the .pfx (or base64 for code signing)
#     WINDOWS_SIGN_PASSWORD="xxxx"                  # .pfx password
#     # optional: WINDOWS_SIGN_HASH="SHA256"
#   Without credentials it enters DRY-RUN: prints the exact sequence and exits 0.
#
#   Requires signtool in PATH (Windows: 'C:\Program Files (x86)\Windows Kits\10\bin\<ver>\x64\signtool.exe'
#   or installed via 'choco install windows-sdk'). On GitHub Actions windows-latest it comes
#   preinstalled with the SDK that the runner ships.

set -euo pipefail

EXE="${1:-}"
[ -n "$EXE" ] || { echo "usage: $0 <cerberus.exe>" >&2; exit 1; }
[ -f "$EXE" ] || { echo "error: $EXE does not exist" >&2; exit 1; }

CERT="${WINDOWS_SIGN_CERT:-}"
PASSWORD="${WINDOWS_SIGN_PASSWORD:-}"
SIGNFILE_TIMESTAMP="${WINDOWS_SIGN_TIMESTAMP:-http://timestamp.digicert.com}"

DRY_RUN=0
if [ -z "$CERT" ] || [ -z "$PASSWORD" ]; then
  DRY_RUN=1
fi

if [ "$DRY_RUN" = "1" ]; then
  cat <<EOF
[DRY-RUN] No WINDOWS_SIGN_CERT / WINDOWS_SIGN_PASSWORD; CI will inject the
          credentials and run (on windows-latest, where the SDK signtool
          is already in PATH):

  signtool sign /f "\$WINDOWS_SIGN_CERT" /p "\$WINDOWS_SIGN_PASSWORD" \\
                 /fd SHA256 /tr $SIGNFILE_TIMESTAMP /td SHA256 cerberus.exe
  signtool verify /pa /v cerberus.exe

[dry-run] OK — no artifact was modified.
EOF
  exit 0
fi

if ! command -v signtool >/dev/null 2>&1; then
  echo "error: signtool not found. Install the Windows SDK (via winget/choco) or use the windows-latest runner (the SDK ships it preinstalled)." >&2
  exit 1
fi

echo "==> signtool sign"
signtool sign /f "$CERT" /p "$PASSWORD" /fd SHA256 /tr "$SIGNFILE_TIMESTAMP" /td SHA256 "$EXE"
echo "==> signtool verify"
signtool verify /pa /v "$EXE"

echo "✔  Authenticode signed: $EXE"