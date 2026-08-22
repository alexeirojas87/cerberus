#!/usr/bin/env bash
# windows-sign.sh — firma Authenticode de cerberus.exe (signtool).
#
#   Uso:
#     tools/release/windows-sign.sh <cerberus.exe>
#
#   Con credenciales (CI) ejecuta la firma REAL:
#     WINDOWS_SIGN_CERT="/path/to/cert.pfx"          # ruta al .pfx (o base64 al code sign)
#     WINDOWS_SIGN_PASSWORD="xxxx"                  # password del .pfx
#     # opcional: WINDOWS_SIGN_HASH="SHA256"
#   Sin credenciales entra en DRY-RUN: imprime la secuencia exacta y sale 0.
#
#   Requiere signtool en PATH (Windows: 'C:\Program Files (x86)\Windows Kits\10\bin\<ver>\x64\signtool.exe'
#   o instalado vía 'choco install windows-sdk'). En GitHub Actions windows-latest viene
#   preinstalado en el SDK que trae el runner.

set -euo pipefail

EXE="${1:-}"
[ -n "$EXE" ] || { echo "uso: $0 <cerberus.exe>" >&2; exit 1; }
[ -f "$EXE" ] || { echo "error: no existe $EXE" >&2; exit 1; }

CERT="${WINDOWS_SIGN_CERT:-}"
PASSWORD="${WINDOWS_SIGN_PASSWORD:-}"
SIGNFILE_TIMESTAMP="${WINDOWS_SIGN_TIMESTAMP:-http://timestamp.digicert.com}"

DRY_RUN=0
if [ -z "$CERT" ] || [ -z "$PASSWORD" ]; then
  DRY_RUN=1
fi

if [ "$DRY_RUN" = "1" ]; then
  cat <<EOF
[DRY-RUN] Sin WINDOWS_SIGN_CERT / WINDOWS_SIGN_PASSWORD; CI inyectará las
          credenciales y ejecutará (en windows-latest, donde signtool del SDK
          ya está en PATH):

  signtool sign /f "\$WINDOWS_SIGN_CERT" /p "\$WINDOWS_SIGN_PASSWORD" \\
                 /fd SHA256 /tr $SIGNFILE_TIMESTAMP /td SHA256 cerberus.exe
  signtool verify /pa /v cerberus.exe

[dry-run] OK — no se modificó ningún artefacto.
EOF
  exit 0
fi

if ! command -v signtool >/dev/null 2>&1; then
  echo "error: signtool no encontrado. Instala el Windows SDK (vía wingset/choco) o usa el runner windows-latest (lo trae el SDK preinstalado)." >&2
  exit 1
fi

echo "==> signtool sign"
signtool sign /f "$CERT" /p "$PASSWORD" /fd SHA256 /tr "$SIGNFILE_TIMESTAMP" /td SHA256 "$EXE"
echo "==> signtool verify"
signtool verify /pa /v "$EXE"

echo "✔  Firmado Authenticode: $EXE"