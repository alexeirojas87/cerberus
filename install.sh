#!/bin/sh
# Cerberus — Installer (curl | sh)
# Usage: curl -fsSL https://get.cerberus.dev | sh
# Or:   curl -fsSL https://get.cerberus.dev | sh -s -- --version 0.1.0

set -eu

REPO="alexeirojas87/cerberus"
VERSION="${1:-latest}"
INSTALL_DIR="${CERBERUS_INSTALL_DIR:-/usr/local/bin}"

# Detect OS and arch
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)  OS="linux"  ;;
  Darwin) OS="macos"  ;;
  *)      echo "Unsupported OS: $OS"; exit 1 ;;
esac

case "$ARCH" in
  x86_64|amd64) ARCH="x86_64"  ;;
  aarch64|arm64) ARCH="aarch64" ;;
  *)            echo "Unsupported arch: $ARCH"; exit 1 ;;
esac

if [ "$VERSION" = "latest" ]; then
  # In a real release, fetch latest from GitHub API
  VERSION="0.1.0"
fi

BINARY="cerberus-${VERSION}-${OS}-${ARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/v${VERSION}/${BINARY}"

echo "✦ Installing Cerberus v${VERSION} (${OS}/${ARCH})..."
echo "  Downloading from ${URL}"

# Create temp dir
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# Download
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$URL" -o "$TMP_DIR/cerberus.tar.gz"
elif command -v wget >/dev/null 2>&1; then
  wget -q "$URL" -O "$TMP_DIR/cerberus.tar.gz"
else
  echo "Error: need curl or wget"
  exit 1
fi

# Verify SHA-256 checksum when CERBERUS_SHA256 is set (supply-chain hygiene).
# Verification is MANDATORY in real deployments: without it there is no
# artifact integrity (P1-14).
if [ -n "${CERBERUS_SHA256:-}" ]; then
  ACTUAL="$( (shasum -a 256 || sha256sum) < "$TMP_DIR/cerberus.tar.gz" | awk '{print $1}' )"
  if [ "$ACTUAL" != "$CERBERUS_SHA256" ]; then
    echo "Error: checksum mismatch. Expected ${CERBERUS_SHA256}, got ${ACTUAL}" >&2
    exit 1
  fi
  echo "✓ SHA-256 checksum verified"
else
  echo "⚠️  CERBERUS_SHA256 not set: cannot verify binary integrity." >&2
  echo "   Export CERBERUS_SHA256=$(curl -fsSL "$URL" | shasum -a 256 | awk '{print $1}') for anti-tamper supply chain." >&2
fi

# Extract
tar xzf "$TMP_DIR/cerberus.tar.gz" -C "$TMP_DIR"

# Install
mkdir -p "$INSTALL_DIR"
cp "$TMP_DIR/cerberus" "$INSTALL_DIR/cerberus"
chmod +x "$INSTALL_DIR/cerberus"

echo "✓ Cerberus installed to ${INSTALL_DIR}/cerberus"
echo ""
echo "Quick start:"
echo "  cerberus init"
echo "  cerberus start"
echo ""
echo "Or run a scan:"
echo "  cerberus test \"my api key is sk-abc123\""