#!/usr/bin/env bash
# publish_tap_pr.sh — R9-4: the tap can never lag.
#
#   Usage:
#     tools/release/publish_tap_pr.sh --version <V> --sums <SHA256SUMS> [--tap-repo OWNER/homebrew-cerberus] [--dry-run]
#
#   Generates the release formula from the REAL release SHA256SUMS
#   (via tools/release/fill_brew_formula.sh — no placeholders, no zero
#   fallbacks), then:
#     --dry-run : prints the generated formula and the diff against
#                 contrib/homebrew/cerberus.rb (if present). No network.
#     real mode : clones the tap repo, opens a PR with the new formula on
#                 a tap-v<V> branch. Requires TAP_PR_TOKEN (fail-closed).
#
#   In CI this is invoked by notify-tap-v2.yml when a release is published.
#   The PR against the tap repo is the human-visible, reviewable path —
#   the tap is never force-updated, but the notification is automatic and
#   carries the exact sha256 of the published artifacts, so it cannot
#   point at a version the release never shipped (the R9-4 failure mode).

set -euo pipefail

VERSION=""
SUMS=""
TAP_REPO="alexeirojas87/homebrew-cerberus"
DRY_RUN=0

while [ $# -gt 0 ]; do
  case "$1" in
    --version)  VERSION="$2"; shift 2 ;;
    --sums)     SUMS="$2"; shift 2 ;;
    --tap-repo) TAP_REPO="$2"; shift 2 ;;
    --dry-run)  DRY_RUN=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
  esac
done

[ -n "$VERSION" ] || { echo "missing --version" >&2; exit 1; }
[ -n "${SUMS:-}" ] || { echo "missing --sums" >&2; exit 1; }
[ -f "$SUMS" ] || { echo "error: $SUMS does not exist" >&2; exit 1; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FORMULA="$(mktemp -d)/cerberus.rb"

# ── Generate the formula with REAL shas from the release sums ─────────────────
"$REPO_ROOT/tools/release/fill_brew_formula.sh" \
  --version "$VERSION" --platforms "$SUMS" --out "$FORMULA" >/dev/null

# Fail-closed: a published tap formula must never contain a zero placeholder
# (that is exactly the R9-4 failure mode) nor a template placeholder.
if grep -qE '0000{15,}|sha256 "0{64}"|\{\{' "$FORMULA"; then
  echo "FAIL: generated formula contains placeholder/zero sha256 — refusing (R9-4)" >&2
  exit 1
fi
ruby -c "$FORMULA" >/dev/null || { echo "FAIL: formula is not valid Ruby" >&2; exit 1; }

if [ "$DRY_RUN" = "1" ]; then
  echo "== DRY-RUN: formula that would be PR'd against $TAP_REPO =="
  cat "$FORMULA"
  echo
  echo "== diff vs current in-repo formula (contrib/homebrew/cerberus.rb) =="
  if [ -f "$REPO_ROOT/contrib/homebrew/cerberus.rb" ]; then
    diff -u "$REPO_ROOT/contrib/homebrew/cerberus.rb" "$FORMULA" || true
  else
    echo "(no in-repo contrib formula to diff against — tap PR would ADD the formula)"
  fi
  echo "DRY-RUN OK: formula valid, shas sourced from $SUMS. No network calls made."
  exit 0
fi

# ── Real mode: open the PR against the tap repo ───────────────────────────────
[ -n "${TAP_PR_TOKEN:-}" ] || {
  echo "FAIL: TAP_PR_TOKEN is not set — tap update cannot be authenticated. Refusing (fail-closed)." >&2
  exit 1
}
command -v gh >/dev/null 2>&1 || { echo "FAIL: gh CLI required" >&2; exit 1; }

TAP_DIR="$(mktemp -d)/tap"
git clone --depth 1 "https://x-access-token:${TAP_PR_TOKEN}@github.com/${TAP_REPO}" "$TAP_DIR" \
  || { echo "FAIL: could not clone tap repo $TAP_REPO" >&2; exit 1; }

mkdir -p "$TAP_DIR/Formula"
cp "$FORMULA" "$TAP_DIR/Formula/cerberus.rb"

BRANCH="tap-v${VERSION}"
cd "$TAP_DIR"
git checkout -q -B "$BRANCH"
git add Formula/cerberus.rb
if git diff --cached --quiet; then
  echo "SKIP: tap formula is already at v${VERSION} (idempotent)"
  exit 0
fi
git -c user.name="cerberus-release-bot" -c user.email="release@cerberus.dev" \
  commit -q -m "cerberus ${VERSION}: update formula with release sha256

Source: ${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-alexeirojas87/cerberus} release v${VERSION}
Sums: SHA256SUMS of the published release artifacts (verified before generation)."
git push -q origin "$BRANCH" || { echo "FAIL: push to tap branch failed" >&2; exit 1; }

gh pr create --repo "$TAP_REPO" \
  --head "$BRANCH" --base main \
  --title "cerberus ${VERSION}" \
  --body "Automated tap update for cerberus v${VERSION}. Formula sha256 values are taken from the release SHA256SUMS (verified against the published artifacts). See the release workflow for provenance." \
  || { echo "FAIL: could not open tap PR" >&2; exit 1; }

echo "PASS: tap PR opened for v${VERSION}"
