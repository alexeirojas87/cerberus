#!/usr/bin/env bash
# bump_version.sh — PR-based version bump (R9-3).
#
#   Usage:
#     tools/release/bump_version.sh <new-version> [--dry-run]
#
#   What it does (in a real run, inside the version-bump-v2.yml workflow):
#     1. Validates <new-version> is strict semver (MAJOR.MINOR.PATCH).
#     2. Rewrites `version` in crates/cerberus/Cargo.toml.
#     3. Refreshes the `package cerberus` entry in Cargo.lock.
#     4. The workflow commits the result on a `release/bump-v<new>` branch
#        and opens a PR against the default branch. NO workflow ever pushes
#        to the protected default branch — a human merges the PR, and only
#        the merged commit may be tagged (enforced by verify_tag_merge.sh).
#
#   --dry-run performs the change, prints the exact `git diff` of the two
#   files, then RESTORES the originals. This is the local gate: the diff
#   output is recorded as evidence and nothing is left dirty.

set -euo pipefail

NEW_VERSION=""
DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    -*) echo "unknown option: $arg" >&2; exit 1 ;;
    *) NEW_VERSION="$arg" ;;
  esac
done

[ -n "$NEW_VERSION" ] || { echo "usage: $0 <new-version> [--dry-run]" >&2; exit 1; }
printf '%s' "$NEW_VERSION" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' \
  || { echo "FAIL: '$NEW_VERSION' is not strict MAJOR.MINOR.PATCH semver" >&2; exit 1; }

TOML="crates/cerberus/Cargo.toml"
CURRENT="$(sed -nE 's/^version = "([^"]+)"/\1/p' "$TOML" | head -1)"
[ -n "$CURRENT" ] || { echo "FAIL: no version in $TOML" >&2; exit 1; }

if [ "$CURRENT" = "$NEW_VERSION" ]; then
  echo "FAIL: version is already $NEW_VERSION (nothing to bump)" >&2
  exit 1
fi

if [ "$DRY_RUN" = "1" ]; then
  # F3: snapshot the two files BEFORE any rewrite. Plain file copies (no git
  # state mutation) keep pre-existing staged + unstaged edits out of the
  # restore path entirely, and the trap restores from the snapshot on both
  # success and failure (EXIT/INT/TERM). Never `git checkout --` — it would
  # destroy pre-existing unstaged edits.
  SNAPSHOT_DIR="$(mktemp -d)"
  cp "$TOML" "$SNAPSHOT_DIR/Cargo.toml"
  cp Cargo.lock "$SNAPSHOT_DIR/Cargo.lock"
  restore() {
    cp "$SNAPSHOT_DIR/Cargo.toml" "$TOML"
    cp "$SNAPSHOT_DIR/Cargo.lock" Cargo.lock
    rm -rf "$SNAPSHOT_DIR"
  }
  trap restore EXIT INT TERM
fi

# 1. Cargo.toml bump (first line-anchored `version = "..."` of the package).
#    Portable awk (BSD sed lacks GNU's `0,/re/` address).
awk -v cur="$CURRENT" -v new="$NEW_VERSION" '
  !done && $0 == "version = \"" cur "\"" {
    sub(/^version = "[^"]+"/, "version = \"" new "\""); done = 1; print; next
  }
  { print }
' "$TOML" > "$TOML.tmp" && mv "$TOML.tmp" "$TOML"

grep -q "^version = \"$NEW_VERSION\"" "$TOML" \
  || { echo "FAIL: Cargo.toml rewrite did not apply" >&2; exit 1; }

# 2. Cargo.lock refresh (workspace member — offline, no network needed).
cargo metadata --format-version 1 --offline >/dev/null 2>&1 \
  || { echo "FAIL: cargo metadata could not refresh Cargo.lock" >&2; exit 1; }

LOCK_VERSION="$(awk -v pkg='name = "cerberus"' '
  $0 == pkg { found = 1; next }
  found && /^version = "/ { gsub(/^version = "|"$/, ""); print; exit }
' Cargo.lock)"
[ "$LOCK_VERSION" = "$NEW_VERSION" ] \
  || { echo "FAIL: Cargo.lock still at $LOCK_VERSION" >&2; exit 1; }

echo "==> bump: $CURRENT -> $NEW_VERSION (Cargo.toml + Cargo.lock)"

if [ "$DRY_RUN" = "1" ]; then
  echo
  echo "── DRY-RUN git diff (files restored on exit) ──────────────────────────"
  git diff -- "$TOML" Cargo.lock
  echo "────────────────────────────────────────────────────────────────────────"
  echo
  echo "DRY-RUN OK. In CI, version-bump-v2.yml commits this diff to"
  echo "release/bump-v$NEW_VERSION and opens a PR against the default branch."
else
  echo "PASS: bump_version.sh — ready to commit on release/bump-v$NEW_VERSION"
fi
