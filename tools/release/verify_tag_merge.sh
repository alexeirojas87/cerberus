#!/usr/bin/env bash
# verify_tag_merge.sh — R9-3 fail-closed gate for tag-triggered releases.
#
#   Usage:
#     tools/release/verify_tag_merge.sh <tag> [--default-branch main]
#
#   Verifies, FAILING CLOSED on every check:
#     1. <tag> matches the semver release pattern: vMAJOR.MINOR.PATCH
#     2. tag version == crates/cerberus/Cargo.toml `version`
#     3. tag version == `package cerberus` version in Cargo.lock
#     4. the tag's commit is reachable from the default branch's merged
#        history (git merge-base --is-ancestor). A tag on a dangling
#        commit / hot-fix branch that was never merged FAILS.
#
#   This is the core R9-3 invariant: no workflow may publish a release
#   from a commit that did not go through a reviewed, merged PR on the
#   default branch. Exits non-zero (and prints the failing check) on any
#   violation. In CI the caller must checkout with fetch-depth: 0 so all
#   history and tags are present.

set -euo pipefail

TAG="${1:-}"
DEFAULT_BRANCH="main"
while [ $# -gt 0 ]; do
  case "$1" in
    --default-branch) DEFAULT_BRANCH="$2"; shift 2 ;;
    *) shift ;;
  esac
done

fail() { echo "FAIL: $1" >&2; exit 1; }

[ -n "$TAG" ] || fail "missing tag argument (usage: $0 <tag> [--default-branch <branch>])"

# ── 1. semver tag shape ───────────────────────────────────────────────────────
case "$TAG" in
  v[0-9]*.[0-9]*.[0-9]*)
    # Reject non-numeric suffixes like v1.2.3-rc or v1.2.3.1 via exact match.
    if ! printf '%s' "$TAG" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'; then
      fail "tag '$TAG' is not a strict MAJOR.MINOR.PATCH semver tag"
    fi
    ;;
  *) fail "tag '$TAG' does not match the release tag pattern 'vMAJOR.MINOR.PATCH'" ;;
esac
VERSION="${TAG#v}"
echo "==> tag '$TAG' semver OK (version $VERSION)"

# ── 2. crates/cerberus/Cargo.toml version ────────────────────────────────────
TOML_VERSION="$(sed -nE 's/^version = "([^"]+)"/\1/p' crates/cerberus/Cargo.toml | head -1)"
[ -n "$TOML_VERSION" ] || fail "could not read version from crates/cerberus/Cargo.toml"
[ "$TOML_VERSION" = "$VERSION" ] \
  || fail "tag $TAG != crates/cerberus/Cargo.toml version $TOML_VERSION"
echo "==> Cargo.toml version OK ($TOML_VERSION)"

# ── 3. Cargo.lock package metadata ───────────────────────────────────────────
LOCK_VERSION="$(awk -v pkg='name = "cerberus"' '
  $0 == pkg { found = 1; next }
  found && /^version = "/ { gsub(/^version = "|"$/, ""); print; exit }
' Cargo.lock)"
[ -n "$LOCK_VERSION" ] || fail "could not read 'package cerberus' version from Cargo.lock"
[ "$LOCK_VERSION" = "$VERSION" ] \
  || fail "tag $TAG != Cargo.lock cerberus package version $LOCK_VERSION"
echo "==> Cargo.lock version OK ($LOCK_VERSION)"

# ── 4. tag commit reachable from default-branch merged history ───────────────
if ! git rev-parse --verify -q "refs/remotes/origin/${DEFAULT_BRANCH}" >/dev/null; then
  # Local fallback: bare branch ref (e.g. when checked out without remotes).
  git rev-parse --verify -q "refs/heads/${DEFAULT_BRANCH}" >/dev/null \
    || fail "default branch '$DEFAULT_BRANCH' not found (need fetch-depth: 0 checkout in CI)"
fi

BRANCH_REF="refs/remotes/origin/${DEFAULT_BRANCH}"
git rev-parse --verify -q "$BRANCH_REF" >/dev/null || BRANCH_REF="refs/heads/${DEFAULT_BRANCH}"

TAG_COMMIT="$(git rev-list -n 1 "$TAG")"
[ -n "$TAG_COMMIT" ] || fail "tag '$TAG' does not resolve to a commit"

if ! git merge-base --is-ancestor "$TAG_COMMIT" "$BRANCH_REF"; then
  fail "tag commit $TAG_COMMIT is NOT reachable from ${DEFAULT_BRANCH} merged history; refusing to release (R9-3)"
fi
echo "==> tag commit $TAG_COMMIT is an ancestor of origin/${DEFAULT_BRANCH} (merged) — OK"

echo "PASS: verify_tag_merge.sh — all R9-3 checks green"
