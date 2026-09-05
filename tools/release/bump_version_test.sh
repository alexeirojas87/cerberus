#!/usr/bin/env bash
# bump_version_test.sh — F3/F11 shell harness for tools/release/bump_version.sh
#
# Spec Req C1 (F3-success/F3-failure) + Req C5 (F11-error/F11-cold); design
# obs #465 testing row "NEW tools/release/bump_version_test.sh". Fixtures are
# throwaway temp git repos laid out like the repo (crates/cerberus/Cargo.toml
# + Cargo.lock) so the script under test runs unmodified, with a pre-existing
# dirty worktree (staged TOML edit + unstaged TOML delta + unstaged lock
# edit) that a `git checkout --` restore would destroy.
#
# Usage: bash tools/release/bump_version_test.sh   (exit 0 = all cases PASS)

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/bump_version.sh"
PASS=0 FAIL=0
ERRFILE="${TMPDIR:-/tmp}/bump_version_test.$$.stderr"
trap 'rm -f "$ERRFILE"' EXIT

ok()  { printf 'PASS: %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf 'FAIL: %s\n' "$1"; FAIL=$((FAIL+1)); }
need() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want [$3] got [$2])"; fi; }
have() { if printf '%s' "$2" | grep -qF -- "$1"; then ok "$3"; else bad "$3 (missing: $1)"; fi; }
in_file() { if grep -qF -- "$1" "$2"; then ok "$3"; else bad "$3 (missing: $1)"; fi; }
needne() { if [ "$2" -ne 0 ]; then ok "$1"; else bad "$1 (want nonzero, got 0)"; fi; }
if command -v sha256sum >/dev/null 2>&1; then sha() { sha256sum "$1" | awk '{print $1}'; }
else sha() { shasum -a 256 "$1" | awk '{print $1}'; } fi

# make_fixture <mode> — mode ok: resolvable workspace (dry-run succeeds);
# broken: member depends on a missing local path crate so `cargo metadata
# --offline` fails mid-run (after the TOML rewrite); regdep: member depends
# on registry crate `serde` absent from the fixture lock — run with an empty
# CARGO_HOME (cold registry) to force the same offline failure through the
# registry path. All deterministic, no network.
make_fixture() {
  local mode="$1" dir; dir="$(mktemp -d)"
  mkdir -p "$dir/crates/cerberus"
  printf '[workspace]\nmembers = ["crates/cerberus"]\nresolver = "2"\n' >"$dir/Cargo.toml"
  {
    printf '[package]\nname = "cerberus"\nversion = "0.1.0"\nedition = "2021"\n\n[lib]\npath = "lib.rs"\n'
    case "$mode" in
      broken) printf '\n[dependencies]\nzz-r9f11-missing = { path = "../zz-r9f11-missing" }\n' ;;
      regdep) printf '\n[dependencies]\nserde = "1"\n' ;;
    esac
  } >"$dir/crates/cerberus/Cargo.toml"
  : >"$dir/crates/cerberus/lib.rs"
  printf 'version = 3\n\n[[package]]\nname = "cerberus"\nversion = "0.1.0"\n' >"$dir/Cargo.lock"
  if [ "$mode" = ok ]; then (cd "$dir" && cargo metadata --format-version 1 --offline >/dev/null 2>&1); fi
  (cd "$dir" && git init -q 2>/dev/null && git add -A \
    && git -c user.name=t -c user.email=t@t commit -qm init)
  # Pre-existing dirty worktree (what the old `git checkout --` destroyed):
  #   Cargo.toml: staged edit + an additional UNSTAGED delta (staged+dirty mix)
  #   Cargo.lock: unstaged edit only
  printf '\n# r9-f3-preexisting-staged-edit\n' >>"$dir/crates/cerberus/Cargo.toml"
  (cd "$dir" && git add crates/cerberus/Cargo.toml)
  printf '\n# r9-f3-preexisting-unstaged-edit\n' >>"$dir/crates/cerberus/Cargo.toml"
  printf '\n# r9-f3-preexisting-unstaged-edit\n' >>"$dir/Cargo.lock"
  printf '%s\n' "$dir"
}

# run_dry <dir> [VAR=val ...] — dry-run the script for 9.9.9 inside <dir>;
# stdout -> OUT, stderr -> ERRFILE, exit status -> RC.
run_dry() {
  local dir="$1"; shift
  RC=0
  OUT="$(cd "$dir" && env "$@" bash "$SCRIPT" 9.9.9 --dry-run 2>"$ERRFILE")" || RC=$?
}

f3_success() {
  local dir toml lock ts ls st; dir="$(make_fixture ok)"
  toml="$dir/crates/cerberus/Cargo.toml"; lock="$dir/Cargo.lock"
  ts="$(sha "$toml")"; ls="$(sha "$lock")"
  run_dry "$dir"
  need "f3-success: dry-run exits 0" "$RC" "0"
  have '+version = "9.9.9"' "$OUT" "f3-success: rewrite really happened (diff shows the bump)"
  need "f3-success: TOML byte-identical after restore" "$(sha "$toml")" "$ts"
  need "f3-success: Cargo.lock byte-identical after restore" "$(sha "$lock")" "$ls"
  in_file '# r9-f3-preexisting-staged-edit' "$toml" "f3-success: pre-existing STAGED TOML edit intact"
  in_file '# r9-f3-preexisting-unstaged-edit' "$toml" "f3-success: pre-existing UNSTAGED TOML delta intact"
  in_file '# r9-f3-preexisting-unstaged-edit' "$lock" "f3-success: pre-existing UNSTAGED lock edit intact"
  in_file 'version = "0.1.0"' "$toml" "f3-success: script's own bump reverted (back to 0.1.0)"
  st="$(git -C "$dir" status --porcelain)"
  have 'MM crates/cerberus/Cargo.toml' "$st" "f3-success: staged+dirty git state preserved (TOML MM)"
  have ' M Cargo.lock' "$st" "f3-success: unstaged git state preserved (lock M)"
  rm -rf "$dir"
}

f3_failure() {
  local dir toml lock ts ls; dir="$(make_fixture broken)"
  toml="$dir/crates/cerberus/Cargo.toml"; lock="$dir/Cargo.lock"
  ts="$(sha "$toml")"; ls="$(sha "$lock")"
  run_dry "$dir"
  needne "f3-failure: dry-run exits nonzero" "$RC"
  have "FAIL: cargo metadata could not refresh Cargo.lock" "$(cat "$ERRFILE")" \
    "f3-failure: failed mid-run (after the TOML rewrite, at lockfile refresh)"
  need "f3-failure: TOML byte-identical after failure" "$(sha "$toml")" "$ts"
  need "f3-failure: Cargo.lock byte-identical after failure" "$(sha "$lock")" "$ls"
  in_file '# r9-f3-preexisting-unstaged-edit' "$toml" "f3-failure: pre-existing TOML edits intact"
  in_file '# r9-f3-preexisting-unstaged-edit' "$lock" "f3-failure: pre-existing lock edit intact"
  rm -rf "$dir"
}

# f11_case <label> <mode> <cargo-error-substring> [VAR=val ...] — the script
# must fail LOUDLY: cargo's REAL error text reaches stderr (the old code
# swallowed it with >/dev/null 2>&1) and the snapshot restore still runs.
f11_case() {
  local label="$1" mode="$2" errtext="$3"; shift 3
  local dir toml lock ts ls; dir="$(make_fixture "$mode")"
  toml="$dir/crates/cerberus/Cargo.toml"; lock="$dir/Cargo.lock"
  ts="$(sha "$toml")"; ls="$(sha "$lock")"
  run_dry "$dir" "$@"
  needne "$label: dry-run exits nonzero" "$RC"
  have "$errtext" "$(cat "$ERRFILE")" \
    "$label: cargo's real error text visible on stderr (not swallowed)"
  need "$label: TOML byte-identical after failure" "$(sha "$toml")" "$ts"
  need "$label: Cargo.lock byte-identical after failure" "$(sha "$lock")" "$ls"
  rm -rf "$dir"
}

f11_error() { f11_case "f11-error" broken "zz-r9f11-missing"; }
f11_cold() {
  f11_case "f11-cold" regdep "no matching package named" "CARGO_HOME=$(mktemp -d)"
}

main() {
  [ -f "$SCRIPT" ] || { echo "FAIL: script under test missing: $SCRIPT" >&2; exit 1; }
  f3_success
  f3_failure
  f11_error
  f11_cold
  printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
  [ "$FAIL" -eq 0 ]
}
main "$@"
