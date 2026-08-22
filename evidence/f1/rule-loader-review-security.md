# Evidence Pack — f1/rule-loader-security

- **Role**: REVIEWER 3 (Security)
- **Panel**: Phase 1 — rule-loader (`crates/cerberus-engine`)
- **Verdict**: PASS
- **Date**: 2026-08-17

## Summary

Security verification of the rule-loader and the hybrid AC+regex engine
(inherited from F0). Build, tests, ReDoS, `unsafe`, value hashing,
file loading, errors, and YAML parsing reviewed. All criteria PASS.
4 residual risks are documented (none blocking for the MVP).

## Security Criteria

### 1. Build ✅

| Command | Result |
|---------|-----------|
| `cargo build --release --workspace` | ✅ 0 errors, 0 warnings (`Finished release profile [optimized] in 26.14s`) |

### 2. Tests ✅

| Command | Result |
|---------|-----------|
| `cargo test -p cerberus-engine` | ✅ 48/48 passed (37 unit + 11 integration) |

### 3. ReDoS — no backtracking ✅

**Context**: the engine uses `regex` 1.13.1 + `regex-automata` 0.4.18 (DFA, no
backtracking; O(n) complexity guaranteed by the `regex` crate). The Aho-Corasick
prefilter only narrows the search, it does not introduce backtracking.

**Dynamic verification** (temporary review test, run in the worktree):

| Pattern | Attack type | Payload | Time | Result |
|--------|----------------|---------|--------|-----------|
| `(a\|aa\|aaa)+b` | prefixed, classic catastrophic | 10 000 × `a` | <5 ms | ✅ no hang, 0 findings |
| `((a)*)*b` | prefixed, nested quantifiers | 10 000 × `a` | <5 ms | ✅ no hang |
| `\d+(\d+)*` | unprefixed (RegexSet), catastrophic | 10 000 digits | <5 ms | ✅ no hang |

**Code detail**: `engine.rs:191` `regex.find(&text[m.start()..])` and
`engine.rs:204` `self.unprefixed_regexes[set_idx].find(text)` — both routes use
the `regex` DFA, with no backtracking. **Conclusion: no ReDoS risk.**

### 4. `unsafe` ✅

- `grep -rn "unsafe" crates/cerberus-engine/` → **0 matches** (exit 1).
- Workspace `Cargo.toml:8` → `[workspace.lints.rust] unsafe_code = "forbid"`.
- Clippy pedantic + nursery also apply at the workspace level.
- **Conclusion: 0 `unsafe` in the crate; the lint guarantees it at compile time.**

### 5. Hashed values — never the raw value ✅

**Flow in `engine.rs:220-234`** (`make_finding`):

```rust
let raw_value = &text[start..end];
let hashed = hash_value(raw_value.trim());
Finding { ..., start, end, hashed_value: hashed }
```

- `raw_value` is a *local slice* of `text`; it is **only used** as input to
  `hash_value()` (SHA-256 hex, `sha256:` prefix, `engine.rs:279`).
- The `Finding` does NOT retain `raw_value` — the only value field is `hashed_value`
  (`engine.rs:265`). No `text[start..end]` stored in the struct.
- Tests that protect it: `finding_never_contains_raw_value` (unit, engine.rs:426)
  and additional dynamic verification: `f.hashed_value != &text[f.start..f.end]`.
- **Note (low):** `Finding.start`/`Finding.end` are offsets. A caller that
  retains the original text can recompute the raw value from the
  offsets. The isolated Finding does not contain the secret; this is documented for
  the output pipeline design (the report must not expose text + offsets
  together without redaction).

### 6. File loading ✅ (risk documented)

`loader.rs:48-51` `load_rules_from_json` → `fs::read_to_string(path)`:
- Reads **any path** it receives (arbitrary path, no sandboxing) — the lib is
  pure and does not restrict paths by design.
- `/etc/passwd`: it is read and fails with `invalid rules JSON` (dynamically verified;
  does not expose the content in the error).
- `/dev/random` / FIFOs: `read_to_string` blocks until EOF → **potential DoS if
  the caller passes a device file**. **Acceptable for MVP** (config loader in
  process, not attackable from the network), but document in README/plan: the caller must
  validate the path before calling.

### 7. Error messages — no sensitive path leakage ✅

- `LoadError` (`loader.rs:12-30`): `Io` → `"cannot read rules file: {e}"`,
  `Json` → `"invalid rules JSON: {e}"`, `Yaml` → `"invalid rules YAML: {e}"`.
- The `io::Error` from `fs::read_to_string` does not include the path (pure OS message,
  e.g. "No such file or directory"). **Dynamically verified**: the error for
  `/tmp/cerberus_nonexistent_file_xyz.json` does NOT contain the absolute path.
- JSON/YAML errors from serde expose the *line/column of the input* (content
  of the rules), never system paths.

### 8. YAML parsing ✅ (documented low risk)

- `serde_yaml` 0.9.34 (deprecated) — **it deserializes into a typed `Vec<Rule>`, NOT into
  `serde_yaml::Value`** (`loader.rs:101-108`). Anchors/aliases only serve as
  references to already-parsed data; there is no runaway recursion toward unlimited
  structures.
- **Dynamically verified**:
  - Simple anchors + aliases (`&a` + 9 × `*a`) → loads correctly (10 rules).
  - "YAML bomb" with nested expansion (10^5 items via alias) → fails with a type
    error (the typed target does not accept the structure) in <5 ms; **no entity
    expansion or OOM**.
- **Residual risk (low):** `serde_yaml` is a deprecated crate without an explicit
  alias limit. The classic billion-laughs attack is only effective against
  deserialization to `Value`/recursive types, not against `Vec<Rule>`. The natural
  migration is to `serde_yml`/`serde_yaml_ng` or `serde_json` (already accepted) when
  maintenance demands it. **Acceptable for MVP.**

## Security Findings

| # | Severity | Finding | Status |
|---|-----------|----------|--------|
| S-1 | Low | `Finding.start/end` + original text in the caller's hands allow reconstructing the raw value | Documented; mitigate in the output report design |
| S-2 | Low | `load_rules_from_json` accepts arbitrary paths (`/etc/passwd`, `/dev/random`); devices can block | Acceptable (pure lib); validate path in the caller |
| S-3 | Low | `serde_yaml` deprecated; no explicit alias limit (billion-laughs only against `Value`) | Acceptable (typed target); migrate when appropriate |
| S-4 | Info | `regex` crate (DFA) guarantees linear time; no backtracking possible | No risk |

## Conclusion

- **Verdict**: PASS
- All REVIEWER 3 checklist criteria met with evidence:
  build OK, tests 48/48, no ReDoS, 0 `unsafe`, values always hashed,
  errors without paths, YAML with documented low risk.
- No blockers for the MVP.
