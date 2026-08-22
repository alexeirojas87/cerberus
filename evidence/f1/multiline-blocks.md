# Evidence Pack — f1/multiline-blocks
- Attempt: 1    Reviewer: BUILDER (auto-verify)    Verdict: PASS

## Acceptance criteria

| Criterion | Command executed | Output | Result |
|----------|-------------------|--------|-----------|
| Compiles | `cargo build` | `Finished dev profile` exit 0 | ✅ |
| Engine tests | `cargo test -p cerberus-engine` | 48 passed; 0 failed | ✅ |
| Integration tests | `cargo test -p cerberus-engine --test integration_test` | 11 passed; 0 failed | ✅ |
| Clippy | `cargo clippy --all-targets` | exit 0, no warnings | ✅ |
| Fmt | `cargo fmt --all -- --check` | exit 0 | ✅ |
| PEM RSA key detection | `detects_pem_rsa_private_key` | test passes | ✅ |
| PEM EC key detection | `detects_pem_ec_private_key` | test passes | ✅ |
| PEM OPENSSH key detection | `detects_pem_openssh_private_key` | test passes | ✅ |
| PEM DSA key detection | `detects_pem_dsa_private_key` | test passes | ✅ |
| Block captures full range (start/end cover it all) | `pem_block_captures_full_range` | verified: starts with BEGIN, ends with END, contains body lines | ✅ |
| Block with blank lines (encrypted PEM) | `pem_block_multi_line_body` | captures Proc-Type, DEK-Info headers | ✅ |
| .env with secrets detection | `detects_env_file_with_secrets` | test passes | ✅ |
| SSH key (id_rsa/OPENSSH) detection | `detects_id_rsa_ssh_key` | test passes | ✅ |
| No false positive on normal text | `no_false_positive_on_normal_text` | finding.is_none() | ✅ |
| No detection without multiline pattern | `no_detection_without_multiline_pattern` | finding.is_none() | ✅ |
| Multiline pattern classification | `multiline_pattern_detection` | `-----BEGIN` → true, `\\n` → true, simple → false | ✅ |

## Applicable NFRs
- **No ReDoS:** patterns evaluated with the `regex` crate (linear time). Multi-line patterns are compiled with the `(?m)` flag.
- **Hashed values:** all findings use `hash_value` (SHA-256), never the raw value
- **Does not break existing rules:** 35 pre-existing engine + loader + rule + scan tests still pass

## Adversarial cases tested
- PEM with a multi-line body of >2 lines → fully captured
- PEM with headers (Proc-Type, DEK-Info) → fully captured
- .env with 3 lines (2 secrets + 1 innocent) → detected
- OPENSSH key (id_rsa) → detected
- Normal text without blocks → no false positive
- Simple pattern like `sk-[A-Za-z0-9]{20,}` → does not trigger multi-line detection

## Modified/created files
| File | Action | SHA |
|---------|--------|-----|
| `crates/cerberus-engine/src/multiline.rs` | CREATE | (see git log) |
| `crates/cerberus-engine/src/lib.rs` | EDIT | +1 line |
| `crates/cerberus-engine/src/engine.rs` | EDIT | +7 lines |

## Deviations
None. Implementation faithful to the build plan spec §8 F1 multiline-blocks + contract of §4.3.
