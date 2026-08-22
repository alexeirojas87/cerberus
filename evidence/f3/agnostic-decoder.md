# Evidence Pack — Phase 3 / agnostic-decoder
- Attempt: 1    Reviewer: Builder    Verdict: PASS

## Acceptance criteria
| Criterion | Command executed | Output | Result |
|----------|-------------------|--------|-----------|
| `cargo test -p cerberus-proxy` | `cargo test -p cerberus-proxy` | 46 passed; 0 failed | ✅ |
| Decode JSON object extracts strings | `test::decode_json_object` | Pass | ✅ |
| Decode JSON array extracts content | `test::decode_json_array` | Pass | ✅ |
| Nested JSON extracts deep text | `test::decode_json_nested` | Pass | ✅ |
| Plain text passes through | `test::decode_plain_text` | Pass | ✅ |
| Empty body → empty string | `test::decode_empty_body` | Pass | ✅ |
| Numbers/bools do not generate false text | `test::decode_json_ignores_numbers_and_bools` | Pass | ✅ |
| Invalid UTF-8 does not panic (lossy fallback) | `test::decode_invalid_utf8_fallback` | Pass | ✅ |

## Adversarial cases tested
- JSON with only numbers → empty text
- Array of nested objects → text extracted recursively
- Invalid bytes → no panic, lossy fallback
- Content type hint ignored (autodetected decoding)

## Applicable NFRs
- N/A

## Files
- `crates/cerberus-proxy/src/decoder.rs`

## Deviations from plan
None. Agnostic by construction: extracts all text from any JSON.
