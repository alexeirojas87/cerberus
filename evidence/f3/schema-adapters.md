# Evidence Pack — Phase 3 / schema-adapters
- Attempt: 1    Reviewer: Builder    Verdict: PASS

## Acceptance criteria
| Criterion | Command executed | Output | Result |
|----------|-------------------|--------|-----------|
| `cargo test -p cerberus-proxy` | `cargo test -p cerberus-proxy` | 46 passed; 0 failed | ✅ |
| OpenAI extracts messages[].content | `test::openai_extracts_messages_content` | Pass | ✅ |
| OpenAI extracts prompt field | `test::openai_extracts_prompt` | Pass | ✅ |
| OpenAI with no match → None | `test::openai_no_match_returns_none` | Pass | ✅ |
| Anthropic extracts messages[].content | `test::anthropic_extracts_messages` | Pass | ✅ |
| Anthropic with no match → None | `test::anthropic_no_match` | Pass | ✅ |
| try_adapt prefers OpenAI over Anthropic | `test::try_adapt_prefers_openai` | Pass | ✅ |
| try_adapt fallback to None | `test::try_adapt_fallback_to_agnostic` | Pass | ✅ |

## Adversarial cases tested
- JSON without messages/prompt → None (do not force a false positive)
- Multiple messages → concatenated content
- Unknown adapter → not applied
- Adapter order: OpenAI first (most common)

## Applicable NFRs
- N/A

## Files
- `crates/cerberus-proxy/src/adapters.rs`

## Deviations from plan
None. Schema adapters are optional and applied before the agnostic decoder.
