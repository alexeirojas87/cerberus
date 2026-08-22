# Evidence Pack — Phase 4 / default-packs
- Attempt: 1    Reviewer: Builder    Verdict: PASS

## Acceptance criteria
| Criterion | Command executed | Output | Result |
|----------|-------------------|--------|-----------|
| `cargo test --workspace` | `cargo test --workspace` | 285 passed; 0 failed | ✅ |
| Default rules parse correctly | `test::default_rules_parse_successfully` | >= 8 rules | ✅ |
| Default rules have required fields | `test::default_rules_have_required_fields` | Pass | ✅ |
| Default rules compile in the engine | `test::default_rules_compile_successfully` | Pass | ✅ |

## Included rules
| Flag | Action | Category |
|------|--------|-----------|
| secret.openai_api_key | block | secrets |
| secret.anthropic_api_key | block | secrets |
| secret.aws_access_key_id | block | secrets |
| secret.generic_bearer_token | redact | secrets |
| secret.github_token | block | secrets |
| secret.stripe_key | block | secrets |
| secret.google_api_key | redact | secrets |
| secret.slack_token | redact | secrets |
| pii.email_address | warn | pii |
| pii.phone_number | warn | pii |

## Files
- `crates/cerberus/src/packs.rs` (new)

## Deviations from plan
None. Rule packs embedded in the binary, active out-of-the-box.
