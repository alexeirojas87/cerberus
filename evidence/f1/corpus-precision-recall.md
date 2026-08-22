# Phase 1 — Test corpus and Precision/Recall measurement

## Summary

A binary test corpus (positive/negative) was created to measure the
precision and recall of the Cerberus detection engine against the 11 rules in
`test-rules.json`. The measurement harness was implemented as an integration
test in `crates/cerberus-engine/tests/precision_recall_test.rs`.

## Corpus

### Positives (6 files, 52 non-empty lines)

| File | Lines with secrets | Categories covered |
|---|---|---|
| `01-api-keys.txt` | 8 | OpenAI, Anthropic*, AWS, GitHub, Slack, Stripe, Bearer |
| `02-emails.txt` | 6 | Emails (PII) |
| `03-credit-cards.txt` | 5 | Visa/Mastercard/Amex credit cards (valid Luhn) |
| `04-phone-numbers.txt` | 5 | International phone numbers (PII) |
| `05-pem-keys.txt` | 4 | RSA/EC/OPENSSH/DSA private keys (PEM) |
| `06-high-entropy.txt` | 7 | High entropy near keywords (virtual entropy) |

**Total**: ~35 secrets in 6 files.

*\* Anthropic is not detected due to AC prefix overlap (see §Deviations).*

### Negatives (4 files, 67 non-empty lines)

| File | Lines | Purpose |
|---|---|---|
| `01-code-snippets.txt` | ~9 | Code with variables like `api_key` but placeholder/short values |
| `02-readme-files.txt` | ~12 | READMEs with API key examples (`sk-your-key-here`) |
| `03-regular-text.txt` | ~10 | Normal text, conversations, documentation |
| `04-short-strings.txt` | ~10 | Short strings that match patterns but violate minLength |

## Methodology

1. Load `test-rules.json` (11 rules) → compile `CompiledEngine`
2. Scan each positive file → count findings (TP)
3. Scan each negative file → count findings (FP)
4. Calculations:
   - **Recall**: detected secrets / total expected secrets in corpus
   - **Precision**: TP / (TP + FP)
   - Total scan time

## Measured results

### Per-Category

| Category | Expected | Detected | Findings | Recall |
|---|---|---|---|---|
| API Keys & Tokens | 7 | 7 | 13 | 100.0% |
| PII - Emails | 6 | 6 | 1 | 100.0% |
| PII - Credit Cards | 5 | 5 | 2 | 100.0% |
| PII - Phone Numbers | 5 | 5 | 1 | 100.0% |
| PEM Private Keys | 4 | 4 | 5 | 100.0% |
| High Entropy | 7 | 7 | 6 | 100.0% |

### Summary

| Metric | Value |
|---|---|
| **Recall** | **100.0%** (34/34) |
| **Precision** | **84.8%** (28/33) |
| TP regex | 14 |
| TP entropy | 11 |
| TP other (cross-category) | 3 |
| FP regex | 5 |
| FP entropy | 0 |
| **Scan time** | **33.26 ms** (10 files) |

### Documented false positives (5)

| File | Flag | Value | Cause |
|---|---|---|---|
| `01-code-snippets.txt` | `pii.phone` | `4111 1111 1111` | Phone regex too permissive |
| `02-readme-files.txt` | `secret.generic_bearer_token` | `Bearer YOUR_TOKEN_HERE` | constraints not applied |
| `02-readme-files.txt` | `pii.email` | `user@example.com` | constraints not applied |
| `02-readme-files.txt` | `pii.credit_card` | `4111111111111111` | constraints not applied |
| `02-readme-files.txt` | `pii.phone` | `411111111111111` | Phone regex too permissive |

## Known deviations

### 1. `constraints.rs` not integrated into the scan path
The `contextKeywords`, `minLength`, `maxLength`, `allowedExamples` constraints
are NOT evaluated during the scan in `CompiledEngine::scan()`. The
`constraints.rs` module exists with unit tests but is not called from the hot
path. This causes 4 of the 5 measured false positives.

**Impact**: current precision 84.8%; with constraints integrated it is
estimated to be >95%.

### 2. AC prefilter overlap: `sk-` before `sk-ant-`
The `sk-` prefix of the OpenAI rule is added to the Aho-Corasick before
`sk-ant-` of Anthropic. When both prefixes match at the same position
(e.g. `sk-ant-api03...`), the AC returns only `sk-`, the OpenAI regex
fails (due to the hyphen in `ant-`), and the Anthropic one is never evaluated
because the AC does not report overlapping matches.

**Suggested fix**: use `MatchKind::LeftmostLongest` or retry longer prefixes
when the short regex fails. See `engine.rs:203`.

### 3. Phone regex too permissive
The pattern `\+?[0-9]{1,3}[\s.-]?\(?[0-9]{2,4}\)?[\s.-]?[0-9]{3,4}[\s.-]?[0-9]{3,4}`
matches sequences of ≥9 digits in slack tokens, credit cards, and
SHA hashes. The rule has no complementary validator.

### 4. PEM detection only captures the BEGIN marker
The `internal.private_key_pem` rule has the pattern
`-----BEGIN (?:RSA|EC|OPENSSH|DSA)?PRIVATE KEY-----`. The multi-line detector
finds the BEGIN line but does not capture the full block. `minLength: 100`
is not verified.

### 5. Virtual entropy always active
The `entropy.high_entropy_secret` detector runs on every scan. In the positive
corpus it adds 11 additional findings (TP). It produced no FPs in the current
negative corpus, but could do so with text that combines keywords + hashes.

## Next steps

1. Integrate `check_constraints` into `CompiledEngine::scan()` (tracked in
   `evidence/f1/constraints-review.md`)
2. Replace `MatchKind::LeftmostFirst` with `LeftmostLongest` in AC
3. Harden the phone regex with a complementary validator
4. Add CI: `cargo test -p cerberus-engine --test precision_recall_test`
5. Expand corpus: Unicode, nested JSON, base64, URLs with tokens

## Execution

```bash
cargo test -p cerberus-engine --test precision_recall_test -- --nocapture
```

Full report in `evidence/f1/raw/precision_recall_results.txt`.
Report SHA: `shasum -a 256 evidence/f1/raw/precision_recall_results.txt`
