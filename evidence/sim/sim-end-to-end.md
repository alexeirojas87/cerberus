# Evidence Pack — sim / end-to-end execution of Cerberus

- **Date:** 2026-08-20
- **Method:** simulation driven with the **real release binary**
  (`target/release/cerberus`) + mock HTTP upstream (`tools/mock-server.py`),
  **Enforce** and **Shadow** phases with a per-phase isolated HOME.
  Decisions/verdict: automated via assertions in `tools/simulate.py`.
- **Verdict: PASS** ✅ (26/26 live assertions) + release unit suites green.

## Transcripts
- `evidence/sim/sim-run-20260820-143618.log` (26 PASS / 0 FAIL)
- Reproducible harness: `tools/simulate.py`

---

## 1. HTTP surface (real daemon) — ENFORCE phase

| # | Functionality | Observed evidence |
|---|---|---|
| 1 | `GET /health` | `{"status":"ok","mode":"enforce","upstream_count":1}` |
| 2 | **Block** (critical rule) | `POST /openai/...` with `OPENAI_API_KEY=sk-...` → **HTTP 403** `{"error":"blocked","flag":"secret.openai_api_key"}`. The secret **never** reaches the upstream. |
| 3 | **Redact** (rule `action=redact`, Bearer) | 200; the mock receives the **transformed** body: `Authorization: [REDACTED:secret.generic_bearer_token]`. The raw token **does not** travel. |
| 4 | **Warn** (PII email, `action=warn`) | 200 and the email **arrives intact** at the upstream (only audited). |
| 5 | Clean pass-through | 200, clean body intact; the mock confirms receipt. |
| 6 | Allowlist (FP triage) | `POST /api/allowlist` → `{"status":"ok","added":"sk-EXAMPLE-do-not-flag"}` |
| 7 | Config API | `GET /api/config` → 200 with `listen`/`mode`/`upstreams`/`fail_policy`. |
| 8 | Telemetry | `GET /api/events` → 4 events with flags, `action_taken`, `hashed_values`; **no** raw value. |
| 9 | Stats per provider | `GET /api/stats` → `total>0` and `by_provider` broken down (local: redact 1, warn 2; openai: block 1) with `top_flags`. |
| 10 | Dashboard | `GET /api/dashboard` → HTML (len 4844). |
| 11 | Zero leak | grep for raw over **the entire HOME** (db/logs) + daemon log → 0 occurrences. |
| 12 | CLI dry-run | `cerberus doctor` (13 rules loaded, RUNNING), `cerberus test` detects a secret with a context keyword. |

## SHADOW phase — §4.7

| # | Functionality | Evidence |
|---|---|---|
| 13 | Shadow lets through | In `shadow` mode (config), the critical secret **does NOT block**: 200 and the body arrives **intact with the raw secret** at the upstream. |
| 14 | Shadow does audit | `/api/events` logs the event with `action_taken":"block"` and `flags:["secret.openai_api_key","secret.env_block"]` despite being let through. |

---

## 2. Unit suites / internal features (release)

| Package | Result |
|---|---|
| `cerberus-engine` (engine) | 168 passed / 0 failed |
| `cerberus-proxy` | 53 passed / 0 failed |
| `cerberus-packs` | 29 passed / 0 failed |
| `cerberus` (CLI) | 21 passed / 0 failed |
| `cerberus-store` | 11 passed / 0 failed |

### Internal engine features coverage verified
- **In-place redaction that preserves JSON**: `json_structure_preserved`, `multiple_redactions`, `redact_replaces_span`, custom token (`custom_token_template`).
- **Action precedence**: `full_precedence_chain_block_over_redact_over_warn_over_allow`, `block__precedence`, `redact_wins_over_warn_and_allow`, `overlapping_spans_most_severe_wins`.
- **Break-glass / audited bypass**: `allow_once`, `allow_once_static_works`, `allow_passes_through`, `block_returns_error`, `enabled_with_block_removes_block`.
- **Dev feedback**: `feedback_block_message`, `feedback_redact_message`, `feedback_warn_message`, `feedback_by_category`, `feedback_summary_line_with_findings`.
- **Reversible vault** (optional): `vault_is_empty_initially`, `store_and_resolve`, `resolve_nonexistent_token`, `entry_round_trip`, `reversible_options_enabled`/`default_disabled`.
- **Generic entropy**: `detect_high_entropy_near_keyword`, `detect_low_entropy_no_finding`, `entropy_finding_never_raw`.
- **Multiline blocks** (PEM / id_rsa / .env): `detects_pem_rsa/dsa/ec/openssh_private_key`, `detects_id_rsa_ssh_key`, `detects_env_file_with_secrets`, `pem_block_captures_full_range`.
- **Constraints / validators**: `context_keywords_case_insensitive_mixed_case`, `allowed_examples_known_false_positive_discarded`, Luhn (`apply_iban_char`), `get_validator_*` elements.
- **No raw leak**: `hash_only` tests, `findings_out_of_order_sorted`, span bounds (`invalid_span_end_before_start/out_of_bounds`).

## 3. NFRs (release, deterministic)
| NFR | Command | Result |
|---|---|---|
| Scan latency | `cargo test --release --package cerberus-hardening --test load_test -- --test-threads=1` | 7 passed / 0 failed (p99 budgets are validated in release in isolation; debug is laxer) |
| No ReDoS | `cargo test --release ... --test redos_fuzz` | 5 passed / 0 failed |
| Fail-safe | `cargo test --release ... --test failsafe` | 6 passed / 0 failed |

---

## Adversarial cases covered
- Env secret `OPENAI_API_KEY=` in **uppercase** (the case that broke in pre-R0) → block OK.
- Payload with 2 findings (openai_key + env) in **shadow**: logged and passed.
- Redact over nested JSON: structure intact, only the value substituted.
- Search for raw secrets across **the entire** VM HOME (db + logs) → 0 remnants.

## Method note
The simulation used `cerberus test "mi openai api key es sk-..."` — with the context keyword `openai`. Without that keyword the constraint discards the finding (correct constraint-engine behavior, not a failure; it's exactly the anti-FP mechanism).
