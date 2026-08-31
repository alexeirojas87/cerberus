# F1.2 repair attempt 5 — independent correctness audit

- Reviewer task: `task_4e40cc8c6023` / dispatch `ctx_f406d2b9c62f`
- Worktree: `docs/fix-install-commands`, `HEAD fccd9e4823e17f3598b0aa27a7ae6bd632dfeec7`
- Verdict: **PASS (correctness)** with one **INFO** evidence-prose discrepancy; no blocking correctness findings.
- Repository edits by reviewer: none. Standalone probe: `/tmp/cerberus-f12-audit.TUAHZK/probe`.

## Frozen identity

All ten requested SHA-256 values matched exactly before any test run. After debug/release product-gate and workspace reproduction, `evidence/f1/raw/production_pack_pr.json` remained byte-identical at `0fc5d7db3111a527db48334ba61cc890e4d385bc40454a25b4c225712364e679`.

## Executed gates

| Command | Result |
|---|---|
| `cargo test -p cerberus-packs --test production_pack_pr -- --nocapture` | PASS: 16 tests, 1 suite |
| `cargo test --release -p cerberus-packs --test production_pack_pr -- --nocapture` | PASS: 16 tests, 1 suite |
| `cargo test --workspace --all-targets` | PASS: 638 tests, 25 suites |
| `cargo test --release --workspace --all-targets` | PASS: 638 tests, 25 suites |
| `cargo fmt --all -- --check` | PASS |
| `git diff --check` | PASS |
| `cargo clippy -p cerberus-engine -p cerberus-packs --all-targets -- -D warnings` | PASS: no issues |
| standalone `cargo run --release` | PASS: every assertion below |

## Attempt-4 finding dispositions

1. **Entropy UTF-8 window — PASS.** `entropy.rs:143-149` floors the 200-byte end to a character boundary before slicing. The standalone shipped-pack probe wrapped all required payloads in `catch_unwind`: `password=` + 200×`é`, `key=` + 197×`x` + `€`, and `key ` + `密钥`×120; all 3 returned without panic.
2. **ContextAnalyzer once-per-scan / per-call semantics — PASS.** `constraints.rs:77-94` performs one ASCII-lowercase and one line split per analyzer; `engine.rs:268-278` constructs at most one analyzer per scan and skips it for keyword-free engines. Independent behavior probe verified: public `check_constraints` preserves whole-context/per-call matching across lines; plain `scan` requires the keyword on the matched line; `scan_with_context` preserves the intentionally unbounded JSON-leaf behavior.
3. **IPv4/dotted-version suppression — PASS.** All four attempt-4 PoCs were silent for `pii.phone_number`; `call 212.555.0123 today` emitted one phone finding with exact span `212.555.0123`.
4. **Separated PAN detection and phone precedence — PASS.** Dot, slash, NBSP, two-space, and an additional three-space format all emitted exactly one `pii.credit_card` finding over the full PAN and no phone finding. `validator.rs:38-53` shows `PaymentCardValidator` and `NotPaymentCardValidator` use the same `payment_card_valid` predicate with direct negation; the independent probe also asserted the predicate true for every format.
5. **Keyword boundary and proximity — PASS.** `constraints.rs:37-54,120-156` applies case-insensitive ASCII word boundaries and same-line proximity on plain scans. `hotel`, `megaphone`, `contactless`, and `XE164foo` inputs were silent, while `phone 8005550199` emitted the exact numeric span.
6. **Leading bracket trim and adjacent-keyword dedup — PASS.** `entropy.rs:54,131-178,194-217` skips opening delimiters, strips an adjacent keyword prefix, and deduplicates absolute spans. `{}`, `()`, `[]`, and `key token=<secret>` each produced exactly one entropy finding whose span was precisely the secret token.
7. **Report-after-assertions — PASS for the product report gate.** `production_pack_pr.rs:362-419` validates the in-memory report before writing the frozen evidence path and directs failures to `target/production_pack_pr_FAILED.json`. Multiple successful debug/release rewrites reproduced the identical frozen report hash.
8. **Pack 1.2.0 identity — PASS.** `DEFAULT_PACK_VERSION` is `1.2.0`; independent SHA-256 over `DEFAULT_PACK_JSON` produced `aa1c0d8d54e22f52fecb4c9912c420d718a6612edeac5badce00979bfb8ff204`, exactly matching `DEFAULT_PACK_IDENTITY`; the embedded pack contains 15 rules.

## Accounting integrity

- **Exact spans:** `expected_spans` and `match_expected` require exact `(flag,start,end)` equality. A wrong-span finding is counted FP and leaves the expected instance unconsumed, so it also becomes FN.
- **No FP exclusion:** `MetricKind::apply` only increments TP/FP/FN; no decrement/removal/suppression path exists. Every unmatched finding calls `increment_metric`; unknown flags panic.
- **Thresholds unchanged:** source and raw report remain recall `0.90` and precision `0.85`, enforced for every evaluable category and flag.
- **All flags evaluable:** raw report contains 15 flags, no unevaluable flags, no failing flags, and aggregate `49 TP / 0 FP / 0 FN`.
- **Negative handling:** all six manifest cases with `expected: []` report zero findings; `validate_product_report` independently rejects any nonzero negative case.
- **Multi-label handling:** manifest occurrence accounting is keyed by `(flag,value)`, so different flags may share a span. Independent probe confirmed an OpenAI token emitted both `secret.openai_api_key` and `entropy.high_entropy_secret` on the identical exact span.
- **Corpus integrity / no test teaching:** no pre-existing corpus file was modified; attempt-5 adds the panel PoCs plus positive recall controls. Production changes are generalized patterns/predicates (separator classes, line/word logic), not literal corpus-value branches.

## Non-blocking finding

**INFO — negative-case count typo in the attempt-5 Evidence Pack.** `evidence/f1/r9-production-pack-pr.md:301` says “all 7 negative cases,” but `manifest-v1.json` has exactly six negative cases (`negative-code`, `negative-readme`, `negative-prose`, `negative-short`, `negative-constraints`, `negative-attempt5`) and the raw report likewise lists six. The substantive statement is true for all actual negative cases (each has zero findings), so this is evidence prose only and does not change the correctness PASS; the coordinator should correct `7` to `6` before final sign-off.
