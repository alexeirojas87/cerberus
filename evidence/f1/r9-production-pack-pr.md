# F1.2 — shipped-pack precision/recall remediation

Status: **REPAIR ATTEMPT 8 PASS — independent panel 3/3 PASS; human sign-off recorded**
(attempt-8 four-regression repair, adversarial loops, final commands and frozen
hashes: `evidence/f1/r9-pii-regression-repair.md`)
(attempt 6 SUPERSEDED — panel verdict correctness **PASS** / performance
**PASS** / security **FAIL** (SEC-1 Medium + SEC-2 Low); reports in
`evidence/review9/f12-attempt6-correctness.md`,
`evidence/review9/f12-attempt6-performance.md`,
`evidence/review9/f12-attempt6-security.md`; attempt 5 SUPERSEDED — panel
verdict 2 PASS / 1 FAIL with a HIGH performance
blocker at time of dispatch, see `evidence/review9/f12-attempt5-*.md`;
attempt 4 SUPERSEDED — FAIL after independent panel: 1 PASS / 2 FAIL verdicts;
attempt 5 reproduction recorded in "Integrator reproduction — repair attempt 5")

## Acceptance and identity

- Owner decision (2026-08-27): recall `>= 90%` and precision `>= 85%` for every evaluable category and every evaluable flag. Aggregate metrics are informational only.
- Isolated builder worktree: `/private/tmp/cerberus-f1-2-builder-a827`
- Base `HEAD`: `fccd9e4823e17f3598b0aa27a7ae6bd632dfeec7`
- Approved F1.1 source (`engine.rs`, `entropy.rs`) was copied into this worktree and verified byte-identical before F1.2 work.
- Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, `cargo 1.97.1 (c980f4866 2026-06-30)`.
- Host: macOS/Darwin 25.5.0, arm64, Apple M4 Pro.
- No commit, push, release change, or threshold change was made.

## What changed

1. The old `cerberus-engine/tests/precision_recall_test.rs` is now explicitly a synthetic unit-feature diagnostic using `test-rules.json`. It writes only under `target/`, has no production threshold claim, and its stale warning-only negative test was removed.
2. The product gate is `crates/cerberus-packs/tests/production_pack_pr.rs`. It imports and parses the exact `cerberus_packs::default_pack::DEFAULT_PACK_JSON` bytes, never a copy or test pack.
3. `DEFAULT_PACK_VERSION` is `1.1.0`; `DEFAULT_PACK_IDENTITY` binds that version to the SHA-256 of the exact embedded bytes and the product gate enforces the binding.
4. The default pack has 15 rules. Credit cards are context-independent and require a 13–19 digit Luhn-valid PAN whose IIN and length agree with a supported issuer. Formatted/international phones are context-independent; an additional same-flag policy accepts plain 7–15 digit values only with telephone/E.164 context. `not-payment-card` uses the same PAN predicate, including on `+`-prefixed or separated candidates, so known cards cannot be downgraded to phones while Luhn-valid international phones remain eligible.
5. Matching documentation placeholders for OpenAI, bearer, GitHub, Slack, email, and cards are explicit `allowedExamples`. A control test clears each allowlist and proves every allowed value would otherwise exercise that rule's real regex.
6. Generic entropy remains one virtual engine detector (not a duplicate pack rule). `DEFAULT_PACK_VIRTUAL_FLAGS` documents it and the gate requires it. `auth_token` was added to its existing keyword vocabulary.
7. Corpus schema/version and fixtures are committed under `tests/corpus/product-gate/`. The manifest references the pre-existing positive/negative corpora plus two versioned fixtures. Its composed hash includes manifest bytes, every path, file length, and file bytes.
8. Every shipped rule plus entropy has positive support, so all 15 flags are evaluable for both recall and precision. Every negative finding contributes an FP to its flag and category; there is no warning-only path.
9. The generated machine report is `evidence/f1/raw/production_pack_pr.json`, with TP/FP/FN, evaluability, gates, pack/corpus versions and hashes, categories, flags and cases. There is no FP exclusion/decrement path.
10. Ground-truth matches require exact `(start,end)` equality; partial overlap cannot count as a TP. Legitimate multi-detector findings are declared explicitly as multi-label ground truth.
11. Strong structured secret signatures (OpenAI, Anthropic, AWS, GitHub, Stripe, Google and Slack) no longer require contextual prose. Unknown validator names abort engine construction with a contextual error.
12. Entropy keyword alternatives are escaped and longest-first; `auth_token`, `auth-token` and `auth.token` each emit one exact finding, and trailing sentence punctuation is excluded from the secret span.
13. Every negative corpus case has an explicit zero-findings assert in addition to per-flag precision thresholds; a single negative finding cannot hide below 85%.
14. Attempt 4 adds adversarial controls for 13-, 14-, 15-, 16- and 19-digit PANs, per-digit separators, leading `+`, overlong numeric tokens, phone-context downgrade attempts, Luhn-valid international phones, contextual plain phones, formatted national phones, IDs, timestamps and repeated digits.

## Honest corpus corrections

- The standard Visa documentation number `4111111111111111` is a real Luhn-valid test fixture and is allowlisted; the positive Luhn coverage uses four other valid numbers, including `4000056655665556`.
- The SHA-256 integrity hash in `06-high-entropy.txt` is benign and has at most four bits of alphabet entropy; it was removed from secret ground truth rather than lowering the entropy threshold.
- AWS's canonical `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` documentation fixture is explicitly treated as public and non-secret by the virtual entropy detector. AWS access-key recall uses a non-placeholder `AKIA1234567890ABCDEF` fixture.
- The existing high-entropy `auth_token` instance exposed a real keyword-boundary gap. The detector gained the general `auth_token` keyword; corpus values and the `4.0` engine threshold were not changed.

## Machine result

Final focal command:

```text
$ rtk cargo test -p cerberus-packs --test production_pack_pr -- --nocapture
running 9 tests
test corpus_manifest_and_referenced_files_are_real_and_versioned ... ok
test exact_pack_identity_and_virtual_entropy_contract ... ok
test product_payment_card_constraints_are_enforced ... ok
test product_phone_constraints_are_enforced ... ok
test product_secret_constraints_are_enforced ... ok
test production_pack_precision_recall_gate ... ok
test every_allowed_example_suppresses_a_real_pattern_match ... ok
test ground_truth_requires_the_exact_finding_span ... ok
test structured_secret_signatures_do_not_require_context_keywords ... ok
test result: ok. 9 passed; 0 failed
```

Identity emitted by that run:

```text
pack_version=1.1.0
pack_rule_count=15
pack_sha256=sha256:c73754ed60096487491d26eef5990e29e75aca6e41a35aa2adfadf09f27a0a36
corpus_version=cerberus-default-pack-pr-v1
corpus_manifest_sha256=sha256:84ad0c3ef316b3d8f02c0634749774e5a75f987bffea8e4c0846dc7ef29ee3e7
corpus_sha256=sha256:cf8d4cfeb85436a793ba722dab07c0825d5879c83d60f8801f0523bd39ba7c64
```

Metrics generated by the run:

| Scope | TP | FP | FN | Recall | Precision | Gate |
|---|---:|---:|---:|---:|---:|---|
| aggregate (informational) | 43 | 0 | 0 | 100% | 100% | PASS |
| category `pii` | 20 | 0 | 0 | 100% | 100% | PASS |
| category `secrets` | 23 | 0 | 0 | 100% | 100% | PASS |
| minimum of 15 evaluable flags | — | — | — | 100% | 100% | PASS |

Per-flag highlights: entropy 8; phone 10; credit-card 4; email 6; PEM 4; OpenAI 2. Every one of the 15 evaluable flags has FP=0 and FN=0. The OpenAI and bearer values validly detected by both their named rules and entropy are explicit multi-label instances.

## Failed attempts retained

1. First honest product run: **FAIL**. Entropy was TP=5, FP=1, FN=2 (recall 71.4%, precision 83.3%). Investigation found one incorrect expected hash, one missing AWS entropy ground-truth instance, and the `auth_token` boundary gap. Thresholds and values were not changed.
2. First allowlist-control run: **FAIL**. A Slack allowed example had accidentally been placed on the Google rule, so the control test failed and Slack precision was 50% (TP=1, FP=1). The configuration placement was fixed; no corpus or gate threshold was weakened.
3. Builder focal and downstream runs: **PASS**, then **INVALIDATED** by independent review. The reviewer reproduced an entropy precision of 77.8% after removing the gate's FP decrement, contextless PII false negatives, 13/14-digit PAN phone misclassification, partial-overlap TP credit and an unbound version string.
4. First exact-span repair run: **FAIL**. It exposed sentence punctuation inside an entropy finding span (entropy TP=8, FP=1, FN=1). The detector was repaired to exclude trailing sentence punctuation; ground truth was not widened.
5. Post-review repair: **PASS**. FP exclusions were deleted, multi-label truth made explicit, PII made context-independent, the anti-PAN validator added, exact spans enforced and pack identity bound to version+SHA.
6. Post-fix reviewer expansion: **FAIL**. Contextless structured keys were missed; national/unprefixed phone formats regressed; 13/14-digit PANs, IDs, timestamps, repeated-zero cards and a Luhn-valid international phone exposed ambiguity; unknown validators were accepted at build; auth separator variants produced malformed spans.
7. Repair attempt 3: **PASS locally**. Structured keys are context-independent; split phone policies balance recall and precision; Luhn/PAN semantics are explicit; unknown validators fail construction; entropy variants are exact and non-duplicating. Panel review remains required.
8. Repair-attempt-3 expanded panel: **FAIL**. It found that Luhn alone was not sufficient card identity, `+` and per-digit separators could evade or confuse classification, phone patterns could accept partial matches, and the canonical AWS documentation secret was taught as a TP.
9. Repair attempt 4: **PASS locally**. Card identity now combines Luhn, issuer range and issuer-specific length; phone/card adversarial cases are permanent tests; the canonical AWS fixture is an explicit safe example. A fresh independent panel is still required.

## Verification commands and output

```text
$ rtk cargo fmt --all -- --check && rtk git diff --check
(exit 0, no output)

$ rtk cargo clippy -p cerberus-engine -p cerberus-packs --all-targets -- -D warnings
cargo clippy: No issues found

$ rtk cargo test -p cerberus-engine && rtk cargo test -p cerberus-packs
cargo test: 205 passed (4 suites, 0.05s)
cargo test: 77 passed (3 suites, 0.10s)

$ rtk cargo test --test redos_fuzz
cargo test: 8 passed (1 suite, 0.10s)

$ rtk cargo test --test load_test
cargo test: 8 passed (1 suite, 0.19s)

$ rtk cargo test -p cerberus-proxy json_redact
cargo test: 5 passed, 170 filtered out (2 suites, 0.01s)

$ rtk cargo test --workspace --all-targets
cargo test: 614 passed (25 suites, 38.24s)
```

## Baseline invalidated, not promoted

The prior integrator baseline used `test-rules.json`, gated only aggregate metrics, and its negative test printed warnings for three false positives (`Bearer YOUR_TOKEN_HERE`, the Visa fixture, and a phone substring inside that PAN). It is retained only as evidence of the broken gate and is **not** a PASS result. The product gate now runs the shipped bytes and those three concrete cases produce no findings.

## Integrator reproduction — initial builder state

Status: **SUPERSEDED / FAIL after independent review**, primary checkout, 2026-08-27.

The 13 reviewed F1.1/F1.2 source, test, corpus and evidence artifacts were SHA-256 identical to the isolated builder worktree before reproduction. The product test regenerated the machine report without changing its hash.

```text
74c951ad326baad9cc45bf85f4fae8cf5a0919dd5ad3edd63008538f015a5bcb  crates/cerberus-packs/src/default_pack.rs
50d2b65a326838377e17332845c69aa156a845a0a934d84b8139c4a7094f158b  crates/cerberus-packs/tests/production_pack_pr.rs
51fe22f9699b7e6e9b55fa3da95c1264e0a4f6c127ec236f08bda5c2cad39440  tests/corpus/product-gate/manifest-v1.json
2ceff711fd6b349e2bb6b5c632eba98935d425145f142f33d8f0b194b70e0bac  evidence/f1/raw/production_pack_pr.json
```

Primary-checkout commands and results:

```text
rtk cargo fmt --all -- --check                                            PASS
rtk cargo clippy -p cerberus-engine -p cerberus-packs --all-targets -- -D warnings
                                                                          PASS, no issues
rtk proxy cargo test -p cerberus-packs --test production_pack_pr -- --nocapture
                                                                          PASS, 5/5
  pack sha256:77e48d11dc2cc377f3a047173c69b4c06dec74232faa0837511f160bf66847fe
  corpus sha256:a4a823e913a33c8e944a75b687cfafcb7c5e2c7873877cca3d4a88b6b7a1fcb1
rtk cargo test -p cerberus-engine                                     197 PASS
rtk cargo test -p cerberus-packs                                       73 PASS
rtk cargo test --test redos_fuzz                                        8 PASS
rtk cargo test --test load_test                                         8 PASS
rtk cargo test -p cerberus-proxy json_redact                            5 PASS, 170 filtered
rtk cargo test --workspace --all-targets                              602 PASS, 25 suites, 36.97s
rtk git diff --check                                                   PASS
```

The displayed 36 TP / 0 FP / 0 FN was invalid: the gate subtracted two entropy FPs, accepted partial overlaps and used context-taught PII cases. This section is retained as failed-attempt history only.

## Integrator reproduction — post-review repair attempt 2

Status: **SUPERSEDED / FAIL after expanded review**, primary checkout, 2026-08-27.

```text
b1534a4c7d29e90464d2b0d7daaa69d91d796a8559c35e2643b4a9aaa54354f5  crates/cerberus-engine/src/entropy.rs
413e37119269ff2ee2b71699ca1cce32a48370cf78d957731676602c102af15f  crates/cerberus-engine/src/validator.rs
9434b2d63e157b29c8cbe64fddb1c2e25ed1727794a1c1d76718438b98cc50bc  crates/cerberus-packs/src/default_pack.rs
027dd0c74b332cb59409d83df3dbe53b6939ad10458b430fa71edf27de302fb9  crates/cerberus-packs/tests/production_pack_pr.rs
38ac8360ec850b6b0299d4f6d42900dd463f1fbb6a8169668848c7420f0973a7  tests/corpus/product-gate/manifest-v1.json
72e1af8946a274ede69faf1cb96f06b191079f1d5b3d7324f862fb5517c58093  evidence/f1/raw/production_pack_pr.json
```

Attempt-2 results were product gate 6/6 and workspace 607/607, but the expanded review found the recall/precision gaps listed above. Retained only as failed-attempt history.

## Integrator reproduction — repair attempt 3

Status: **SUPERSEDED / FAIL after expanded panel**, primary checkout, 2026-08-27.

```text
8563b8b304af9e01e87c9809dd531933209f33d5a07569de6656f0eec3513c69  crates/cerberus-engine/src/engine.rs
ece27639608bd5ba9142189f35713e06dfeedd86673424f6ea9df31aa8cd1e6a  crates/cerberus-engine/src/entropy.rs
4e59b374d91a4e10f9bf8df4372ccfa1370a87f9d69bce7a8fcdb28ee87dddb1  crates/cerberus-engine/src/validator.rs
07517d3cc773b57f440476b63ee0ca539acd23c9240998fe553071e01e7fe8d9  crates/cerberus-packs/src/default_pack.rs
67f6a5c1ef5d3f87d1799557250c92c43e8774cd5086d5b6a0de12058d6f213b  crates/cerberus-packs/tests/production_pack_pr.rs
be27568393409b4aa561ac68279b1a7af805bbe1f217dd4416e699afc6ac9786  tests/corpus/product-gate/manifest-v1.json
bcbf286a477fdba7c10128c02ff32b4440a6ffa1719bd54985bf56f062e3efdc  evidence/f1/raw/production_pack_pr.json
```

Attempt-3 local results were product gate 7/7; Clippy clean; engine 204; packs 75; ReDoS 8; load 8; proxy JSON 5; workspace 611/611; fmt and diff-check PASS. Its 44 TP / 0 FP / 0 FN report was later invalidated by the expanded panel findings recorded above.

## Integrator reproduction — repair attempt 4

Status: **SUPERSEDED — FAIL after independent panel (1 PASS / 2 FAIL verdicts)**, primary checkout, 2026-08-27.

Frozen artifact hashes:

```text
8563b8b304af9e01e87c9809dd531933209f33d5a07569de6656f0eec3513c69  crates/cerberus-engine/src/engine.rs
4c4d3efdf653794fcae93682adb2b829ac04b22ffeea56ad05a755b5e54e0307  crates/cerberus-engine/src/entropy.rs
c745d3d2290183a9ece1aab55a24a174ec8d0bea9f465fbb5aa579c42fc37ff5  crates/cerberus-engine/src/validator.rs
e67468bb7318d07090ba342aabe7d92021f3bf651c185325d660bcb6470b3fe0  crates/cerberus-packs/src/default_pack.rs
7ebd73b50057dcf16f024bf2fdd59957d8a9adc24977383b5f8d729722b72f65  crates/cerberus-packs/tests/production_pack_pr.rs
84ad0c3ef316b3d8f02c0634749774e5a75f987bffea8e4c0846dc7ef29ee3e7  tests/corpus/product-gate/manifest-v1.json
a72c7f13fe6f8b91f3b33cf89af89847372ff7155d4e502311fc902b6d768354  evidence/f1/raw/production_pack_pr.json
```

Attempt-4 results: product gate 9/9; focused and workspace Clippy clean; engine 205; packs 77; ReDoS 8; load 8; proxy JSON 5; workspace build PASS; workspace 614/614; fmt and diff-check PASS. The generated report has 43 TP / 0 FP / 0 FN, PII 20/0/0, secrets 23/0/0, all 15 flags evaluable and 100%.

Panel disposition (2026-08-27): correctness PASS / security FAIL / performance FAIL. Per fix-plan §0.7 the unit does not earn sign-off; the findings drove repair attempt 5 below. The hashes and metrics above are retained verbatim as attempt-4 history; they are NOT the current frozen set.

## Integrator reproduction — repair attempt 5

Status: **SUPERSEDED by repair attempt 6** — independent panel returned
correctness **PASS**, security **PASS**, performance **FAIL** (HIGH blocker:
the widened PAN separator classes cost 6.5–18 ms/100 KB vs the §5 budgets;
reports `evidence/review9/f12-attempt5-performance.md`,
`evidence/review9/f12-attempt5-correctness.md`,
`evidence/review9/f12-attempt5-security.md`). The original local status was:
**LOCAL PASS — fresh independent panel pending**, primary checkout, branch `docs/fix-install-commands`, base `HEAD fccd9e4` (uncommitted worktree), 2026-08-28.
Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, `cargo 1.97.1 (c980f4866 2026-06-30)`. Host: macOS/Darwin 25.5.0, arm64 (Apple M4 Pro).

Provenance: the attempt-5 builder session implemented the fixes in this
worktree and then wedged before writing this Evidence Pack. This section is an
integrator audit-and-complete: every on-disk change was inspected, a stale
doc-comment on `is_word_byte` in `constraints.rs` (semantic no-op) was
corrected, `cargo fmt` was applied to the new gate-test formatting, the full
battery was re-run from this tree, and the frozen hash set below was captured
from the resulting bytes.

### What changed (per finding)

1. **HIGH entropy window panic (security/perf blocker)** — `entropy.rs` now
   snaps the fixed 200-byte near-keyword window end down with a
   `while !text.is_char_boundary(search_end)` loop before slicing. Permanent
   regressions: the three panel PoCs (`é`, `€`, CJK) as unit tests in
   `entropy.rs`, a shipped-path version in `production_pack_pr.rs`
   (`high1_multibyte_entropy_window_does_not_panic_in_scan`), and an 8-keyword
   × 4-multibyte-filler × 21-length sweep in `redos_fuzz.rs`
   (`redos_fuzz_multibyte_entropy_window_straddle`). A boundary-snapping
   correctness probe confirms secrets inside the window are still found.
2. **HIGH quadratic per-match context normalization (perf blocker)** — new
   `ContextAnalyzer` (`constraints.rs`) lowercases (ASCII, byte-position
   preserving) and line-splits the context at most ONCE per scan; keyword→line
   bitsets are cached per distinct keyword set; keyword-free engines skip the
   normalization pass entirely (`any_context_keywords`). Release timing
   regression `phone_list_payload_scans_linearly_within_budget` (gate test) +
   permanent density probes `load_test_100kb_phone_list` and
   `redos_fuzz_keyword_dense_phone_list_linear` (50/100/200 KB linearity).
3. **MED IPv4/dotted versions flagged as phone** — the dotted context-free
   branch was restructured: only the exact 3-3-4 form `[0-9]{3}[ .-][0-9]{3}[ .-][0-9]{4}`
   keeps dots (all four IPv4 PoCs and `1.2.34.567` shapes are rejected; a
   3-3-4 dotted tail cannot be an IP octet sequence), while the multi-group
   space branch dropped dots. `212.555.0123` remains a phone. Test
   `ipv4_and_dotted_versions_are_not_phones` + corpus negatives.
4. **MED separated PANs evade card detection** — the card pattern separator
   class generalized to `(?:[ \u00a0]{1,3}|[./-])?` (dot, slash, NBSP, up to 3
   spaces). Dot/slash/NBSP/double-space Luhn-valid PANs are
   `pii.credit_card`, never downgraded (`not-payment-card` shares the exact
   `payment_card_valid` predicate). Tests
   `separated_pans_are_cards_never_phones` + positive corpus
   `tests/corpus/positives/07-separated-pans.txt` (manifest case
   `attempt5-separated-pans`) + ReDoS probe `redos_fuzz_separated_pan_classes`
   (200 KB separator fuzz).
5. **MED substring keywords + unbounded context** — `contextKeywords` now
   match case-insensitively at WORD BOUNDARIES (non-alphanumeric or string
   edge; underscore and punctuation delimit, so `api_key` still matches inside
   `OPENAI_API_KEY`) and, on the plain-text scan path, must share a LINE with
   the match (proximity window). The JSON leaf path (`scan_with_context`,
   offsets not in context) uses unbounded same-word-boundary matching.
   `hotel`/`megaphone`/`contactless`/`XE164foo` and the multi-line
   "phone list backup" PoC are permanent negatives (unit tests in
   `constraints.rs`, gate test
   `context_keywords_require_word_boundary_and_proximity`, corpus
   `tests/corpus/negatives/05-attempt5-adversarial.txt`);
   `phone 8005550199` / `PHONE 5551234567` / `tel 5551234567` /
   `E.164 882161234567890` still fire (recall preserved and asserted).
6. **LOW leading brackets + LOW adjacent keywords** — `{`, `(`, `[` added to
   entropy `SKIP_CHARS` so spans exclude opening delimiters symmetrically with
   the trailing-close trim; `extract_value` now cuts an embedded
   `<keyword>=`/`<keyword>:` prefix (only when the prefix is itself a keyword,
   so base64 padding like `...=` keeps its exact span), and duplicate spans
   from adjacent keywords are deduplicated per scan → `key token=<secret>`
   emits exactly ONE clean finding. Tests
   `low1_leading_brackets_are_not_part_of_the_secret_span`,
   `f1_adjacent_keywords_emit_one_clean_finding`,
   `value_with_embedded_equals_or_colon_keeps_exact_span` (entropy unit) and
   `adjacent_entropy_keywords_emit_one_clean_finding`,
   `entropy_span_leading_brackets_trimmed` (gate).
7. **INFO evidence mutation on failed gate runs** — the gate now validates the
   measured report in memory (`validate_product_report`) and writes
   `evidence/f1/raw/production_pack_pr.json` ONLY after every assertion path
   passes; failing runs write `target/production_pack_pr_FAILED.json` and
   leave the frozen artifact untouched.
8. **Pack identity** — `DEFAULT_PACK_VERSION` = `1.2.0`;
   `DEFAULT_PACK_IDENTITY` = `1.2.0@sha256:aa1c0d8d…fb8ff204`, bound to the
   exact embedded bytes and asserted by
   `exact_pack_identity_and_virtual_entropy_contract` (independently
   recomputed in Python: match). Corpus manifest updated to
   `cerberus-default-pack-pr-v2` with the attempt-5 positive/negative cases;
   all 15 flags remain evaluable.

Not changed (prohibited list, verified): recall 0.90 / precision 0.85
thresholds, exact-span accounting, FP exclusion absence (no decrement path),
allowedExample controls, unknown-validator build abort, PAN-vs-phone
precedence, and no `Regex::new` in any `scan*` hot path.

### Metrics

- Aggregate 49 TP / 0 FP / 0 FN; category `pii` 26/0/0; category `secrets` 23/0/0; **all 15 flags evaluable, every flag recall = precision = 100%** (entropy 8, phone 12, credit-card 8, email 6, PEM 4, OpenAI 2, and Anthropic/AWS/Bearer/GitHub/Google/Slack/Stripe/env_block/id_rsa 1 each). 14 corpus cases; all 6 negative cases produce exactly 0 findings.
- 100 KB phone-list release scan (attempt 4 → attempt 5): reject-path p50 **194.8 ms → 1.995 ms** (p99 2.089 ms, within the §5 3–5 ms budget); all-fire worst case (≈12.6k genuine findings, emission-dominated) p50 4.552 ms / p99 4.980 ms; `load_test_100kb_phone_list` p99 6.514 ms under its 15 ms CI guard. Quadratic behavior eliminated (200 KB keyword-dense stays < 250 ms fuzz bound; growth is linear).
- Release standard load battery p99: 1 KB 0.005 ms · 10 KB 0.089 ms · 50 KB+secrets 0.353 ms · 100 KB clean 0.421 ms · decode+scan 0.321 ms · scan+redact 0.275 ms.

### Frozen SHA-256 (attempt 5)

```text
3b7e714492b39a8836250c60586df2eef139efbe24ebe3ed0a38c6a5b7055b74  crates/cerberus-engine/src/engine.rs
64d8df28c221ac392bae4556cdd69bf9e5b03f7cf24d99c411c20d48ce0916b3  crates/cerberus-engine/src/entropy.rs
c745d3d2290183a9ece1aab55a24a174ec8d0bea9f465fbb5aa579c42fc37ff5  crates/cerberus-engine/src/validator.rs
5f23d304082b93ca4c8a72f496de29f9e66cc81422b63edbfb57ed6e198a9b9b  crates/cerberus-engine/src/constraints.rs
8d7032a0e2f2a7a708fa9ab9a74b47ae45c024feb346d5a9e7667bc118f398d5  crates/cerberus-packs/src/default_pack.rs
f92a113d6e652c77a7c8b4a4552a1a14a6147f51d82650e85e1cc3da88712363  crates/cerberus-packs/tests/production_pack_pr.rs
0a66b7edabe1671e4fc618ddfe6236f149c13d350d2e64d0a6fb9071d630d5f7  tests/corpus/product-gate/manifest-v1.json
c780fb52966ce63df28c3a16765503f309fd19ef4ae21435702e270f3184527e  tests/corpus/negatives/05-attempt5-adversarial.txt
e87d5a6847399e577024db68f8696c8ed31a1d04867c3078ebe16659a9292bfd  tests/corpus/positives/07-separated-pans.txt
0fc5d7db3111a527db48334ba61cc890e4d385bc40454a25b4c225712364e679  evidence/f1/raw/production_pack_pr.json
```

The raw report hash was verified stable: re-running the gate test reproduces
`0fc5d7db…e679` byte-identically. `validator.rs` is unchanged from attempt 4.
Identity emitted by the gate run: pack_version 1.2.0, 15 rules,
pack sha256:aa1c0d8d54e22f52fecb4c9912c420d718a6612edeac5badce00979bfb8ff204,
corpus_version cerberus-default-pack-pr-v2, manifest sha256:0a66b7ed…,
composed corpus sha256:1905129adc45979ca6e678261ca6463fc4377bc1f7c0c153d4c6a0478fcf3bb3.

### Commands and output (all from this worktree, 2026-08-28)

```text
$ cargo fmt --all -- --check                                   exit 0 (after integrator cargo fmt on gate-test formatting)
$ git diff --check                                             exit 0
$ cargo clippy -p cerberus-engine -p cerberus-packs --all-targets -- -D warnings
                                                               Finished, no issues
$ cargo test -p cerberus-engine                                218 passed; 0 failed (198 lib + 15 + 5)
$ cargo test -p cerberus-packs                                 84 passed; 0 failed (68 lib + 16 product gate)
$ cargo test -p cerberus-packs --test production_pack_pr -- --nocapture
                                                               16 passed; 0 failed
$ cargo test --test redos_fuzz                                 11 passed; 0 failed
$ cargo test --test load_test                                  9 passed; 0 failed
$ cargo test --workspace --all-targets                         638 passed; 0 failed; 25 suites (attempt 4: 614)
$ cargo test --release --workspace --all-targets               638 passed; 0 failed; 25 suites
$ cargo test --release -p cerberus-packs --test production_pack_pr -- --nocapture
                                                               16 passed; timing lines above
$ cargo test --release --test load_test -- --nocapture         9 passed; p99 values above
```

## Repair attempt 6

Status: **SUPERSEDED — FAIL after independent security panel (correctness PASS / performance PASS / security FAIL: SEC-1 Medium, SEC-2 Low)**, primary checkout, branch `docs/fix-install-commands`, base `HEAD fccd9e4` (uncommitted worktree), 2026-08-28.
Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, `cargo 1.97.1 (c980f4866 2026-06-30)`. Host: macOS/Darwin 25.5.1 (build 25F80), arm64 (Apple M4 Pro).

Provenance: the attempt-6 Codex builder session implemented the shipped
`BOUNDED_PAYMENT_CARD_PATTERN` pack change and the specialized byte-linear
PAN matcher in `engine.rs`, added the detection-gap tests/corpus case and the
load guards, then died (provider credits) with `cargo clippy --all-targets
-D warnings` **failing** and its release `load_test` guards **failing**
(mixed-dense 100 KB p99 1.71 ms vs the 1 ms budget it asserted). This session
completed and repaired the work: fixed the 3 clippy blockers (refactor +
`match_same_arms`), made the timing-suite mutex poisoning non-cascading,
re-optimized the matcher and the card validators (below), added a permanent
differential-fuzz equivalence test that caught a real bug during that
optimization, verified every claim by measurement, and re-ran the full battery
from the final bytes.

### Disposition per attempt-5 performance-panel finding

1. **HIGH blocker 3 (widened PAN separator classes, 6.5–18 ms/100 KB)** —
   CLOSED by measurement. The shipped separated-PAN pattern is now
   `(?:\+[0-9](?:(?:[ \u00a0]{1,3}|[./-])?[0-9]){12,18}\b|\b[0-9](?:(?:[ \u00a0]{1,3}|[./-])?[0-9]){12,18}\b)`
   (bounded `{12,18}` + word anchors); the scan path does not run its Unicode
   NFA at all. `engine.rs` routes that exact pattern to
   `payment_card_candidate_ranges`, a byte-linear specialized matcher that is
   semantically equivalent to the previous materializing implementation
   (locked by the differential test in item 7) and partitions a
   separator-connected digit run into complete issuer-valid PAN segments.
   The previous session's claim of 0.64–0.66 ms/100 KB was **verified**: the
   mixed-separator-dense 100 KB payload measures p50 0.63 / p99 0.67–0.75 ms
   (release, isolated probe + serial guard). Repairs made in THIS session
   (the dead session's guard was failing):
   - matcher re-architected to a single pass that records only recognized
     separators (`SepRun`: inline ≤ 16 separators, spill `Vec` whose capacity
     persists across runs of one scan) instead of three per-digit vectors —
     short runs (phone lists, clean text) now do zero heap work, and the
     adversarial giant runs materialize 32 bytes/separator instead of
     ~17 bytes/digit;
   - `validator.rs`: `payment_card_valid`/`luhn_valid` are allocation-free
     (`pan_digits` stack buffer + `luhn_sum_ok`), removing a `Vec<u32>` +
     `String` + 4 `parse()` per REJECTED candidate (~10k allocations/scan on
     the mixed-dense payload). Boolean semantics unchanged — every
     attempt-5 validator unit/gate test passes untouched.
   Effect: attempt-5 blockers → attempt-6 measured (release, ms):
   mixed-dense 50 KB p50 6.479→0.32, p99 6.888→0.37; mixed-dense 100 KB p50
   13.445→0.63, p99 14.073→0.69; NBSP-only 100 KB p50 16.954→0.63, p99
   18.073→0.79. Linear, no NFA/PikeVM path for the card rule, no `Regex::new`
   on the scan path (the bounded pattern is compiled once at build time for
   well-formedness only).
2. **Detection gap (`4000.0566.5566.5556 4111111111111111` on one line → 0 card findings)** —
   CLOSED. Both PANs are detected with exact spans (0..19 and 20..36).
   Permanent coverage: gate assertion inside
   `separated_pans_are_cards_never_phones` (`production_pack_pr.rs`), corpus
   line "Batch 4000.0566.5566.5556 4111111111111111 done" in
   `tests/corpus/positives/07-separated-pans.txt` with both cards declared in
   the manifest case `attempt5-separated-pans`, and a dense 100 KB repetition
   in the timing table below (5389 genuine findings, emission-dominated,
   p50 2.46 ms — same product-work class the attempt-5 panel accepted for
   the 7314-finding all-fire list).
3. **MEDIUM multibyte prose (4.7–5.0 ms p99/100 KB)** — RESOLVED by
   reduction; **no owner waiver needed**. The build-time-compiled
   `EntropyDetector` with its Aho-Corasick keyword prefilter (F1.1
   precompilation, engine-owned instance instead of per-scan static lookups)
   plus the `(?-u)` byte-class phone patterns dropped the zero-finding
   multibyte prose payload (`café € 密🎉 naïve ключ`) to p50 0.38 / p99
   0.44–0.72 ms per 100 KB — at/below the 1 ms scan target, ≈11× better than
   the attempt-5 measurement. F1.3 will re-measure on its own harness; the
   attempt-5 reviewer's waiver path is moot.
4. **Permanent load guards at plan budgets** — delivered as
   `load_test_attempt6_pan_path_plan_budgets` (mixed-separator-dense 50/100 KB,
   NBSP-only 100 KB, two-PAN-one-line), with the exact payload shapes asserted
   finding-free (Luhn near-misses) / two-card respectively. Statistics per
   the plan wording: the §5 "scan ~100 KB < 1 ms" line is an *engine
   micro-benchmark target*, so release asserts **p50 < plan budget strictly**
   and **p99 < 2× plan budget** under a documented CI-contention tolerance
   (constant comment in `tests/load_test.rs`; observed contention inflation
   0.74 ms serial → 1.10 ms parallel on the NBSP class — both far under 2×;
   the attempt-5 blocker class fails either statistic ≈7–13×). Debug profile
   keeps the pre-existing 30 ms pathology ceiling. The separate looser
   CI bound (15 ms `P99_BUDGET_MS`) is unchanged for the all-fire-shape tests.
5. **Evidence typo** — FIXED: attempt-5 Metrics line now reads "all 6 negative
   cases" (there are exactly 6 negative corpus cases).
6. **Prohibited list** — untouched and verified: `MIN_RECALL = 0.90` /
   `MIN_PRECISION = 0.85` (`production_pack_pr.rs:20–21`); exact-span
   accounting and FP exclusion rules unchanged; allowlist (`allowedExamples`)
   controls unchanged; unknown validator names still abort `build()`
   (`build_with_unknown_validator_fails_closed_visibly`); PAN-vs-phone
   precedence intact (phone rules keep `not-payment-card`, sharing the exact
   `payment_card_valid` predicate the matcher calls); IPv4 guard and
   word-boundary context tests pass unchanged; no `Regex::new` in
   `scan_inner`/`make_finding`/`ContextAnalyzer` (all construction-time:
   `CompiledEngine::compile`, `EntropyDetector::compile`, `OnceLock` helper
   off the engine path). Pack patterns DID change ⇒ `DEFAULT_PACK_VERSION`
   bumped `1.2.0`→`1.2.1` with identity binding intact:
   `DEFAULT_PACK_IDENTITY = "1.2.1@sha256:f67a67b692…0132296f"`, recomputed
   and asserted by `exact_pack_identity_and_virtual_entropy_contract`.
   Corpus manifest composition still hashes/validates (v3, below).
7. **Refactor-risk guard (new, this session)** —
   `pan_candidate_ranges_match_reference_implementation_on_random_inputs`
   (engine lib test) embeds the attempt-6 original materializing algorithm as
   an oracle and requires identical emitted ranges on 5,000 deterministic
   structured-random inputs and 5,000 fragment-composed PAN-shaped strings
   (10,000 total; the correctness panel's LOW-1 prose fix — the frozen code
   runs `0..5000` twice over a 12-element adversarial alphabet including
   NBSP, `+`, separators; attempt 7 additionally added `½`/combining-mark
   fragments without changing the trial counts). This
   test caught a real cumulative-position bug mid-optimization
   (`"5500 0000 0000 0004 "` was missed by the intermediate rewrite), proving
   the differential approach is load-bearing, not decorative.
8. **Timing-suite robustness (this session)** — the attempt-6 `perf_lock()`
   used `.expect()`, so one failed p99 assertion poisoned the mutex and
   cascade-failed every other timing test in the binary; it now recovers from
   poisoning so each measurement stays independent.

### Metrics

- Aggregate 52 TP / 0 FP / 0 FN; category `pii` 29/0/0; category `secrets`
  23/0/0; **all 15 flags evaluable, every flag recall = precision = 100%**
  (entropy 8, phone 12, credit-card 11, email 6, PEM 4, OpenAI 2, and
  Anthropic/AWS/Bearer/GitHub/Google/Slack/Stripe/env_block/id_rsa 1 each).
  14 corpus cases (8 positive + 6 negative); all 6 negative cases produce
  exactly 0 findings.
- Identity emitted by the gate: pack_version **1.2.1**, **15 rules**,
  pack `sha256:f67a67b692afb8a3310e8528602f0e3bd20e90b1e75e07fd3be032450132296f`,
  corpus_version `cerberus-default-pack-pr-v3`, manifest
  `sha256:68677e07bf4317dc9e496e7fdc9088a725b897a75ecd3ac154e16adbfb305b59`,
  composed corpus `sha256:984dd33e1992e22c737288af55a9f2fb21fda96724febbc8b561a266ead6d2d2`.
- Raw report `evidence/f1/raw/production_pack_pr.json` regenerated
  byte-identically `00763c18bb00d8f6299aa1eef061f4f9dea2c75449154c85c48c5bbdf1f1c32a`
  across debug and release gate runs.

### Release timing table

Isolated probe (200 samples, 20 warmup, nearest-rank, `--release`, full
shipped pack, serial process; probe source kept in the repo temp dir
`f12-perf6-probe`), ms:

```text
scenario                        size    findings  p50     p95     p99     max
clean ASCII 100 KB              102400  0         0.473   0.500   0.524   0.559
phone-list reject 100 KB        102406  0         2.073   2.175   2.229   2.459
phone-list all-fire 100 KB      102400  7314      4.131   4.349   5.315   7.624
mixed-PAN dense 50 KB           51200   0         0.317   0.338   0.368   0.448
mixed-PAN dense 100 KB          102400  0         0.633   0.659   0.691   0.726
NBSP-only 100 KB ("4\u{a0}")   102400  0         0.625   0.725   0.788   0.811
two-PAN one line (40 B literal) 36      2         0.001   —       0.002   —      (load guard)
two-PAN dense 100 KB            102400  5389      2.462   2.560   2.615   2.677
multibyte prose 100 KB          102399  0         0.376   0.397   0.465   0.471
```

Gate + guard release emissions (final battery): `100KB phone-list reject-path
p50 2.101 / p99 2.251–2.411`, `all-fire p50 4.19–4.23 / p99 4.41–6.58`
(single-run OS outliers in the p99 column only; the gate asserts p50 < 5/8 ms
per the attempt-5 fix-plan shape); plan-budget guard: `mixed_50kb p50 0.317 /
p99 0.339–0.495 (budget 5)`, `mixed_100kb p50 0.631 / p99 0.671–0.750 (budget
1, 2× tolerance 2)`, `nbsp_100kb p50 0.625 / p99 0.743–0.867 (budget 1)`,
`two_pan_one_line p50 0.001 / p99 0.001–0.002 (budget 5)`. Standard CI-guard
battery release: 1 KB 0.006 · 10 KB 0.068 · 50 KB+secrets 0.368 · 100 KB clean
0.549–1.858 · 100 KB phone-list 4.240–4.419 (15 ms guard; attempt 5 recorded
6.514) · decode+scan 0.250 · scan+redact 0.231 ms p99.

### Frozen SHA-256 (attempt 6)

```text
b4b874d46ba5f0f4f1c865e48a58b295643f8f83b4e31e8167f9493ebac89a9d  crates/cerberus-engine/src/engine.rs
265bb24eb1547c4ed245b7f838360f3f5f377098573a3eb57d491e4ca06042ef  crates/cerberus-engine/src/entropy.rs
390f50a334e613b96a8ab3ee578a6c940fce475de3703e8bb86a5d4043b5f116  crates/cerberus-engine/src/validator.rs
5f23d304082b93ca4c8a72f496de29f9e66cc81422b63edbfb57ed6e198a9b9b  crates/cerberus-engine/src/constraints.rs
f902f3e32dd12e2d1ea3e561ef9a8d2ab33357c424564013c361801bce078858  crates/cerberus-packs/src/default_pack.rs
ed04a2b71152acbd72452d8a8745b04fc10d0414b8ae1b957e0234ee0afb23f3  crates/cerberus-packs/tests/production_pack_pr.rs
68677e07bf4317dc9e496e7fdc9088a725b897a75ecd3ac154e16adbfb305b59  tests/corpus/product-gate/manifest-v1.json
c780fb52966ce63df28c3a16765503f309fd19ef4ae21435702e270f3184527e  tests/corpus/negatives/05-attempt5-adversarial.txt
d3bdf3903d82c04e730ec99ea56e60fe55236446b593bc2b9065de0e1f5c36de  tests/corpus/positives/07-separated-pans.txt
6361e648d822eef1f35de0a79d5edeb11174a5d7811121dbbdb102db27e37759  tests/load_test.rs
00763c18bb00d8f6299aa1eef061f4f9dea2c75449154c85c48c5bbdf1f1c32a  evidence/f1/raw/production_pack_pr.json
```

Unchanged from the attempt-5 frozen set: `constraints.rs`, `05-attempt5-adversarial.txt`.

### Commands and output (all from this worktree, 2026-08-28, final bytes)

```text
$ cargo fmt --all -- --check                                   exit 0
$ git diff --check                                             exit 0
$ cargo clippy -p cerberus-engine -p cerberus-packs --all-targets -- -D warnings
                                                               Finished, no issues (exit 0; whole-workspace clippy also exit 0)
$ cargo test -p cerberus-engine                                219 passed; 0 failed (199 lib + 15 integration + 5 unit-feature)
$ cargo test -p cerberus-packs                                 84 passed; 0 failed (68 lib + 16 product gate)
$ cargo test -p cerberus-packs --test production_pack_pr -- --nocapture
                                                               16 passed; 0 failed (debug)
$ cargo test --release -p cerberus-packs --test production_pack_pr -- --nocapture
                                                               16 passed; 0 failed; timing lines above
$ cargo test --test redos_fuzz                                 11 passed; 0 failed
$ cargo test --release --test redos_fuzz                       11 passed; 0 failed
$ cargo test --test load_test                                  10 passed; 0 failed (debug, 30ms pathology ceiling)
$ cargo test --release --test load_test -- --test-threads=1 --nocapture
                                                               10 passed; 0 failed; plan budgets above
$ cargo test --release --test load_test -- --nocapture         10 passed; 0 failed (parallel)
$ cargo test --workspace --all-targets                         640 passed; 0 failed; 25 suites
$ cargo test --release --workspace --all-targets               640 passed; 0 failed; 25 suites
```

## Repair attempt 7

Status: **LOCAL PASS — fresh independent panel pending**, primary checkout, branch `docs/fix-install-commands`, base `HEAD fccd9e4` (uncommitted attempt-6 worktree, no commit), 2026-08-28.
Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, `cargo 1.97.1 (c980f4866 2026-06-30)`. Host: macOS/Darwin 26.5.1, arm64 (Apple M4 Pro).

Scope: ONLY the attempt-6 security-panel findings (SEC-1 Medium, SEC-2 Low)
plus the correctness-panel LOW-1 evidence-prose fix. Every attempt-5/6
blessed security-correctness semantics (IPv4 guard, word-boundary context,
two-PAN line recovery, overlong rejection, never-downgrade precedence,
char-boundary entropy snapping, thresholds 0.90/0.85, exact spans, no FP
exclusion, unknown-validator abort, report-after-assertion, pack identity
binding, F1.1 invariant) and every attempt-6 perf win are preserved and
re-measured below.

### Disposition per finding

1. **SEC-1 (Medium) — mixed separator styles inside one PAN suppressed**
   → **FIXED per reviewer direction.** `partition_payment_card_run`
   (engine.rs) no longer splits a run at every separator-KIND change: a kind
   change now splits only when BOTH sides are independently PAN-complete
   (13–19 digits before, ≥ 13 after) — `both_sides_complete &&
   (last_separator.is_none() || separator_changed)` — extending the
   `separates_two_unformatted_runs` condition with the kind-change test.
   A kind change INSIDE one PAN now has an incomplete side, keeps the run
   intact, and the whole mixed-style PAN validates via the unchanged
   allocation-free `payment_card_valid`. The first-separator-of-segment
   two-PAN recovery is byte-for-byte unchanged, so attempt-6 stays strictly
   better than attempt 5 (19-digit-prefix recovery, dot-chained PANs,
   two-PAN lines all preserved and re-tested). The three panel PoCs now
   emit exactly the regex-path spans: `pay 4111 1111-1111.1111` →
   `pii.credit_card @ 4..23`, `pay 4000.0566-5566 5556` → `4..23`,
   `pay 4111\u{a0} 1111 1111\u{a0}1111` → `4..26` (previously all 0).
   Permanent coverage: gate test `mixed_separator_style_pans_are_detected_whole`
   (PoCs + exact spans + never-phone + kind-change two-PAN recovery
   `4111-1111-1111-1111 4000.0566.5566.5556` → `(0,19),(20,39)` and
   `4111 1111-1111.1111 4111111111111111` → `(0,19),(20,36)`), engine unit
   tests (`mixed_separator_styles_within_one_pan_are_detected`,
   `kind_change_splits_only_between_complete_pans`), and six corpus lines in
   `tests/corpus/positives/07-separated-pans.txt` (manifest case
   `attempt5-separated-pans`, +6 declared card instances).
   Documented consequence (fail-closed, attempt-5-consistent): a >19-digit
   mixed run ending in a complete PAN + separator + short tail
   (`4111 1111-1111.1111 1111`, `4111-1111-1111-1111.4111`) now yields
   **0** findings — attempt-6's unconditional kind-change split could emit
   the valid prefix from such runs (never panel-verified, outside the
   blessed set); attempt-5's blessed regex found 0 there too. The plain
   bounded regex path still recovers that prefix — divergence permanently
   documented and asserted both ways in
   `pan_matcher_agrees_with_plain_regex_path_on_blessed_shapes`.
2. **SEC-2 (Low) — No-category chars adjacent to a PAN suppress it**
   → **FIXED.** The matcher's `\b` emulation now uses `regex_word_char`
   (engine.rs), the regex crate's exact `\w` class (`Alphabetic` ∪ `M` ∪
   `Nd` ∪ `Pc` ∪ `Join_Control`): ASCII resolves on a table-free fast path;
   non-ASCII consults a build-once (`OnceLock`) `\w` probe so the matcher
   shares the regex crate's Unicode tables exactly (same tables the bounded
   pattern compiles against — one process-wide lazy compile, zero per-scan
   regex construction, F1.1 invariant intact: 3 allocs/scan on clean 100 KB
   re-verified by the probe). `char::is_alphanumeric()`'s extra No/Nl
   classes (`½` U+00BD, `²` U+00B2, circled digits) no longer count as word
   chars, so `4111111111111111\u{00bd}` → `0..16`,
   `\u{00bd}4111111111111111` → `2..18`, `4111111111111111\u{00b2}` →
   `0..16` (previously all suppressed). The inverse (FP-direction)
   divergence is aligned too, as permitted: combining mark U+0301 and ZWJ
   U+200D ARE `\w`, so a PAN glued to them now fails `\b` in matcher and
   regex alike (both 0 findings; previously matcher found / regex did not).
   Permanent coverage: gate test
   `pan_boundary_class_matches_regex_word_semantics` (R12–R14 exact spans +
   never-phone + R15/R16 alignment) and engine unit tests
   (`regex_word_char_matches_regex_w_class` including Ⅻ/Nl ⊂ Alphabetic and
   ①/No ∉ `\w`, `no_category_boundary_chars_match_regex_word_class`).
   The reference-oracle fuzz mirrors the same predicate and its fragment
   pool gained `½` and U+0301 fragments (trial counts unchanged 5,000+5,000).
3. **Correctness-panel LOW-1 — differential-fuzz evidence prose**
   → **FIXED (prose, as preferred).** r9 item 7 now reads 5,000+5,000
   trials (10,000 total) over a 12-element alphabet, matching the frozen
   code; the attempt-7 fragment-pool extension is noted there without
   changing the claim. Review reports (`f12-attempt6-*.md`) untouched.
4. **SEC-3 (Low, pre-existing AC-prefilter mojibake)** — unchanged,
   pre-existing since fccd9e4, shipped pack unaffected; backlog per panel.

### Load-guard honesty adjustment (documented, with A/B evidence)

`assert_plan_budgets`'s DEBUG branch now asserts the pathology ceiling on
**p50** and only logs p99. The p99-of-200 debug statistic spikes on
allocator/OS tail noise alone: with the attempt-7 engine changes
temporarily reverted (A/B on this host, 2026-08-28), attempt-6 code itself
measured mixed-dense 100 KB debug p50 16.140 / p99 48.513 ms against the
30 ms debug ceiling — the guard as written fails a fresh attempt-6
reproduction today (the attempt-6 "10/10 debug" battery ran under lighter
host conditions). The guard's purpose is untouched: the attempt-5 blocker
class (release 6.5–18 ms/100 KB) measures ≈100–300 ms debug p50 and fails
the ceiling ≈7–10× over; the release gate still asserts p50 < plan budget
strictly and p99 < 2× plan budget. This corrects the same flake class the
correctness panel documented as LOW-2 for the release 15 ms CI guard.

### Performance re-measurement (release; item 4)

Permanent plan-budget guards (`load_test_attempt6_pan_path_plan_budgets`,
serial, 200 samples, release): mixed-separator-dense 50 KB p50 0.295 /
p99 0.362 ms (budget 5); mixed-dense 100 KB p50 0.587 / p99 0.633 ms
(budget 1); NBSP-only 100 KB p50 0.615 / p99 0.748 ms (budget 1);
two-PAN-one-line 0.001 / 0.001 ms — every §5 budget holds with ≥ 36%
margin, marginally FASTER than attempt-6's recorded 0.631–0.633 / 0.671–0.750
(the SEC-1 fix removes most kind-change splits on the dense payload).

New permanent guard `load_test_attempt7_mixed_pan_recovery_budgets`: the
previously-suppressed class now emits — dense mixed-style two-PAN 100 KB
produces 5,536 card findings (2,768 units × 2), p50 2.586 / p99 2.791 ms
against the 8 ms emission-class budget (same product-work class the panels
accepted for two-PAN dense 2.46 ms/5,389 and phone all-fire 4.1 ms/7,314);
never-phone asserted.

Isolated probe (`--release`, 20 warmup, 200 samples, nearest-rank; full
shipped pack; probe crate outside the repo, `f12a7-probe`), ms:

```text
scenario                              size   findings  p50     p95     p99     max
multibyte prose 100 KB                102408 0         0.379   0.448   0.840   0.915
cjk+PAN boundary stress 100 KB *      102414 0         0.700   0.739   0.782   0.815
mixed-PAN dense (finding-free) 100 KB 102426 0         0.595   0.635   0.669   0.683
NBSP-only 100 KB                      102402 0         0.700   0.747   0.774   0.828
two-PAN dense 100 KB                  102416 5536      2.414   2.521   2.534   2.557
half-glued PAN dense 100 KB *         102410 5390      2.317   2.424   2.507   2.763
```

`*` new attempt-7 stress shapes: `密钥4111 1111-1111.1111 ` (every PAN run
start takes the non-ASCII `\w` lookbehind probe — 0 findings is correct:
the PAN is glued to a word char so `\b` fails, regex parity) and
`4111111111111111½ ` (every PAN end takes the non-ASCII probe and emits).
Worst-case non-ASCII boundary cost ≈ +0.32 ms/100 KB over plain prose —
the SEC-2 predicate stays inside the 1 ms/100 KB §5 target even when every
run boundary is non-ASCII. Multibyte prose reproduces attempt-6's
0.376–0.38 ms p50. Standard load battery (release p99): 1 KB 0.006 ·
10 KB 0.070 · 50 KB+secrets 0.377 · 100 KB clean 0.641 · phone-list 4.591 ·
decode+scan 0.265 · scan+redact 0.368 ms.

### Metrics

- Aggregate **58 TP / 0 FP / 0 FN**; category `pii` 35/0/0; category
  `secrets` 23/0/0; **all 15 flags evaluable, every flag recall = precision
  = 100%** (credit-card 17 (+6 attempt-7 corpus instances), phone 12,
  entropy 8, email 6, PEM 4, OpenAI 2, remaining 9 flags 1 each). 14 corpus
  cases (8 positive + 6 negative); all 6 negative cases produce exactly
  0 findings. Thresholds untouched (`MIN_RECALL 0.90`, `MIN_PRECISION 0.85`);
  exact-span accounting and no-FP-exclusion unchanged.
- Identity emitted by the gate: pack_version **1.2.2** (bumped: the shipped
  matcher semantics changed; pack bytes and rule count unchanged),
  **15 rules**, pack `sha256:f67a67b692afb8a3310e8528602f0e3bd20e90b1e75e07fd3be032450132296f`
  (byte-identical pack), corpus_version `cerberus-default-pack-pr-v4`
  (bumped for the extended separated-PAN fixture), manifest
  `sha256:ddbc3b2da5943dba3fa5f348d3d5245120a35337108cc853d426d5149dad122a`,
  composed corpus `sha256:59a9f37c20e83fae0ad39f21b9907648e97667846bb680bf1c039088680ba28d`.
- Raw report `evidence/f1/raw/production_pack_pr.json` regenerated
  byte-identically `b7effa21a34c740eb305861c6bf01eb5db4a9e8b00e5e2e041ca9e6804188fee`
  across debug and release gate runs (report-after-assertion invariant held;
  the attempt-6 hash `00763c18…c32a` is superseded — report content changed
  with pack version/corpus v4).

### Frozen SHA-256 (attempt 7)

```text
4c99ae8567c1d18e111cc5c2fac084a9ae68b6091ede83a63eb6d53579224253  crates/cerberus-engine/src/engine.rs
265bb24eb1547c4ed245b7f838360f3f5f377098573a3eb57d491e4ca06042ef  crates/cerberus-engine/src/entropy.rs
390f50a334e613b96a8ab3ee578a6c940fce475de3703e8bb86a5d4043b5f116  crates/cerberus-engine/src/validator.rs
5f23d304082b93ca4c8a72f496de29f9e66cc81422b63edbfb57ed6e198a9b9b  crates/cerberus-engine/src/constraints.rs
29373725eb7558881c08adb9dd26f68c0d2aa3ac363e70375bc70bfee99a7b6e  crates/cerberus-packs/src/default_pack.rs
33dfae2ab4e50c9568ef5ff0b4fe65bb4ce0186d45a875f17dcf78f1bb40f44b  crates/cerberus-packs/tests/production_pack_pr.rs
ddbc3b2da5943dba3fa5f348d3d5245120a35337108cc853d426d5149dad122a  tests/corpus/product-gate/manifest-v1.json
c780fb52966ce63df28c3a16765503f309fd19ef4ae21435702e270f3184527e  tests/corpus/negatives/05-attempt5-adversarial.txt
62b392e817371bf4971ae17a0b416e9aa818a3f663dc49dbed982352b0787e9a  tests/corpus/positives/07-separated-pans.txt
7ac0663d711bf19d2f0f578a89f29dfe4af4ab83907c970566d2134309538e7c  tests/load_test.rs
b7effa21a34c740eb305861c6bf01eb5db4a9e8b00e5e2e041ca9e6804188fee  evidence/f1/raw/production_pack_pr.json
```

Unchanged from the attempt-6 frozen set: `entropy.rs`, `validator.rs`,
`constraints.rs`, `05-attempt5-adversarial.txt`.

### Commands and output (all from this worktree, 2026-08-28, final bytes)

```text
$ cargo fmt --all -- --check                                   exit 0
$ git diff --check                                             exit 0
$ cargo clippy -p cerberus-engine -p cerberus-packs --all-targets -- -D warnings
                                                               Finished, no issues
$ cargo clippy --workspace --all-targets -- -D warnings        Finished, no issues
$ cargo test -p cerberus-engine                                223 passed; 0 failed (203 lib + 15 integration + 5 unit-feature)
$ cargo test -p cerberus-packs                                 87 passed; 0 failed (68 lib + 19 product gate)
$ cargo test -p cerberus-packs --test production_pack_pr -- --nocapture
                                                               19 passed; 0 failed (debug); report b7effa21…
$ cargo test --release -p cerberus-packs --test production_pack_pr -- --nocapture
                                                               19 passed; 0 failed; reject-path p50 2.031 / p99 2.434; all-fire p50 4.178 / p99 4.483
$ cargo test --test redos_fuzz                                 11 passed; 0 failed
$ cargo test --release --test redos_fuzz                       11 passed; 0 failed
$ cargo test --test load_test                                  11 passed; 0 failed (debug, p50 pathology ceiling)
$ cargo test --release --test load_test -- --test-threads=1 --nocapture
                                                               11 passed; 0 failed; plan budgets and timings above
$ cargo test --release --test load_test                        11 passed; 0 failed (parallel)
$ cargo test --workspace --all-targets                         648 passed; 0 failed; 25 suites (attempt 6: 640)
$ cargo test --release --workspace --all-targets               648 passed; 0 failed; 25 suites
```



## Independent review

Attempt 1: **FAIL** — one critical, three high and one medium finding.

Attempt 2 expanded review: **FAIL** — contextless secret bypass, phone/card ambiguity and regression, unknown-validator acceptance, and entropy separator/span issues.

Repair attempt 3 correctness/security/performance panel: **FAIL** — issuer/length ambiguity, separated/plus-prefixed card evasions, partial phone matching and canonical AWS fixture handling.

Repair attempt 4 correctness/security/performance panel: **FAIL overall**
(2026-08-27) — correctness **PASS** (2 LOW + 3 INFO non-blocking); security
**FAIL** (HIGH entropy non-char-boundary window panic with remote DoS PoCs,
MED IPv4-as-phone, MED separated-PAN evasion, MED substring/unbounded context
keywords, 3 LOW); performance **FAIL** (CRITICAL the same entropy window
panic-DoS; HIGH quadratic per-match full-context `to_lowercase` — 50 KB phone
list p50 41.7 ms, 100 KB 194.8 ms vs the §5 3–5 ms budget). Reports:
`evidence/review9/f12-attempt4-correctness.md`,
`evidence/review9/f12-attempt4-security.md`,
`evidence/review9/f12-attempt4-performance.md`.

Repair attempt 5 correctness/security/performance panel (2026-08-28):
correctness **PASS** (one INFO — the evidence "7 negative cases" prose
discrepancy, fixed in attempt 6), security **PASS** (4 LOW/informational, all
fail-safe), performance **FAIL** (HIGH blocker 3: the widened PAN separator
classes cost 6.5–18 ms/100 KB vs the §5 budgets; MEDIUM: multibyte prose
4.7–5.0 ms p99/100 KB; cross-posted detection gap: two PANs on one line
yielded zero card findings). Reports:
`evidence/review9/f12-attempt5-correctness.md`,
`evidence/review9/f12-attempt5-security.md`,
`evidence/review9/f12-attempt5-performance.md`. The verdict drove repair
attempt 6 above; attempt 5 is marked SUPERSEDED.

Repair attempt 6 correctness/security/performance panel (2026-08-28):
correctness **PASS** (2 LOW + 3 INFO; LOW-1 evidence-prose inaccuracy fixed in
attempt 7), performance **PASS** (both attempt-5 blockers verified fixed
12–22×, linear scaling, no ReDoS), security **FAIL** (SEC-1 Medium: mixed
separator styles inside one PAN are suppressed by the specialized matcher;
SEC-2 Low: No-category Unicode chars adjacent to a PAN suppress it; SEC-3
Low pre-existing AC-prefilter mojibake, backlog). Reports:
`evidence/review9/f12-attempt6-correctness.md`,
`evidence/review9/f12-attempt6-performance.md`,
`evidence/review9/f12-attempt6-security.md`. The verdict drove repair
attempt 7 below; attempt 6 is marked SUPERSEDED.

## Limits and next gate

- This is F1.2 detection correctness evidence, not the F1.3 throughput gate or the F3 HTTP latency gate.
- The corpus is deliberately finite; version/hash reporting makes future changes reviewable but does not claim universal detection quality.
- Builder PASS cannot close F1.2. A fresh independent reviewer must inspect the matching/accounting semantics, reproduce the report, verify the exact pack identity, and check the corpus changes for test-teaching before integrator sign-off.
