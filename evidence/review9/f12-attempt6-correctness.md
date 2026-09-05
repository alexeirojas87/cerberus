# F1.2 repair attempt 6 — independent review-only correctness audit

- Verdict: **PASS** — no blocking findings. 2 LOW (evidence-prose inaccuracy; CI-guard contention flake susceptibility) + 3 INFO (behavior notes, all outside the blessed set).
- Reviewer: task_fe7c203a1520 / dispatch ctx_52090bcd5881 · 2026-08-28 · review-only, zero repo edits; all scratch under `target/` (probe crate `target/f12a6-probe`, logs `target/audit/`).
- Worktree: branch `docs/fix-install-commands`, base `fccd9e4`, uncommitted. Host: macOS arm64 (Apple M4 Pro).

## 0. Frozen identity — ALL PASS (11/11)

All 11 SHA-256 values matched exactly before any run and re-verified byte-identical after all runs, including `evidence/f1/raw/production_pack_pr.json` `00763c18bb00d8f6299aa1eef061f4f9dea2c75449154c85c48c5bbdf1f1c32a` across debug AND release gate re-runs (report deterministic, report-after-assertions invariant holding).

## 1. Reproduced suites (exact commands) — ALL PASS

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | exit 0 |
| `git diff --check` | exit 0 |
| `cargo clippy -p cerberus-engine -p cerberus-packs --all-targets -- -D warnings` | clean, no issues |
| `cargo test --workspace --all-targets` | 640 passed / 0 failed, 25 suites |
| `cargo test --release --workspace --all-targets` | 640 passed / 0 failed, 25 suites |
| `cargo test -p cerberus-engine` | 219 passed (199 lib + 15 integration + 5 unit-feature) |
| `cargo test -p cerberus-packs` | 84 passed (68 lib + 16 product gate) |
| `cargo test -p cerberus-packs --test production_pack_pr -- --nocapture` (debug) | 16 passed |
| `cargo test --release -p cerberus-packs --test production_pack_pr -- --nocapture` | 16 passed; reject-path p50 2.080 / p99 3.288 ms; all-fire p50 4.165 / p99 4.486 ms |
| `cargo test --test redos_fuzz` (debug + release) | 11 passed each |
| `cargo test --test load_test` (debug) | 10 passed |
| `cargo test --release --test load_test -- --test-threads=1 --nocapture` | 10 passed ×2 (see LOW-2); plan-budget guard: mixed_50KB p50 0.322/p99 0.453, mixed_100KB 0.636/0.743, nbsp_100KB 0.623/0.746, two_pan_one_line 0.001/0.001 ms — all inside budgets |
| `cargo test -p cerberus-engine --lib pan_candidate_ranges_match_reference_implementation_on_random_inputs` (debug + release) | PASS each |
| probe `target/f12a6-probe`: `cargo run --release` | ALL CHECKS PASS |

## 2. Audit (1): PAN matcher equivalence — PASS

Static review: `engine.rs:492-711` routes only the exact `BOUNDED_PAYMENT_CARD_PATTERN` to `payment_card_candidate_ranges`; the bounded pattern is still compiled at build time; `partition_payment_card_run` splits only at separator change or between two complete 13–19-digit unformatted PANs; `push_payment_card_segment` enforces 13..=19 digits + `payment_card_valid` (Luhn + issuer range/length, allocation-free in `validator.rs:234-311`). Phone rules keep `not-payment-card` sharing the exact same predicate — PAN-vs-phone precedence intact.

Independent probe through the full shipped `DEFAULT_PACK` engine (exact-span asserts):
- dot / slash / NBSP / 1-, 2-, 3-space / per-digit hyphen / per-digit dot / `+`-prefixed (plain + `+3400 0000 0000 009`) → `pii.credit_card` over the full PAN, **never** `pii.phone_number`; attempt-5-replica engine agrees (plus-prefix: new span includes the `+` — INFO-4).
- two-PAN-one-line `4000.0566.5566.5556 4111111111111111` → exactly 2 cards, exact spans **(0,19)** and **(20,36)**, no phone; corpus "Batch … done" line → both cards; 3-style mixed line → all valid PANs found with exact spans.
- overlong: 24-digit run (raw + spaced), 20-digit, dot-joined 32-digit → **0** card findings.
- Luhn-invalid: `1234567812345678`, `4000.0566.5566.5557`, `4111-1111-1111-1112`, all-identical digits → **0** findings.
- IP shapes: 4 panel PoCs + `1.2.34.567` → **no** phone finding; `212.555.0123` still a phone with exact span.

Differential fuzzing:
- In-repo oracle test (`pan_candidate_ranges_match_reference_implementation_on_random_inputs`): PASS debug + release. **Note (LOW-1):** evidence item 7 claims "10,000 deterministic structured-random inputs … and 10,000 fragment-composed PAN-shaped strings" and a "13-char adversarial alphabet"; the frozen code runs `0..5000` twice (=10,000 total) with a 12-element alphabet. Prose inaccuracy only — substance re-verified beyond the claimed numbers below.
- My own independent **20,000-trial** engine-level differential (shipped vs attempt-5-replica engine: digit-anchored unbounded chain `\\b[0-9](?:(?:[ \u{a0}]{1,3}|[./-])?[0-9]){11,}` + same validators): 19,151 identical; 708 new-only = intended multi-PAN partition fix (every new-only span is a complete Luhn+issuer-valid PAN); 252 old-only = new trailing-`\b` tightening (PAN followed by word char — no blessed case); 270 old-only = `+` absorbed into the new span (INFO-4); **1** old-only = mixed-separator single PAN (INFO-3); **0 regressions outside those classes; 0 non-card (phone/other) differences.**
- Independent corpus replay in the probe (own manifest parser + occurrence-keyed span computation, not reusing gate code): all 14 cases match exactly, 52 expected instances.

## 3. Audit (2): accounting, thresholds, identity, corpus — PASS

- `MIN_RECALL = 0.90` / `MIN_PRECISION = 0.85` (`production_pack_pr.rs:20-21`); `validate_product_report` gates **every category AND every flag** (iterates `categories.chain(&flags)`) and rejects any non-evaluable metric.
- Exact spans: `match_expected` requires exact `(flag, start, end)` equality; wrong span ⇒ FP + unconsumed ⇒ FN. `increment_metric`/`MetricKind::apply` only add TP/FP/FN — **no FP exclusion/decrement path**; unknown flags panic.
- Negative handling: every `expected == 0` case must have `findings == 0`, enforced independently of thresholds.
- Report: **15 flags, all evaluable, all gate_pass**; thresholds embedded in the raw report.
- Pack identity recomputed **independently in Python** by extracting the `DEFAULT_PACK_JSON` raw literal from `default_pack.rs` and hashing: `f67a67b692afb8a3310e8528602f0e3bd20e90b1e75e07fd3be032450132296f` = `DEFAULT_PACK_IDENTITY` `1.2.1@sha256:f67a67b692…132296f` — MATCH; 15 rules parsed.
- Corpus v3 recomputed independently with the identical composition (manifest bytes + per-case path bytes + little-endian u64 length + file bytes): manifest `68677e07…05b59` MATCH; composed corpus `984dd33e…6d2d2` MATCH.
- Negative case count: evidence says **6** (r9:309 and r9:473; the attempt-5 "7 negative cases" typo is fixed), manifest has exactly 6 (`negative-code/readme/prose/short/constraints/attempt5`) — MATCH.

## 4. Audit (3): claimed metrics reproduce byte-identically — PASS

Gate emitted: aggregate **52 TP / 0 FP / 0 FN**; `pii` 29/0/0; `secrets` 23/0/0; every one of 15 flags 100%/100% (entropy 8, phone 12, credit-card 11, email 6, PEM 4, OpenAI 2, remaining 9 flags 1 each); pack 1.2.1 / 15 rules; corpus `cerberus-default-pack-pr-v3`. Raw report rewritten by debug and release gate runs, hash `00763c18…c32a` byte-identical before/after — matches the frozen evidence exactly.

## 5. Non-blocking findings

| # | Severity | Finding |
|---|---|---|
| 1 | LOW | Evidence-prose inaccuracy (r9 item 7): differential test described as 10,000+10,000 trials over a "13-char" alphabet; frozen code runs 5,000+5,000 (10,000 total) over a 12-element alphabet. Substance independently re-verified (my 20,000-trial differential: 0 regressions). Fix prose at next evidence touch. |
| 2 | LOW | `load_test_100kb_phone_list` (15 ms CI guard, not a plan budget) hit p99 31.3 ms once under machine contention in my first serial run; isolated/serial re-runs: p99 4.38/4.66/5.45 ms, full serial suite 10/10 twice — consistent with evidence (4.24–4.42 ms) and its documented contention-tolerance note. Flake susceptibility under heavy co-tenancy only; plan-budget guards passed throughout with large headroom. |
| 3 | INFO | Behavior change vs attempt-5 regex semantics, outside the blessed set: a single 13–19-digit PAN formatted with **mixed separator styles** (e.g. NBSP+dot+hyphen+space) was accepted by attempt 5 (greedy chain → validator on whole value) but is partitioned at separator changes by the attempt-6 matcher and rejected when no segment is a complete PAN (1 occurrence in 20,000 random trials). No corpus/gate/panel case uses mixed separators on one PAN; all blessed cases are single-style per PAN. Documented design consequence ("a PAN formatted with one separator style stays intact"). |
| 4 | INFO | `+`-prefixed PAN spans now include the leading `+` (frozen pattern's `\+[0-9]` alternative); attempt 5 spanned digits only. No blessed exact-span case for plus-prefixed PANs; card-presence/phone-absence assertions unchanged. |
| 5 | INFO | Unguarded alternate shape (mixed-style runs chained into one 100 KB run via recognized separators, finding-free) measured p50 0.637 ms (matches claim 0.633) but p99 ~4.5 ms in my probe; still under the §5 3–5 ms proxy ceiling and the authoritative plan-budget guards pass on the blessed shapes. Candidate extra load shape for F1.3. |

## 6. Disposition

**PASS.** Attempt-6's re-architected allocation-free PAN matcher is behaviorally equivalent to attempt 5 on every blessed case, the intended two-PAN fix works with exact spans, the performance blockers reproduce as resolved, accounting/thresholds/identity/corpus integrity are independently verified, and the claimed 52/0/0 metrics reproduce byte-identically. F1.2 panel sign-off can proceed; LOW-1 prose should be corrected at the next evidence edit.
