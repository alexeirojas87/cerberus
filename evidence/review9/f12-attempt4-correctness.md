# F1.2 — Repair Attempt 4: Independent Correctness Audit (fresh reviewer)

- Attempt: 4    Reviewer: term_e80c1d71 (correctness panel, independent of builder)    Verdict: **PASS** (with 2 LOW + 3 INFO non-blocking findings)
- Date: 2026-08-27    Worktree: /Users/alexeirojas/Work/Personal/Cerberus (primary checkout, uncommitted changes on base HEAD `fccd9e4`)
- Toolchain: rustc 1.97.1 (8bab26f4f), cargo 1.97.1 — matches recorded builder toolchain.
- Review-only provenance: all audited files verified SHA-256 byte-identical before and after (`shasum -a 256 -c` snapshot at `/var/folders/l8/.../f12-audit/before.txt`, all OK). No file was edited.

## 1. Frozen identity — 6/6 PASS + 2 extras

```
entropy.rs              4c4d3efd…0307  ✅
validator.rs            c745d3d2…7ff5  ✅
default_pack.rs         e67468bb…3fe0  ✅
production_pack_pr.rs   7ebd73b5…2f65  ✅
manifest-v1.json        84ad0c3e…e3e7  ✅
raw report              a72c7f13…8354  ✅
(engine.rs 8563b8b3…3c69 from evidence pack) ✅ extra
```

## 2. Product gate reproduction — PASS

`cargo test -p cerberus-packs --test production_pack_pr -- --nocapture` → 9 passed; 0 failed.
Regenerated `evidence/f1/raw/production_pack_pr.json` is **byte-identical** to the frozen hash a72c7f13….
Report: 43 TP / 0 FP / 0 FN aggregate; PII 20/0/0, secrets 23/0/0; **all 15 flags evaluable** (recall+precision denominators > 0) with R=P=100%; per-flag: entropy 8, phone 10, email 6, card 4, PEM 4, id_rsa 1, OpenAI 2, others 1.
Identity emitted: pack `1.1.0@sha256:c73754ed…0a36` (independently recomputed in Python from the exact `DEFAULT_PACK_JSON` bytes: match; 15 rules, 14 distinct flags, phone policy split across 2 same-flag rules), corpus manifest sha `84ad0c3e…` ✅, composed corpus sha `sha256:cf8d4cfe…7c64` — **independently recomputed** (manifest bytes ‖ path ‖ len(u64-LE) ‖ file bytes per case) and matches.

Full battery (exact commands + results):
| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | PASS exit 0 |
| `git diff --check` | PASS exit 0 |
| `cargo clippy -p cerberus-engine -p cerberus-packs --all-targets -- -D warnings` | PASS, no issues |
| `cargo test -p cerberus-engine` | 205 passed, 0 failed (3 test-binaries) |
| `cargo test -p cerberus-packs` | 77 passed, 0 failed |
| `cargo test --test redos_fuzz` / `--test load_test` | 8 / 8 passed |
| `cargo test --workspace --all-targets` | **614 passed, 0 failed** — matches attempt-4 evidence exactly |

## 3. Criterion-by-criterion audit

| Criterion | Verdict | Evidence |
|---|---|---|
| Exact-span accounting | ✅ | `match_expected` requires `(flag, start, end)` equality with `spans_match`; partial overlap → FP + FN (both counted honestly). `Counts::add` only increments; **no FP exclusion/decrement path exists** (grep confirms). Findings with a flag not in the pack panic via `increment_metric` ("unregistered finding flag"). Engine dedupes by `(flag,start,end)`; spans are regex byte offsets, byte-consistent with `match_indices`-derived ground truth. |
| Category/flag thresholds | ✅ | `MIN_RECALL 0.90`, `MIN_PRECISION 0.85` asserted for **every** category and **every** flag; evaluable-assert prevents a flag with zero positive support passing vacuously; aggregate informational only. Matches owner decision 2026-08-27. |
| Negative zero-findings | ✅ | All 5 negative cases: `expected==0` → explicit `assert_eq!(case.findings, 0)` **plus** per-flag FP accounting. Report shows findings=0 for all five. |
| Corpus integrity / no test-teaching | ✅ | Negatives are untouched since initial release `01d27a8` (not stripped). Ground truth values are genuine literals located in-file (missing value panics). The two "corrections" are factually honest: the SHA-256-of-"password" fixture has measured Shannon 3.8075 < 4.0 (independently computed — legitimately not a high-entropy secret; threshold 4.0 unchanged, `DEFAULT_ENTROPY_THRESHOLD` confirmed in engine.rs); `4111111111111111` is the canonical documentation PAN, allowlisted with four *other* Luhn-valid positives retained. |
| allowedExamples control | ✅ | `every_allowed_example_suppresses_a_real_pattern_match`: production engine suppresses each example; allowlist-cleared control **must still fire** on the same context — kills vacuous/typo'd allowlist entries and misplacement (the attempt-1 Slack-on-Google failure mode is structurally prevented). 7 rules carry allowlists (verified against pack JSON). |
| Contextless strong-secret recall | ✅ | All 7 signatures (OpenAI, Anthropic, AWS, GitHub, Stripe, Google, Slack) fire with zero contextual prose (gate test + my standalone probe P7). |
| Phone formats | ✅ | Probe: `+44-20-7946-0958`, `+1 (555) 123-4567`, `555-123-4567`, `(212) 555-1234`, `212.555.0123`, national `44 20 7946 0958` — all detected; no context required for formatted policies. |
| Contextless 7–15-digit phones | ✅ | Bare 10-digit contextless → silent; `phone 8005550199` / `PHONE 5551234567` (case-insensitive) → detected; 6-digit → too short; 16-digit → too long; `E.164 882161234567890` → phone. |
| PAN IIN+length+Luhn | ✅ | Probe matrix: Visa 13/16/19, MC 51–55 + 2221-range, Amex 15, Diners 14 (both 300–305 and 36/38/39), Discover 6011, JCB 3528–3589 all classify as `pii.credit_card`; Luhn-invalid (4111111111111112, 5454545454545428 — verified Luhn-false by hand), 12-digit, 17-digit, out-of-range 2220, and repeated-zero all fail closed. `+86 138 0013 8002` is genuinely Luhn-**valid** (luhn=true, computed twice independently) yet is correctly *not* a card via the issuer predicate and remains a phone — the exact attempt-3 panel failure now fixed. |
| Overlong / partial matches | ✅ | 24-digit run → no card, no phone, nothing (no partial 16-digit substring credit; RE2-style greedy match cannot shrink and the validator length gate rejects). `41111111111111111` (17-digit) rejected. Formatted-card spans are exact even with trailing ".". |
| Plus / separator evasions | ✅ | `+4111111111111111`, per-digit dash and per-digit space separated 16-digit PANs, and `+3400 0000 0000 009` are all cards with **zero** phone downgrade (fail-closed `not-payment-card` uses the same PAN predicate incl. separators — `payment_card_valid("+5500000000000004")=true`). |
| Unknown validator rejection | ✅ | Probe: `bogus`, typo `not-payment-crd`, `luhn ` (trailing space), `shannon-entropy>` (no operand), `payment-card-typo` → all **abort engine construction** with `Unknown validator '<x>' configured for rule '<flag>'`. Runtime registry additionally fails closed (`all_pass` drops the finding). |
| Attempt-4 claims vs code | ✅ | Every numbered claim in `evidence/f1/r9-production-pack-pr.md` §"What changed" traces to code I read (pack identity const + gate assert; synthetic harness relabeled, writes only `target/unit_feature_measurement.txt`; report has no exclusion path; keyword list escape+longest-first; `auth_token` added; punctuation trim in `extract_value`). Failed-attempt history (§81-90) is consistent and retained per §8B.1 #5. |

## 4. Adversarial cases tested (probe harness outside worktree)

Scratch crate `/var/folders/l8/.../f12-audit/probe` (path-deps only; worktree untouched), 60+ probes across P1-P12 groups; results above. Two of my initial probe expectations were **wrong**, not the engine (5454545454545428 and the 15-digit `4-111-1111-1111` run both fail Luhn — engine behavior correct in each case; hand-verified with independent Python implementation).

## 5. Findings (non-blocking; none contradicts an acceptance criterion)

| # | Severity | Finding |
|---|---|---|
| F-1 | LOW | Entropy keyword-adjacency double-count: `key token=<secret>` yields **two** findings, one spanning `token=<secret>` (keyword text inside the secret span). The "one exact finding" claim holds for the `auth_*` separator variants (probe-verified) but not arbitrary adjacent keyword pairs. No corpus case exercises it; F2 redaction would over-consume the span. |
| F-2 | LOW | Bare-phone context keywords match by substring (`constraints.rs:44` `contains`): `"hotel"` enables keyword `"tel"`, `"megaphone"` enables `"phone"` — probes confirm a 10-digit order id next to those words is classified as phone. Pre-existing constraint design (F1 rule-loader), but the attempt-4 same-flag policy widens its exposure. Negative corpus has no such near-miss. |
| F-3 | INFO | Entropy span includes a leading `(` for `secret=(TOKEN)` (trailing punctuation is trimmed; opening delimiters are not a skip/trim class). |
| F-4 | INFO | Real-world format recall gaps beyond the declared-finite corpus: current `sk-proj-…` OpenAI keys and multi-segment `xoxb-<a>-<b>-<c>` Slack tokens evade the named patterns (class excludes `-`; segment length < 20). Entropy+context may still catch them in realistic config text. Pack coverage item, not a gate defect. |
| F-5 | INFO | Gate writes the machine report **before** its assertions; a future failing gate run mutates the frozen evidence artifact (evidence-hygiene nit). |

## 6. If FAIL: reproduction

N/A — verdict is PASS. Any re-verification: commands in §2, hashes in §1, probe source retained under `/var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/f12-audit/`.

## 7. Scope note

This pack is the F1.2 correctness panel (per §8B.3 high-risk unit = diverse panel): my verdict covers **correctness** only. Security/performance panel verdicts and the integrator sign-off remain separate gates; F1.2 must not be closed on this review alone. Builder PASS was not assumed; everything above was executed or independently recomputed.
