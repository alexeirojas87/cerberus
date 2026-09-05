# F1.2 — Independent adversarial security review, repair attempt 5

Verdict: **PASS** — no High, no Medium regressions in the NEW attempt-5 code.
4 Low / informational findings (all fail-safe, non-blocking). Attempt-4 HIGH-1,
MED-1/2/3 and LOW-1/2 PoCs all re-run and now behave safely; nothing regressed.
Reviewer: independent panel (security), review-only; no repo file under audit was
edited (this file is the only addition, per panel convention).
Date: 2026-08-28. Host: macOS/Darwin arm64. Toolchain: rustc stable (same as gauntlet).

## Frozen-hash verification (PASS)

All ten hashes verified identical before and after every run:

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

## Reproduction (PASS)

```text
cargo test --workspace --all-targets                         → 638 passed / 0 failed (25 suites)
cargo test --release -p cerberus-packs --test production_pack_pr -- --nocapture → 16 passed
  100KB phone-list reject-path: p50=1.999ms p99=2.142ms   (attempt 4: ~195 ms — quadratic gone)
  100KB phone-list all-fire:    p50=4.492ms p99=4.912ms
cargo clippy -p cerberus-engine -p cerberus-packs --all-targets -- -D warnings → clean
cargo fmt --all -- --check && git diff --check               → clean
```

The gate test regenerates `evidence/f1/raw/production_pack_pr.json` byte-identically
(hash stable across debug AND release runs → report is deterministic, no timestamps).

Probes ran from an out-of-repo crate linking the frozen engine + pack by path
(`/var/folders/.../opencode/f12a5-probe`, bins `f12a5-probe` + `extra`; main suite
63 checks pass — the single reported "FAIL" was a probe-side expectation error for a
151-byte pad, which IS inside the 200-byte window and was correctly detected).

## Attempt-5 attack results (new code)

### Char-boundary snapping (entropy.rs:144-148) — HOLDING

* Systematic sweep: 10 multibyte classes (2-byte é, 3-byte €/密, 4-byte 🎉,
  4-byte flag sequence 🇺🇸, combining e+U+0301, ZWJ U+200D, ZWSP U+200B, U+FFFD,
  mixed), repetition 0..110 × 3 keyword prefixes (`password=`, `key`, `token: `),
  both through `detect_near_keywords` and full `CompiledEngine::scan`
  (~6,600 payloads) + window-edge alignment sweep (pad 0..210 with CJK+x) —
  **zero panics, zero non-boundary finding spans**. The previous PoC trio
  (é×100, x×197+€, 密钥×120) now scans clean.
* Soundness argument verified live: `kw_end` is always a regex-match boundary, so
  the snap-down loop terminates at ≥ `kw_end`; `min(kw_end+200, len)` ≥ `kw_end`
  for any real string (wrapping_add cannot underflow at any allocatable length);
  `text.len()` is a boundary, so the loop never underflows.
* Snapping never breaks recall inside the window: secret + trailing é-run
  straddling the edge is still found with the exact span (P1c).
* Invalid-UTF-8 sources: the shipped data-plane paths (`decoder.rs:53`,
  `json_redact.rs:59`) funnel bytes through `String::from_utf8_lossy`, which
  guarantees valid UTF-8; feeding lossy-mangled adversarial byte streams
  (0xFF runs, lone 0xC2 leads, split emoji) through the detector and full scan →
  no panics, boundary-valid spans.
* 60,000-iteration seeded PRNG fuzz over a pool including all the above
  (ASCII, multibyte, controls, keyword text) through both entry points:
  0 panics, 0 invalid spans, deterministic results.

### Proximity-window bypasses (entropy.rs:150, 194-217) — known gaps unchanged, no new hole

* Near-vs-far boundary behaves exactly at 200 B from the keyword end (found at
  151 B pad, not found beyond the window) — snapping costs at most 3 B.
* Unicode whitespace directly after `=`/`:`/space (NBSP, U+2028, VT, FF, thin
  space) aborts first-token extraction → entropy detector yields nothing.
  **Byte-identical behavior in attempt 4** (same SKIP_CHARS + first-token logic);
  structured pack rules still catch signature-bearing secrets in the same text.
  Informational (LOW-5 below), not an attempt-5 regression.
* ZWSP glued to the value is INCLUDED in the finding span (span hygiene only;
  hashing is of the value, no leak).
* Adjacent-keyword cut (F-1) cannot be spoofed to skip a real value:
  `key=key=<secret>` → clean secret span; `password=password: <secret>` → clean;
  `token=hash:<secret>` → clean; prose-leak and duplicate paths verified closed;
  `seen_spans` dedup is span-keyed and per-call, so no cross-payload interference.

### Word-boundary context keywords (constraints.rs:27-54, 142-156) — MED-3 FIXED

All attempt-4 MED-3 PoCs (`hotel`, `motel`, `intl`, `megaphone`, `contactless`,
`XE164foo`, cross-line `phone list backup` block) produce **no phone findings**,
while legitimate same-line contexts (`tel`, `Tel:`, `PHONE\t`, `phone:`) still
fire. Accepted residuals:

* `is_word_byte` is ASCII-alnum only → non-ASCII letters count as boundaries:
  `teléfono 5551234567` / `contactó 5551234567` GRANT phone context (semantically
  correct — those ARE phone words in ES/PT); `tel<U+200D>` also grants. A crafted
  FP source, negligible precision impact (LOW-6).
* Underscore deliberately grants (`hotel_tel 5551234567` → phone; intended for
  `api_key`-style env names).
* Line split is `\n`-only: CR-only line endings collapse the whole document into
  one "line" and restore unbounded proximity (`phone\rinvoice id 1234567` flags).
  Precision-only direction (more FPs, never suppression); legacy-CR payloads rare
  in the proxy path. LOW-6 companion note.
* JSON leaf path (`scan_with_context`, offsets_in_context=false) falls back to
  word-boundary keyword ANYWHERE in the body (line proximity undefined across
  buffers) — documented at constraints.rs:149-156; MED-3 fully closed only on the
  plain-text scan path, partially on the leaf path.

### PAN separator class (default_pack.rs:149) — MED-2 FIXED, no ReDoS, no ambiguity exploit

* Dots, slashes, NBSP, double spaces, mixed separators, per-digit dashes and
  plus-prefixed forms of `4000056655665556` are all detected as
  `pii.credit_card` and **never** carry a concurrent `pii.phone_number` finding
  (validator.rs `not-payment-card` + `payment_card_valid` range checks).
* ReDoS: adversarial 1 MB digit run, 500 K three-space groups, 1 MB `.1`-chain
  (leftmost match fails at trailing letter), 100 K `-4` chain + letter — release
  scan times 11.2 / 16.7 / 7.5 / 3.1 ms (linear; regex-crate automaton holds for
  the nested `(?:[ ]{1,3}|[./-])? … {12,}` shape; no exponential state because
  there is no backtracking engine).
* Unicode digits (Arabic-Indic, fullwidth): zero findings, zero panics — `[0-9]`
  is ASCII-scoped; `\b` (Unicode-aware) also correctly refuses partial credit
  when fullwidth digits glue onto ASCII runs. Known recall gap only.
* Evades (documented gaps, same posture as attempt 4): tab or ≥4-space group
  separators, and valid PANs swallowed into >19-digit or >38-byte runs
  (maxLength fail-closed). Attacker who controls the payload can always add
  separators; inherent to any regex-DLP tier.
* FP vector (LOW-7): the `\+[0-9]…` alternative has no leading `\b`, so a PAN
  glued behind `+` inside a token still matches (`…/pay/+4000056655665556` →
  card). Confined to `+`-adjacent gluing (alpha-then-digits is still blocked),
  and the digits are Luhn+BIN valid; over-redaction direction, never a leak.

### IPv4 guard (phone rules, default_pack.rs:152-173) — MED-1 FIXED, no suppression

All four attempt-4 IP PoCs plus `v1.0.2024.1205`, `192.168.100.234` produce zero
phone findings; the guard is structurally sound (the 3-3-4 dotted branch cannot
match any valid IPv4 since the final group exceeds 3 digits). Eleven real-phone
formats verified undisturbed, including a dotted 4-group IPv4 tail edge
(`192.168.100.2345` is not an IPv4, and was not tested as one). The narrowing of
the context-free branch does lose some formats attempt-4 accepted (trunk-prefixed
`0800 555 0199`, compact `07700900123` even with `phone` context because
`[1-9]` excludes a leading zero) — a deliberate precision/recall rebalance that
was the MED-1 remedy; no attempt-4 **positive** detection of a corpus-represented
format was lost (LOW-8).

### Report-after-assertion path (production_pack_pr.rs:358-419) — F-5 holds

`run_product_measurement()` asserts (corpus reads, ground-truth presence) BEFORE
any artifact write; `validate_product_report()` returns violations instead of
panicking. Reproduced in an out-of-repo full copy of the worktree with a poisoned
negative corpus: test FAILED, panic message names the debug report path,
`target/production_pack_pr_FAILED.json` was written, and the frozen
`evidence/f1/raw/production_pack_pr.json` byte-hash was untouched. Residual
(LOW-9): both writes are `std::fs::write` (truncate+write, not
write-temp-then-rename), so a crash mid-write could leave the artifact truncated;
scope is a local CI/evidence file, and the success path only ever opens it on a
fully validated report. `target/` is gitignored (repo `.gitignore:1`), so debug
artifacts cannot leak into commits even if `CARGO_TARGET_DIR` points elsewhere
(the test pins the path to the workspace root, not cargo's dir — benign split-brain).

### Pack identity mismatch — fails loudly

Out-of-repo copy with a 1-byte pack whitespace edit (semantics unchanged):
`exact_pack_identity_and_virtual_entropy_contract` FAILED with the full
left/right identity diff (`1.2.0@sha256:aa1c0d8d…` vs `1.2.0@sha256:44f426ae…`),
and the regenerated report's `pack_sha256` exposes the mismatch even on paths
where the P/R gate itself still passes. Version, bytes, corpus hash and per-flag
accounting are all recorded in the report (49 TP / 0 FP / 0 FN; 15 flags across 2
categories, every one evaluable with perfect per-flag P/R).

## Attempt-4 PoC regression panel (none regressed)

| attempt-4 finding | probe | attempt-5 result |
|---|---|---|
| HIGH-1 window panic | é×100 / x×197+€ / 密钥×120 via `scan` | no panic (also permanent corpus negative + unit + gate test) |
| MED-1 IPv4-as-phone | 4 PoCs | 0 findings; guard structurally complete |
| MED-2 separated PANs | dot / slash / NBSP / double-space | all `pii.credit_card`, never phone |
| MED-3 substring context | hotel/motel/intl/megaphone/contactless/XE164foo/cross-line | 0 phone findings; legit contexts preserved |
| LOW-1 brackets | `{}` `()` `[]` wrapped secret | clean exact spans |
| LOW-2 AWS fixture | canonical + `…EXAMPLEKEX` variant | suppressed exact-only, variant flagged |
| LOW-3 compact e164 | `+15551234567` | still no finding (documented gap, unchanged) |

## Low / informational findings (non-blocking)

1. **LOW-4** — Public `luhn_valid` (validator.rs:236) silently narrowed to a
   PAN-shaped policy (13–19 digits, non-repeating). Unknown to external callers;
   the sibling test still checks `get_validator("luhn")` on 16 digits. Layering
   nit: rename or split generic-vs-PAN semantics.
2. **LOW-5** — Entropy first-token extraction aborts (no finding) on non-ASCII
   whitespace directly after the keyword separator and can be masked by any
   low-entropy ≥8-char first token. Identical in attempt 4; defense-in-depth
   layer only; recommend continuation to next tokens in a future attempt.
3. **LOW-6** — Word-boundary keyword check treats non-ASCII letters and CR as
   boundaries (accented-word and CR-only-line granting noted above). Precision
   direction only.
4. **LOW-7** — `+`-prefixed PAN alternative lacks a leading `\b` (glued-after-
   non-space tokens still redact). Over-redaction direction only.
5. **LOW-8** — Trunk-prefixed leading-zero numbers (`0800 555 0199`,
   `phone 07700900123`) are no longer classified (structural `[1-9]` head +
   4-digit first group in the context-free branches). Recall trade of the
   MED-1 fix; no corpus positive lost.
6. **LOW-9** — Evidence/debug report writes are not atomic (no temp+rename).
   Local artifact integrity nit only.

## Gate disposition

Attempt 5 closes every blocking item from attempt 4 with permanent regression
coverage (unit tests in entropy.rs/constraints.rs, gate tests in
production_pack_pr.rs, corpus positives `07-separated-pans.txt` / negatives
`05-attempt5-adversarial.txt`, and `redos_fuzz_multibyte_entropy_window_straddle`).
The shipped scan path survived ~75k adversarial UTF-8 payloads, ReDoS-shaped
1 MB inputs, lossy invalid-UTF-8 streams, proximity/word-boundary bypass
attempts, and IP/phone/PAN classification attacks with **no panic, no leak, no
unsafe suppression**. The performance blocker (p50 195 ms @100 KB) is fixed and
measured inside budget. Per fix-plan §0.7, the security panel **signs off F1.2
attempt 5: PASS**. The Lows above are follow-ups for the backlog, not gate
conditions.

Probe sources: `/var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/f12a5-probe/`
(`src/main.rs`, `src/bin/extra.rs`); sabotage copies:
`…/opencode/a5-fail/`, `…/opencode/a5-ident/`; logs: `/tmp/ws_test.log`,
`/tmp/rel_gate.log`, `/tmp/failgate.log`.
