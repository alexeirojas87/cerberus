# F1.2 — Independent adversarial security review, repair attempt 4

Verdict: **FAIL** — 1 High, 3 Medium, 3 Low findings.
Reviewer: independent panel (security), review-only; no repo file was edited.
Date: 2026-08-27. Host: macOS/Darwin arm64. Toolchain: rustc 1.97.1.

## Frozen-hash verification (PASS)

All six hashes verified identical to the frozen set before and after all test runs:

```text
4c4d3efdf653794fcae93682adb2b829ac04b22ffeea56ad05a755b5e54e0307  crates/cerberus-engine/src/entropy.rs
c745d3d2290183a9ece1aab55a24a174ec8d0bea9f465fbb5aa579c42fc37ff5  crates/cerberus-engine/src/validator.rs
e67468bb7318d07090ba342aabe7d92021f3bf651c185325d660bcb6470b3fe0  crates/cerberus-packs/src/default_pack.rs
7ebd73b50057dcf16f024bf2fdd59957d8a9adc24977383b5f8d729722b72f65  crates/cerberus-packs/tests/production_pack_pr.rs
84ad0c3ef316b3d8f02c0634749774e5a75f987bffea8e4c0846dc7ef29ee3e7  tests/corpus/product-gate/manifest-v1.json
a72c7f13fe6f8b91f3b33cf89af89847372ff7155d4e502311fc902b6d768354  evidence/f1/raw/production_pack_pr.json
```

Bonus: `engine.rs` = `8563b8b304af9e01e87c9809dd531933209f33d5a07569de6656f0eec3513c69`, matching the attempt-4 pack record. The report hash is stable across regeneration by the gate test itself.

## Reproduction (PASS)

```text
rtk cargo test -p cerberus-packs --test production_pack_pr   → 9 passed
rtk cargo test -p cerberus-engine                            → 205 passed
rtk cargo test -p cerberus-packs                             → 77 passed
rtk cargo test --test redos_fuzz                             → 8 passed
rtk cargo test --test load_test                              → 8 passed
rtk cargo test --workspace --all-targets                     → 614 passed (25 suites)
rtk cargo clippy -p cerberus-engine -p cerberus-packs --all-targets -- -D warnings → clean
rtk cargo fmt --all -- --check && rtk git diff --check       → clean
```

Report accounting verified from `evidence/f1/raw/production_pack_pr.json`: aggregate 43 TP / 0 FP / 0 FN; pii 20/0/0; secrets 23/0/0; 15 flags, all recall- and precision-evaluable, zero FP/FN on every flag; all five negative cases produce exactly 0 findings. No FP exclusion/decrement path exists in the harness (`match_expected` credits only exact `(flag,start,end)` matches; unknown flags panic). Allowed-example control, exact-span enforcement, contextless structured signatures, and PAN-vs-phone precedence (PAN never downgraded to phone at 13–19 digits) were independently confirmed via an out-of-repo probe crate linking the shipped `DEFAULT_PACK_JSON` + engine (no repo edits).

## Findings

### HIGH-1 — Entropy detector panics on non-char-boundary window slice (remote DoS in shipped scan path)

`crates/cerberus-engine/src/entropy.rs:138-139`:

```rust
let search_end = std::cmp::min(kw_end.wrapping_add(NEAR_KEYWORD_WINDOW), text.len());
let context = &text[kw_end..search_end];
```

`kw_end + 200` can land inside a multi-byte UTF-8 character; string slicing panics. Any scanned payload containing an entropy keyword (`password`, `key`, `token`, …) followed by ≥~200 bytes of non-ASCII text that straddles the boundary crashes the scan. This is attacker-controlled input for Mode A/B proxy traffic and for the daemon.

Repro (out-of-repo probe against the frozen artifacts):

```text
P1 utf8-window-panic catch_unwind ok=false
thread 'main' panicked at .../cerberus-engine/src/entropy.rs:139:28:
end byte index 208 is not a char boundary; it is inside 'é' (bytes 207..209 of string)
```

Second repro with CJK: `"key " + "密钥".repeat(120) + " <secret>"` → same panic (index 203). Fix direction: snap `search_end` down with `text.floor_char_boundary(...)` (or iterate `char_indices`). Not covered by any existing test; corpus is pure ASCII so the P/R gate cannot see it.

### MED-1 — Shipped phone rule classifies IPv4 addresses as `pii.phone_number`

The context-free branch `\b[0-9]{1,3}[ .-][0-9]{1,4}(?:[ .-][0-9]{2,4}){1,2}\b` (`default_pack.rs:160`) accepts dots as separators with no octet validation:

```text
"connect to 192.168.100.23 now"      => pii.phone_number@11..25 [192.168.100.23]
"server 192.168.1.100 responded"     => pii.phone_number@11..20 [168.1.100]
"pkg 1.2.34.567 installed"           => pii.phone_number@4..14  [1.2.34.567]
"listen on 10.255.224.10:8080"       => pii.phone_number@10..23 [10.255.224.10]
```

IPs and dotted version numbers are ubiquitous in logs/prompts; every one is a real-FP producer under the shipped pack. The product-gate corpus contains none, so the 100% precision claim masks this.

### MED-2 — Dot/NBSP/double-space/slash-separated PANs fully evade card detection

Attempt 4's separator hardening covers only single `' '`/`'-'` (`default_pack.rs:149`). Luhn-valid Visa `4000056655665556` in common human formats:

```text
card 4000.0566.5566.5556   => []   (dots)
card 4000/0566/5566/5556   => []   (slashes)
card 4000␠0566␠5566␠5556   => []   (U+00A0 per group)
card 4000  0566  5566  5556 => []  (double spaces)
```

Single-space, single-dash, per-digit and plus-prefixed variants are correctly caught (verified). Dotted grouping is a routine paste format from payment UIs/spreadsheets; treat as a known detection gap or extend the separator class.

### MED-3 — Whole-document context turns unrelated numbers into phones

`scan()` passes the entire buffer as context, and `contextKeywords` match by substring (`constraints.rs:44`). One occurrence of a keyword anywhere flags every plain 7–15 digit run in the document:

```text
"phone list backup:\norder id 1234567\ninvoice 2345678\nserial 3456789\n"
  => 3 × pii.phone_number
"hotel 5551234567 lobby"          => phone   (keyword "tel" ⊂ "hotel")
"XE164foo 5551234567 bar"         => phone   (keyword "e164" ⊂ "XE164foo")
"contactless order 5551234567"    => phone   (keyword "contact" ⊂ "contactless")
```

Substring keyword matching ("tel" in hotel/motel/intl/extent-adjacent words) plus unbounded context distance compounds the FP surface. Consider word-boundary keyword matching and/or a proximity window.

### LOW-1 — Entropy finding spans include leading brackets

Trailing punctuation is trimmed but leading `{`, `(`, `[` are neither skipped nor trimmed (`SKIP_CHARS` in `entropy.rs:52` excludes them while `trim_end_matches` removes their closing partners):

```text
password={J8sK…C0dE}  => span "{J8sK…C0dE"
password=(J8sK…C0dE)  => span "(J8sK…C0dE"
password=[J8sK…C0dE]  => span "[J8sK…C0dE"
```

No secret leakage (findings are hashed); span hygiene only.

### LOW-2 — Canonical AWS fixture suppression is hardcoded in the engine, not the pack

`KNOWN_SAFE_EXAMPLES` (`entropy.rs:59`) embeds a pack-level documentation decision inside the engine module. Suppression is exact-match only — verified variant `…EXAMPLEKEZX` is still flagged — so behavior is safe, but layering belongs in pack config if this pattern ever grows.

### LOW-3 — Compact E.164 without contextual prose is missed

`"+15551234567"` and `"To: <sip:+15551234567>"` produce no finding (branch 1 requires a separator after the country code; rule 2 requires context). With any `phone`/`tel` keyword present it is caught (span drops the `+`). Recall tradeoff, documented format coverage should state this.

## What held up under attack

- Unknown validators (`payment-cardx`, `PAYMENT-CARD`, `luhn `, `shannon-entropy>abc`, `shannon-entropy=>4`) all abort `EngineBuilder::build()` with a contextual error; runtime lookup fails closed.
- Allowed examples suppress only their exact value; padded variants (`sk-EXAMPLE…0000`, `xoxb-EXAMPLE…01`) are detected; control test proves each example exercises its real pattern.
- PAN identity across 13/14/15/16/19-digit Visa/MC/Amex/Diners/Discover/JCB/UnionPay: always `pii.credit_card`, never downgraded under `phone` context; grouped formats (`4222 2222 22222`, `3400-000000-00009`, per-digit dashes/spaces, `+` prefixed incl. exactly-38-char maxLength edge) detected. Non-PAN 13-digit (`5222222222222`, Luhn-invalid) and 16-digit `6221269577067432` (Luhn-invalid) correctly remain phones/nothing.
- Repeated-digit strings (`0000000000000`, `1111111111111111`, `8888888888888888`), overlong 20/24-digit runs, IDs/timestamps, PAN substrings glued inside base64/hex tokens (`\b` blocks partial credit) — all produce zero findings.
- Entropy separators: tab/newline/quote/colon forms each emit exactly one exact-span finding; trailing `. , ; : ) ]` excluded; duplicate auth-keyword variants emit one finding; hex SHA-256 near `hash=` correctly not flagged.
- Multi-label accounting (openai+bearer vs entropy) uses distinct flags with identical spans — both credited, no double-count games.
- Negative-corpus accounting: per-case zero-findings assert + per-flag FP increment on every unmatched finding; no decrement/exclusion path; unregistered flags panic.

## Gate disposition

F1.2 attempt 4's *stated claims* (pack identity binding, honest per-flag accounting, contextless signatures, PAN/phone precedence, exact spans, AWS fixture handling, unknown-validator fail-closed) are all reproduced and hold. However HIGH-1 is a reachable panic in the frozen `entropy.rs` shipped scan path, and MED-1/2/3 are material precision/recall gaps in the shipped pack that the finite corpus does not cover. Per fix-plan §0.7 (security panel must PASS) and the final gate criterion ("todos los PoCs de seguridad fallan de forma segura" — this PoC crashes instead of failing safely), **attempt 4 does not earn panel sign-off**. Recommend repair attempt 5: char-boundary-safe window slicing (High), IP-aware phone branch or octet guard (Med), separator class extension for PANs (Med), word-boundary/proximity context matching (Med). Add regression probes above to the permanent suite.
