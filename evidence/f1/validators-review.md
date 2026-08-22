# Evidence Pack: Phase 1 — Validators Review (REVIEWER 1 — correctness)

**Reviewer:** REVIEWER 1 (correctness)
**Date:** 2026-08-17
**Worktree:** `cerberus-wt-f1-review-validators`
**Branch:** `f1/review-validators`

---

## Verdict summary

| Criterion | Status | Evidence |
|---|---|---|
| 1. `cargo build --workspace` | ✅ PASS | Compiles without errors |
| 2. `cargo test -p cerberus-engine` (164 tests) | ✅ PASS | 115 unit + 38 adversarial + 11 integration — all OK |
| 3. `cargo clippy -p cerberus-engine --all-targets -- -D warnings` | ✅ PASS | No warnings |
| 4. `cargo fmt --check` | ✅ PASS | No format errors |
| 5. `Validator` trait well-defined | ✅ PASS | Minimalist and correct interface: `fn validate(&self, value: &str) -> bool` |
| 6. Luhn: valid/invalid | ✅ PASS | "4111111111111111" → true; "1234567812345678" → false |
| 7. Luhn: edge cases | ✅ PASS | non-digits, too short, too long, only non-digits, hyphens, alpha around |
| 8. Shannon entropy: correct calculation | ✅ PASS | "aaaa"=0.0, "ab"=1.0, unicode, repeated patterns, empty=0.0 |
| 9. Shannon entropy: threshold > vs >= | ✅ PASS | `above(1.0)` fails on "ab", `at_least(1.0)` passes on "ab" |
| 10. IBAN/checksum valid | ✅ PASS | BE and GB valid; invalid check digit, lowercase, special chars, too short/long |
| 11. `get_validator` factory | ✅ PASS | luhn, checksum, shannon-entropy, shannon-entropy>N, shannon-entropy>=N → Some; nonexistent, empty → None |
| 12. `ValidatorRegistry.all_pass` | ✅ PASS | empty list → true; unknown → fail closed; mixed → fail closed; all pass → true |
| 13. Engine integration: validators filter findings | ✅ PASS | `make_finding()` runs validators after regex match; if they fail, the finding is discarded (`None`) |
| 14. Unknown validator fail-closed | ✅ PASS | `all_pass` with `"nonexistent"` returns `false` |

**FINAL VERDICT: ✅ PASS**

---

## 1. Compilation and toolchain

```bash
$ rustc --version
rustc 1.97.1 (8bab26f4f 2026-07-14)

$ cargo build --workspace 2>&1 | tail -5
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 8.06s

$ cargo test -p cerberus-engine 2>&1 | grep "^test result:"
test result: ok. 115 passed; 0 failed   # unit tests
test result: ok. 38 passed; 0 failed    # adversarial (new)
test result: ok. 11 passed; 0 failed    # integration tests
test result: ok. 0 passed; 0 failed     # doc tests

$ cargo clippy -p cerberus-engine --all-targets -- -D warnings 2>&1 | tail -3
    Finished `dev` profile [unoptimized + debuginfo]

$ cargo fmt --check 2>&1 | wc -l
0   # no output = no errors
```

---

## 2. Analysis of the `Validator` trait (`validator.rs:15-18`)

```rust
pub trait Validator {
    fn validate(&self, value: &str) -> bool;
}
```

**Verdict: ✅ Correct.** Simple and generic interface. Takes `&str` (does not consume ownership), returns `bool`. Zero non-essential dependencies. The three implementations (`LuhnValidator`, `ShannonEntropyValidator`, `ChecksumValidator`) correctly fulfill the contract.

---

## 3. LuhnValidator — deep analysis

**Code:** `validator.rs:24-31`, implementation in `luhn_valid()` (lines 206-228).

| Test | Input | Expected | Actual | Result |
|---|---|---|---|---|
| Valid Visa | `"4111111111111111"` | true | true | ✅ |
| Valid MasterCard | `"5555555555554444"` | true | true | ✅ |
| Valid AmEx | `"378282246310005"` | true | true | ✅ |
| Random number | `"1234567812345678"` | false | false | ✅ |
| All zeros | `"0000000000000000"` | true | true | ✅ (degenerate but mathematically correct) |
| With hyphens | `"4111-1111-1111-1111"` | true | true | ✅ |
| Alpha around | `"card 4111111111111111 here"` | true | true | ✅ |
| Only 1 digit | `"1"` | false | false | ✅ |
| 2 invalid digits | `"12"` | false | false | ✅ |
| Only non-digits | `"abcdef"` | false | false | ✅ |
| 160 digits (10× repeated) | `"4111111111111111"*10` | true | true | ✅ |
| 14 valid digits | `"12345678903555"` | true | true | ✅ |

**Algorithm detail:** 
1. Filters non-digit characters (`filter(char::is_ascii_digit)`)
2. Requires ≥ 2 digits
3. Reverses, doubles every second digit (odd position in the reversed iterator), sums digits (for doubles > 9, sums `d*2 - 9`)
4. Verifies that the total sum is a multiple of 10 (`sum.is_multiple_of(10)` — stabilized in Rust 1.66)

**Verdict: ✅ Correct.** Canonical implementation without errors.

---

## 4. ShannonEntropyValidator — deep analysis

**Code:** `validator.rs:46-89`, function `shannon_entropy()` (lines 185-199).

| Test | Input | Expected entropy | Result |
|---|---|---|---|
| Empty | `""` | 0.0 | ✅ |
| 1 character | `"x"` | 0.0 | ✅ |
| 2 equal | `"aa"` | 0.0 | ✅ |
| 2 different | `"ab"` | 1.0 | ✅ |
| Unicode (3 chars) | `"日本語"` | log₂(3) ≈ 1.585 | ✅ |
| Repeated pattern | `"abababababababab"` | 1.0 | ✅ |
| Long low diversity | `"a"*10000 + "b"` | < 0.01 | ✅ |

**Formula:** H = -Σ p(c) · log₂ p(c), implemented with `p.mul_add(-p.log2(), acc)` which is numerically stable.

**Thresholds:**
| Test | Validator | Input | Expected | Result |
|---|---|---|---|---|
| above(4.0) rejects low | `above(4.0)` | `"aaaa"` | false | ✅ |
| above(4.0) accepts high | `above(4.0)` | `"J8sK4mL2pX9qR5vW1nB6tY3cD7fH0gA"` | true | ✅ |
| at_least(1.0) on boundary | `at_least(1.0)` | `"ab"` | true | ✅ |
| above(1.0) on boundary | `above(1.0)` | `"ab"` | false | ✅ |
| empty + above(0.0) | `above(0.0)` | `""` | false | ✅ (0.0 > 0.0 is false) |
| empty + at_least(0.0) | `at_least(0.0)` | `""` | true | ✅ (0.0 >= 0.0 is true) |

**Name parsing:**
| Name | Result | Threshold |
|---|---|---|
| `"shannon-entropy"` | `Above(3.0)` | ✅ |
| `"shannon-entropy>4.5"` | `Above(4.5)` | ✅ |
| `"shannon-entropy>=4.5"` | `AtLeast(4.5)` | ✅ |
| `"shannon-entropy=4.0"` | `None` | ✅ (invalid format) |
| `"shannon-entropy>"` | `None` | ✅ (empty threshold) |
| `"shannon-entropy>abc"` | `None` | ✅ (non-numeric) |

**Verdict: ✅ Correct.** Entropy calculation correct. > vs >= distinction correct. Robust name parsing.

---

## 5. ChecksumValidator (IBAN) — deep analysis

**Code:** `validator.rs:94-101`, function `iban_valid()` (lines 235-267).

| Test | Input | Expected | Result |
|---|---|---|---|
| Valid BE | `"BE68539007547034"` | true | ✅ |
| Valid GB | `"GB29NWBK60161331926819"` | true | ✅ |
| With spaces | `"BE68 5390 0754 7034"` | true | ✅ |
| Invalid check digit | `"BE68539007547035"` | false | ✅ |
| Lowercase | `"be68539007547034"` | false | ✅ |
| Empty | `""` | false | ✅ |
| Too short | `"DE123"` | false | ✅ |
| Too long (35+ chars) | `"DE89370400440532013000000000000000000000"` | false | ✅ |
| Special characters | `"BE68!5390?0754&7034"` | false | ✅ |
| Non-ASCII | `"BE68😀39007547034"` | false | ✅ |

**Algorithm:** Mod-97 (ISO 7064). Moves the first 4 characters to the end, converts A→10...Z→35, computes `n % 97`, the result must be 1.

**Verdict: ✅ Correct.** Complete and robust implementation.

---

## 6. Engine integration (`engine.rs`)

In `make_finding()` (engine.rs:258-276):

```rust
let trimmed = raw_value.trim();
if !self.validators.all_pass(&rule.validators, trimmed) {
    return None;  // finding discarded
}
```

**Flow:** `scan()` → regex match → `make_finding()` → `all_pass(validators, trimmed)` → if any validator fails → `None` (finding discarded).

| Test | Scenario | Result |
|---|---|---|
| No validators | Match is kept | ✅ |
| Luhn on valid number | Finding is kept | ✅ |
| Luhn on invalid number | Finding is discarded | ✅ |
| Shannon-entropy on high entropy | Finding is kept | ✅ |
| Shannon-entropy on low entropy | Finding is discarded | ✅ |
| Unknown validator | Fail closed — finding is discarded | ✅ |
| Multiple validators (all pass) | Finding is kept | ✅ |
| Multiple validators (one fails) | Finding is discarded | ✅ |

**Verdict: ✅ Correct.** Validators run after the regex match. If any validator fails, the finding is discarded. Fail-closed for unknown validators.

---

## 7. Edge cases covered by adversarial tests

File: `crates/cerberus-engine/tests/adversarial_validators.rs` (38 new tests)

**Categories covered:**
- **Luhn (12 tests):** Visa, MasterCard, AmEx, invalid, all zeros, with hyphens, alpha around, single digit, two digits, only non-digits, too long, 14 digits
- **Entropy (11 tests):** single char, two equal, two different, unicode, repeated pattern, very long low diversity, threshold reject/accept, at_least/above boundary, empty+above/at_least
- **IBAN (10 tests):** BE, GB, spaces, invalid check digit, lowercase, empty, too short, too long, special chars, non-ASCII + checksum validator delegate
- **Factory/Registry (5 tests):** 11 get_validator names, registry get, all_pass edge cases, all_pass multiple validators

---

## 8. Conclusion

The validators module meets all correctness criteria for Phase 1:

- The `Validator` trait is correctly defined
- `LuhnValidator` implements the ISO 7812 checksum correctly
- `ShannonEntropyValidator` calculates entropy correctly with > and >= thresholds
- `ChecksumValidator` implements IBAN mod-97 correctly
- `get_validator` and `ValidatorRegistry` resolve names correctly and fail-closed
- Integration with `engine.rs` runs validators after the regex match and discards findings that fail
- 38 new adversarial tests cover edge cases not covered by existing tests

**FINAL VERDICT: ✅ PASS**
