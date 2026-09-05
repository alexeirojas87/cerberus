# Evidence Pack — F9.A / R9-21 JSON key-name context asymmetry

- Unit: F9.A — R9-21 (registered by the F3 re-verification panel)
- Builder status: **FIX executed — returns to VERIFY**
- Base HEAD: `0ee508a` (branch `r9-remediation`, clean)
- Attempt: 1 (branch `r9-f9a-attempt1`, isolated worktree, NOT pushed)
- Date: 2026-09-04 · Host: macOS arm64 (Apple M4 Pro) · `rustc/cargo 1.97.1`
- Builder: the orchestrator gatekeeper (inline) after TWO sub-agent transport
  failures at startup; one mid-build file corruption (a bad splice during
  debug-instrumentation removal) was recovered via git checkout + re-application
  of the two affected files.

## The finding (R9-21)

The JSON analog of the multipart F-1: a `contextKeywords` match can fire in
the JSON LEAF re-scan while the pipeline DECISION path misses it. Two shapes
documented by the F3 panel (evidence/review9/f32-attempt2-correctness.md):
adv5b (leaf-re-scan fires → fail-open under the default policy → raw
forwarded) and adv5 (word-boundary miss on the key → silent raw pass).

## Plan-reading decision (§4.2, documented)

Detection covers "all textual content" — key names included (the flat-text
scan is retained and stays part of the decision view). Redaction splices only
leaf substrings (in-place, structure-preserving, per §4.2's "replace the
substrings that match, preserving the surrounding JSON/byte structure").

## Design (the F3.1/F3.2 one-scan-pass model extended to JSON)

1. `JsonScan` + `scan_json_leaves` (json_redact.rs): ONE authoritative
   per-leaf scan pass — every string leaf scanned in document order with
   `scan_with_context_analyzer` against ONE `ContextAnalyzer` over the full
   lossy body; the operator allowlist applied per leaf on the leaf-relative
   raw value (HMAC fingerprints, R9-7 semantics).
2. `json_decision_output(flat, scan)`: the pipeline decision view =
   flat-text scan UNION leaf findings, deduped by `(flag, hashed_value)`,
   action_overall = precedence max. Leaf-only findings carry leaf-relative
   spans (documented artifact: flag/category/severity/action/hash are exact).
3. `AuthoredScan` enum: the redaction receives the ONE pass the decision was
   made from (`redact_body_with_scan(..., AuthoredScan::Json/Multipart/None)`)
   — the splice phase (`splice_json_value`) consumes the pre-collected leaf
   findings and performs NO scan of its own.
4. Fail-closed under-redaction: a decision finding with a Redact action that
   NO leaf carries (e.g. a multiline match spanning two leaves) cannot be
   redacted in place without corrupting the schema — the redaction returns
   Err and the fail-policy decides (Closed/ClosedOnCritical+critical → 502;
   Open → honest fail-open). Silent under-redaction is impossible.

## Behavior deltas (documented)

1. **Allowlist authoritative on JSON leaves** (was: JSON leaf re-scans were
   unfiltered and over-redacted allowlisted values — the F3.1/F3.2 pack
   documented that exception; this fix aligns JSON with the multipart/text
   model). Consequence: the old tests' redaction-failure mechanism (an
   allowlisted value's block finding reaching the unfiltered leaf scan) no
   longer exists; those tests were re-semantized to the honest
   cross-leaf mechanism (below).
2. **Cross-leaf redact findings fail closed** instead of silently passing.
3. adv5 (word-boundary miss on the key): DOCUMENTED, not fixed — the
   keyword does not fire on EITHER surface (both decision and redaction see
   the same absence — no divergence); it is regex word-boundary semantics,
   not a scan inconsistency.

## Tests (pipeline layer, spawn_proxy → proxy_handler)

- `r921_keyword_in_json_key_blocks_via_pipeline`: adv5b block shape — the
  keyword ONLY in a JSON key name, on a different line from the match
  (flat same-line window misses; analyzer keyword_anywhere does not) → 403,
  nothing forwarded. Pre-fix: 200 raw.
- `r921_keyword_in_json_key_redacts_via_pipeline`: adv5b redact shape — the
  context-validated secret is redacted (`[REDACTED:test.ctxredact]`), the
  redaction splices the SAME findings the decision saw.
- `r921_cross_leaf_redact_finding_fails_closed`: the decision sees a
  cross-leaf REDACT match no leaf carries → 502 fail-closed, nothing
  forwarded. Pre-fix: silent raw pass.
- `r921_*` plus re-semantized `closed_on_critical_*` (fail-open/reject now
  exercised through the honest cross-leaf mechanism) and the forward.rs
  `connect_tls_redaction_failure_obeys...` (authoritative-allowlist
  semantics: allowlisted value passes untouched, non-allowlisted redacted,
  no failure to fail-open over).

## Verification matrix

| Command | Exit | Result |
|---|---|---|
| `cargo fmt --all -- --check` | 0 | clean |
| `cargo clippy --workspace --all-targets -- -D warnings` (un-piped) | 0 | 0 issues |
| `rtk cargo test --workspace --all-targets` (debug) | 0 | **868 passed / 0 failed** |
| `rtk cargo test -p cerberus-packs --test production_pack_pr -- --test-threads=1` | 0 | **19/19** |
| `rtk cargo test --release --test redos_fuzz -- --test-threads=1` | 0 | **11/11** |
| `rtk cargo test --release --test load_test -- --test-threads=1` | 0 | **14/14** |
| honest HTTP gate (release, 2,000 samples) | 0 | PASS: proxy p99 **1.219 ms** vs strict 5.0 ms; fingerprint `e3f206dd…7022` UNCHANGED |
| JSON many-leaf gate | 0 | 64-leaf p99 0.252 ms / 512-leaf p99 0.383 ms (budget 5 ms) |
| `rtk git diff --check` | 0 | clean |

## Builder verdict

**FIX executed — returns to VERIFY.** The unit is NOT closed; per §8B closure
requires the independent panel and the F9 phase gate sign-off.
