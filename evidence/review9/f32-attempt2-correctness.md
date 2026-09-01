# Evidence Pack — review9 / F3.1+F3.2 attempt 2 — CORRECTNESS lens (independent adversarial re-verification)

- Unit: **F3.1 + F3.2** (R9-11 per-upstream mode, R9-12 ClosedOnCritical default, R9-13 multipart MVP decoder, R9-20 wire-name fix)
- Candidate: commit **c532732** (branch `r9-remediation`, parent `7519ad9`) — the FIX attempt 2 that had to close round-1 findings F-1/F-2 (correctness lens) and P1-1/P1-2/P1-3/P2-1/P2-2 (security lens)
- Attempt: 2 (re-verification)    Lens: **CORRECTNESS** (independent reviewer; did not build; blind to the sibling security-lens report of this round)
- Date: 2026-09-01    Host: Apple M4 Pro, macOS (darwin) — verification worktree `/var/folders/.../opencode/f32-attempt2-correctness` (detached HEAD c532732, never modified — `git status` clean at the end)
- Method: §8B — every gate RE-RUN by this reviewer + the round-1 attacks REPRODUCED against the fixed candidate through the REAL pipeline (`spawn_proxy` → `proxy_handler` → byte-capturing upstream) in a throwaway crate outside the repo. No repo code/test/threshold was touched. "Couldn't run" never occurred.

---

## Commands run (verbatim, exit codes)

| # | Command | Exit | Result |
|---|---|---|---|
| 1 | `git -C /Users/alexeirojas/Work/Personal/Cerberus worktree add --detach /var/folders/.../opencode/f32-attempt2-correctness c532732` | 0 | worktree at c532732 |
| 2 | `rtk cargo fmt --all -- --check` | 0 | clean |
| 3 | `rtk cargo clippy --workspace --all-targets -- -D warnings` | 0 | `No issues found` |
| 4 | `rtk cargo test --workspace --all-targets` | 0 | **753 passed; 0 failed** (25 suites, 51.6 s) — matches the builder's claim exactly |
| 5 | `rtk cargo test -p cerberus-packs --test production_pack_pr` | 0 | **19 passed** |
| 6 | `uptime` + `cargo test --release --test load_test -- --test-threads=1 --nocapture` | 0 | **14 passed; 0 failed**. Honest HTTP gate: `proxy p50=0.723ms p95=0.822ms p99=0.908ms`, `direct p99=0.182ms`, `overhead_p99=0.726ms strict_p99_budget_ms=5.0 result=PASS`, fingerprint `sha256:e3f206dd25ecce9adfdd7b16f752e64f4db75faf7f51677f3214f62ff1667022` **unchanged**. Many-leaf gate green (p99 0.296 ms @64 leaves / 0.394 ms @512). Load average at run: **9.16 / 8.56 / 6.45** (heavier than the builder's 4.x runs) — still well under budget |
| 7 | `cargo test -p cerberus-proxy --test smoke_harness -- f1_repro… multipart_context_keyword… multipart_keyword_in_part_metadata… multipart_preamble_epilogue… multipart_block_secret… multipart_binary_claimed… closed_on_critical_fail_open_is_audited… closed_on_critical_reject_is_audited… shadow_mode_events_carry… --test-threads=1 --nocapture` | 0 | **9 passed** (all new attempt-2 pipeline tests) |
| 8 | `cargo test -p cerberus-proxy --lib forward::tests -- connect_tls_per_upstream` | 0 | **22 passed** — incl. `connect_tls_per_upstream_mode_resolves_by_url_host_and_never_silently_shadows` and `connect_tls_per_upstream_shadow_mode_never_blocks_on_mitm_path` (both ok), plus the full MITM fail-policy loop for all three policies |
| 9 | throwaway crate `/var/folders/.../opencode/adv-f32a2` (path-dep on the candidate's `cerberus-proxy`/`cerberus-engine`/`cerberus-store`): `cargo test --test adv -- --test-threads=1 --nocapture` | 0 | **10 passed / 0 failed** — 11 adversarial probes (adv5+adv5b are the JSON-analog pair), outputs quoted below |
| 10 | `cargo test -p cerberus-proxy --test smoke_harness -- per_upstream closed_on_critical multipart a1_yaml auth_header_wire` | 0 | **19 passed** (attempt-1 acceptance filter set) |
| 11 | `cargo test -p cerberus-proxy --lib config::` | 0 | **23 passed** (round-trips, parse validation, wire names) |
| 12 | `cargo test -p cerberus-hardening --test failsafe -- fail_policy` | 0 | 1 passed (`fail_policy_default_is_closed_on_critical`) |
| 13 | `cargo test -p cerberus-proxy --lib json_redact -- multipart` / `--lib decoder -- multipart` | 0 | **37 / 38 passed** |
| 14 | `git diff 7519ad9..c532732` (read-only inspection) + file reads of `json_redact.rs`, `proxy.rs`, `decoder.rs`, `engine.rs`, `redact.rs`, `constraints.rs` at the candidate | 0 | 8 files, +1677/−128 — one-scan-pass architecture verified in source (see task c below) |
| 15 | `git -C …/f32-attempt2-correctness status --short` | 0 | empty — the candidate tree was never modified |

---

## Per-criterion verdicts

| Criterion | Verdict | Evidence (this reviewer's runs) |
|---|---|---|
| Gate 1 fmt | ✅ PASS | run 2, exit 0 |
| Gate 2 clippy `-D warnings` | ✅ PASS | run 3, exit 0 |
| Gate 3 workspace tests (builder claims 753) | ✅ PASS | run 4: **753/0** — exact match |
| Gate 4 production pack | ✅ PASS | run 5: 19/19 |
| Gate 5 load suite release serial + honest HTTP gate | ✅ PASS | run 6: 14/14; p99 **0.908 ms** < 5.0 strict; drift-guard fingerprint identical; F2 many-leaf perf intact inside the same run |
| **(a) F-1 closure** — original exploit + unanticipated variants through the REAL pipeline | ✅ PASS | adv1 (exact attempt-1 shape) → **403, nothing forwarded**; adv2 (keyword in **epilogue**) → 403; adv3 (**critical REDACT rule**, keyword in header) → 200, both secrets `[REDACTED]`, no failure; adv4 (allowlist-armed block value on multipart) → 200 with **no redaction failure manufactured**; adv9 (cross-part payload keyword, block direction) → 403. Never 200-with-raw for a non-allowlisted critical-rule match on multipart |
| **(b) F-2 closure** — region-isolation model, no pipeline-visible multiline finding can vanish from redaction | ✅ PASS | adv6 (multiline rule matching **within one region**, embedded newline) → decision sees it AND redaction redacts it; adv7 (multiline match spanning the `\n` join of two parts) → matched by **neither** decision nor redaction, no event claims a redaction, no failure state — consistent blindness exactly as documented (updated limit #2); adv8 (default-pack-style multiline PEM **block** rule, full PEM inside one part) → 403 — the engine's multiline pass runs on every scan entry point (engine.rs:610–624), so region-local multiline is never under-scanned. No silent non-redaction found: the redaction consumes the very findings the decision was made from |
| **(c) ONE-SCAN-PASS architecture** — `redact_multipart` does NO scanning of its own | ✅ PASS | Source-verified: the only `engine.scan*` calls in `json_redact.rs` are the authoritative `scan_multipart_regions` (:146) and the pre-existing JSON leaf scan (:306). `redact_multipart` (:202–230) splices the caller-supplied `MultipartScan` findings verbatim; when the pipeline calls the 7-arg `redact_body_with_multipart_scan` (the only production path — proxy.rs:710–719 decision view, :793+ redaction) there is no second scan. The 6-arg `redact_body` convenience form (tests/load_test only) does an identical local self-scan with an **empty allowlist** — over-redact direction only |
| **(d) Builder's new tests are genuinely pipeline-layer** | ✅ PASS | Read the test source: all 9 smoke_harness tests drive `spawn_proxy` + `reqwest` + a byte-capturing mock upstream (assertions on status, captured upstream body, and audit events); the two P1-2 tests drive real CONNECT tunnels in `forward.rs`. None call `redact_body` directly. All pass (runs 7–8) |
| **(e) Regression** — F2 single-parse; config round-trips; R9-11/12/20 acceptance | ✅ PASS | Many-leaf gate green inside run 6; `redact_json` consumes `decoded.parsed` (json_redact.rs:79 — no re-parse); config:: 23/23 incl. round-trips (run 11); harness acceptance filter 19/19 (run 10); failsafe default-policy test green (run 12); MITM fail-policy loop all three policies (run 8); 503 upstream-failure cell intact (proxy.rs:974) |
| **(f) Allowlist-semantics change** — documented, tested, matches the pre-existing text path | ✅ PASS | Documented as updated limit #3; tested by the builder's `multipart_authoritative_scan_is_the_single_consistent_model` (in gate 3) and re-proved by me end-to-end: adv4 (multipart) and adv4b (**text-path control**) behave **identically** — an allowlisted value is neither flagged nor redacted, the other secret is redacted, 200, and no failure is manufactured. The deliberate JSON-leaf difference (leaf re-scan still over-redacts allowlisted values) is pre-existing and disclosed in the same limit — not a new inconsistency |

---

## Round-1 findings closure table

| Round-1 finding | Original attack | Reproduction outcome on c532732 | Verdict |
|---|---|---|---|
| **F-1 (P1, correctness)** scan-context asymmetry → critical-rule match routed into fail-open, raw forwarded under the DEFAULT policy (attempt-1 adv1: 200, `raw_block_secret_reached_upstream=true`) | Exact adv1 payload re-run through the real pipeline: critical BLOCK rule, keyword `harmlessword=` ONLY in part-2's header, low-redact secret in part-1 | **adv1: 403 Forbidden, upstream received nothing**, event `("block", ["test.lowredact","test.critblock"])` — the rule fires in the DECISION because the decision view now comes from the same authoritative per-region scan with `keyword_anywhere` over the full body | ✅ **CLOSED** |
| F-1 variant: keyword in **epilogue** (not header) | builder did not ship this variant | **adv2: 403, nothing forwarded** (epilogue is a scanned region since P1-1 fix; full-body analyzer validates) | ✅ CLOSED |
| F-1 variant: **different rule kind** — critical REDACT rule, keyword only in a part header | builder did not ship this variant | **adv3: 200** with BOTH secrets `[REDACTED:test.ctxredact]` / `[REDACTED:test.lowredact]`, structure intact, **no** `redact-failed` flag (decision saw the critical finding; redaction consumed the same finding and succeeded) | ✅ CLOSED |
| F-1 variant: the original **failure mechanism** (allowlist-armed block value) on multipart | builder did not ship this multipart variant | **adv4: 200**, non-allowlisted secret redacted, allowlisted value forwarded (operator decision), and — decisive — **no redaction failure can be manufactured**: the authoritative pass applies the allowlist end to end, so no re-scan the policy cannot see exists | ✅ CLOSED |
| **F-2 (P2, correctness)** cross-join multiline matches visible to the pipeline but to no region → silent non-redaction | Multiline redact rule matching across the `\n` join | **adv7: the match is now visible to NEITHER** — no finding, no event claims a redaction, no failure state (200 raw, consistent by construction, documented limit #2); **adv6: a region-local multiline match (the only kind that exists under the model) is visible to BOTH and gets redacted**; **adv8: default-pack-style multiline PEM block rule inside one part → 403** (multiline pass runs on every scan entry point — no under-scan regression vs the old joined view) | ✅ **CLOSED** (documented consistent model; no silent non-redaction possible) |
| **P1-1 (security)** preamble/epilogue/part headers never scanned (silent under-scan) | attempt-1 A2/A3/A12 probes | Regions now cover all four kinds (decoder.rs `RegionKind`); builder tests `multipart_preamble_epilogue_and_header_secrets_never_forward_raw` (200 + zero raw) and `multipart_block_secret_in_part_header_blocks_via_pipeline` (403) pass in run 7; my adv2 independently confirms an epilogue keyword drives the decision | ✅ **CLOSED** |
| **P1-2 (security)** per-upstream mode silently inert on the MITM path (enforce could silently shadow) | attempt-1 forbidden-state probe | `mitm_provider_of` resolves CONNECT host → upstream whose `url` host matches (deterministic tiebreak); both MITM tests pass in run 8, incl. the exact forbidden state (global shadow + per-upstream enforce → **403, nothing forwarded**) and the reverse (per-upstream shadow under global enforce → intact pass) | ✅ **CLOSED** |
| **P1-3 (security)** cross-part context keywords dead in the DECISION path; acceptance test at the wrong layer | attempt-1 A6/A6b | Decision now scans regions with `keyword_anywhere` over the full body; rewritten pipeline-layer tests pass (run 7); my adv9 confirms the **block** direction through the real pipeline (403) | ✅ **CLOSED** |
| **P2-1 (security)** binary-claimed parts carry text secrets raw — silently | attempt-1 A4/A5 | `binary_parts_skipped` counted per payload; `binary-unscanned` audit flag + WARN + visibility event with zero findings; `multipart_binary_claimed_part_under_scan_is_audited` passes (run 7). Byte-exact preservation unchanged (plan trade-off) | ✅ **CLOSED** (made visible; trade-off kept per plan) |
| **P2-2 (security)** fail-open audited as plain `action_taken:"redact"` | attempt-1 C2/C4 | `RedactDecision::FailOpenForward` variant; my adv5b independently observed a real fail-open forward audited as `("fail-open", ["test.lowredact","redact-failed"])`; adv3 confirmed a successful redaction is NOT flagged; 502 rejects audited `("fail-closed", …)`; shadow events carry the `shadow` flag (builder tests, run 7); forward.rs loop asserts flags for all three policies (run 8) | ✅ **CLOSED** |
| **P3-1 (security)** boot config parse errors swallowed | attempt-1 probe | `load_proxy_config_from` now logs the real serde error at ERROR with the fail-closed consequence (code-read; behavior unchanged, fail-closed); workspace suite green | ✅ CLOSED (log-only fix, as scoped) |
| **P3-2 (security)** mode/provider TOCTOU across two config reads | theoretical | Accepted residual, unchanged and documented in the pack — out of this fix round's scope | ☑ unchanged (accepted) |

---

## Attack vectors tried (all executed as live tests through the real pipeline)

1. **adv1 — F-1 original exploit shape**: critblock (critical, `contextKeywords: ["harmlessword="]`) + lowredact; keyword only in part-2 header. → **403, nothing forwarded** (was 200-raw in attempt 1).
2. **adv2 — keyword in the EPILOGUE** instead of a header. → **403** (epilogue is now a scanned region and the analyzer context is the full body).
3. **adv3 — critical REDACT rule (different rule kind), keyword only in a part header.** → **200, both secrets redacted**, no `redact-failed` flag, structure intact.
4. **adv4 — the F-1 failure mechanism (allowlist-armed block value) on multipart.** → **200, no failure manufactured**; allowlisted value raw (operator decision), other secret `[REDACTED]`. This is the updated limit #3 semantics.
5. **adv4b — text-path control** for the same shape. → identical behavior to adv4 (multipart now matches the pre-existing text path exactly).
6. **adv5 / adv5b — JSON-path analog of F-1** (keyword in a JSON key name; keys are absent from `decoded.text` per `json_to_string`, present in the leaf re-scan's full-body analyzer). See Residual R-1 below — the analog **persists** (pre-existing surface, outside this unit).
7. **adv6 — region-local multiline redact rule** (pattern contains `\n`, payload carries an embedded newline). → visible to decision AND redaction; forwarded `[REDACTED:test.multiredact]`.
8. **adv7 — cross-join multiline redact rule** (match exists only across the `\n` join of two parts). → visible to NEITHER; no event claims a redaction; no failure state; 200 raw. Consistent blindness, exactly the documented model — the attempt-1 "decision says redact, redaction cannot splice" state is unreachable because both views are the same per-region findings.
9. **adv8 — default-pack-style multiline PEM block rule, complete PEM inside ONE part.** → **403** (the engine's multiline pass runs in `scan_inner_prepared_with_presence` for every entry point — no under-scan vs the old joined view).
10. **adv9 — cross-part payload keyword, block direction** (attempt-1 A6b shape). → **403**.
11. **Code-level hunts**: (i) `multipart_scan_output` dedup collapses identical (flag,start,end) across regions — decision direction only, redaction still redacts every region (over-redact direction, safe); (ii) `redact_multipart` trusts a caller scan by **length only** (`s.findings.len() == regions.len()`) — see Residual R-3 (latent API footgun, not reachable in-repo); (iii) allowlist slicing on the region-relative raw value is bounds-checked and trim/exact — same semantics as the text-path filter; (iv) lossy-UTF8 determinism between scan and redact over the same region bytes — spans cannot drift; (v) `decoded.text` for multipart is now informational only — no joined-text scan remains anywhere in the pipeline.

### Key probe outputs (verbatim)

```
adv1 status=403 Forbidden captured_empty=true
adv1 flags=[("block", ["test.lowredact", "test.critblock"])]
adv2 status=403 Forbidden captured_empty=true
adv3 status=200 OK forwarded=… [REDACTED:test.lowredact] … [REDACTED:test.ctxredact] …
adv3 flags=[("redact", ["test.lowredact", "test.ctxredact"])]
adv4 status=200 OK … BLOCKSECRET1gggggggggggg (allowlisted, raw, operator decision)
adv4 flags=[("redact", ["test.lowredact"])]          ← no redaction failure manufactured
adv5  status=200 OK forwarded={"harmlessword=x":"BLOCKSECRET1cccccccccccc","note":"[REDACTED:test.lowredact]"}
adv5b status=200 OK forwarded={"harmlessword=x":"BLOCKSECRET1cccccccccccc","note":"REDACTSECRET2dddddddddddd"}
adv5b flags=[("fail-open", ["test.lowredact", "redact-failed"])]   ← honest audit works even here
adv6 status=200 OK forwarded=… [REDACTED:test.multiredact] …      ← region-local multiline redacts
adv7 status=200 OK forwarded=… AAA-1234 … BBB-5678 …  adv7 flags=[] ← cross-join: consistent blindness
adv8 status=403 Forbidden captured_empty=true                     ← PEM in one part still blocks
adv9 status=403 Forbidden captured_empty=true
```

---

## Findings

### R-1 [P2 — RESIDUAL, PRE-EXISTING, NOT a regression of this unit] The JSON-path analog of F-1 persists: a keyword hidden in a JSON key name can still route a critical-rule match into the fail-open branch (or bypass it silently) on the JSON leaf path
- **What**: adv5b — JSON body `{"harmlessword=x":"BLOCKSECRET1…","note":"REDACTSECRET2…"}` with a critical block rule gated by keyword `harmlessword` (word-boundary-matching the key). The pipeline scan runs over `decoded.text` = string VALUES only (`json_to_string`, decoder.rs:175-190 — keys excluded), so the rule never fires in the decision; the JSON leaf re-scan (`redact_value`, json_redact.rs:306) evaluates keywords against the FULL body analyzer (keys included), fires the block rule, `apply_redaction` errors, and the default policy — seeing only the non-critical pipeline findings — fail-opens: **200 with both secrets raw**. A second spelling (adv5, keyword `harmlessword=`) fails the word-boundary check against `"harmlessword=x"` (trailing `x`), so the leaf re-scan does not fire either and the critical-rule secret passes **raw with no finding, no event, no flag** — fully silent.
- **Why it does NOT block this unit**: the mechanism predates the unit (verified at parent `fac8236` in round 1 via `git show`; the leaf scan and `json_to_string` are byte-identical between 71c5939 and c532732 — this diff touched only the multipart machinery). Round 1 explicitly scoped F-1 to the multipart surface this unit introduced, and that surface **is** closed. The P2-2 fix at least makes the failure-mechanism variant honest now (adv5b shows `("fail-open", ["test.lowredact","redact-failed"])`).
- **Recommendation**: file as its own R9 finding for the JSON path (fix shape: give the pipeline's JSON scan the same full-body keyword context the leaf re-scan uses, or judge criticality on the leaf re-scan view). Updated limit #3's wording ("fails closed iff the request carries non-allowlisted critical findings visible to the authoritative scan") overstates the property for JSON — worth a doc amendment either way.

### R-2 [P3 — behavior delta, documented, accepted] Cross-region matches are no longer OVER-blocked
The old joined view could 403 on a pattern spanning two parts (over-block direction). The region-isolation model removes that (adv7). Consistent by construction and documented as updated limit #2; shipped-pack impact is limited to a PEM/OPENSSH key deliberately split across parts (contrived). Accepted — noting it so the panel sees the deliberate over-block removal, not just the under-scan framing.

### R-3 [P3 — latent, not reachable in-repo] `redact_multipart` trusts a caller-supplied scan by LENGTH only
json_redact.rs:212: `scan.is_some_and(|s| s.findings.len() == regions.len())`. A `MultipartScan` built from *different* regions with the same count would be consumed with mismatched offsets. The only production call site passes the scan built from the very same `decoded.multipart` vector (proxy.rs), so this is unreachable today; the doc-comment claims region identity is checked but the code checks only length. Suggestion: compare region offsets (first/last + count) before trusting a caller scan. Defensive hardening only.

### No other findings
Every other vector came back exactly as the pack documents: the gates are genuinely green (753/0 reproduced), the honest HTTP gate reproduces under heavier load (9.16) at p99 0.908 ms with the identical fingerprint, `tests/load_test.rs` is untouched, the worktree was returned clean.

---

## Final verdict: **PASS** (round-1 P1s closed; unit returns to the F3 phase gate for sign-off)

All five gates pass independently (fmt clean; clippy clean; **753/0** workspace — exactly the builder's count; **19/19** production pack; **14/14** load suite with the honest HTTP gate at p99 **0.908 ms** < 5.0 strict and the drift-guard fingerprint unchanged, the F3.3 latency work not regressed even under a load average of 9.16). The decisive round-1 finding **F-1 is closed**: the one-authoritative-scan architecture is real in source (the redaction splices the very findings the decision was made from — no second scan exists on the multipart path), and the original adv1 exploit now yields **403 with nothing forwarded**; my three unanticipated variants (keyword in the epilogue, a critical *redact* rule, the allowlist-armed failure mechanism) all behave consistently, and no 200-with-raw state exists for a non-allowlisted critical-rule match on multipart. **F-2 is closed as a documented consistent model**: region-local multiline matches are visible to both decision and redaction (adv6, adv8 with a default-pack-style PEM rule), cross-region matches are visible to neither (adv7) — the silent non-redaction state (decision promises, redaction cannot) is unreachable by construction. The security lens's P1-1/P1-2/P1-3/P2-1/P2-2 closures all reproduce green at the pipeline layer, the acceptance tests genuinely drive `spawn_proxy → proxy_handler` (I read them before running them), and the allowlist-semantics change is documented, tested, and byte-for-byte consistent with the pre-existing text path (adv4 == adv4b). One pre-existing residual survives — the JSON key-name keyword analog of F-1 (R-1, P2), which predates this unit, was scoped out in round 1, and is now at least honestly audited in its failure form — plus two P3 notes (deliberate over-block removal; a latent length-only authority check). None of these blocks the unit's own surface. Per §8B, F3.1+F3.2 attempt 2 **passes independent correctness re-verification** and proceeds to the phase gate.

## Verification hygiene

- Worktree created detached at c532732 and removed after the review; only file created in the main repo: this report.
- No repo code, tests, or thresholds touched (`git status` clean in the worktree before removal). All adversarial code lives in `/var/folders/.../opencode/adv-f32a2` (throwaway, outside the repo).
- The sibling security-lens report of THIS round was never read (blind review maintained).
