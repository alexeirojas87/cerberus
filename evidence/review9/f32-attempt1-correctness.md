# Evidence Pack — review9 / F3.1+F3.2 attempt 1 — CORRECTNESS lens (independent adversarial review)

- Unit: **F3.1 + F3.2** (R9-11 per-upstream mode, R9-12 ClosedOnCritical default, R9-13 multipart MVP decoder, R9-20 wire-name fix)
- Candidate: commit **71c5939** (branch `r9-remediation`, parent `fac8236`)
- Attempt: 1    Lens: **CORRECTNESS** (independent reviewer; did not build; blind to the security lens)
- Date: 2026-09-01    Host: Apple M4 Pro, macOS (darwin) — verification worktree `/var/folders/.../opencode/f32-attempt1-correctness` (detached HEAD 71c5939)
- Method: §8B — every gate RE-RUN by this reviewer (not trusted from the builder pack) + adversarial tasks (a)–(e) executed as live tests in a throwaway crate outside the repo. No repo code/test/threshold was modified. "Couldn't run" never occurred; every criterion below was executed.

---

## Commands run (verbatim, exit codes)

| # | Command | Exit | Result |
|---|---|---|---|
| 1 | `git -C /Users/alexeirojas/Work/Personal/Cerberus worktree add --detach /var/folders/.../opencode/f32-attempt1-correctness 71c5939` | 0 | worktree created at 71c5939 |
| 2 | `rtk cargo fmt --all -- --check` | 0 | clean |
| 3 | `rtk cargo clippy --workspace --all-targets -- -D warnings` | 0 | `cargo clippy: No issues found` |
| 4 | `cargo test --workspace --all-targets` | 0 | **734 passed; 0 failed** (25 suites) — matches builder's claim |
| 5 | `rtk cargo test -p cerberus-packs --test production_pack_pr` | 0 | **19 passed** |
| 6 | `cargo test --release --test load_test -- --test-threads=1 --nocapture` | 0 | **14 passed; 0 failed** — honest HTTP gate: `proxy p50=0.709ms p95=0.783ms p99=0.844ms`, `direct p99=0.164ms`, `overhead_p99=0.680ms strict_p99_budget_ms=5.0 result=PASS`, fingerprint `sha256:e3f206dd25ecce9adfdd7b16f752e64f4db75faf7f51677f3214f62ff1667022` (identical to builder/baseline). Load avg at run: 4.38 / 4.40 / 3.96 |
| 7 | throwaway crate `/var/folders/.../opencode/adv-correctness`: `cargo test` (7 adversarial tests) | 0 | 7 passed (incl. 2 leak probes) |
| 8 | `cargo test -p cerberus-proxy --test smoke_harness -- per_upstream closed_on_critical multipart a1_yaml auth_header_wire` | 0 | 12 passed |
| 9 | `cargo test -p cerberus-hardening --test failsafe -- fail_policy` | 0 | `fail_policy_default_is_closed_on_critical` ok |
| 10 | `cargo test -p cerberus-proxy --lib forward::tests -- connect_tls_redaction_failure connect_tls_invalid_json` | 0 | 25 + 20 passed (MITM fail-policy loops incl. `ClosedOnCritical`) |
| 11 | `cargo test -p cerberus-proxy --lib config:: -- fail_policy per_upstream_mode a1_yaml expected_auth default_config` | 0 | all passed |
| 12 | `cargo test -p cerberus-proxy --lib json_redact -- multipart` / `-- vault` | 0 | 33 / 11 passed |
| 13 | `cargo test -p cerberus-proxy --lib decoder -- multipart_records` | 0 | 30 passed |
| 14 | `git diff fac8236..71c5939` (read-only inspection, main repo) | 0 | 12 files, +2141/−69 — reviewed |

---

## Per-criterion verdicts

| Criterion | Verdict | Evidence (this reviewer's runs) |
|---|---|---|
| **R9-11** per-upstream `mode` parses + validates | ✅ PASS | adv5: `mode: shadow` parses from A.1-style YAML; `mode: bogus` → parse error (fail-closed); absent → `None` (inherit global) |
| R9-11 mixed fleet routes correctly (shadow never blocks; enforce enforces; global fallback) | ✅ PASS | harness `per_upstream_shadow_mode_never_blocks_in_mixed_fleet` + `per_upstream_enforce_mode_overrides_global_shadow` (both ok in run 8: 200 on `/shadowed/…` while default 403s; 403 on `/enforced` under global shadow); my adv6: unknown provider inherits global enforce |
| R9-11 mode survives config serialization + API | ✅ PASS | adv5 (YAML/JSON round-trip), adv7 (live `GET /api/config` reports `"mode":"shadow"`, `PUT` changes it to `"enforce"`, invalid mode → 400) |
| R9-11 MITM path parity | ✅ PASS | Single mode-read at proxy.rs:580-586 in `proxy_handler` AFTER provider resolution; `DirectUpstream` (MITM) flows through the same handler (proxy.rs:512); forward.rs MITM tests exercise all three fail policies on the TLS-intercept path (run 10) |
| **R9-12** `closed-on-critical` parses (+aliases), is DEFAULT | ✅ PASS | adv5: `fail_policy: closed-on-critical`, `closedoncritical`, and `fail_mode:` alias all parse; `default_config` + `fail_policy_default_is_closed_on_critical` (run 9); default asserted `ClosedOnCritical` |
| R9-12 decision table: critical failure → 502, raw never leaves | ✅ PASS (with P1 caveat below) | harness `closed_on_critical_rejects_redaction_failure_with_critical_findings` (502, upstream received nothing); forward.rs MITM loop: `ClosedOnCritical` → 502 on critical redaction failure |
| R9-12 decision table: non-critical failure → 200 + ORIGINAL forwarded | ✅ PASS | harness `closed_on_critical_forwards_original_for_non_critical_redaction_failure` (byte-exact assertion on captured upstream body); forward.rs MITM loop same behavior |
| R9-12 decision table: decode failure → closed (502) | ✅ PASS | harness `closed_on_critical_rejects_undecodable_json_body`; forward.rs `Closed | ClosedOnCritical → 502` |
| R9-12 decision table: upstream failure → 503 | ✅ PASS | proxy.rs:839-852 (`fail_policy == Open ? 502 : 503`) — code-verified; consistent with existing upstream-failure tests in gate 4 run |
| **R9-13** multipart text parts scanned with JSON-leaf context machinery | ✅ PASS | json_redact multipart tests (33 passed, run 12); my adv4a/j: secrets in multiple text parts redacted; keyword in another part validates (analyzer over full body) |
| R9-13 boundary robustness (quoted/special/long/missing/malformed) | ✅ PASS | adv4e/f/l: quoted boundary with `;`/space parses; 300-char boundary → Text over-scan; missing boundary → Text over-scan (secret still caught); builder's 12-entry malformed corpus passes in gate 3 |
| R9-13 binary parts byte-exact, not scanned; nested multipart declared-type-only | ✅ PASS | adv4h: `multipart/mixed` part NOT scanned (no recursion); adv4j: 256-byte all-values binary through decode+redact — byte-exact, boundaries intact, redacted body re-parses as multipart |
| R9-13 truncated bodies scan-to-EOF; part bomb → over-scan (never under-scan) | ✅ PASS | adv4c (truncated: last payload scanned); adv4g (4200 parts → Text fallback, secret in a LATE part still caught) |
| R9-13 redaction splicing correct (reverse order, multi-part, boundary-in-content) | ✅ PASS | adv4a (mid-line boundary lookalike does not split), adv4k (line-start fake boundary inside payload: both payloads redacted independently, all delimiters intact, body re-parses), adv4j (reverse splice with binary between text parts) |
| R9-13 CTE/base64 treated per plan (no pre-decode in MVP) | ✅ PASS | adv4i: base64 part scanned as text (no decode); raw secret not extracted; no panic — consistent with §4.2 MVP and R9's "no pre-decode" clean-bill item |
| Preamble/epilogue not scanned | ✅ PASS (documented limit) | adv4m: excluded from scan (declared known limit #2 in the pack) |
| **R9-20** `expected_auth` alias parses; other values fail-closed; never serialized; `auth_header` canonical | ✅ PASS | adv5 (`expected_auth: header` parses; `query`/`cookie`/empty → parse errors; YAML+JSON serialization contain `fail_policy`/`auth_header` and NEVER `fail_mode`/`expected_auth`); adv7 (live API: `GET /api/config` and `GET /api/upstreams` never emit `expected_auth`; `PUT` with invalid values → 400) |
| **Regression** config round-trips preserve new fields; fail_policy tests updated; F2 single-parse intact; many-leaf gate | ✅ PASS | adv7 (PUT/GET /api/config round-trip `mode` + `fail_policy`); updated fail_policy tests pass (runs 8-10); `redact_json` consumes `decoded.parsed` (clone, no re-parse) — code-verified single-parse; many-leaf gate green inside run 6 (p99 0.253 ms @64 leaves / 0.398 ms @512 leaves); honest HTTP gate fingerprint unchanged |

---

## Attack vectors tried (all executed as live tests)

1. **Asymmetric scan-context leak (the decisive hunt)** — SEE FINDING F-1. A critical-severity BLOCK rule with `contextKeywords` whose keyword the client places in a **part header** (`X-Note: harmlessword=`): the pipeline scan (over the joined region text) provably cannot fire the rule; the multipart region re-scan (analyzer over the FULL body, headers included) fires it; redaction fails; the ClosedOnCritical policy sees no critical pipeline findings → **200, ORIGINAL body with the raw critical-rule secret forwarded** (adv1, output quoted below). adv3 proves the same body under explicit `Closed` → 502. adv2 proves the keyword visible to the pipeline → 403 block.
2. **JSON-path analog** — keyword hidden in a JSON **key name** (keys are absent from `decoded.text`, present in the leaf re-scan's full-body analyzer): identical leak, both secrets forwarded raw (adv8). Verified via `git show fac8236:.../json_redact.rs` that the analyzer-over-full-body leaf re-scan predates this commit — the mechanism is pre-existing on JSON and **extended** by this candidate to multipart with a broader attacker-controlled context.
3. **Cross-join multiline blind spot** — the pipeline scan sees `part1_tail + \n + part2_head` (parts joined with `\n`), so a multiline pattern can match ACROSS the join; the region re-scan can never see such a match (each region is scanned in isolation). With the shipped default pack this cannot leak: PEM/id_rsa are `block`+`critical` (over-block = fail-closed direction) and all redact rules are single-line (cannot match across `\n`). Latent for custom redact-action multiline rules (silent non-redaction, no failure signal). SEE FINDING F-2.
4. **Boundary confusion** — mid-line boundary lookalike (not split — correct), line-start fake boundary inside a payload (split, tail rescanned as its own part payload; redaction preserves structure; body re-parses), CRLF and LF-only delimiters, delimiter at exact buffer edge, quoted boundary with `;`/space, 300-char boundary (cap → over-scan), boundary inside epilogue/preamble (ignored, documented).
5. **Part-bomb over-scan** — 4200 parts → structured parse abandoned → whole-text over-scan; secret planted in the last part still caught (never under-scan).
6. **Binary integrity under redaction** — 256-byte all-byte-values `application/octet-stream` part between two redacted text parts: byte-exact, delimiters intact, redacted body re-parses as multipart with the same region count.
7. **Redaction splice corruption** — secrets redacted in multiple regions (reverse order); payload containing the boundary string; upstream-parseability of the redacted output re-verified by running the decoder on it.
8. **CTE/base64** — no pre-decode attempt (per plan MVP); encoded payload scanned as text; no panic.
9. **Per-upstream pathing toward the fail-open branch** — shadow upstream forwards everything (by §4.7 design); unknown provider inherits global (adv6); mode cannot be swapped mid-request without the control plane (single config read); allow-once/break-glass does NOT weaken the redaction-failure policy (bypass only affects the block stage — proxy.rs:677 — a valid bypass still 502s on a critical redaction failure, unchanged from parent).
10. **Wire-name abuse** — `expected_auth: query|cookie|""` all fail parse at config AND at the API layer (PUT → 400); no value of `expected_auth` is ever echoed by any API route; `fail_mode` likewise never serialized.

### F-1 probe output (verbatim, adv1)

```
adv1 status=200 OK resp="{\"ok\":true}"
adv1 forwarded_body="--XBOUND123\r\nContent-Disposition: form-data; name=\"f1\"\r\n\r\nREDACTSECRET2dddddddddddd\r\n--XBOUND123\r\nX-Note: harmlessword=\r\nContent-Disposition: form-data; name=\"f2\"\r\n\r\nBLOCKSECRET1cccccccccccc\r\n--XBOUND123--\r\n"
adv1 LEAK_FLAG raw_block_secret_reached_upstream=true
```

Rules: `test.lowredact` = `REDACTSECRET2[A-Za-z0-9]{10,}` (Redact, Low, no keywords); `test.critblock` = `BLOCKSECRET1[A-Za-z0-9]{10,}` (Block, **Critical**, `contextKeywords: ["harmlessword="]`). The keyword appears ONLY in part-2's header. Pipeline findings = [low redact] → non-critical → fail-open forwarded the original with the critical-rule match in cleartext.

### F-1 analog on the pre-existing JSON path (adv8, verbatim)

```
adv8 status=200 OK
adv8 forwarded="{\"harmlessword=x\":\"BLOCKSECRET1cccccccccccc\",\"note\":\"REDACTSECRET2dddddddddddd\"}"
adv8 LEAK_FLAG raw_block_secret_reached_upstream=true
```

(keyword `harmlessword` in the JSON key name; both secrets raw in the forwarded body after the redaction failure.)

---

## Findings

### F-1 [P1 — VERIFIED] Multipart region re-scan sees a broader context than the pipeline scan → a critical-rule match can be routed into the fail-open branch and the raw secret forwarded under the DEFAULT policy
- **What**: `redact_multipart` (json_redact.rs:70-107) re-scans each text region with `ContextAnalyzer` built over the **full lossy body** — including part headers, binary-part bytes, preamble and epilogue, none of which are in `decoded.text`. The pipeline scan that feeds `decide_redact_result` (proxy.rs:470-503) runs over `decoded.text` ONLY, where `contextKeywords` are evaluated with same-line proximity. A rule can therefore **fire in the re-scan but not in the pipeline scan**. When the re-scan finding has action `block`, `apply_redaction` errors (redact.rs Blocked), redaction fails as a whole, and the policy judges criticality from the pipeline view alone: no critical findings → **fail-open → the ORIGINAL body (containing the critical-rule secret) is forwarded with 200** (adv1). Under the previous `Closed` default the same request 502s (adv3).
- **Why it violates the intent**: §4.1 mandates fail-closed for critical rules. The builder's delta table guarantees "redaction failure with critical findings → 502" — true only for critical findings **visible to the pipeline scan**. The pack discloses the allowlist variant of this window (known limit #3) but not this one: no operator allowlist is needed; the client alone constructs it by placing the keyword outside the scanned text. This is realistic without malice: a form part named `password` puts the keyword in `Content-Disposition` (a part header) and the secret in the payload.
- **Scope honesty**: the JSON-path analog (keyword in a key name; adv8) pre-exists at parent `fac8236` (analyzer-over-full-body leaf re-scan already present). This candidate **extends** the mechanism to the new multipart surface where the context is even richer and fully attacker-shaped. Trigger requires a `contextKeywords` rule (documented, supported MVP feature — the shipped default_pack has none; the project's own `test-rules.json` uses them heavily).
- **Fix direction** (builder's call, not this reviewer's): make the policy criticality view include re-scan findings (fail closed when redaction fails AND the re-scan produced a critical/block finding not present post-allowlist), or align both scan views (include part headers/keys in the pipeline's context, or re-derive pipeline findings with the same analyzer scope).
- **Not P0**: requires a context-keyword rule (not the default pack); the JSON analog predates this unit; a client that fully controls the body already has the documented binary-part escape (different, disclosed trade-off) — but that path never triggers a rule, whereas F-1 defeats an explicitly configured critical rule, which §4.1 says must fail closed.

### F-2 [P2 — VERIFIED, latent] Cross-join multiline matches are visible to the pipeline scan but to NO region: silent non-redaction possible for custom multiline redact rules
- The parts are joined with `\n` for the pipeline scan, so a multiline pattern can match across a part boundary. The region re-scan never sees such a match, and redaction proceeds region-wise: with a **redact**-action multiline rule the pipeline says "redact" yet the span is silently left intact (200, no error, no policy involvement). With the shipped default pack this cannot fire (PEM/id_rsa/.env are block/block/warn; block over-blocks → 403 fail-closed; warn passes by definition) — hence P2, latent behind custom rules. Same root cause as F-1 (two different scan views over one body).

### No other findings
R9-11, R9-20 and the regression criteria survived every vector tried; the gates are genuinely green; the builder's test count (734) reproduces exactly; the honest HTTP gate reproduces at p99 0.844 ms with the identical drift-guard fingerprint (no threshold moved: `tests/load_test.rs` untouched in the diff).

---

## Final verdict: **FAIL** (returns to the builder; one P1 on the unit's own new surface)

All five gates PASS independently (fmt clean; clippy clean; **734/0** workspace; **19/19** production pack; **14/14** load suite with the honest HTTP gate at p99 **0.844 ms** < 5.0 ms strict, fingerprint unchanged — the F3.3 latency work is not regressed). R9-11 (per-upstream mode) and R9-20 (wire name) are correct end-to-end — parse validation is fail-closed, mixed fleets route correctly, the MITM path shares the mode read, and the compat aliases are input-only and provably never serialized back through YAML, JSON, or any API route. R9-13's multipart decoder survived the full structural battery (boundary confusion, truncation, part bombs, nested MIME, CTE, binary byte-exactness, splice integrity, re-parseability of redacted output) with over-scan fallbacks that never under-scan. R9-12's decision table is implemented exactly as the pack specifies and every disclosed cell reproduces. The unit still fails verification because of **F-1 (P1)**: the redaction-failure policy's criticality oracle is the pipeline scan, but the new multipart re-scan evaluates rules against a strictly broader context, so a request can carry a critical-rule match that the policy never sees — and on redaction failure the DEFAULT policy then forwards the critical secret raw with a 200, a path I constructed and executed (adv1), worse than the disclosed allowlist window and without needing any operator misconfiguration beyond a supported custom rule. F-2 (P2) is the same root cause in its silent form. Per §8B the P1 blocks closure: the fix is small and localized (reconcile the two scan views or extend the fail-closed condition), after which this unit should re-enter VERIFY.

### Explicit judgment on the ClosedOnCritical leak-window question

**Can a request carrying CRITICAL findings reach the "non-critical only" branch through constructed pathing? YES — F-1 (P1).** The decision table itself is faithful to §4.1 and to the R9-12 finding text: critical pipeline findings → 502; non-critical-only → 200 + original (verified byte-exact); decode failure → 502 (indeterminate → closed); upstream failure → 503; explicit `open`/`closed` unchanged; the MITM path obeys all three. Multi-upstream routing, mode overrides, and break-glass do NOT open the window (shadow forwarding is §4.7 by design; bypass never reaches the redact decision). The allowlist interaction the builder disclosed does open it, as documented. But the decisive leak is **scan-context asymmetry**: the criticality signal is taken from the pipeline scan while the failure is often *caused* by findings only the re-scan can see (keyword hidden in a part header — or, pre-existing, in a JSON key). In that state the request "carries" a critical-rule match that the policy's findings view does not contain, and the default forwards the secret raw. The builder's own acceptance criterion — "critical failure → closed behavior (502), raw secret never leaves" — therefore holds only under the pipeline's definition of critical, which is incomplete on the surface this unit introduced. The disclosed limit #3 is a special case of this; the general case is unbounded and demoed. This is the finding that fails the unit.

---

## Verification hygiene

- Worktree removed after the review (`git worktree remove --force`).
- Only file created in the main repo: this report. No repo code, tests, or thresholds were touched. All adversarial code lives in `/var/folders/.../opencode/adv-correctness` (throwaway, outside the repo).
- The sibling security-lens report was never read (blind review maintained).
