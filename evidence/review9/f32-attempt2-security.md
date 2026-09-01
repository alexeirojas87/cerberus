# F3.1+F3.2 — Independent Adversarial Review (SECURITY lens), FIX attempt 2

- Unit: **F3.1 + F3.2** (R9-13 multipart MVP, R9-11 per-upstream mode, R9-12 ClosedOnCritical, R9-20 wire name)
- Candidate: commit `c532732` (branch `r9-remediation`, parent `7519ad9`) — worktree `/var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/f32-attempt2-security`
- Reviewer: independent security subagent (did NOT build; blind to the correctness lens). Round-1 report: `evidence/review9/f32-attempt1-security.md` (3×P1 + 2×P2 → FAIL)
- Date: 2026-09-01 — Host: Apple M4 Pro, macOS 26.5.1, rustc/cargo 1.97.1
- Method: §8B — gates re-run verbatim, then EVERY round-1 finding reproduced against the fixed candidate through the **real daemon** (`target/release/cerberus`, isolated `$HOME`, byte-exact mock upstream on :9411, live audit/events inspection), plus unanticipated variants and direct attacks on the new fix surfaces (one-scan-pass architecture, region splice, authoritative allowlist, region scanner DoS).

**Final verdict: PASS** — all 4 gates green, all 3 round-1 P1s and both P2s empirically closed against the live candidate; attacks on the fix itself produced no exploitable hole (residuals are the pack's own documented tradeoffs, confirmed and downgraded to P3).

## Commands run

| # | Command (verbatim) | Exit | Result |
|---|---|---|---|
| 1 | `git -C /Users/alexeirojas/Work/Personal/Cerberus worktree add --detach /var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/f32-attempt2-security c532732` | 0 | worktree at c532732 |
| 2 | `git diff --stat 7519ad9..c532732` | 0 | 8 files, +1677/−128 (decoder/json_redact/proxy/log/forward/smoke_harness/daemon/evidence) |
| 3 | `rtk cargo clippy --workspace --all-targets -- -D warnings` | 0 | `No issues found` |
| 4 | `rtk cargo test --release --test redos_fuzz -- --test-threads=1 --nocapture` | 0 | **11/11 passed** |
| 5 | `rtk cargo test -p cerberus-proxy` | 0 | **254 passed** (3 suites — matches builder's count) |
| 6 | `rtk cargo test -p cerberus-packs --test production_pack_pr` | 0 | **19/19 passed** |
| 7 | `cargo build --release -p cerberus` | 0 | real-daemon vehicle |
| 8 | `cargo test --workspace --all-targets` (debug, extra gate) | 0 | 0 failed across all suites |
| 9 | `rtk cargo test -p cerberus-proxy --lib connect_tls_per_upstream` | 0 | 2 passed (real-tunnel MITM mode tests) |
| 10 | `rtk cargo test -p cerberus-proxy --lib mitm_provider` / `upstream_url_host` | 0 | 2 + 2 passed (mapping + URL-host parse) |
| 11 | mock upstream :9411 + `HOME=<isolated> ./target/release/cerberus start --port 9410` | 0 | boot: `mode=enforce fail_policy=closedoncritical … 18 rules (15 base)` |
| 12 | `python3 f32s2_attack_a.py` (P1-1/P1-3/P2-1 reproductions + variants V1–V4) | 0 | table below |
| 13 | `curl -s -X POST http://127.0.0.1:9410/api/allowlist -d '{"value":"BLOCKSECRET1cccccccccccc"}'` | 200 | redaction-failure mechanism armed |
| 14 | `python3 f32s2_attack_c.py` + C1'' re-run (fail-policy table + events honesty) | 0 | C2' 200+raw+honest event / C1'' 502+event / C4' no fail-open / C5' 502 |
| 15 | `python3 f32s2_attack_d.py` (block parity B1–B3, F-2 span demo S1–S2, DoS D1–D7) | 0 | table below |
| 16 | `curl -s /api/events?limit=N` after each battery | 0 | flags/actions inspected live |
| 17 | second daemon boot with corrupt `config.yaml` (isolated HOME, :9412) | 0 | P3-1: real serde error logged at ERROR |
| 18 | raw-secret scan: daemon logs + `sqlite3` full dump of `audit_events` (10 secrets) | 0 hits | hash-only (`sha256:…`) |
| 19 | cleanup: daemons/mock killed; worktree removed | 0 | sibling-lens process (f23, :18789) untouched |

Note on MITM live-driving: a live daemon MITM tunnel requires binding the mock upstream on **:443** (`parse_connect_target` hard-rejects every other port) — permission denied unprivileged. P1-2 closure evidence therefore = the builder's **real-tunnel tests** (actual forward proxy + actual TLS handshake + byte-capturing upstream, in-process) + mapping unit tests + code-level variant analysis. This is real-path evidence, not mock-layer.

## Per-criterion verdicts

| Criterion | Evidence | Verdict |
|---|---|---|
| **G1** clippy `-D warnings` | cmd 3, exit 0 | ✅ PASS |
| **G2** redos_fuzz 11/11 (release, single-thread) | cmd 4 | ✅ PASS |
| **G3** cerberus-proxy suite | cmd 5: **254 passed** | ✅ PASS |
| **G4** production_pack_pr 19/19 | cmd 6 | ✅ PASS |
| **F-1/P1-1** preamble/epilogue/part-header scan | A2'/A3'/A12' live redact-in-place; B1/B2/B3 live 403; structure byte-verified | ✅ CLOSED |
| **P1-2** per-upstream mode live on MITM | real-tunnel tests 9/10 (enforce-blocks-under-global-shadow + reverse), mapping tests, variant analysis | ✅ CLOSED (see residual R2) |
| **P1-3** cross-part keywords in DECISION; pipeline-layer tests | A6b'/A6' live redact via decision; smoke tests read and confirmed pipeline-layer | ✅ CLOSED |
| **P2-2** honest fail-open/fail-closed/shadow audit | C2'/C1''/C6' live events (`fail-open`/`fail-closed` + `redact-failed`, `shadow` flag); forward.rs loop asserts same on MITM for all 3 policies | ✅ CLOSED |
| **P2-1** binary-unscanned visibility | live A4' event `binary-unscanned`; zero-findings visibility events observed (`allow + [binary-unscanned]`) | ✅ CLOSED (tradeoff kept per plan) |
| **F-2** region-isolation consistency | S1/S2 live demo: span inside region matched, span across regions invisible to BOTH decision and redaction; no divergence surface | ✅ PASS (residual R1 documented) |
| **New surfaces** (splice corruption, over-scan, allowlist interplay, region-scanner ReDoS, secret logging) | V3/V4, D1–D7, C4', leak scan | ✅ PASS — no exploitable hole found |
| **P3-1** boot parse-error logging | cmd 17: `ERROR … config.yaml is INVALID and will be IGNORED …: config parse error: expected value at line 1 column 1` | ✅ CLOSED |

## Round-1 findings closure table

| Round-1 finding | Reproduction against c532732 | Outcome |
|---|---|---|
| **P1-1** secret in preamble/epilogue/part header forwarded raw+silent | A2' (preamble), A3' (epilogue), A12' (header): all **200 + `[REDACTED:test.redactrule]` in place**, delimiters/blank lines intact in upstream capture; B1/B2/B3 (block variants): **403, nothing forwarded** | **CLOSED** |
| **P1-2** per-upstream mode silently inert on MITM (enforce shadows) | `connect_tls_per_upstream_mode_resolves_by_url_host_and_never_silently_shadows`: global shadow + per-upstream enforce → intercepted request **403, zero bytes to upstream**; reverse test: per-upstream shadow never blocks; unmapped host inherits global (documented) | **CLOSED** |
| **P1-3** cross-part keyword dead in decision; test at wrong layer | A6b' (keyword other part) and A6' (keyword in field name): **decision-path redaction** live; `f1_repro_keyword_in_part_header_blocks_via_pipeline` (attempt-1 adv1 payload) now **403 via pipeline**; acceptance tests verified to drive `spawn_proxy→proxy_handler` | **CLOSED** |
| **P2-2** fail-open audited as plain `redact` | C2' live: 200 + original byte-exact raw + event `action_taken="fail-open"`, flags `[test.redactrule, redact-failed]`; C1'': 502 + `fail-closed` + `redact-failed`; decode-failure events `fail-closed` + `decode-failed`; shadow event `block` + `shadow` flag; MITM loop test asserts all of it per policy | **CLOSED** |
| **P2-1** binary-claimed part under-scan silent | A4' live: 200 raw (documented plan tradeoff) + **`binary-unscanned` flag on the event**, including zero-findings visibility events | **CLOSED** |
| **P3-1** boot config errors swallowed | second daemon boot with corrupt YAML logs the real serde error at ERROR with path + fail-closed consequence | **CLOSED** |
| **P3-2** mode/route TOCTOU | unchanged, accepted residual (authenticated control-plane race only) | UNCHANGED (P3) |

## Attack vectors tried (payload → observed result)

Secrets: `BLOCKSECRET1…` (critical block), `REDACTSECRET2…` (high redact), `CTXSECRET-…` (critical redact, keyword `zeta`). "Capture" = byte-exact mock-upstream record.

| ID | Vector | Observed |
|---|---|---|
| A1 | sanity: secret in canonical text part | REDACTED in place, structure intact ✅ |
| A2' | **P1-1 original**: secret in PREAMBLE | **REDACTED in place**: `preamble leaks [REDACTED:test.redactrule] here\r\n--SECBOUND…` — delimiter still at line start ✅ |
| A3' | **P1-1 original**: secret in EPILOGUE | **REDACTED in place** after closing `--` ✅ |
| A12' | **P1-1 original**: secret in PART HEADER | **REDACTED in place**, blank separator + payload intact ✅ |
| V1 | variant: secret in header of a **BINARY-claimed** part | header REDACTED in place; `\x00\x01\x02\x03BINARYPAYLOAD` byte-exact; `binary-unscanned` counted ✅ |
| V2 | variant: preamble + header body (attacker-adjacent shapes) | parsed as preamble region; scanned ✅ |
| V3 | variant: redaction adjacent to next delimiter | REDACTED, both delimiters intact (line-start preserved) ✅ |
| V4 | variant: fake `--SECBOUND` + secret INSIDE payload (line-start) | decoder legitimately sees a binary-claimed fake part → secret raw (P2-1 tradeoff) **+ `binary-unscanned` event** ✅ (flagged, not silent) |
| A6b' | **P1-3 original**: keyword in ANOTHER part's payload | **decision-path redaction** `[REDACTED:test.ctxredact]` ✅ |
| A6' | **P1-3 original**: keyword only in field name `name="zeta"` | **decision-path redaction** ✅ |
| A4' | **P2-1 original**: text secret in binary-claimed part | 200 raw (plan tradeoff) + `binary-unscanned` event; zero-findings visibility events confirmed live ✅ |
| A5' | **P2-1 variant**: boundary smuggling spawns fake binary part around secret | raw forwarded as binary part + `binary-unscanned` event (flagged, not silent) ✅ |
| B1/B2/B3 | block secret in part header / preamble / epilogue | **403**, capture empty — detection parity with the old lossy path ✅ |
| C2' | **P2-2**: JSON redaction failure, non-critical only (allowlist-armed) | **200**, original byte-exact raw forwarded (§4.1 valve) + event `action_taken="fail-open"`, flags `[test.redactrule, redact-failed]` — never plain `redact` ✅ |
| C1'' | **P2-2**: JSON redaction failure WITH visible critical finding | **502**, error body carries only the rule flag, event `fail-closed` + `redact-failed` ✅ |
| C4' | **allowlist interplay**: multipart with allowlisted block secret + redact secret | redaction SUCCEEDS: allowlisted value kept (operator choice), redact secret redacted, **no fail-open manufactured** — the attempt-1 exploit chain is dead ✅ |
| C5' | undecodable JSON under default | **502 `cannot decode`** ✅ (also accidentally exercised: multipart body with `application/json` hint → 502 + `decode-failed` event, fail-closed) |
| C6' | decode-failure audit honesty | events `action="fail-closed"`, flags `["decode-failed"]` ✅ |
| S1 | F-2 control: multiline span INSIDE one region | matched → REDACTED ✅ |
| S2 | F-2 span ACROSS preamble→header with custom multiline rule | **raw forwarded** — visible to neither decision nor redaction (documented limit #2; see residual R1) ⚠ P3 |
| D1 | 4 000 parts / ~8 000 scanned regions | **6 ms** (linear) ✅ |
| D2 | delimiter lookalike flood (no line starts) | 3 ms ✅ |
| D3 | 4 000 true delimiters, no closing | 5 ms ✅ |
| D4 | 2 MB preamble region | 26–30 ms ✅ |
| D5 | 43 MB single part | 614 ms ✅ (faster than attempt-1's 2.7 s) |
| D6 | 5 000-part bomb (+secret) → over-scan fallback | **4 ms**, secret REDACTED via whole-text over-scan ✅ |
| D7 | 65 MB body (> 64 MiB cap) | **413** ✅ |
| L | log/audit leak scan (10 raw secrets × daemon logs + SQLite dump) | **0 hits**; audit rows hash-only (`sha256:…`) ✅ |

## Findings

### P0 — none. P1 — none. P2 — none.

### P3 residuals (documented tradeoffs confirmed live; none gate closure)

- **R1 (P3) — region-span under-scan for custom multiline rules (F-2, confirmed).** A pattern whose charset crosses structural boundaries (empirically: `SPANSTART[\s\S]{0,60}SPANEND`, S2) matches in the old whole-text model but is invisible to BOTH the decision and the redaction in the region-isolated model. This is the pack's documented limit #2 and it is *consistent* (the divergence class P1-3/F-1 exploited is gone — the redaction performs no scan of its own). Impact requires an operator-authored multiline rule spanning a delimiter/preamble/header boundary; default packs have none. Acceptable; should stay visible in operator docs.
- **R2 (P3) — upstream `url` host with trailing dot would miss the URL-host mapping.** `normalize_host` strips a trailing dot from the CONNECT host but `upstream_url_host` (proxy.rs:1067) does not from the configured URL — `url: https://api.openai.com.` would never map, so that upstream's per-upstream `enforce` falls back to the global mode. Operator-config-typo edge, fail-safe direction (inherits global, visible in audit provider + debug log), not attacker-controllable. Suggest stripping in a future hardening pass.
- **R3 (P3) — TOCTOU across config snapshots (round-1 P3-2)** unchanged; requires authenticated control-plane access mid-request.

## Final verdict

**PASS.** All four gates re-ran clean on the candidate worktree (clippy `-D warnings` exit 0, ReDoS fuzz 11/11 in release, cerberus-proxy **254** passed, production_pack_pr **19/19**), plus a full debug workspace run with zero failures. Every round-1 security finding was reproduced against the FIXED candidate and is demonstrably closed: secrets in the preamble, epilogue and part headers are now redacted in place with the MIME structure byte-verified intact and blocked (403) in the block direction; the per-upstream mode is live on the MITM path through real TLS-intercepted tunnels with the exact "enforce under global shadow" forbidden state now failing closed; cross-part and metadata context keywords drive the DECISION path, with acceptance tests genuinely at the pipeline layer; fail-open/fail-closed/shadow/decode outcomes are audited with honest actions and flags on both reverse-proxy (live) and MITM (real-tunnel test) paths; and the binary-claim tradeoff is no longer silent. Attacks on the fix itself — splice corruption at region edges (delimiter line-breaks and blank separators stay outside all regions), the one-scan-pass architecture (redaction consumes the decision's findings; mismatch falls back to an over-redacting self-scan), authoritative-allowlist interplay (the attempt-1 allowlist-armed fail-open chain is dead on multipart), and a region-scanner DoS corpus (worst case 614 ms on 43 MB, bombs over-scanned in 4 ms, 413 above cap) — found no exploitable hole, and no raw secret reaches logs or the audit store. The three P3 residuals above are the pack's own disclosed tradeoffs (one newly empirically confirmed) plus one config-typo edge; none gates closure. Per §8B the unit may proceed to the F3 phase gate with this panel's sign-off.
