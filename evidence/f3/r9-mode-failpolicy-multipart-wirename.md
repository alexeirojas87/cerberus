# Evidence Pack — f3/r9-mode-failpolicy-multipart-wirename

- Unit: **F3.1 + F3.2** (decoder MVP completo — multipart; policy operacional — per-upstream mode, fail policy, wire name)
- Findings: **R9-11** (P2, F3.2), **R9-12** (P2, F3.2), **R9-13** (P2, F3.1), **R9-20** (LOW, F3.2)
- Attempt: 1    Builder: F3.1+F3.2 builder subagent    Verdict: **FIX executed — returns to VERIFY** (not closed by the builder; §8B.3)
- Date: 2026-09-01    Base: `fac8236` (branch `r9-remediation`, clean tree)    Work branch: `r9-f3-attempt2` (isolated worktree, NOT pushed)
- Host: Apple M4 Pro, macOS 26.5.1 (darwin)    Toolchain: rustc/cargo 1.97.1 (8bab26f4f 2026-07-14)
- Baseline at `fac8236`: `cargo test --workspace --all-targets` → **681 passed; 0 failed** (command run on this worktree before any edit).
- F3.3 dependency: the honest HTTP latency gate (already PASS at base) re-ran in this matrix — **no latency regression** (see §Verification matrix, run 7).

## Reconciliation (what existed / what was broken / what was built)

### R9-11 — per-upstream `mode: shadow|enforce`
- **Existed (finding, VERIFIED):** `UpstreamConfig` (config.rs:120-133 at base) carried only `url`, `path_prefix`, `auth_header`; shadow/enforce was global-only (`ProxyConfig.mode`), read once per request at proxy.rs:520-523. §4.7 requires the mode "globally **and per provider**".
- **Built:**
  - `UpstreamConfig.mode: Option<OperationMode>` (`#[serde(default)]`), config.rs:148. `None` (absent) = inherit the global mode. Invalid values fail the parse (test `per_upstream_mode_rejects_invalid_value`).
  - Proxy application: proxy.rs:580-586 — after the request's provider is resolved, one config read does `cfg.upstreams.get(&provider).and_then(|u| u.mode).unwrap_or(global)`; the effective `mode` drives the existing `shadow::apply_mode` (block/redact decision) unchanged. Works for both the reverse-proxy route and the MITM `DirectUpstream` path (MITM providers that are not in the upstreams map inherit the global mode).
  - Config API consistency (§4.6 golden rule — YAML is the serialized state): `POST /api/upstreams` accepts `mode` (api.rs:811-814, payload field `mode`), `GET /api/upstreams` reports it (api.rs:812-830); `PUT /api/config` round-trips it through `ConfigPatch`'s serde deserialization of `UpstreamConfig` automatically.

### R9-12 — `FailPolicy::ClosedOnCritical` + default
- **Existed (finding, VERIFIED):** only `enum FailPolicy { Open, Closed }` (old config.rs:100-106); the §4.1 recommended default and the A.1 example `fail_mode: closed-on-critical` did not parse — **two** defects: the KEY (`fail_mode` vs the code's `fail_policy`) and the VALUE (`closed-on-critical` had no variant). The real default was `Closed` (total).
- **Built:**
  - `FailPolicy::ClosedOnCritical` variant, config.rs:112-127, serde canonical name `closed-on-critical` (+ alias `closedoncritical`), `#[default]`.
  - `fail_mode` accepted as a deserialization alias of the canonical `fail_policy` field (config.rs:25) — the A.1 example parses; the canonical persisted name stays `fail_policy`.
  - Decision table (§4.1 "fail-closed for critical rules, fail-open for the rest"):
    - **Redaction failure** (proxy.rs:470-503): reject (502) only when the request's pipeline findings (post-allowlist) include `Severity::Critical`; otherwise forward the ORIGINAL body (fail-open) with a warn log. `policy.rs::evaluate` (policy.rs:30-40) exposes the same table for tests/failsafe.
    - **Decode failure** (proxy.rs:643-652): an undecodable JSON body has NO findings — criticality is indeterminate → fail-closed (502), same observable behavior as `Closed`. Only `Open` forwards.
    - **Upstream connection failure/timeout** (proxy.rs:839-852): not an engine failure, no criticality signal → closed posture (503); only `Open` returns 502. Status-code semantics unchanged from the previous behavior for Closed.
  - `fail_policy` failures that stay configurable: `open` and `closed` keep parsing and behave exactly as before (forward.rs tests extended to prove all three).
- **Behavioral delta vs the previous default (`Closed`)** — see the dedicated section below.

### R9-13 — multipart/form-data MVP decoder
- **Existed (finding, VERIFIED):** `decoder.rs` only `ContentType::{Json, Text}` (old decoder.rs:21-30); zero multipart handling in proxy+engine. Any multipart body was scanned as lossy whole-body text and redacted as plain text (structure destroyed on redaction).
- **Built (§4.2 MVP boundary — text parts scan only):**
  - `ContentType::Multipart` + `DecodedBody.multipart: Option<Vec<TextRegion>>` (decoder.rs:20-62): the raw body is parsed ONCE at decode time; the byte offsets of every textual part payload are recorded for the redaction path (no double-parse; mirrors the F2.1 single-parse JSON contract).
  - Bounded parser (decoder.rs): `multipart_boundary` (config.rs of the hint; quoted boundaries unwrapped; > `MAX_BOUNDARY_LEN`=256 → unusable), `parse_multipart` (decoder.rs:223) — linear single pass with first-byte-probe delimiter search (`find_delimiter`, decoder.rs:286; no `windows()` quadratic blow-up), line-start-only delimiters (`\r\n`/`\n`/body start), transport padding tolerated, preamble ignored, epilogue ignored, truncated body → last payload runs to EOF and is still scanned, `MAX_MULTIPART_REGIONS` = 4096 → part-count bombs abandon the structured parse for the over-scan Text fallback.
  - Textual/binary classification (decoder.rs:186): parts with NO `Content-Type` default to text/plain (RFC 7578 §4.4); `text/*` and a documented textual-`application` list (`json`, `xml`, `x-www-form-urlencoded`, `javascript`, `yaml`, `x-yaml`) are scanned; everything else (octet-stream, image/*, audio/*, video/*, multipart/* nested, unknown) is binary → NOT scanned, preserved byte-exact.
  - Redaction (json_redact.rs:70-107): per recorded region, `engine.scan_with_context_analyzer(part_text, full-body-context)` — the SAME context machinery as the JSON leaf path — then in-place splice in REVERSE offset order; boundaries, part headers and binary parts are never touched. Vault (F2.2) path supported; `apply_redaction` errors propagate to the fail policy.
  - The block path works on the concatenated text (`decoded.text`, parts joined with `\n`), so block decisions and the allowlist behave exactly as on the existing paths.

### R9-20 — `expected_auth` vs `auth_header` wire-name mismatch
- **Existed (finding, VERIFIED):** A.1 writes `expected_auth: header`; the implementation names the credential header `auth_header: String` (default `"authorization"`). The A.1 YAML failed to parse (unknown field).
- **Decision (documented):** `auth_header` (the header NAME) stays the single **canonical** wire name; `expected_auth` is accepted as an Appendix A.1 **input-compat alias** whose only supported MVP value is `header` ("the credential travels in a header — the one named by `auth_header`"); any other value is a parse error (fail-closed, never silently ignored). `expected_auth` is validated at deserialization (config.rs:169-184) and is **never serialized back** — the canonical serialized state is `auth_header` alone. Rationale: `auth_header` is the tested, API-persisted field with real semantics; `expected_auth: header` carries no additional information at MVP (A.2's `inject_key` is a separate, out-of-scope mechanism).

## Behavioral delta — R9-12 default change (`Closed` → `ClosedOnCritical`)

| Failure site | Old default (`Closed`) | New default (`ClosedOnCritical`) | Delta |
|---|---|---|---|
| Redaction failure, request HAS critical findings | 502 reject | 502 reject | none |
| Redaction failure, only non-critical findings | 502 reject | **200, ORIGINAL body forwarded** (fail-open, §4.1 "the rest"), warn logged | **CHANGED** — this is the availability valve §4.1 mandates |
| Decode failure (json hint, undecodable body) | 502 reject | 502 reject (indeterminate criticality → closed posture) | none |
| Upstream connection failure / timeout | 503 / 503 | 503 / 503 (not an engine failure) | none |
| `fail_policy: open` / `closed` explicitly configured | unchanged | unchanged | none |

Notes for the panel:
- A deployment that relied on the implicit `Closed` default for redaction failures on non-critical requests now gets fail-open for those requests only; operators who want the old behavior set `fail_policy: closed` (still first-class, tested).
- An operator allowlisted value that later trips a block rule inside the JSON leaf re-scan (the known redaction-failure mechanism) now forwards raw under the default **only when the request carries no critical findings** — with critical findings it still 502s. The old default rejected both cases.
- Updated existing tests that pinned the old default: config.rs `default_config`, tests/failsafe.rs `fail_policy_default_is_closed_secure` → `fail_policy_default_is_closed_on_critical` (asserts the delta table), forward.rs fail-policy loops extended with a `ClosedOnCritical` case (decode failure behaves like Closed; non-critical redaction failure behaves like Open).

## Acceptance criteria — R9-11 (per-upstream mode)

| Criterion | Command run | Output | Result |
|---|---|---|---|
| Per-upstream `mode` parses from A.1-style YAML (block + flow style), validates | `cargo test -p cerberus-proxy per_upstream_mode_parses_with_global_fallback per_upstream_mode_rejects_invalid_value` | `cargo test: 235 passed (2 suites)` (both included) | ✅ |
| Proxy applies the per-upstream mode: shadow upstream never blocks | `cargo test -p cerberus-proxy --test smoke_harness per_upstream_shadow_mode_never_blocks_in_mixed_fleet` | passed (200 intact on `/shadowed/…`, 403 on default upstream, same ctx) | ✅ |
| Enforce upstream enforces; mixed-fleet routing | `cargo test -p cerberus-proxy --test smoke_harness per_upstream_enforce_mode_overrides_global_shadow` | 403 on `/enforced` while global shadow; 200 on `/shadowed` and default | ✅ |
| Global default still works for upstreams without `mode` | same tests (`default` upstream rows assert 403 under global enforce / 200 under global shadow) | as above | ✅ |
| Mode survives config serialization (hot-reload persistence) | `cargo test -p cerberus-proxy per_upstream_mode_survives_config_serialization` | passed | ✅ |

## Acceptance criteria — R9-12

| Criterion | Command run | Output | Result |
|---|---|---|---|
| `closed-on-critical` parses (variant + serde name), `fail_mode` alias parses (A.1) | `cargo test -p cerberus-proxy fail_policy_deserialize a1_yaml_with_fail_mode_and_expected_auth_parses fail_policy_open_and_closed_still_configurable` | passed (incl. the exact A.1 key/value) | ✅ |
| It is the DEFAULT | `cargo test -p cerberus-proxy default_config fail_policy_defaults_to_closed_on_critical_when_absent` + `cargo test -p cerberus-hardening --test failsafe fail_policy_default_is_closed_on_critical` | passed | ✅ |
| Critical failure → closed behavior (502, raw secret never leaves) | unit: `cargo test -p cerberus-proxy closed_on_critical_rejects_when_critical_findings_present`; pipeline: `--test smoke_harness closed_on_critical_rejects_redaction_failure_with_critical_findings` | 502 + no raw secret; upstream received nothing | ✅ |
| Non-critical failure → previous behavior (fail-open forwards original) | unit: `closed_on_critical_forwards_original_for_non_critical_findings`; pipeline: `--test smoke_harness closed_on_critical_forwards_original_for_non_critical_redaction_failure` | 200; captured upstream body == original byte-exact | ✅ |
| Indeterminate criticality (undecodable JSON) → closed posture under the default | `--test smoke_harness closed_on_critical_rejects_undecodable_json_body` | 502 `cannot decode` | ✅ |
| `open`/`closed` unchanged; MITM path obeys all three policies | forward.rs `connect_tls_invalid_json_obeys_closed_and_open_fail_policy_without_audit_leak`, `connect_tls_redaction_failure_obeys_closed_and_open_fail_policy_without_leak` (loops now include `ClosedOnCritical`) | passed (in cerberus-proxy 235) | ✅ |
| Behavioral delta documented | this pack, §"Behavioral delta" | — | ✅ |

## Acceptance criteria — R9-13

| Criterion | Command run | Output | Result |
|---|---|---|---|
| Text parts extracted + scanned with the same context machinery as JSON leaf paths | `cargo test -p cerberus-proxy multipart_context_keyword_in_other_part_redacts` (json_redact.rs tests) | keyword in a DIFFERENT part redacts the secret part (ContextAnalyzer over full body — same machinery as `redact_value`) | ✅ |
| Boundary parsing robust: quotes, long boundaries, nested mime, malformed | `cargo test -p cerberus-proxy multipart_ -- --list` subset: `multipart_quoted_boundary_parses`, `multipart_boundary_with_special_characters`, `multipart_boundary_too_long_falls_back_to_text`, `multipart_nested_mime_part_treated_by_its_declared_type`, `multipart_never_panics_on_adversarial_bodies` (12-entry malformed corpus: empty, `--`, `----`, no closing, CR-only, no blank line, empty ctype, mixed EOL…) | passed; never panics; regions in bounds | ✅ |
| Multiple parts, filename/Content-Type | `multipart_multiple_text_parts_extracted`, `multipart_binary_part_not_scanned_and_metadata_excluded`, end-to-end `--test smoke_harness multipart_text_part_redacted_binary_part_byte_exact_end_to_end` | regions==N; filename/headers preserved; upstream receives `[REDACTED:test.redact]` + byte-exact 256-byte binary | ✅ |
| Binary parts handled per plan scope (not scanned, byte-exact) | decoder + json_redact + smoke_harness tests above (`audio/wav`, `application/octet-stream`, `image/png`, unknown type → binary) | passed | ✅ |
| Truncated body, part-count bomb, size limit | `multipart_truncated_body_still_scans_last_payload`, `multipart_part_count_bomb_falls_back_to_text_over_scan`, `--test smoke_harness multipart_over_body_limit_returns_413` | 200-scan of truncated payload; bomb → text over-scan; 413 over `max_body_bytes` | ✅ |
| Adversarial corpus | decoder.rs `multipart_*` tests (22 cases) incl. mid-line delimiter lookalike, LF-only, transport padding, preamble/epilogue, empty payloads, part-count bomb, headerless parts | passed | ✅ |
| Integrates with `DecodedBody` (no double-parse regression) | `decoder_records_multipart_regions_for_single_parse_redaction` + `redact_body` consumes `decoded.multipart` regions (json_redact.rs:36-56); `parsed` stays `None` (no JSON tree for multipart) | passed | ✅ |
| Block + shadow semantics on multipart | `--test smoke_harness multipart_block_rule_blocks_the_request` (403, nothing forwarded), `multipart_shadow_mode_forwards_intact` (byte-exact pass-through) | passed | ✅ |
| Malformed multipart never under-scans | `--test smoke_harness multipart_malformed_structure_still_blocks_via_text_fallback` (multipart hint without boundary → text over-scan → 403) | passed | ✅ |
| F2.2 interop (reversible vault) on multipart | `multipart_reversible_vault_round_trip` | `[VAULT:…]` in part, `unredact` restores, binary byte-exact | ✅ |

## Acceptance criteria — R9-20

| Criterion | Command run | Output | Result |
|---|---|---|---|
| `expected_auth: header` parses (A.1 compat) | `cargo test -p cerberus-proxy expected_auth_header_only_supported_value a1_yaml_with_fail_mode_and_expected_auth_parses` | passed | ✅ |
| Chosen option documented (canonical `auth_header`, compat alias) | this pack §R9-20 + doc comments (config.rs:151-159) | — | ✅ |
| Unsupported `expected_auth` value → parse error (fail-closed) | `expected_auth_header_only_supported_value` (`expected_auth: query` → err mentioning `expected_auth`) | passed | ✅ |
| Canonical name tested end-to-end (A.1 YAML drives the proxy, `authorization` forwarded) | `--test smoke_harness a1_yaml_config_drives_the_proxy_end_to_end` + `auth_header_wire_name_remains_canonical` | passed | ✅ |

## Verification matrix (builder run, all commands verbatim)

| # | Command | Exit | Result |
|---|---|---|---|
| 1 | `cargo fmt --all -- --check` | 0 | clean |
| 2 | `cargo clippy --workspace --all-targets -- -D warnings` | 0 | `No issues found` |
| 3 | `cargo test --workspace --all-targets` (debug) | 0 | **734 passed; 0 failed** (25 suites) — baseline 681 + 53 new |
| 4a | `cargo test -p cerberus-proxy --all-targets` | 0 | 235 passed (2 suites) |
| 4b | `cargo test -p cerberus --all-targets` | 0 | 69 passed (5 suites) |
| 4c | `cargo test -p cerberus-hardening --all-targets` | 0 | 35 passed (4 suites) |
| 4d | `cargo test -p cerberus-packs --all-targets` | 0 | 87 passed (2 suites) |
| 5 | `cargo test -p cerberus-packs --test production_pack_pr` | 0 | **19/19 passed** |
| 6 | `cargo test --release --test redos_fuzz -- --test-threads=1` | 0 | **11/11 passed** |
| 7 | `cargo test --release --test load_test -- --test-threads=1 --nocapture` | 0 | **14/14 passed**, incl. the F3.3 honest HTTP gate (below) |
| 8 | `git diff --check` | 0 | clean |

### Honest HTTP latency gate (run 7 detail) — no-latency-regression proof

Command: `rtk proxy cargo test --release --test load_test load_test_f3_3_honest_http_round_trip_gate -- --test-threads=1 --nocapture`
Workload: 50 KB / 37-leaf JSON redact, enforce, default pack, real HTTP round trip proxy↔mock, 2,000 individual samples per scenario, interleaved 1:1 proxy/direct, keep-alive, `fingerprint=sha256:e3f206dd25ecce9adfdd7b16f752e64f4db75faf7f51677f3214f62ff1667022` (drift-guarded, unchanged).

| Metric | This run (with F3.1+F3.2 changes) | F3.3 baseline @ fac8236 (5 runs, `evidence/f3/r9-honest-latency-gate.md`) |
|---|---:|---:|
| proxy p50 | 0.686 ms | 0.686–0.720 |
| proxy p99 | **0.848 ms** | 0.851–1.553 |
| direct p99 | 0.172 ms | 0.168–0.225 |
| overhead p99 | 0.676 ms | 0.684–1.327 |
| strict budget | p99 < 5.0 ms → **PASS** | 5/5 PASS |

Load average at run time: 4.71 / 4.32 / 3.94 (1/5/15m) — the host carried background contention (opencode/Chrome processes); the result matches the baseline distribution's best run, with the added per-request cost of R9-11 (one RwLock read + HashMap lookup) invisible at p99. No threshold was moved (`tests/load_test.rs` untouched: `git diff` shows zero changes to it).

## Adversarial cases tested (attempt to break)

- Multipart with quoted boundary / special-char boundary / over-long boundary (600 chars) / missing boundary → parsed or bounded Text fallback; never unbounded work. ✅
- Part-count bomb (5,000 parts) → structured parse abandoned, whole-text over-scan (never under-scan). ✅
- Malformed corpus (12 bodies: empty, `--`, truncated, CR-only, no blank line, mixed line endings) → never panics, regions in bounds. ✅
- Binary preservation: 512-byte all-byte-values audio part through decode+redact+vault round trip AND through the real proxy → byte-exact. ✅
- Redaction failure under the default policy: critical findings → 502 with no raw secret; non-critical → original forwarded (both at unit and pipeline level). ✅
- Undecodable JSON under the default → 502 (closed posture). ✅
- `expected_auth: query` → parse error (no silent ignore). ✅
- Per-upstream mode `bogus` → parse error. ✅
- Mixed fleet: shadow upstream never blocks even with a block-rule match; enforce upstream blocks even under global shadow; unset-mode upstreams inherit the global. ✅
- Multipart secret spanning what would be separate TCP chunks → buffered before decode, whole secret scanned. ✅ (buffered-decoder invariant; noted as design, not streaming)

## Applicable NFRs

- Latency: honest HTTP gate proxy p99 = **0.848 ms** (< 5.0 ms strict) → ✅ (matrix run 7).
- Security: no new panic sites (adversarial corpus); block-path upstream starvation verified (`multipart_block_rule_blocks_the_request`); redaction failures still refuse to emit raw critical secrets; `redos_fuzz` 11/11 unchanged (multipart scanning uses the same crate `regex` engine, no lookarounds). ✅
- MVP boundary respected: multipart = text-part scan only; no streaming, no recursive MIME walking, no binary-part scanning (see Known limits). ✅

## Frozen SHA-256 hashes (touched files, worktree state at commit)

```
22304e2ea2b822989449e1a885fe198bf38fa3cc0102243e65267468f8ac0e26  crates/cerberus-proxy/src/api.rs
8972d3fdfa30bfe3ad98fa8fd417375dce4d5ab07d707cac73bb221a440970a5  crates/cerberus-proxy/src/config.rs
91db52417d00670678bee3f1785accd5f13ee46bda97c5cf3431e696ba279707  crates/cerberus-proxy/src/decoder.rs
f69b8c6437f2f0643698ca53602cb79ac7d42cd67727b6b5920059187345ef19  crates/cerberus-proxy/src/forward.rs
94c2ab5fca09767bfb219911d09680fedfcdd72b2378971029a670e99aadf6b0  crates/cerberus-proxy/src/json_redact.rs
df68cb68d5c899af194f833eb0b2fbd38f7a76dc91754b74a624f82d6edaafa8  crates/cerberus-proxy/src/policy.rs
ce04cfefc7e24a056b370de807c607348bd171740f06b633dfb4c8bec0d89ff6  crates/cerberus-proxy/src/proxy.rs
689fdd7026353f4a0481641871394adb37b1941b2beb45b2bc5ea0ea5cb0fc00  crates/cerberus-proxy/src/test_utils.rs
87b003523fd13fbd3f45dd65e945ba27c1be84380f76dcb9dbe5807d16c1d792  crates/cerberus-proxy/tests/smoke_harness.rs
aacf8b2c864e92709e9f252838259ad802c8457ba7dddfa29092ae53ad579184  crates/cerberus/src/daemon.rs
3c3c0a59f56fd823717c86e4092aaf0842952175701fcb04607099698a8d008d  tests/failsafe.rs
```

## Known limits (MVP boundary, for the panel)

1. **Multipart** (§4.2 MVP): text-part scan only. Binary classification uses an explicit textual list (`text/*` + 6 known textual `application/*` types); any other content type — including unknown future types — is treated as binary and NOT scanned (fails toward byte-exact preservation, per F3.1's "preservación exacta de binarios"). No recursive MIME walking (a nested `multipart/*` part is handled by its declared type). A body that fails structured parsing falls back to today's whole-text lossy scan (over-scan; redaction then rewrites it as text, same as the pre-existing Text path).
2. **Preamble** text before the first delimiter is not scanned (epilogue too); both are tolerated and ignored per RFC 2046. Extremely exotic for LLM traffic; the structured parse otherwise over-scans rather than under-scans.
3. **R9-12 semantics**: the criticality signal at the redaction site is the pipeline's post-allowlist finding view; an operator-allowlisted critical secret whose leaf re-scan still fails redaction therefore fails OPEN under the default (documented in the delta table). Decode failures and upstream failures keep the closed posture (indeterminate criticality).
4. **R9-20**: `expected_auth` is input-compat only (never serialized back); the only supported value is `header`. API payloads (`POST /api/upstreams`) expose `mode` but not `expected_auth` (compat is a config-file concern; full API/CLI parity is F6.4).
5. `tests/load_test.rs` was NOT touched (gate budgets frozen); the gate re-ran green.

## If FAIL: what fails and how to reproduce it

- Nothing failed in this attempt. All matrix commands re-runnable verbatim from the worktree `/var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/f3-attempt2-builder` (branch `r9-f3-attempt2`, commit recorded below).

## Builder verdict

**FIX executed for R9-11, R9-12, R9-13, R9-20 — returns to VERIFY** with an independent reviewer. The unit is NOT closed; per §8B.7 closure requires the independent VERIFY pass and the F3 phase gate sign-off.

---

# FIX attempt 2 — builder repair round (post attempt-1 panel FAIL)

- Attempt: 2    Builder: F3.1+F3.2 builder subagent    Verdict: **FIX executed — returns to VERIFY** (unit NOT closed; §8B.3)
- Date: 2026-09-01    Candidate base: `7519ad9` (branch `r9-remediation`, clean tree; parent of the attempt-1 candidate 71c5939 = the attempt-1 panel reports)
- Work branch: `r9-f3-attempt3` (isolated worktree `/var/folders/l8/.../opencode/f3-attempt3-builder`, NOT pushed)
- Scope guard: all four findings' (R9-11/12/13/20) attempt-1 acceptance criteria kept intact; no threshold moved; `tests/load_test.rs` untouched; no scope beyond §4.2 MVP.

## Root causes and fixes (per finding)

### F-1 [P1, correctness] scan-context asymmetry → critical-rule matches routed into fail-open
- **Root cause:** TWO different scan models over one body. The pipeline decision scanned `decoded.text` (part payloads joined with `\n`, same-line proximity, `engine::scan`), while the multipart redaction re-scanned each region with a `ContextAnalyzer` over the FULL raw body (`keyword_anywhere`) — headers, preamble, epilogue and binary bytes included. A rule could fire in the re-scan but not in the decision; on redaction failure the policy's criticality oracle (the pipeline view) never saw the critical finding → fail-open forwarded the raw secret (200).
- **Fix — one authoritative scan pass feeding both the decision and the redaction:**
  - `scan_multipart_regions` (json_redact.rs:129) is now THE one scan pass: every recorded text region is scanned **in isolation** with `engine.scan_with_context_analyzer` against ONE `ContextAnalyzer` built over the full lossy body (the same context machinery as the JSON leaf path — cross-part and metadata keywords validate matches, fix P1-3). It produces `MultipartScan { regions, per-region findings }` (json_redact.rs:115) with the allowlist applied per region on the region-relative raw value.
  - The pipeline consumes it at proxy.rs:710-719: decision view = `multipart_scan_output(&scan)` (json_redact.rs:171), so block/redact/criticality is judged from exactly these findings.
  - The redaction performs **NO scan of its own**: `redact_body_with_multipart_scan` (json_redact.rs:68) → `redact_multipart` (json_redact.rs:202) splices the very same per-region findings (pipeline call site proxy.rs:793-801). There is no surface left where a region scan can fire a rule the decision never saw — or vice versa. This reaches the same consistency the JSON leaf path already had (one analyzer per body).
  - Direct callers of the 6-arg `redact_body` (tests, load_test) keep the old signature; on multipart they get an identical local self-scan (empty allowlist — can only over-redact, never under-redact). The PIPELINE always uses the 7-arg entry with its own pass.
- **Why this also closes the allowlist window honestly:** the allowlist is now authoritative end to end on multipart (same as the pre-existing text path): an operator-allowlisted value is neither flagged nor redacted — no "failure" is manufactured by a re-scan the policy cannot see. Known limit #3 below is updated accordingly.
- **Tests (pipeline layer):** `f1_repro_keyword_in_part_header_blocks_via_pipeline` (smoke_harness.rs) drives the EXACT attempt-1 adv1 payload (critblock rule, keyword `harmlessword=` ONLY in part-2's header, low-redact secret in part-1): the decision now fires the critical block rule → **403, upstream received nothing**. Companion `multipart_authoritative_scan_is_the_single_consistent_model` (json_redact.rs) proves decision-view and redaction agree with and without the allowlist.

### P1-3 [P1, security] cross-part context keywords dead in the DECISION path; acceptance test at the wrong layer
- **Root cause:** the decision scan joined payloads with `\n` and applied same-line proximity (`constraints.rs:157 keyword_near_match`) — a keyword in another part (or in field-name metadata) could never be on the same line as the match → no finding → the redact-layer re-scan never ran. The attempt-1 acceptance test called `redact_body` directly, bypassing the pipeline.
- **Fix:** the authoritative per-region scan uses `keyword_anywhere` over the full body for the DECISION too (same machinery as the JSON leaf path). The wrong-layer acceptance test was rewritten at the pipeline layer.
- **Tests (pipeline layer):** `multipart_context_keyword_in_other_part_redacts_via_pipeline` (keyword in part-1 payload, secret in part-2 → 200, upstream receives `[REDACTED:test.ctxredact]`) and `multipart_keyword_in_part_metadata_redacts_via_pipeline` (keyword ONLY in `name="zeta"` part-header metadata → secret redacted) — both through `spawn_proxy` → `proxy_handler` with a byte-capturing upstream. The redaction-layer unit test (`multipart_context_keyword_in_other_part_redacts`, json_redact.rs) now documents that the acceptance lives in the harness.

### P1-1 [P1, security] preamble / epilogue / part headers never scanned (silent under-scan vs the old lossy path)
- **Root cause:** `parse_multipart` recorded regions for part payloads only; preamble, epilogue and all part-header bytes were dropped from the scan surface (no finding, no event, no feedback).
- **Fix (decoder.rs):**
  - `TextRegion` gains `kind: RegionKind` (`Preamble | PartHeaders | Payload | Epilogue`, decoder.rs:71-93).
  - `parse_multipart` (decoder.rs:277) now records: the **preamble** (decoder.rs:294-302, ending before the line break that belongs to the first delimiter line so a redaction splice can never de-line-start a delimiter), the **epilogue** (decoder.rs:313-324, after the closing `--` and its terminating line break — nothing structural follows, splicing is safe), and every part's **header block** (decoder.rs:349-361, for ALL parts including binary-claimed ones — header bytes are text regardless of the part type; the blank separator line stays OUT of the region so redaction cannot eat it).
  - All recorded regions are scanned by the authoritative pass and redacted in place (reverse-offset splice); boundaries and binary part PAYLOADS remain byte-exact (F3.1 mandate).
- **Tests:** decoder-level `multipart_preamble_epilogue_and_headers_are_scanned_regions`, `multipart_preamble_region_never_swallows_the_delimiter_line_break`, `multipart_part_header_secret_is_scanned_and_redacted_in_place`, `multipart_preamble_and_epilogue_secrets_are_redacted` (redaction in place, body re-parses as multipart); pipeline-level `multipart_preamble_epilogue_and_header_secrets_never_forward_raw` (200 + zero raw secrets in the captured upstream body + structure intact) and `multipart_block_secret_in_part_header_blocks_via_pipeline` (403, detection parity with the old lossy path).

### P1-2 [P1, security] per-upstream mode silently inert on the MITM path
- **Root cause:** `forward.rs` set `DirectUpstream.provider = CONNECT hostname` (`api.openai.com`); the mode lookup keys on upstream map KEYS (`openai`) → unless an operator literally named an upstream by hostname, every MITM request inherited the global mode; with global `shadow` + per-upstream `enforce`, MITM traffic silently forwarded unredacted (task-forbidden state).
- **Fix — resolve the mapping per the config's own keying (preferred over fail-closed):** `mitm_provider_of` (proxy.rs:1091) resolves the CONNECT host at request time: (1) exact key match (the documented hostname-keying convention, unchanged); (2) the upstream whose `url` HOST equals the CONNECT host — case-insensitive, deterministic name-order tiebreak (`upstream_url_host`, proxy.rs:1067, parsed via `hyper::Uri`); (3) unmapped host keeps the hostname as provider and inherits the global mode — the same documented fallback as an unknown provider on the reverse-proxy path (audit shows the raw host; `tracing::debug!` marks both fallbacks). The resolution feeds mode, audit provider and break-glass scope consistently.
- **Tests (MITM layer, forward.rs):** `connect_tls_per_upstream_mode_resolves_by_url_host_and_never_silently_shadows` — the exact forbidden state: global `shadow` + upstream `openai` (url host = CONNECT host) with `mode: enforce` → intercepted request **403, nothing reaches the upstream**; control: an unmapped host under the same ctx inherits global shadow → 200 intact. `connect_tls_per_upstream_shadow_mode_never_blocks_on_mitm_path` — reverse direction: per-upstream `shadow` under global `enforce` never blocks, body passes intact. Unit tests: `mitm_provider_maps_connect_host_to_upstream_url_host`, `mitm_provider_exact_hostname_key_wins_and_mapping_is_deterministic`, `upstream_url_host_parses_scheme_and_port` (proxy.rs).

### F-2 / P2 [correctness] cross-join multiline matches visible to the pipeline but to no region
- **Root cause:** the `\n` join let a multiline pattern match ACROSS a part boundary in the pipeline scan; the region-wise redaction could never splice such a span → silent non-redaction (latent behind custom rules).
- **Fix — consistent model, documented:** regions are the scan unit. The pipeline now scans each region in isolation (payloads, headers, preamble, epilogue) — there is NO joined-text view left for the decision to disagree with. A pattern spanning two regions is visible to NEITHER the decision NOR the redaction; a region-local multiline match is visible to BOTH. Decision and redaction can no longer diverge. Documented as known limit #2 below. (The structured-parse fallback — part bombs, unusable boundary — remains the whole-text model where redaction consumes the pipeline findings, consistent by construction.)

### P2-2 [security] fail-open audited as `action_taken: "redact"`
- **Root cause:** the event was derived from the rule action (`Redacted` + `action_taken="redact"`) regardless of whether redaction SUCCEEDED; an auditor could not distinguish "redacted" from "redaction failed, raw forwarded". Shadow events had the mirror ambiguity.
- **Fix (proxy.rs):**
  - `RedactDecision::FailOpenForward` is its own variant (proxy.rs:478); `SecurityEvent::RedactFailed` (log.rs:25, WARN level) logs the true outcome.
  - Every outcome is audited with an honest action + flag (flags: proxy.rs:163-173; `record_outcome_event`, proxy.rs:1231): fail-open forward after redaction failure → `action_taken="fail-open"` + flag `redact-failed` (never plain `redact`); the 502 fail-closed reject → `action_taken="fail-closed"` + `redact-failed`; decode failure → flag `decode-failed` with `fail-closed` (reject) / `fail-open` (Open-policy forward); shadow with findings → flag `shadow` on the would-be-action event.
- **Tests:** `closed_on_critical_fail_open_is_audited_honestly` (200 + original byte-exact forwarded + exactly one event with `action_taken="fail-open"` + `redact-failed`), `closed_on_critical_reject_is_audited_honestly` (502 + event `fail-closed`), `shadow_mode_events_carry_the_shadow_flag` (would-be `block` recorded while the body passed, flag `shadow`) — all pipeline-layer; plus the forward.rs fail-policy loop now asserts the flag and the honest action on the MITM path for all three policies, and the MITM shadow test asserts the `shadow` flag.

### P2-1 [security] binary-claimed parts carry text secrets raw — silently
- **Root cause:** skipped binary payloads were invisible (documented trade-off, but silent — A4/A5 probes).
- **Fix:** `DecodedBody.binary_parts_skipped: usize` (decoder.rs:61) counts every non-empty binary-claimed payload skipped by the structured parse; the pipeline pushes the `binary-unscanned` flag + a WARN log on such requests (proxy.rs:743-750), and records a visibility event even with zero findings (proxy.rs:893-905) — under-scan is never silent. Byte-exact preservation unchanged (plan trade-off kept).
- **Tests:** `multipart_binary_claimed_part_under_scan_is_audited` (pipeline layer: 200 forwarded, audit event carries `binary-unscanned`).

### P3-1 [cosmetic, security-adjacent] boot config parse errors swallowed
- **Fix:** `load_proxy_config_from` (daemon.rs:125-143) logs the real serde error at ERROR level with the file path and the fail-closed consequence; behavior unchanged (invalid file ignored, defaults apply / boot refuses where required).

### P3-2 [theoretical TOCTOU] — accepted residual, unchanged
Mode/provider and `resolve_route` still take separate config snapshots; exploiting it requires authenticated control-plane access mid-request. Out of this fix round's scope (not a required finding); unchanged behavior, still documented.

## Updated known limits (MVP boundary)

1. **Multipart** (§4.2 MVP): text-part scan only for PAYLOADS; binary classification unchanged (explicit textual list; everything else binary, byte-exact, now flagged `binary-unscanned`). No recursive MIME walking. Part bombs / unusable boundary → whole-text fallback (over-scan).
2. **Consistent scan model (fix F-2):** regions are the scan unit — a pattern spanning two regions (only possible for custom multiline rules whose charset tolerates the delimiter text between them) is matched by neither the decision nor the redaction. No silent non-redaction is possible: the redaction never sees a different model than the decision. The whole-text fallback paths scan everything.
3. **Allowlist semantics on multipart (updated):** the operator allowlist is authoritative end to end — an allowlisted value is neither flagged nor redacted on any path (JSON leaf re-scan still over-redacts allowlisted values; text/multipart do not). A redaction failure under the default policy therefore fails closed iff the request carries non-allowlisted critical findings visible to the authoritative scan.
4. **R9-20** unchanged (input-compat alias, never serialized).
5. `tests/load_test.rs` untouched (gate budgets frozen); the honest HTTP gate re-ran green with the identical drift-guard fingerprint.

## Acceptance evidence — attempt-1 findings closed

| Finding | Closing mechanism (file:line) | Closing test (pipeline layer unless noted) | Result |
|---|---|---|---|
| F-1 (P1) | One authoritative scan pass: scan_multipart_regions json_redact.rs:129; decision view proxy.rs:710-719; redaction consumes the same findings proxy.rs:793-801 | `f1_repro_keyword_in_part_header_blocks_via_pipeline` — adv1 payload → 403, nothing forwarded; `multipart_authoritative_scan_is_the_single_consistent_model` (unit) | ✅ |
| P1-3 (P1) | `keyword_anywhere` over the full body in the decision pass; wrong-layer test rewritten | `multipart_context_keyword_in_other_part_redacts_via_pipeline`; `multipart_keyword_in_part_metadata_redacts_via_pipeline` | ✅ |
| P1-1 (P1) | Preamble/epilogue/part-header regions: decoder.rs:294-361; scanned + redacted in place | `multipart_preamble_epilogue_and_header_secrets_never_forward_raw`; `multipart_block_secret_in_part_header_blocks_via_pipeline` (+ 4 decoder/json_redact unit tests) | ✅ |
| P1-2 (P1) | mitm_provider_of URL-host mapping: proxy.rs:1067-1134 | `connect_tls_per_upstream_mode_resolves_by_url_host_and_never_silently_shadows`; `connect_tls_per_upstream_shadow_mode_never_blocks_on_mitm_path` (+ 3 unit tests) | ✅ |
| F-2 (P2) | Region-isolation model — decision cannot depend on joins redaction cannot see; documented | Covered by the authoritative-scan consistency unit test + all multipart pipeline tests | ✅ |
| P2-2 (P2) | FailOpenForward variant proxy.rs:478; SecurityEvent::RedactFailed log.rs:25; honest actions + flags proxy.rs:163-173, 799-871, 1231 | `closed_on_critical_fail_open_is_audited_honestly`; `closed_on_critical_reject_is_audited_honestly`; `shadow_mode_events_carry_the_shadow_flag`; forward.rs loop flag assertions (all three policies, MITM path) | ✅ |
| P2-1 (P2) | binary_parts_skipped decoder.rs:61; `binary-unscanned` flag + visibility event proxy.rs:743-750, 893-905 | `multipart_binary_claimed_part_under_scan_is_audited` | ✅ |
| P3-1 (P3) | Loud ERROR log on parse failure: daemon.rs:125-143 | behavior unchanged (fail-closed); log-only fix | ✅ |

## Verification matrix (builder run, attempt 2, all commands verbatim)

| # | Command | Exit | Result |
|---|---|---|---|
| 1 | `rtk cargo fmt --all -- --check` (after `rtk cargo fmt --all`) | 0 | clean |
| 2 | `rtk cargo clippy --workspace --all-targets -- -D warnings` | 0 | `No issues found` |
| 3 | `cargo test --workspace --all-targets` (debug) | 0 | **753 passed; 0 failed** (25 suites; baseline 734 + 19 net new) |
| 4 | `rtk cargo test -p cerberus-packs --test production_pack_pr` | 0 | **19/19 passed** |
| 5 | `cargo test --release --test redos_fuzz -- --test-threads=1` | 0 | **11/11 passed** |
| 6 | `cargo test --release --test load_test -- --test-threads=1 --nocapture` | 0 | **14/14 passed** incl. the honest HTTP gate (below) |
| 7 | `git diff --check` | 0 | clean |

### Honest HTTP latency gate (matrix run 6 detail) — no-latency-regression proof

`f3_3_http_round_trip: profile=release payload_bytes=51200 leaves=37 warmup=100 samples_per_scenario=2000 interleaving=proxy_direct_1to1 fingerprint=sha256:e3f206dd25ecce9adfdd7b16f752e64f4db75faf7f51677f3214f62ff1667022` (drift-guard fingerprint UNCHANGED — the workload was not touched).

| Metric | Attempt-2 run | Attempt-1 builder run | F3.3 baseline @ fac8236 |
|---|---:|---:|---:|
| proxy p50 | 0.699 ms | 0.686 ms | 0.686–0.720 |
| proxy p95 | 0.763 ms | — | — |
| proxy p99 | **0.917 ms** | 0.848 ms | 0.851–1.553 |
| direct p99 | 0.194 ms | 0.172 ms | 0.168–0.225 |
| overhead p99 | 0.723 ms | 0.676 ms | 0.684–1.327 |
| strict budget | p99 < 5.0 ms → **PASS** | PASS | 5/5 PASS |

The +0.07 ms p99 delta vs attempt 1 is inside the baseline's run-to-run spread and far under the 5.0 ms strict budget. The attempt-2 scan model does not add a pass (the redaction no longer re-scans regions; the header-region scan adds only the header bytes).

## Frozen SHA-256 hashes (touched files, attempt-2 commit state)

```
d5e1b4a077f7dcb7e80eb451bdd6942fe5d42d1cc095d224234c6ec463056eea  crates/cerberus-proxy/src/decoder.rs
6e1da7f0b8bb4e6ccc26edf66a32c27e56dcd28700a067f7e113f61db7bdcb56  crates/cerberus-proxy/src/forward.rs
bfc4596b1b2f76b21a7c5b5b1f978dcb34fde93a0e7b0bcf14fc5d2a67d42e3b  crates/cerberus-proxy/src/json_redact.rs
8177059c789b3e22b857d0189c84f4938e739b861340606c07e613f7b1503fed  crates/cerberus-proxy/src/log.rs
94f9e82a5717bd507bbf557b056f3df800af3a1e96252c7e59d387e6bcf72d1e  crates/cerberus-proxy/src/proxy.rs
ea3d41a727accd3f0f53f3228f918cd8dd1fac6b0c7fe91939d97690b2c4b431  crates/cerberus-proxy/tests/smoke_harness.rs
72c8f39fc7fdd46c3da334b8b5595c9dcef0a1454e7d6d319d9df1761b51c801  crates/cerberus/src/daemon.rs
```

(Attempt-1 hashes above remain the record for the files this round did not touch. `tests/load_test.rs` untouched — zero changes, verified via `git status`.)

## If FAIL: what fails and how to reproduce it

Nothing failed in this attempt. All matrix commands re-runnable verbatim from the worktree `/var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/f3-attempt3-builder` (branch `r9-f3-attempt3`, commit recorded in the repo history; worktree left in place for the panel).

## Builder verdict (attempt 2)

**FIX executed for F-1, P1-1, P1-2, P1-3, P2-1, P2-2, F-2, P3-1 — returns to VERIFY.** The unit is NOT closed; per §8B.7 closure requires the independent re-verification pass and the F3 phase gate sign-off.
