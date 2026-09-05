# F3.1+F3.2 — Independent Adversarial Review (SECURITY lens), attempt 1

- Unit: **F3.1 + F3.2** (R9-13 multipart MVP decoder, R9-11 per-upstream mode, R9-12 ClosedOnCritical default, R9-20 wire-name fix)
- Candidate: commit `71c5939` (branch `r9-remediation`, parent `fac8236`) — worktree `/var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/f32-attempt1-security`
- Reviewer: independent security subagent (did NOT build; blind to the correctness lens)
- Date: 2026-09-01 — Host: Apple M4 Pro, macOS 26.5.1, rustc/cargo 1.97.1
- Method: §8B — gates re-run verbatim, then adversarial verification against the **real proxy** (`target/release/cerberus`, isolated `$HOME`, mock upstream with byte-exact capture) with attacker-crafted multipart/mode/fail-policy payloads.

**Final verdict: FAIL** (three P1 findings; gates and core acceptance criteria PASS — details below).

## Commands run

| # | Command (verbatim) | Exit | Result |
|---|---|---|---|
| 1 | `git -C /Users/alexeirojas/Work/Personal/Cerberus worktree add --detach /var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/f32-attempt1-security 71c5939` | 0 | worktree at 71c5939 |
| 2 | `rtk cargo clippy --workspace --all-targets -- -D warnings` | 0 | `No issues found` |
| 3 | `rtk cargo test --release --test redos_fuzz -- --test-threads=1 --nocapture` | 0 | **11/11 passed** |
| 4 | `rtk cargo test -p cerberus-proxy` | 0 | **235 passed** (3 suites) |
| 5 | `rtk cargo test -p cerberus-packs --test production_pack_pr` | 0 | **19/19 passed** |
| 6 | `cargo build --release -p cerberus` | 0 | harness vehicle (real daemon) |
| 7 | `python3 mock_upstream.py 9401` + `HOME=<tmp> ./target/release/cerberus start --port 9400` (isolated HOME, config with 3 custom rules + `shadowed`/`enforced` upstreams, default fail policy) | 0 | daemon up: `mode=enforce fail_policy=closedoncritical … 18 rules (15 base)` |
| 8 | `python3 attack_a.py` (21 adversarial vectors through the live proxy) | 0 | results below |
| 9 | `python3 analyze_capture.py` (byte-exact upstream capture analysis) | 0 | raw-vs-redacted verdicts |
| 10 | `curl -s -X POST http://127.0.0.1:9400/api/allowlist -d '{"value":"BLOCKSECRET1cccccccccc"}'` | 200 | redaction-failure mechanism armed |
| 11 | `python3 attack_c.py` + `attack_c2.py` (fail-policy table + events honesty) | 0 | C1 502 / C2 200+raw / C3fix 502 / C4 200+raw / C5 502 |
| 12 | `python3 attack_d.py` + D6'/D6''/D7/D8 (DoS corpus, wall-clock) | 0 | bounded/linear (table below) |
| 13 | boot tests with `expected_auth: none` / `query` / `header` (3 isolated HOMEs) | 1/1/0 | none+query **refused to boot**; header boots, `/health` 200 |
| 14 | `fail_policy: open` daemon on :9404 → undecodable JSON | 200 | forwarded (Open semantics unchanged) |
| 15 | `sqlite3 …/cerberus.db` greps for 5 raw secrets over all audit columns; `grep` over daemon logs | 0 rows / 0 hits | hashed-only (`sha256:…`) |
| 16 | live binary-preservation probe (512 B all-byte-values part through proxy) | 200 | byte-exact, structure intact |
| 17 | cleanup: `kill <daemon>`, harness pids stopped | 0 | sibling-lens process left untouched |

## Per-criterion verdicts

| Criterion | Evidence | Verdict |
|---|---|---|
| **G1** clippy `-D warnings` | cmd 2, exit 0 | ✅ PASS |
| **G2** redos_fuzz 11/11 | cmd 3 | ✅ PASS |
| **G3** cerberus-proxy 235 | cmd 4 | ✅ PASS |
| **G4** production_pack_pr 19/19 | cmd 5 | ✅ PASS |
| **R9-11** per-upstream mode parses/validates; shadow never blocks; enforce enforces; global fallback; serialization | unit tests (in 235) + live B1 (`/shadowed` block secret → **200 intact**), B2 (`/enforced` → **403**), B5 (case-mangled prefix falls to default=enforce, fails safe), B4 (attacker `Host:` ignored for routing), `GET /api/upstreams` reports `mode` | ✅ PASS (reverse-proxy path) — ⚠ **P1-2 MITM parity** below |
| **R9-12** `closed-on-critical` parses, is the default, critical→502, non-critical→forward original, decode-fail closed, open/closed unchanged | unit + live: C1 **502** (nothing forwarded), C3fix (multipart) **502**, C2/C4 **200 + original byte-exact raw**, C5 undecodable **502**, `fail_policy: open` daemon → undecodable **200 forwarded**; boot log `fail_policy=closedoncritical` | ✅ PASS — ⚠ **P2-2 audit honesty** below |
| **R9-13** multipart MVP: text parts scanned w/ structure preserved; binary byte-exact; bounded parser; truncated/CR-LF/boundary-cap handled | live A1/A7/A8/A9/A10/CT-variant probes (all redacted, boundaries+headers intact); binary 512 B byte-exact at offset 97; part bomb 6 001 parts → over-scan in **3 ms**; 4 000 parts 2.5 ms; 43 MB worst case 2.7 s (linear, under 64 MiB cap → 413 beyond); adversarial corpus in unit tests | ✅ PASS gates — ⚠ **P1-1, P1-3, P2-1 bypass findings** below |
| **R9-20** `expected_auth: header` only; other values fail closed; `auth_header` canonical | live boot: `none`/`query` → `start failed`, exit 1, **no no-auth state**; `header` → boots, health 200; unit tests assert serde error mentions `expected_auth`; `skip_serializing` verified by unit test | ✅ PASS (P3-1 diagnostic note) |
| **Task f** no secret logging in new paths | 0 hits for 5 raw secrets in all daemon logs; 0 raw rows in SQLite audit (hashed `sha256:…` only); decoder emits no logs (metadata only) | ✅ PASS |

## Attack vectors tried (payload → observed result)

Multipart boundary `SECBOUND`; secrets: `BLOCKSECRET1…` (block/critical), `REDACTSECRET2…` (redact/high), `CTXSECRET-…` (redact/critical, requires context keyword `zeta`). "RAW" = secret present byte-exact in the mock upstream's captured body.

| ID | Vector | Observed |
|---|---|---|
| A1 | sanity: secret in canonical text part | **REDACTED** `[REDACTED:test.redactrule]`, structure intact ✅ |
| A2 | **secret in PREAMBLE** (before first boundary) | **RAW-FORWARDED**, no finding, no event, no feedback header — old lossy path scanned this. Evidence: `preamble secret REDACTSECRET2bbbbbbbbbb here` forwarded verbatim ❌ **P1-1** |
| A3 | **secret in EPILOGUE** (after closing `--`) | **RAW-FORWARDED**, silent ❌ **P1-1** |
| A4 | text secret in part **claimed binary** (`application/octet-stream`) | **RAW-FORWARDED**, silent — documented MVP tradeoff ⚠ **P2-1** |
| A5 | **boundary smuggling**: text-part payload contains `\n--SECBOUND\r\nContent-Type: application/octet-stream\r\n\r\nSECRET` → fake binary part | **RAW-FORWARDED**, silent ⚠ **P2-1** |
| A6 | context keyword only in form **field name** (`name="zeta"`) | **RAW-FORWARDED** (metadata not in scan text) |
| A6b | context keyword in **another part's payload** | **RAW-FORWARDED** — decision scan uses same-line proximity over payloads-joined text; redact-layer re-scan never runs ❌ **P1-3** |
| A6c | control: same secret+keyword in a `text/plain` body (old-path equivalent) | **REDACTED** ✅ (proves old path caught it) |
| A7 | truncated final part, secret at EOF | **REDACTED** ✅ (scan-to-EOF claim holds) |
| A8 | LF-only delimiters | **REDACTED** ✅ |
| A9 | CR-only delimiters (parser-invisible) | whole-body text over-scan → **REDACTED** ✅ (fails safe) |
| A10a | boundary at 255 B cap edge | **REDACTED** ✅ |
| A10b | boundary 600 B (> cap) | text fallback → **REDACTED** ✅ |
| A11 | part-count bomb (6 001 parts) | structured parse abandoned → over-scan → **REDACTED**, 3 ms ✅ |
| A12 | **secret in part HEADERS** (`filename=`, custom header) | **RAW-FORWARDED**, silent ❌ **P1-1** |
| CT+ | `TEXT/PLAIN; charset=utf-8`, quoted params, headerless parts | all **REDACTED** in place, headers preserved ✅ |
| BIN | 512 B all-byte-values binary part + redacted text part through live proxy | binary **byte-exact**, boundaries intact, secret redacted ✅ |
| B1/B2 | shadow / enforce upstream with block secret | 200 intact / 403 ✅ |
| B4 | attacker `Host: api.openai.com` on `/shadowed` | routing unaffected (path-based) ✅ |
| B5 | `/SHADOWED/` case-mangled prefix | falls to default (enforce) → 403, fails safe ✅ |
| B6 | `/shadowed/../enforced/` traversal | prefix match on raw path → shadowed upstream; mode and destination never diverge ✅ |
| C1 | JSON redaction failure **with critical finding** | **502**, upstream received nothing, error body has flag only ✅ |
| C2 | JSON redaction failure, **non-critical only** | **200**, original forwarded **byte-exact raw** (documented §4.1) — audit event says `action_taken:"redact"` ⚠ **P2-2** |
| C3fix | MULTIPART redaction failure with critical finding | **502** ✅ |
| C4 | MULTIPART redaction failure, non-critical only | **200**, raw forwarded incl. a non-allowlisted redact secret — same P2-2 ⚠ |
| C5 | undecodable JSON under default | **502** ✅; under `open` → 200 forwarded ✅ |
| D0–D8 | DoS corpus (10 MB part, 4 000 parts, 6 000-part bomb, lookalike flood, 8 MB preamble, 255 B-boundary 43 MB near-miss, 4 000 true delims, nested MIME, 2 000×51 headers) | 187 / 2.5 / 2.7 / 17 / 62 / 2 727 / 371 / 1.3 / 12 ms — bounded, no blow-up, no panic; 64 MiB cap enforced (413 → connection cut) ✅ |
| E | log/audit secret-leak scan | 0 raw hits anywhere ✅ |

## Findings

### P1-1 — Silent under-scan: preamble, epilogue and part headers are never scanned (regression vs the old lossy path)
`decoder.rs:223 parse_multipart` records regions for part **payloads** only; bytes before the first delimiter, after the closing delimiter, and all part-header bytes are dropped from `decoded.text`. A secret placed there is forwarded **raw with no finding, no event, no feedback** (A2/A3/A12 — one-line attacker payload). The old path (`ContentType::Text` over the whole body) scanned all of it. This contradicts the pack's own claim ("the structured parse otherwise over-scans rather than under-scans", Known limits #2 downplays it as "extremely exotic" — it is trivially craftable). Fix direction: include preamble/epilogue/header bytes as additional text regions (over-scan).

### P1-2 — Per-upstream mode is silently inert on the MITM path (enforce can silently shadow)
`forward.rs:785` sets `DirectUpstream.provider = host.clone()` (CONNECT hostname, e.g. `api.openai.com`); `proxy.rs:587` resolves mode via `cfg.upstreams.get(&provider)`. Upstream keys are operator names (`openai`, `anthropic` per A.1), so unless an operator names entries by literal hostname, **every MITM request inherits the global mode**. Dangerous direction (task-b forbidden state): global `mode: shadow` + per-upstream `mode: enforce` → MITM traffic for that provider silently forwards unredacted while the operator believes enforce is active. The pack's claim "Works for both the reverse-proxy route and the MITM DirectUpstream path" is only true under an undocumented hostname-key convention; there is no MITM-mode test (0 hits in `forward.rs`/`smoke_harness.rs`).

### P1-3 — Cross-part context keywords are dead in the decision path; the acceptance test validates the wrong layer
The decision scan runs `engine.scan(decoded.text)` (payloads joined with `\n`), which applies **same-line proximity** (`constraints.rs:157 keyword_near_match`) — a keyword in a *different part* (or in field-name metadata) can never be on the same line as the match, so the finding is never produced and `redact_multipart`'s `keyword_anywhere` re-scan is never reached (A6/A6b: secret forwarded raw, zero findings). The acceptance test `multipart_context_keyword_in_other_part_redacts` calls `redact_body` **directly**, bypassing the pipeline scan — green test, false pipeline property (the panel's known root-cause class: gates measuring the easy path). Shipped-pack impact is warn-only today (`pii.phone_number`, `entropy.*` are the only keyword-gated rules); any keyword-gated **block/redact rule in a custom pack** (a product feature) becomes fully bypassable in multipart traffic. Note: the old lossy path also missed the *cross-part* variant (same-line window over the raw body), so this is not a regression — but the acceptance criterion "scanned with the same context machinery as JSON leaf paths" does not hold for the decision path.

### P2-1 — Binary-claimed parts carry text secrets raw (documented tradeoff, judged acceptable but exploitable)
Any part with a non-textual declared `Content-Type` (`application/octet-stream`, `image/*`, unknown, nested `multipart/*`) is skipped, and boundary smuggling lets a text part spawn a fake binary part around a secret (A4/A5). This is the plan-mandated binary-preservation tradeoff and is documented in the pack ("fails toward byte-exact preservation"), so I do not gate on it — but it is a one-header DLP bypass and, like P1-1, completely **silent** (no finding, no event). Content sniffing or at minimum an audit event for skipped bytes would shrink the gap.

### P2-2 — Audit dishonesty on the fail-open branch (and ambiguous shadow events)
On the `ClosedOnCritical` fail-open branch (`proxy.rs:493-499`) the request is logged/audited via `SecurityEvent::Redacted` and `AuditEvent::action_taken = "redact"` (C2/C4: event `{"action_taken":"redact",…}` while the capture shows the raw original forwarded). The only honest trace is an ephemeral `tracing::warn`. An auditor querying `/api/events` or the SQLite store cannot distinguish "redacted" from "redaction failed, raw forwarded". Same ambiguity for shadow: a would-be block is persisted as `action_taken:"block"` while the request passed (arguably by design; add a flag). Fix: push a flag (e.g. `redact-failed`, `shadow`) into `event.flags`.

### P3-1 — Config parse errors are swallowed at boot (`P3`, cosmetic but security-adjacent)
`daemon.rs load_proxy_config_from` does `ProxyConfig::from_file(path).ok()`; a config with `expected_auth: none` refuses to boot (✅ fail-closed, verified) but the operator sees the misleading `no upstreams configured` instead of the real serde error, and with `CERBERUS_UPSTREAM_URL` set an invalid config file would be silently ignored in favor of env config.

### P3-2 — Mode/provider TOCTOU across two config reads (theoretical)
`provider_of`/mode read (proxy.rs:576-588) and `resolve_route` (proxy.rs:786) take separate `RwLock` snapshots; a concurrent control-plane write can pair one upstream's mode with another's destination. Requires authenticated (or R9-5-open) control-plane access mid-request.

**R9-5 interaction (out of scope, flagged):** with the unauthenticated loopback control plane (R9-5), any local page/process can drive the allowlist API used to arm the redaction-failure mechanism — i.e., remotely force the C2/C4 fail-open branch in dev mode. P1-1/P2-1 bypasses are equally silent under any R9-5 posture.

## Final verdict

**FAIL** — returns to FIX. All four gates pass (clippy clean, redos_fuzz 11/11, cerberus-proxy 235, production_pack_pr 19/19) and the core acceptance criteria are empirically confirmed against the real proxy: per-upstream shadow/enforce behaves correctly on the reverse-proxy path, the `ClosedOnCritical` decision table is exactly as documented (critical→502 with nothing forwarded; non-critical→original forwarded; decode/upstream failures stay closed), the wire-name fix boots only on the supported value, multipart text parts are redacted in place with binaries byte-exact, the bounded parser survives every DoS vector I threw at it (worst case 2.7 s on a 43 MB adversarial body, well under the 64 MiB cap, no panic), and no raw secret reaches logs or the audit store. However, this is a dataplane scanner whose reason to exist is "no secret leaves unredacted," and I demonstrated three P1 holes: (1) secrets in the preamble, epilogue, or part headers cross silently — scannable text the old path covered and the pack wrongly claims is over-scanned; (2) the per-upstream mode feature this unit exists to deliver is silently inert on the MITM path with the exact "enforce silently shadows" failure the task forbids; and (3) the cross-part context-keyword acceptance test exercises the redaction layer while the decision path — the only one that matters — never produces the finding, leaving keyword-gated block/redact rules bypassable for custom packs and the evidence pack overstating parity. Two P2s (silent binary-claim bypass as a documented tradeoff; audit events recording `redact` for requests forwarded raw) round out the picture. None of these invalidate the builder's work; all are fixable without design changes (over-scan the discarded bytes as text regions, derive the MITM mode key or document+test the hostname convention, make the acceptance test drive `proxy_handler`, flag failed redactions in the audit). Per §8B, the unit is NOT closed.
