# Evidence Pack — F2.1 / R9-1 JSON dataplane repair

- Unit: F2.1 — R9-1 single-parse JSON redaction (residual reconciliation + repair)
- Builder status: **FIX executed — returns to VERIFY** (unit NOT closed)
- Base HEAD: `74e9c9a6e6f4f4968ff42ca90e23127a6c6a2aa6` (branch `r9-remediation`, clean tree)
- Attempt: 1 (branch `r9-f2-attempt1`, isolated worktree)
- Date: 2026-08-31 (21:22 UTC)
- Host: `Darwin 25.5.0 arm64` (M-series, same host class as the Review 9 measurement)
- Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, `cargo 1.97.1`
- Worktree: `/var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/f2-attempt1-builder`

## Finding under repair (R9-1, P0)

Review 9 measured, on pre-repair code (`fccd9e4`): redact JSON 37-leaf 50 KB through the
real proxy (enforce, default pack, n=100, M-series, release) at **p50 37.4 / p99 38.9 ms
(max 67.4)** vs the closed §5/§9 budget p99 < 3–5 ms for prompts ≤ 50 KB. The value was
marked **NEEDS REPRODUCTION** by the fix-plan §0.1. Blamed mechanisms (VERIFIED part):
per-leaf `scan_with_context` over the full body, per-scan `Regex::new` for multiline and
entropy patterns, and repeated context normalization.

## STEP 1 — Honest reproduction on the current code (74e9c9a, pre-this-fix)

**Permanent gate (in-process `redact_body`, the exact proxy JSON path, 50 KB body,
release, serial, 200 samples + 20 warm-up; gate: `tests/load_test.rs:474`
`load_test_json_many_leaf_context_reuse`, budget `PLAN_PROXY_50KB_BUDGET_MS` = 5 ms):**

| Leaves | p50 (ms) | p99 (ms) |
|---:|---:|---:|
| 64 | 0.211 | 0.220 |
| 512 | 0.336 | 0.383 |

**Throwaway end-to-end HTTP probe** (temp dir `f2-repro/probe.py`, NOT in the repo; exact
R9-1 shape: real release `cerberus` proxy → mock upstream, mode enforce (config default),
default pack, redact JSON 37 leaves / 52,133 bytes, serial keep-alive client, warm-up 20,
n=200 measured, redaction verified per run: `[REDACTED]` present and raw token absent from
what reaches the upstream):

| Path | n | p50 | p95 | p99 | max |
|---|---:|---:|---:|---:|---:|
| proxy (pre-this-fix, 74e9c9a) | 200 | 1.488 ms | 1.663 ms | **1.788 ms** | 1.821 ms |
| direct upstream (same body/client) | 200 | 0.306 ms | 0.542 ms | 0.603 ms | 0.662 ms |

Reproduction result: the 38.9 ms p99 is **NOT reproduced** on the current code — the same
shape measures **1.788 ms p99 end-to-end (~22× below the claim, proxy overhead ≈ 1.2 ms)**,
consistent with the R9-1 hot-path causes having been eliminated by F1.1 (regex
precompilation) and F1.2 (shared context analyzer). The 38.9 ms stands as a pre-repair
measurement; archived probe output: `f2-repro/results*.json` (builder temp artifacts,
quoted above; the F3.3 HTTP-latency gate remains the official end-to-end harness).

Contention note recorded honestly: the first serial `load_test` run at 74e9c9a failed
`load_test_attempt6_pan_path_plan_budgets` (NBSP-only 100 KB p99 3.306 ms vs its 2 ms
CI-contention bound) while builds and the HTTP probe ran concurrently; a clean re-run
passed 13/13. This matches the sensitivity F1.2 already documented ("One final NBSP p99
run hit 2.267 ms under OS contention"). No threshold was touched.

## STEP 2 — Residual scope reconciliation (finding text → mechanism → gate)

F2.1 requirement "single-parse JSON with precomputed context" mapped against the code at
74e9c9a:

| F2.1 plan bullet | State at 74e9c9a | Verdict |
|---|---|---|
| Precalculate ONE normalized context for `contextKeywords` | `redact_json` builds one `ContextAnalyzer` per body (`json_redact.rs:65-66`); `keyword_anywhere` caches per keyword-set (`constraints.rs:176-183`); per-leaf scans use `scan_with_context_analyzer` (`engine.rs:434-436`) | **Already covered by closed F1.2** |
| Keep per-leaf scan after F1.1, profile first; batch only if out of budget | Per-leaf scan on leaf text only; no O(leaves × body) remains; permanent 64/512-leaf gate (`tests/load_test.rs:474-521`) proves p99 ≤ 0.383 ms | **Already covered — no batching needed** |
| Never apply raw-JSON offsets to `serde_json::Value` | Redaction operates per leaf string; reserialize via `serde_json::to_vec` | **Already satisfied** |
| Parse JSON ONCE in the pipeline | `decoder.rs:45` parses (`decode` → text for scan) **and** `json_redact.rs:55` parsed the same bytes again on the redact path | **RESIDUAL — repaired in this attempt** |

Other re-decode sites audited and rejected as in-scope: `adapters.rs` takes an
already-parsed `&Value` and is not wired into the request path (no call sites outside its
own file/tests); `api.rs` parses are control-plane, not the redaction dataplane.

## STEP 3 — Residual repair (this attempt)

Single-parse per request on the redaction path, minimal blast radius:

- `crates/cerberus-proxy/src/decoder.rs:16-20` — `DecodedBody` gains
  `pub parsed: Option<serde_json::Value>` (`Some` iff the body decoded as JSON).
- `crates/cerberus-proxy/src/decoder.rs:46-64` — `decode()` keeps the tree it already
  parses for `json_to_string`; no extra parse is introduced on the scan path.
- `crates/cerberus-proxy/src/json_redact.rs:36` — `redact_body` threads
  `decoded.parsed.as_ref()`.
- `crates/cerberus-proxy/src/json_redact.rs:55-76` — `redact_json` reuses the decoded
  tree (`v.clone()` — an exact copy with no re-parse/re-validation, O(body) once per
  request, cheaper than the removed `from_slice`) and keeps the `from_slice` fallback for
  a hand-built `DecodedBody` carrying `parsed: None` (unreachable via `decode()`,
  defensive only).

Findings-preservation argument: both paths parse the same bytes with the same parser;
`serde_json::Value: Clone` is exact; redaction logic, context semantics (raw body as
analyzer context, keys included), findings, actions and hashes are untouched.

New permanent tests (`crates/cerberus-proxy/src/json_redact.rs`):

- `single_parse_reuse_and_fallback_outputs_are_byte_identical` (`:238`) — pipeline path
  (`decode()` → `redact_body`) and fallback path produce **byte-identical** redacted JSON;
  secret absent from output.
- `text_body_decoded_without_parsed_tree_falls_back_to_text_redaction` (`:271`) —
  `parsed: None` text body still redacts via the caller-supplied findings (as proxy.rs
  supplies them).

No new gate was added: the R9-1 shape is already covered by the permanent 64/512-leaf
gate (in-process) and the end-to-end HTTP harness is F3.3 scope per the fix-plan.

## Builder verification matrix (this attempt, post-fix)

| # | Command | Result |
|---|---|---|
| 1 | `rtk cargo fmt --all -- --check` | exit 0 (after one fmt application to new code) |
| 2 | `rtk cargo clippy --workspace --all-targets -- -D warnings` | 0 issues (one `clippy::redundant_clone` nursery finding in a new test repaired) |
| 3 | `rtk cargo test --workspace --all-targets` (debug) | **666 passed; 0 failed** (664 baseline + 2 new) |
| 4 | `rtk cargo test -p cerberus-proxy json_redact` | 7 passed; 0 failed (5 existing + 2 new) |
| 4b | full cerberus-proxy suite | 139 + 38 = 177 passed; 0 failed |
| 5 | `rtk cargo test -p cerberus-packs --test production_pack_pr` | **19/19** |
| 6 | `rtk cargo test --release --test load_test -- --test-threads=1 --nocapture` ×3 | **13/13, 13/13, 13/13**; JSON gate p99: 64-leaf 0.216/0.231/0.225 ms, 512-leaf 0.351/0.363/0.358 ms |
| 7 | 5-consecutive-run table | N/A — no new/extended gate |
| 8 | `rtk git diff --check` | exit 0, clean |

Baseline reference (STEP 1, pre-fix at 74e9c9a): first serial load run 12/13 with the
unrelated F1.2 NBSP contention flake (3.306 ms vs 2 ms bound), clean re-run 13/13.

End-to-end HTTP probe re-run post-fix (same shape/client as STEP 1): proxy
p50 1.495 / p95 1.697 / **p99 1.871** / max 3.702 ms; direct p99 0.620 ms — unchanged
within noise, redaction verified (`[REDACTED]` present, raw token absent).

## Frozen SHA-256 (every touched file)

```text
295958b07fafb010aa2349813ecdc939309092c6f93540156baa8c9274497afa  crates/cerberus-proxy/src/decoder.rs
539176cbae62dcb790f096aef0595ced208a0a2ba1220b94dcd75bdcd065185f  crates/cerberus-proxy/src/json_redact.rs
```

## Known limits and reviewer focus

- The repaired residual is one O(body) `Value` clone per redacted request (replacing a
  more expensive re-parse). It is not observable in the gate or probe numbers above.
- The end-to-end HTTP numbers here are builder reproduction evidence with a throwaway
  probe (n=200, serial keep-alive, one host); the official end-to-end latency gate with
  the plan-mandated harness (≥2,000 samples, alternating direct/proxy, slow-sink case)
  remains F3.3 scope and must not cite this pack.
- The F1.2 NBSP contention sensitivity (2 ms CI bound) reproduced once on this host under
  concurrent load; it is out of F2.1 scope but reviewers should keep serial runs clean.
- Out-of-scope reminders honored: no threshold movement, no retry/trim/outlier logic, no
  multipart/streaming/NER work, F3/F9 findings (R9-2, R9-14) untouched.
