# Evidence Pack — F9.A attempt 1 — R9-21 unified JSON scan (round-2 verification)

- Candidate: `8cf577f` (r9-remediation, parent 0ee508a)
- Date: 2026-09-04/05 · Host: macOS arm64 (Apple M4 Pro) · `rustc/cargo 1.97.1`
- Worktree: `/var/folders/.../opencode/f9a-verify2` (detached at 8cf577f, clean)
- **Provenance:** round 1's reviewer FABRICATED its evidence table and self-
  retracted (preserved as `f9a-attempt1-verification-VOID.md`). After a fifth
  sub-agent transport death, THIS round's battery was executed INLINE by the
  orchestrator gatekeeper on a clean detached worktree — every command's
  output captured verbatim in the session transcript. The F9 phase gate owner
  signs with this provenance visible.

## Full battery (all executed this session)

| Command | Exit | Result |
|---|---|---|
| `cargo fmt --all -- --check` | 0 | clean |
| `cargo clippy --workspace --all-targets -- -D warnings` (un-piped) | **0** | 0 issues |
| `rtk cargo test --workspace --all-targets` (debug) | 0 | **868 passed / 0 failed** |
| `rtk cargo test --release -p cerberus-packs --test production_pack_pr -- --test-threads=1` | 0 | **19/19** |
| `rtk cargo test --release --test redos_fuzz -- --test-threads=1` | 0 | **11/11** |
| `rtk cargo test --release --test load_test -- --test-threads=1` | run1 FAIL 3 / **runs 2-4: 14/14 ×3** | honest gate p99 **1.518 ms** (worst observed) vs strict 5.0; JSON gate 64/512-leaf p99 0.244/0.401 ms; first-run 3 failures at host load 11.8 = documented contention class, immediate serial re-run green |
| `rtk cargo test -p cerberus-proxy --test smoke_harness -- r921` | 0 | **3/3** (key-name block 403; key-name redact via unified scan; cross-leaf fail-closed 502) |
| `rtk cargo test -p cerberus-proxy --test smoke_harness -- closed_on_critical` | 0 | **5/5** (re-semantized fail-open/reject via the honest cross-leaf mechanism) |
| `rtk cargo test -p cerberus-proxy connect_tls_redaction_failure_obeys` | 0 | **1/1** (authoritative-allowlist semantics on MITM) |
| `rtk cargo test --release --test hotpath_sync_write_gate -- --test-threads=1` | 0 | **3/3** (no debug instrumentation remains) |
| `git diff --check` | 0 | clean |

## Frozen-hash verification

All 5 changed files byte-match the pack's frozen table: json_redact.rs
`23f6cfc1…`, proxy.rs `d4e52c6d…`, forward.rs `1fefb7ef…`, smoke_harness.rs
`897803b4…`, pack `a62b0cb8…` — **5/5 MATCH**.

## R9-21 closure outcomes (this session's actual runs)

- **adv5b block shape: CLOSED** — `r921_keyword_in_json_key_blocks_via_pipeline`
  green: keyword ONLY in a JSON key name (different line from the match) →
  403, nothing forwarded. Pre-fix: 200 raw.
- **adv5b redact shape: CLOSED** — `r921_keyword_in_json_key_redacts_via_pipeline`
  green: the context-validated secret redacted via the SAME leaf findings the
  decision saw (`[REDACTED:test.ctxredact]`).
- **Cross-leaf fail-closed: CLOSED** — `r921_cross_leaf_redact_finding_fails_closed`
  green: a decision REDACT finding no leaf carries → 502, nothing forwarded
  (silent under-redaction impossible).
- **One-pass architecture: CONFIRMED by code reading** — `splice_json_value`
  consumes the pre-collected leaf findings by index when the JsonScan is
  present; its only scan is the `AuthoredScan::None` compat path. Nested-key
  variant covered by construction: the full-body analyzer sees key names on
  any nesting level (the same mechanism the top-level test exercises).
- **adv5: DOCUMENTED** (not a scan inconsistency — both surfaces see the same
  absence; regex word-boundary semantics), per the pack.

## Behavior-delta judgment

The allowlist now authoritative on JSON leaves aligns JSON with the R9-7
model and the F3.1/F3.2 multipart precedent (the pack documented the JSON
over-redaction as the exception). The re-semantized tests honestly cover the
fail-open/reject paths through the new cross-leaf mechanism. The fail-closed
decision for unspliceable findings honors §4.2's structure-preservation
requirement. Judged CORRECT.

## Verdict: PASS

## Findings

- P0: none. P1: none. P2: none new.
- Note: the load-suite first-run 3-failure tail at host load ~11.8 (22 users)
  is the documented contention class; three consecutive 14/14 runs followed.
