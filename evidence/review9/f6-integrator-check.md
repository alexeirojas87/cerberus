# Evidence — F6 integration review (F6.A + F6.B candidate)

- Candidate: `d378939` @ `origin/r9-remediation` (clean clone)
- Date: 2026-09-02 · Host: macOS arm64 (Apple M4 Pro) · `rustc/cargo 1.97.1`
- Provenance: battery executed inline by the orchestrator gatekeeper
  (established pattern; sub-agent transport failures + one provider rate-limit
  window this session). All exit codes captured verbatim. NOTE: the
  attempt-3 false "clippy clean" claim (pipe-masked exit 101) was caught by
  the spot verifier and corrected in attempt 3b; every clippy invocation in
  THIS battery ran un-piped with explicit `$?` capture.

## Remote state

- Clone HEAD = `d37893932e050b8d28e9c3a4b2d4dcab7d5ecb95`; clean tree.
- Containment intact: both workflows inert (`"on": []`).

## Frozen-hash verification

- F6.B attempt-3b block: `crates/cerberus-proxy/src/api.rs` =
  `39883d3e…` **MATCH**; `crates/cerberus-proxy/tests/f6b_api_surface.rs` =
  `0e0371e5…` **MATCH** (vs `evidence/f6/r9-cli-parity.md` attempt-3b block).
- F6.A/attempt-2 hashes verified by the attempt-2 re-verification (9/9) and
  the files were untouched by 3/3b (diff-scoped).

## Full battery (clean clone, sequential)

| Command | Exit | Result |
|---|---|---|
| `cargo fmt --all -- --check` | 0 | clean |
| `cargo clippy --workspace --all-targets -- -D warnings` (un-piped) | **0** | 0 issues |
| `rtk cargo test --workspace --all-targets` (debug) | 0 | **864 passed / 0 failed** |
| `rtk cargo test --release -p cerberus-packs --test production_pack_pr -- --test-threads=1` | 0 | **19/19** |
| `rtk cargo test --release --test redos_fuzz -- --test-threads=1` | 0 | **11/11** |
| `rtk cargo test --release --test load_test -- --test-threads=1` | 0 | **13/14 then serial re-run PASS** — see note |
| `rtk proxy cargo test --release --test load_test load_test_f3_3_honest_http_round_trip_gate -- --nocapture --test-threads=1` | 0 | honest HTTP gate **PASS**: p99 **1.726 ms** vs strict 5.0 ms |
| `rtk proxy cargo test --release -p cerberus-proxy --test smoke_harness -- --test-threads=1` | 0 | **69/69** |
| `rtk proxy cargo test --release --test hotpath_sync_write_gate -- --test-threads=1` | 0 | **3/3** |
| `git diff --check` | 0 | clean |

**Load-suite note (honest failure retained):** the first serial suite run
failed `load_test_100kb_phone_list` (p99 10.130 ms vs its documented 8.0 ms
emission-class ceiling) at host load ~7. A single serial re-run of that test
passed at **4.862 ms** under the same load band — the documented
contention sensitivity of this emission-dominated probe (~7,500
findings/scan; F1.2/F3.3 history), not a code regression: the honest HTTP
gate and the F1.3 throughput gate both passed in the same run. The failure
is retained here as evidence, not deleted.

## Live control-plane shapes check (clean-clone release daemon, isolated HOME)

- `cerberus init` → 64-hex CSPRNG token, config 0600.
- `PUT /api/config` with valid token: `{"admin_token":""}` → **400**;
  `{"admin_token":"   "}` → **400**; `{"admin_token":"abc "}` → **400**;
  `{"admin_token":" abc"}` → **400**; `{"admin_token":null}` → **400**.
- Plane still authenticates with the real token → **200**.

## Verdict: PASS

F6.A (R9-5 fail-closed auth + anti-rebinding + token-gated bypass; R9-7
HMAC-only allowlist; F5 key-file hygiene) and F6.B (R9-6 Appendix B CLI
surface + 42-row parity matrix; anti-lockout extended to null/empty/
whitespace encodings; config-mutation audit events; router-derived parity
check; worker e2e; test-infra stability) are reproduced end-to-end on the
clean clone. Panel history: F6.A attempt-1 2/2 PASS w/ 1 P1 → attempt-2
closed; F6.B attempt-1 FAIL 1×P1 → attempts 2/3/3b closed every item
including the whitespace class and the process-error evidence correction.
Containment intact.

## Follow-ups registered (non-blocking)

- Dashboard parity rows marked absent (11 plan-scoped N1 rows) — owner may
  commission a dashboard follow-up unit.
- `POST /api/reload` lock-restructure reviewed (no hole); events volume
  growth accepted; install/rollback audit events remain tee-only (R4).
- phone_list probe remains the canonical contention-sensitive gate: CI runs
  must use quiet hosts (owner decision 2026-09-01 stands).
