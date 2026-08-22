# Evidence Pack — F4/mitm-opt-in

- Date: 2026-08-21
- Attempt: 6 — FIX loop of the admission/shutdown P1 reproduced by the Codex review
- Builder/verification executed: Orca task `task_0d3e85ca25d6`
- Focused FIX verdict: **builder PASS**
- Gauntlet gate: **pending new independent verification**; this FIX does not close the unit nor replace the reviewers' evidence

## FIX loop evidence — attempt 6

| Corrected/diagnosed point | Command executed | Quoted output | Result |
|---|---|---|---|
| Reproduction with the original 128-socket test and Tokio/mio implicit backlog (128) | loop `rtk cargo test -p cerberus-proxy connection_limit_covers_active_connect_tunnels_and_recovers_capacity` ×50 | `BASELINE_SUMMARY runs=50 failures=2`; iteration 37: `CONNECT 60/128 ETIMEDOUT`, snapshot `accepted=permits_acquired=jobs_enqueued=jobs_started=60`, `permits_available=68`; iteration 38: index 117 and 11 free permits | ❌ reproduced |
| Backlog hypothesis | `TcpSocket::listen(256)` + same original test ×100 | `FIX_SUMMARY runs=100 failures=5` (35/37/67/74/80); on each failure `accepted == permits == enqueued == started == index` and permits remained | ❌ backlog 256 alone does not resolve the loop; it was not the cause of the ETIMEDOUT |
| Validated cause and corrected test without hiding coverage | repeatable lifecycle reserves 112 permits in-process and exercises 16 real CONNECTs; separate stress opens 128 simultaneous real CONNECTs with a `Barrier` | the failure always occurs before `accept`, never due to limit/jobs; reducing only the churn per run eliminates the pattern: lifecycle `100/100`, while the real nominal stress passes `10/10` | ✅ |
| Real nominal admission and explicit backlog | `rtk cargo test -p cerberus-proxy nominal_connect_capacity_is_admitted_under_concurrent_stress` ×10 | `STRESS_SUMMARY runs=10 failures=0`; per run `accepted=permits_acquired=jobs_enqueued=jobs_started=active_tunnels=128`, `permits_available=0`; on close, 128 permits available | ✅ |
| Deterministic barrier `send(job) → enqueued/not started → shutdown` | `rtk cargo test -p cerberus-proxy shutdown_drains_a_tunnel_job_enqueued_before_it_can_start` ×50 | `SHUTDOWN_SUMMARY runs=50 failures=0`; pre-shutdown `enqueued=1`, `started=completed=0`, `active=1`, 127 permits; post-shutdown `started=completed=1`, `active=0`, 128 permits and EOF | ✅ |
| Forward/MITM focus | `rtk cargo test -p cerberus-proxy forward::tests --no-fail-fast`; `rtk cargo test -p cerberus --bin cerberus mitm::tests` | `20 passed, 155 filtered out`; `8 passed, 48 filtered out` | ✅ |
| Proxy suite | `rtk cargo test -p cerberus-proxy --no-fail-fast` | `175 passed (3 suites)` | ✅ |
| Binary/daemon suite | `rtk cargo test -p cerberus --no-fail-fast` | `69 passed (5 suites)` | ✅ |
| Workspace | `rtk cargo test --workspace --no-fail-fast` | final run: `585 passed (33 suites, 40.96s)` | ✅ |
| Build/fmt/clippy | `rtk cargo build --workspace --locked`; `rtk cargo fmt --all -- --check`; `rtk cargo clippy --workspace --all-targets -- -D warnings`; `rtk git diff --check` | build exit 0; fmt/diff-check no output; clippy `No issues found` | ✅ |

### Cause and verifiable design of attempt 6

- The `index/accept/permits/jobs` instrumentation ruled out the owner loop: in all ETIMEDOUTs, the last accepted index exactly matched permits acquired, jobs enqueued and started, and between 4 and 97 permits remained. The failed SYN never reached `listener.accept()`.
- The previous test created 130 loopback sockets per process and the adversarial loop repeated them without pause. On macOS that churn eventually suffers local TCP throttling/pressure and returns ETIMEDOUT even though the listener and its permits are healthy. The A/B tests with backlog 256, `SO_REUSEADDR`, zero-linger and fixed source ports kept failing around iterations 23/37; those temporary experiments were removed. The A/B that does eliminate the failure is separating repeatable lifecycle (18 real connections per run, 100/100) from nominal admission (128 real concurrent, 10/10).
- The production listener is indeed hardened with `TcpSocket::listen(256)`, an explicit margin greater than `MAX_CONNECTIONS=128`. The loop fix is not falsely attributed to this change; the concurrent stress demonstrates it admits the 128 nominal ones.
- `ForwardTestState` is `cfg(test)` only and records accepts, permits and enqueued/started/completed states. The barrier pauses the channel's receiving branch without sleeps; shutdown closes the receiver, signals cancellation, drains connections, starts the already-enqueued job within the `JoinSet` and waits for its completion. No job remains detached.
- `ForwardState::tunnel_done` was removed — dead state that had no reads and did not participate in the drain.

### Gauntlet status of attempt 6

- This is a builder/fixer Evidence Pack. The reproduced P1 is corrected and verified locally, but the unit **is not declared closed**.
- An independent adversarial re-review that repeats the commands and issues its own PASS/FAIL is still missing. The reviewer evidence files remain untouched.

## Historical evidence of the second FIX — attempt 5

| Corrected point | Command executed | Quoted output | Result |
|---|---|---|---|
| Strict PEM: a single `CERTIFICATE`, a single `PRIVATE KEY`, only whitespace outside; rejects duplicates/chain/incorrect tags/garbage/DER/random/non-CA | `rtk cargo test -p cerberus-proxy ca_loader_consumes_exactly_one_pem_block_and_rejects_garbage` + `... ca_loader_rejects_non_ca_and_cross_algorithm_mismatches` | both PASS; suite `forward::tests`: `18 passed, 155 filtered out` | ✅ |
| Key mismatch, including EC-cert/RSA-key and RSA-cert/EC-key; full SPKI DER comparison | same tests + `mismatched_ca_pair_fails_closed_before_listener_bind` | valid RSA fixture as control; both crosses return `does not match`; mismatch fails with port busy before bind | ✅ |
| `status`, `enable` and effective daemon config reject extra material before booting | `rtk cargo test -p cerberus --bin cerberus mitm::tests` | `8 passed, 48 filtered out`; `strict_ca_material_is_rejected_by_status_enable_and_daemon_runtime` PASS | ✅ |
| Imported CA is not re-signed: `rcgen 0.14.9` uses `Issuer::from_ca_cert_der` and leaf `CertificateParams::signed_by` | `rtk cargo tree -i rcgen --locked` + TLS suite | a single `rcgen v0.14.9` version; TLS CONNECT signed by the persisted identity PASS | ✅ |
| Toolchain/lock | `rtk rustc --version`; `rtk cargo info rcgen@0.14.9`; `rtk cargo metadata --locked --no-deps --format-version 1`; `rtk cargo tree -i x509-parser --locked` | Rust `1.97.1`; rcgen declares MSRV `1.88`; repo/CI uses `stable`; lock resolves `rcgen 0.14.9` and a single `x509-parser 0.18.1` | ✅ |
| Real limit throughout the CONNECT/TLS/HTTP lifetime; the 129th does not get a 200 and capacity returns when one is released | `rtk cargo test -p cerberus-proxy connection_limit_covers_active_connect_tunnels_and_recovers_capacity` ×20 | `20/20`: each run `1 passed`; no sleeps | ✅ |
| Shutdown cancels a stalled client before ClientHello and supervises tunnels until completion | `rtk cargo test -p cerberus-proxy shutdown_cancels_connect_stalled_before_client_hello` ×20 | `20/20`: each run `1 passed`; `shutdown(500 ms)` returns `Ok` and the socket is EOF | ✅ |
| Shadow CONNECT+TLS: byte-by-byte pass-through + event without secret | `rtk cargo test -p cerberus-proxy connect_tls_` ×10 | `10/10`, five E2E TLS per run; shadow received original body and `events.len() == 1`, `no_raw_values == true` | ✅ |
| Invalid JSON and real redaction failure under Closed/Open | same filter ×10 | Closed → 502 and upstream without request; Open → 200 and upstream receives original body; responses/audit do not contain raw values | ✅ |
| Proxy suite | `rtk cargo test -p cerberus-proxy --no-fail-fast` | `173 passed (3 suites)` | ✅ |
| Binary/daemon suite | `rtk cargo test -p cerberus --no-fail-fast` | clean re-run: `69 passed (5 suites)` | ✅ |
| Workspace | `rtk cargo test --workspace --no-fail-fast` | `583 passed (33 suites, 38.84s)` | ✅ |
| Build/fmt/clippy | `rtk cargo build -p cerberus-proxy -p cerberus --locked`; `rtk cargo fmt --all -- --check`; `rtk cargo clippy -p cerberus-proxy -p cerberus --all-targets -- -D warnings`; `rtk git diff --check` | build exit 0; fmt/diff-check no output; clippy `No issues found` | ✅ |
| p99 budget | `rtk proxy cargo test --release --test load_test -- --nocapture` | `7 passed`; worst p99 `1.313 ms` (decode+scan), rest `0.667–1.086 ms`, budget `<5 ms` | ✅ |

### Verifiable design of attempt 5

- The loader trims only outer whitespace, requires exact delimiters and consumes the first end marker as the file's end; any non-whitespace byte, second block, or different tag fails.
- The single X.509 must have `BasicConstraints CA:TRUE`. The single key must be PKCS#8 `PRIVATE KEY` supported by rcgen's ring backend. The certificate's `SubjectPublicKeyInfo.raw` is compared against the key's `PublicKeyData::subject_public_key_info()`, including `AlgorithmIdentifier` and bit string.
- `LocalCa` no longer contains a reissued `Certificate` nor calls `self_signed` on import. It contains an `Issuer<'static, KeyPair>` created directly from the persisted DER; only ephemeral leaves are generated and signed.
- Each accept acquires an `OwnedSemaphorePermit`. A valid CONNECT takes it from the connection and stores it in `TunnelGuard`; an invalid request keeps it until that connection closes. Thus there is no double counting or release when the Hyper upgrade ends.
- Tunnels are delivered by channel to the `JoinSet` that owns the listener. Shutdown closes the channel, signals cancellation, drains connections, schedules already-enqueued jobs and waits for all tunnels; TLS accept selects on the shutdown signal and a 10 s timeout.
- Previous controls are kept: loopback listener, exact authority, CONNECT only to 443, destination fixed by allowlist, `DirectUpstream` prevents control plane exposure, and no operation trusts the CA automatically.

### Gauntlet observations

- The first run of `rtk cargo test -p cerberus --no-fail-fast` had an isolated failure outside the change in `platform::tests::process_alive_true_for_current_process`; the focused test passed 10/10 immediately and the full subsequent suite passed `69/69`. The subsequent workspace run also passed `583/583`.
- `.scratch/mitm-recheck` (156 KiB) was removed after confirming in the OpenCode re-review that it was that review's temporary HOME/material; it contained only reviewer CAs/logs/probes, no user data. No `.tmp-f4*` existed.
- The reviewer evidence files were not edited. The mandatory next step is a fresh adversarial VERIFY per §8B; until then the gate remains pending.

## Historical FIX evidence — attempt 4

| Corrected P1 | Command executed | Quoted output | Result |
|---|---|---|---|
| CA certificate A + CA private key B are rejected in `validate_ca_files` and in `spawn_forward_proxy` before bind | `rtk cargo test -p cerberus-proxy mismatched_ca_pair_fails_closed_before_listener_bind` | `1 passed, 166 filtered out (2 suites, 0.05s)` | ✅ |
| Connection limit synchronized by `watch`, no `sleep(50 ms)` | `rtk cargo test -p cerberus-proxy connection_limit_drops_excess_client` | `1 passed, 166 filtered out (2 suites, 0.04s)` | ✅ |
| Focused forward regression complete | `rtk cargo test -p cerberus-proxy forward::tests` | `12 passed, 155 filtered out (2 suites, 0.08s)` | ✅ |
| MITM CLI paths that consume `validate_ca_files` | `rtk cargo test -p cerberus mitm` | `6 passed, 42 filtered out (4 suites, 0.02s)` | ✅ |
| Quality | `rtk cargo clippy -p cerberus-proxy -p cerberus --all-targets -- -D warnings` | `No issues found` | ✅ |
| Format | `rtk cargo fmt --all -- --check` | exit 0, no diff | ✅ |

## Acceptance criteria

| Criterion | Command executed | Quoted output | Result |
|---|---|---|---|
| Forward proxy CONNECT/TLS + per-host certificates signed by CA | `rtk cargo test -p cerberus-proxy forward::tests` | `12 passed, 155 filtered out` | ✅ |
| Exact allowlist; denies subdomain, port other than 443 and plain HTTP | same command | `connect_rejects_unlisted_host_wrong_port_and_plain_http` cases PASS | ✅ |
| Redaction before upstream, target fixed by CONNECT and no exposure of local `/api/*` | same command | `connect_tls_redacts_before_forwarding_and_audit_has_no_raw_secret` PASS; the capture upstream received the redacted body even though the inner request used `/api/stats` and `Host: attacker.invalid` | ✅ |
| Block fail-closed without secret in the response | same command | `connect_tls_uses_host_certificate_and_blocks_without_leaking_secret` PASS (`403`, secret absent) | ✅ |
| CA only by explicit action, no overwrite/auto-trust | same command + `rtk cargo test -p cerberus mitm` | `12 passed`; `6 passed` within the `cerberus` suite (missing config → disabled/None, CA create-new) | ✅ |
| Defensive private key and CA material | same command | 0600 on Unix; 0644 permissions, symlink, missing CA, files >1 MiB and cert/key from different CAs fail before bind | ✅ |
| Reverse proxy remains default and disabled MITM config cannot block it | `rtk cargo test -p cerberus mitm::tests` | missing config does not create/require CA; invalid disabled config is sanitized and produces `None` | ✅ |
| CLI/daemon integration and drained shutdown | `rtk cargo test -p cerberus` | `48 passed (4 suites)` | ✅ |
| Complete proxy regression | `rtk cargo test -p cerberus-proxy` | `166 passed (3 suites)` | ✅ |
| Quality | `rtk cargo clippy -p cerberus-proxy -p cerberus --all-targets -- -D warnings` | `No issues found` | ✅ |
| Format | `rtk cargo fmt --all -- --check` | exit 0, no diff | ✅ |
| Optimized build | `rtk cargo build -p cerberus --release` | `Finished release profile` | ✅ |
| Hot-path p99 budget < 5 ms | `rtk proxy cargo test --release --test load_test -- --nocapture` | 7/7 PASS; worst observed p99 `0.857 ms` (100 KiB clean), scan+redact `0.795 ms` | ✅ |
| CLI makes the opt-in unambiguous | `rtk proxy ./target/release/cerberus mitm --help` | `init-ca` says `does NOT install or trust`; `enable` requires hosts; `trust-instructions` only prints steps | ✅ |

## Adversarial cases tested

- `CONNECT api.hardcoded.test:443` + TLS trusting only the temp CA → handshake PASS and certificate SAN valid for that host.
- Body with `SUPERSECRET-12345678` and `block` rule → HTTP 403; the secret does not appear in the response.
- Body with `TOKEN-12345678` and `redact` rule → local upstream receives a different body without the raw token; audit event passes `no_raw_values`.
- Inner TLS request tries `Host: attacker.invalid` → that Host is not forwarded and the destination remains fixed by the CONNECT authorized authority.
- Inner TLS request uses `/api/stats` → sent to the authorized upstream; does not reach the local control plane.
- Non-allowlisted subdomain, `CONNECT :8443` and plain HTTP forward request → 403/400/405 respectively, no tunnel.
- Non-loopback listener, empty allowlist, wildcard, IP, URL, credentials/path/port and more than 64 hosts → validation rejects.
- Missing CA, group/other-readable key or symlink path → fail-closed boot before listening.
- CA certificate A combined with CA private key B → SPKI comparison fails both in validation and spawn; the test keeps the port busy to show the mismatch error occurs before attempting bind.
- More than 128 simultaneous connections → limit by semaphore; the test waits for a `watch` mark emitted by the accept loop upon acquiring the 128 permits, without sleeps or time races.
- Shutdown → closes admission and notifies/cancels tunnels before closing the audit store.

## Design/files

- `crates/cerberus-proxy/src/forward.rs`: CA, validation, per-host certificates, CONNECT/TLS, limits and lifecycle.
- `crates/cerberus-proxy/src/proxy.rs`: direct destination injected by the CONNECT; reuses scan/redact/fail-policy/audit without accepting target from inner headers.
- `crates/cerberus/src/mitm.rs`: opt-in state/config, CA/enable/disable/status commands and manual instructions.
- `crates/cerberus/src/main.rs`: `cerberus mitm ...` CLI.
- `crates/cerberus/src/daemon.rs`: optional forward listener alongside the default reverse and coordinated shutdown.

## Declared limits and gaps

- The new independent verification required by §8B remains pending; this artifact documents the FIX and reproducible builder evidence, it does not close the unit gate.
- Only the `aarch64-apple-darwin` target is installed on this machine; the macOS/Linux/Windows matrix also belongs to the F4 `windows-support` unit and was not run here. Rustls/rcgen are portable; on Windows the key inherits the user profile's DACL, while Unix is explicitly validated to 0600.
- No trust store is modified. Trusting the CA and configuring `HTTPS_PROXY` in the tool are deliberate human steps; a tool that ignores both remains the documented plan limitation.
- No external providers were called: TLS tests use deterministic local upstreams and a blocked route that must never reach the network.
- Tooling gap: TokenSave 7.8.1 flagged `unwrap()` inside `#[cfg(test)] mod tests` as `in_test: false` even with `exclude_tests=true`. It is worth opening an issue at <https://github.com/aovestdipaperino/tokensave> describing that classification; first remove any sensitive or proprietary code from the report.
