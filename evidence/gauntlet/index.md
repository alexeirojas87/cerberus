# Evidence Pack — Gauntlet v6.1: closed adversarial loop with Codex + OpenCode

> **CURRENT RELEASE GATE: FAIL — REVIEW 9 CONTAINMENT ACTIVE (2026-08-26).**
> The prior F1–F9 PASS/closure claims in this index are **SUPERSEDED AND
> INVALIDATED BY REVIEW 9** as current gate evidence. They remain below only as
> immutable history; they must not be cited to publish, release, or claim GA
> readiness. See `evidence/review9/gauntlet-findings.md` and the G0 containment
> record at `evidence/review9/g0-containment.md`.
> G0 also requires both GitHub workflows that can publish or notify distribution
> (`release.yml` and `notify-tap.yml`) to remain disabled remotely until their
> inert replacements are merged.

## Review 9 invalidation register

| Prior phase status | Current gate status | Reason for invalidation |
|---|---|---|
| F1 PASS | **SUPERSEDED / INVALIDATED BY REVIEW 9** | Real/default-pack correctness and performance gates require re-verification. |
| F2 PASS | **SUPERSEDED / INVALIDATED BY REVIEW 9** | Vault and allow-once production reachability/zeroization claims require re-verification. |
| F3 PASS | **SUPERSEDED / INVALIDATED BY REVIEW 9** | Honest HTTP/JSON dataplane performance and hot-path behavior require re-verification. |
| F4 PASS | **SUPERSEDED / INVALIDATED BY REVIEW 9** | Shipped default-pack and end-to-end product claims depend on reopened findings. |
| F5 PASS | **SUPERSEDED / INVALIDATED BY REVIEW 9** | Synchronous hot-path logging/storage interactions require re-verification. |
| F6 PASS | **SUPERSEDED / INVALIDATED BY REVIEW 9** | Control-plane auth, anti-rebinding, secret storage, and CLI/dashboard parity require repair. |
| F7 PASS | **SUPERSEDED / INVALIDATED BY REVIEW 9** | Pack-backed precision/recall and related product evidence require re-verification. |
| F8 PASS | **SUPERSEDED / INVALIDATED BY REVIEW 9** | Release automation and published installer/tap state are not a valid distribution gate. |
| F9 PASS | **SUPERSEDED / INVALIDATED BY REVIEW 9** | Load/security/GA gates measured incomplete paths and cannot support release. |

The invalidation applies to the **current verdict and release authority**, not
to preservation of the underlying transcripts. Every historical record below
is intentionally retained for auditability. A phase can regain PASS only via
the §8B build → evidence → independent review loop and its explicit phase gate.

## Review 9 revalidated units

- **F1.2 shipped-pack PII repair: CLOSED/PASS (2026-08-31, panel 3/3 + human sign-off).** Four reported
  PII regressions, subsequent PAN/Unicode/JSON adversarials, precision/recall,
  ReDoS and release performance passed. Evidence:
  `evidence/f1/r9-pii-regression-repair.md`.
- This unit PASS does **not** clear the Review 9 containment register or close
  F1/F9; all other invalidated units and the phase integration gate remain
  required. *(Historical note: F1 was subsequently closed the same day — see the
  F1 phase-gate entry below.)*

- **F1.3 engine throughput: CLOSED/PASS (2026-08-31, fix attempt 6; fresh
  panel 2/2 — correctness + security — and clean-clone integration PASS).**
  Attempt 5 was rejected by the security lens with a confirmed P1: the
  Unicode-case-insensitive entropy keyword regex matches U+017F (ſ→s) and
  U+212A (K→k) payloads that the merged ASCII presence automaton never marks,
  so the detector was skipped and real findings lost (base `fccd9e4` detected
  them). Attempt 6 restores detection via a build-time derived fold-to-ASCII
  presence bucket plus 5 permanent regression tests (proven FAIL pre-fix, PASS
  post-fix); the fold closure {U+017F, U+212A} was independently re-derived by
  both panel lenses. Clean-clone battery: 664/0 debug, 664/0 release, pack
  19/19, ReDoS 11/11, load 13/13, throughput gate 3/3 strict PASS with worst
  p99 0.306 ms vs the 1.0 ms budget. Evidence:
  `evidence/f1/r9-engine-throughput.md` (attempt-6 section),
  `evidence/review9/f13-attempt6-correctness.md`,
  `evidence/review9/f13-attempt6-security.md`,
  `evidence/review9/f13-integrator-check.md`.

- **F1 phase gate: CLOSED (2026-08-31, owner sign-off).** All three R9 repair
  units of F1 are closed (F1.1, F1.2, F1.3) and the integration reviewer
  reproduced the full battery from a clean clone of the pushed candidate
  (`fdebc39` on `r9-remediation`), including frozen-hash verification (10/10)
  and G0 containment intactness on the pushed branch. F2 opens; F2–F9 remain
  under Review 9 containment.

- **Final recheck date:** 2026-08-21 (America/New_York)
- **Checkout:** `HEAD 09612f2142b8ab4e7655da6682231b2548e78bef` + current working tree, uncommitted
- **Orchestration:** Orca Run `run_a64b51716aba`; workers exclusively **Codex** and **OpenCode**. No Claude was used in the v6.1 review/fix/recheck.
- **Historical result (SUPERSEDED / INVALIDATED BY REVIEW 9):** technical PASS v6.1 — 0 P0 / 0 P1 of the MVP. This is not a current gate.

## Historical Phase 9 record — Hardening and GA (SUPERSEDED / INVALIDATED BY REVIEW 9)

- **Commits:** `c327527` (feat F9) → `c684591` (fix P1 load_test flake, gauntlet loop)
- **Adversarial reviewers:** Codex (initial gate: FAIL P1 flake) + OpenCode (recheck: PASS)
- **Evidence:** `evidence/f9/{redos-fuzz,load-test,failsafe,security-review,docs,integration-gate}.md` + `evidence/review8/{codex-f9-gate,codex-f9-findings,opencode-f9-findings}.md`

| F9 unit | Verdict |
|---------|---------|
| security-review | ✅ PASS |
| redos-fuzz (real pack, 13 rules incl. multiline) | ✅ PASS |
| load-test (real pack, release p99 2.6 ms) | ✅ PASS |
| failsafe (secure-by-default + proxy-level + 5 error classes) | ✅ PASS |
| docs (user/operator/security with F4/F8) | ✅ PASS |

### Final F9 gates (commit `c684591`)
| Command | Result |
|---------|-----------|
| `cargo fmt --all -- --check` | ✅ 0 |
| `cargo clippy --workspace --all-targets -- -D warnings` | ✅ 0 |
| `cargo test --workspace --all-targets` (debug) ×3 | ✅ 596/0 ×3 reproducible |
| `cargo test --release --workspace --all-targets` ×2 | ✅ 596/0 ×2 |
| `python3 tools/simulate.py` | ✅ 29/0 |

### F9 structural changes
- Default pack (13 rules) moved to `cerberus-packs/src/default_pack.rs` as the single source of truth; CLI and tests consume the same pack (no drift).
- redos-fuzz + load-test now fuzz/benchmark the real pack (no inline copy) — satisfies "redos-fuzz(all packs)" of plan §8B.6.
- failsafe extended with secure-by-default + proxy pipeline + 5 heterogeneous error classes.
- Fix env-race release flake (`pid_path`/`config_dir` take ENV_LOCK).
- Fix P1 load_test debug flake: the p99 budget is a release gate (plan §5); debug only bounds the 30× pathology.
- Docs updated with F4/F8 (MITM opt-in, Windows winget, feedback, telemetry, Helm, Ed25519 packs).

## Historical MVP status (SUPERSEDED / INVALIDATED BY REVIEW 9)

**All phases of the §8 DAG (F0→F9) closed with a technical PASS.**

- F0 (scan-spike, proxy-spike, scaffold+CI, latency-budget) ✔
- F1 (engine: rule-loader, regex-compiler, validators, multiline, entropy, constraints, corpus) ✔
- F2 (in-place redaction, reversible-vault, action-precedence, break-glass, feedback-hook) ✔
- F3 (reverse-proxy-core, agnostic-decoder, schema-adapters, shadow/enforce, fail-policy, healthcheck+logs) ✔
- F4 (local-daemon, cerberus-init, default-packs, mitm-opt-in, windows-support, dev-feedback-ux) ✔
- F5 (sqlite-store, event-schema, async-writer, retention, no-leak-guarantee) ✔
- F6 (config-api, stats-per-provider, config-screens, fp-triage-1click, CLI↔dashboard-parity) ✔
- F7 (pack-format, pack-signing, auto-update) ✔
- F8 (installers, signed-binaries, licensing/entitlements, docker/helm, opt-in-telemetry) ✔
- **F9 (security-review, redos-fuzz, load-test, failsafe, docs) ✔**

**Post-GA (backlog)** — outside the MVP by contract (AGENTS.md):
- Contextual PII via NER/NLP (Pro futurible)
- Streaming response scanning (SSE)
- Native hooks per tool
- Tool-call / MCP scanning
- Decoding before scanning (base64/hex/URL-encoded)
- Prometheus endpoint + SIEM export (Pro)
- Compliance reporting (Pro)
- Slack/Teams/webhook alerts (Pro)
- Tamper detection / heartbeat (Pro)
- Embeddable SDK (Python/Node/Go FFI)
- Per-provider/route policy

## v6.1 loop (prior to F9)

| Step | Agent | Evidence | Result |
|---|---|---|---|
| Full initial gate | Codex | `evidence/review7/codex-gate.md` | PASS: 534/0 debug+release, sim 29/29, deterministic PR, p99 1.412 ms |
| Initial adversarial review | OpenCode | `evidence/review7/opencode-findings.md` | **FAIL: 1 P1** — dashboard sent `{path}` wire v1 and the API wire v2 rejected it with 400 |
| FIX loop | Codex | `evidence/f6/dashboard-pack-wire-v2-v61-fix.md` | `type=file` selector, bounded UTF-8 bytes, `{wire_version,pack}`, no local path; shared bound and historical evidence clarified |
| Recheck gate from scratch | Codex | `evidence/review7/codex-gate-recheck.md` | **PASS**: 534/0 debug+release, sim 29/29, identical PR SHA, worst p99 1.169 ms |
| Findings recheck from scratch | OpenCode | `evidence/review7/opencode-findings-recheck.md` | **PASS: 0 P0 / 0 P1**; no regressions in config/policy/packs/store/daemon/CSP |

The initial FAIL is kept as historical evidence. Its later addendum doesn't change the original verdict; the two final rechecks live in new files.

## v6.1 findings closed

| Area | Verified closure |
|---|---|
| Config/control-plane | `ConfigView` never exposes `admin_token`; PATCH omit/null/read-only correct; non-loopback revalidated before persist/publish; config load injectable and deterministic |
| F6 policy | categories/overrides, custom rules, and allowlist persist to YAML, survive reopen, and hot-swap the dataplane while preserving the base actions |
| Packs/F7 | explicit trust root, Pro-gated at boot; wire v2 transports bytes; `{path}` rejected before the worker; policy and packs reloaded under lock with no race |
| Dashboard packs | local file read via `File.arrayBuffer` + `TextDecoder` fatal; exact request `{wire_version:2,pack}`; no `path`/`origin_name`; CSP still without `unsafe-inline` |
| Store/daemon | no post-close admission, single deadline enqueue+ACK, ordered drain, honest drops/errors and graceful shutdown |
| Determinism | workspace and release 534/0; sim 29/29; PR SHA `969e84903ef58e72a7d706e2d50ab938c35d0c2c5851b5f40f64736355114d2e`; recall 94.3%, precision 89.2% |

## Final v6.1 gates

| Gate | Final independent result |
|---|---|
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --workspace --all-targets -- -D warnings` | PASS, 0 warnings |
| `cargo test --workspace --all-targets` | PASS, **534 / 0** |
| `cargo test --release --workspace --all-targets` | PASS, **534 / 0** |
| `python3 tools/simulate.py` | PASS, **29 / 0** |
| `cargo test -p cerberus-packs --all-targets` | PASS, **59 / 0** |
| CLI packs (`pack_cli_e2e`, `pack_cli_via_api`) | PASS, **3 / 0** and **4 / 0** |
| Load release | PASS, 7 / 0; worst p99 **1.169 ms** |
| Precision/recall x2 | PASS; identical SHA |
| `git diff --check` | PASS |

## Residual risk and phase gate

- Non-blocking P2s documented by OpenCode: hardening `deny_unknown_fields` of the envelope, stale `endpoint.json` descriptor, conservative JSON envelope margin, and extra sanitization of `metadata.name/version`. None opens client paths, relaxes auth/trust-root, or breaks the MVP; they remain explicit in `evidence/review7/opencode-findings-recheck.md`.
- F4 (MITM opt-in) and F8 (distribution) **were not run in this Run**. The repo contract requires stopping at this gate and requesting sign-off before opening the next phase.

---

## Background: Gauntlet v6 (reviews 1–6)

- **Date:** 2026-08-21
- **Method:** 7 closing subagents (wave1: P0 signing / store drops / evidence; wave2: CLI→API / Pro-gate / F6 parity / XSS) + **integration** (gates) + **2 adversarial reviewers** in separate worktrees → **loop** (1 FAIL re-closed in the local mode of pack_rollback) → **adversarial re-verification of both** on loop-commit worktrees.
- **Final verdict: 7/7 findings PASS (gate PASS + findings PASS after recheck).**

## Reviews (isolated worktrees)
| Reviewer | Commit | Evidence | Verdict |
|---|---|---|---|
| gate v6 | `31c14cd` | `evidence/review6/v6-gate.md` | PASS (fmt/clippy 0; debug 454; release 454; sim 29/29) |
| findings v6 | `31c14cd` | `evidence/review6/v6-findings.md` | 6/7 PASS + **1 FAIL (#6)** |
| gate recheck | `12bc776` | `evidence/review6/v6-gate-recheck.md` | PASS (debug/release **455**, sim 29/29, packs 46, stable PR sha) |
| findings recheck | `12bc776` | `evidence/review6/v6-findings-recheck.md` | **#6 → PASS** (pack_rollback local Pro-gated + tests) |

## The 7 v6 findings → status
| # | Finding | Fix | Reviewer verdict |
|---|---|---|---|
| 1 | **P0** packs without signature verification at boot | `rebuild_active_set(trust_root)` + `extract_with_root`; tamper→deactivate+persist; no root→fail-closed 0 packs | PASS |
| 2 | CLI not connected to hot-reload | `cli_pack.rs`: pack install/rollback/list = HTTP client of the live daemon (x-cerberus-admin-token); local fallback without daemon | PASS |
| 3 | store confirms durability after drops | `flush`/`close` report new drops (dropped_acknowledged); barrier on spawn_blocking | PASS |
| 4 | F6 CLI/UI parity | PUT config persists YAML; GET config doesn't leak token (`admin_token_configured`); authenticated CRUD `/api/upstreams` | PASS |
| 5 | XSS dashboard | DOM+textContent with no dynamic innerHTML; chips via closure; CSP in head; token never in DOM | PASS |
| 6 | Pro-gate /api/packs | unified `require_pro_for_pack_ops`: worker(install+rollback), local CLI(install+rollback), boot omits packs in Free | **FAIL→PASS** (loop closed in `12bc776`) |
| 7 | Evidence not reproducible | real SHA documented; index v6 without v4 contradiction | PASS |

## Gates (independent rechecks over `12bc776`)
| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | ✅ 0 |
| `cargo clippy --workspace --all-targets -- -D warnings` | ✅ 0 |
| `cargo test --workspace --all-targets` | ✅ 455 passed / 0 failed |
| `cargo test --release --workspace --all-targets` | ✅ 455 passed / 0 failed |
| `python3 tools/simulate.py` | ✅ 29 PASS / 0 FAIL |
| `cargo test -p cerberus-packs --all-targets` | ✅ 46 passed |
| Deterministic PR (sha) | ✅ `969e8490…` stable |

## Phase status (honest)
- F1 (engine) ✔ PR per instance/spans; gates 90/85; deterministic
- F2 redaction ✔ JSON-safe + fail_policy
- F3 proxy ✔ auth default-secure, TLS, limits, routing, fail-policy
- F5 store ✔ real durability (bounded/drops/err/closure)
- F6 control-plane/UI ✔ (API parity, YAML persistence, upstream CRUD, XSS, CSP)
- F7 packs/licensing ✔ (signature at boot, real hot-reload same engine, durable rollback, CLI→API, full Pro-gate)

## F4/F8 opening (2026-08-21) — closed with adversarial reviewers
| Area | Implemented | Review |
|---|---|---|
| **F4 — Windows** | `platform.rs` (APPDATA/_exe_), `stop_process_graceful`, `tasklist`, 3-OS CI matrix (`ci.yml`), embedded in init | `evidence/review7/f4-adversarial.md` PASS |
| **F4 — Dev feedback** | `feedback_ux.rs` (notify-rust + stderr fallback) active watch in the daemon after block/redact/warn, rate-limit 1/s, flag+hash only | idem PASS |
| **F4 — Zero-config** | `init` writes openai/anthropic upstreams by default | idem PASS |
| **F4 — MITM opt-in** | `forward.rs` exact CONNECT+TLS allowlist, CA create_new validated (symlink/perms/>1MiB), fail-closed before bind, `cerberus mitm` wiring | idem PASS (19/19 forward, mitm_cli e2e) |
| **F8 — installers** | `tools/release/*` (build_release tar/zip+SHA256), install.sh checksum, brew.rb+fill, deb/rpm, winget **zip** (+winget-fix), release.yml | `evidence/review7/f8-adversarial.md` PASS* and `f8-winget-fix.md` PASS |
| **F8 — Helm** | `deploy/helm/cerberus` Mode A chart (configmap 0.0.0.0:8080, admin secret, required, health tests) | idem PASS |
| **F8 — Opt-in telemetry** | `telemetry.rs` real HTTP POST (reqwest blocking, 5s timeout, silent), persistent uuid install_id, never secrets | idem PASS |

\* F8: the only FAIL (winget .msi) entered the loop and was **re-closed** pointing at the real `.zip` from the pipeline (`f8-winget-fix.md` PASS).

**F4/F8 gates**: workspace build OK; debug/release `cargo test --workspace --all-targets` ✅ (582→583 full suite); clippy -D 0; fmt 0; sim 29/29; release pipeline e2e (real `dist/cerberus-0.1.0-macos-aarch64.tar.gz` + SHA256SUMS + windows zip). `helm` not local → YAML templates parsed.

**Documented debt (non-blocking):**
- `show_feedback` (engine) with no production caller — real feedback goes via `feedback_ux.rs` (to remove in cleanup).
- Real Windows: cross-compile/taskkill needs CI (local has no target).
- winget `InstallerSha256` is a placeholder → CI must inject the real sha from SHA256SUMS before the PR to winget-pkgs.
- Native MSI (WiX) stays as a note; the publishable installer is the `.zip` (winget supports zip).

F4/F8 commits: `a04a84d` (implementation) → `winget fix` pending commit.
