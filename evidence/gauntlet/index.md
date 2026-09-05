# Evidence Pack — Gauntlet v6.1: closed adversarial loop with Codex + OpenCode

> **CURRENT RELEASE GATE: GA-READY — REVIEW 9 REMEDIATION COMPLETE (2026-09-05,
> owner sign-off).** The F1–F9 invalidation below is now fully re-verified:
> every R9 finding (R9-1..R9-20) plus the registered R9-21 was repaired and
> re-closed under the §8B loop across phases F1–F9 (this file's phase-gate
> entries below, 2026-08-31 → 2026-09-05). The G0 containment remains
> ACTIVE until the owner performs the lift: flip the `review9_f8_pending`
> guards in `release-v2.yml` / `version-bump-v2.yml` / `notify-tap-v2.yml`,
> merge `r9-remediation` to main, and cut the first tag through the new
> PR-based release flow. Until that lift, the frozen
> `release.yml`/`notify-tap.yml` stay inert and the historical
> F1–F9 PASS claims below remain superseded by the new evidence chain.

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

- **F2.1 JSON dataplane (R9-1 F2 scope): CLOSED/PASS (2026-09-01, attempt 1;
  panel 2/2 — correctness + security).** Reconciliation found the residual:
  the request body was parsed twice on the redact path (`decoder.rs` +
  `json_redact.rs`); `DecodedBody` now retains the parsed value and
  `redact_json` reuses it (byte-identical outputs proven by A/B over 25
  hostile shapes). Review 9's 38.9 ms p99 claim does NOT reproduce: honest
  HTTP probe of the R9-1 shape p99 ~1.8 ms; permanent 64/512-leaf gate
  p99 0.298/0.361 ms vs the 5 ms budget. Evidence:
  `evidence/f2/r9-json-redaction.md`,
  `evidence/review9/f21-attempt1-correctness.md`,
  `evidence/review9/f21-attempt1-security.md`.

- **F2.2+F2.3 vault zeroization + live break-glass (R9-8): CLOSED/PASS
  (2026-09-01, attempt 1; panel 2/2 — correctness + security, ~30 live
  adversarial probes, zero successful attacks).** `Vault` rewritten
  (`Zeroizing`, wipe on every exit path, CSPRNG ids, request-scoped,
  irreversible default / reversible opt-in); `BreakGlassLedger` rewritten and
  wired live: admin-gated `POST /api/break-glass` → 256-bit nonce → one-shot
  `X-Cerberus-Bypass` → audited; restart fails closed. Evidence:
  `evidence/f2/r9-vault-zeroization.md`,
  `evidence/review9/f23-attempt1-correctness.md`,
  `evidence/review9/f23-attempt1-security.md`.

- **F2 phase gate: CLOSED (2026-09-01, owner sign-off).** Integration battery
  reproduced on a clean clone of `975be15`: 680/0 debug and release, pack
  19/19, ReDoS 11/11, load 13/13, smoke-harness e2e 42/42, frozen-hash
  verification all-match across documented re-freeze chains, containment
  intact. Provenance: two integration-reviewer sub-agent transport failures
  were followed by an inline orchestrator battery (noted in the report).
  Evidence: `evidence/review9/f2-integrator-check.md`. F3 opens; F3–F9 remain
  under Review 9 containment.

- **F3.3 honest HTTP latency gate (R9-2): CLOSED/PASS (2026-09-01, attempt 1;
  panel 2/2 — correctness+security and performance).** The gate measures the
  real HTTP round trip (client → proxy in enforce mode with the default pack →
  mock upstream → client), 2,000 individual samples per scenario, interleaved
  1:1 with a direct upstream baseline, strict absolute proxy p99 < 5.0 ms
  (§5 closed budget). Builder series 5/5 (worst p99 1.553 ms); the
  `phone_list` probe was reclassified to its pre-existing documented 8.0 ms
  emission-class ceiling (no §5 budget moved; the performance lens
  independently reproduced the marginality). The performance lens's P1
  (contention fragility of the absolute assert) was resolved by **owner
  decision: keep the absolute strict assert**; quiet-host requirement
  documented; the gate fails loudly, never silently. Evidence:
  `evidence/f3/r9-honest-latency-gate.md`,
  `evidence/review9/f33-attempt1-correctness.md`,
  `evidence/review9/f33-attempt1-performance.md`.

- **F3.1+F3.2 per-upstream mode / ClosedOnCritical / multipart MVP decoder /
  wire-name (R9-11/12/13/20): CLOSED/PASS (2026-09-01, attempt 2; panel
  re-verification 2/2).** Attempt 1 was REJECTED by both lenses with 4×P1
  (scan-context asymmetry routing critical-rule matches into the fail-open
  branch under the new default; preamble/epilogue/part-header under-scan;
  per-upstream mode silently inert on MITM; cross-part context keywords dead
  in the decision path). Attempt 2 closed every P1: ONE authoritative scan
  pass now feeds both the criticality decision and redaction (no re-scan),
  preamble/epilogue/part headers are scanned regions, MITM resolves
  per-upstream mode by url-host mapping, fail-open is audited honestly
  (`fail-open` + `redact-failed` flag), binary-part skips emit a
  `binary-unscanned` event. Evidence:
  `evidence/f3/r9-mode-failpolicy-multipart-wirename.md`,
  `evidence/review9/f32-attempt1-correctness.md`,
  `evidence/review9/f32-attempt1-security.md`,
  `evidence/review9/f32-attempt2-correctness.md`,
  `evidence/review9/f32-attempt2-security.md`.

- **F3 phase gate: CLOSED (2026-09-01, owner sign-off).** Integration battery
  on a clean clone of `5ac2564`: 753/0 debug and release, pack 19/19, ReDoS
  11/11, load 14/14, smoke-harness e2e 63/63, honest HTTP gate p99 0.871 ms
  vs strict 5.0 ms, frozen hashes verified (attempt-2 block 7/7; every
  mismatch explained by re-freeze chains), containment intact. Evidence:
  `evidence/review9/f3-integrator-check.md`.

- **R9-21 (NEW, P1-class, registered 2026-09-01, OPEN)** — JSON key-name
  context asymmetry: a `contextKeywords` match can fire in the JSON leaf
  re-scan while the pipeline decision path misses it (the JSON analog of the
  multipart F-1 fixed in F3.1/F3.2; the JSON code predates R9-13 and was
  unchanged in that diff). Surfaced by the F3 re-verification panel
  (`evidence/review9/f32-attempt2-correctness.md`). Must be repaired and
  re-verified before GA; tracked as a standalone repair unit.

F4 opens; F4–F9 remain under Review 9 containment.

- **F4.3 smoke-test hygiene (R9-17): CLOSED/PASS (2026-09-01, attempt 1;
  combined correctness+security verification PASS).** All three broken checks
  repaired (curl http_code misread, `smock` typo grepping a never-existing
  file, swallowed init failure) plus 3-surface leak-check enumeration with
  fail-closed semantics (missing artifact = FAIL, grep rc≥2 = FAIL). The
  decisive negative test was independently reproduced: the OLD test passed
  vacuously on an injected real leak while the repaired test failed it
  (exit 1, raw-secret hit named). No product code changed. Evidence:
  `evidence/f4/r9-smoke-test-hygiene.md`,
  `evidence/review9/f43-attempt1-verification.md`.

- **F4 phase gate: CLOSED (2026-09-01, owner sign-off).** Integration battery
  on a clean clone of `3b59407`: 753/0 debug, pack 19/19, load 14/14,
  smoke-harness e2e 63/63, frozen hash match, containment intact. Evidence:
  `evidence/review9/f4-integrator-check.md`.

F5 opens; F5–F9 remain under Review 9 containment.

- **F5.1 non-blocking hot-path logging (R9-10) + F5.2 HMAC keyed default
  (R9-16): CLOSED/PASS (2026-09-01, attempt 1; panel 2/2, zero P0/P1).**
  Hot path free of synchronous console writes (structural gate 3/3):
  bounded 8,192-entry queue, single worker thread, WorkerGuard-pattern
  shutdown with bounded drain, dropped-writes counted with rate-limited
  content-free notice. HMAC-SHA256 keyed by default with domain separation
  (`cerberus:audit-event:v1`, `cerberus:break-glass:v1`,
  `cerberus:allowlist:v1` reserved), persisted 0600 CSPRNG key file,
  legacy `sha256:` rows kept readable + prefix-gated (migration
  discontinuity documented). Security lens confirmed RFC-4231-conformant
  HMAC, key reach into every production construction site, and durable
  persistence of 24,164 security events under console-sink flood.
  `redos_fuzz.rs` byte-untouched (R9-16 rule). Evidence:
  `evidence/f5/r9-logging-and-hmac.md`,
  `evidence/review9/f5-attempt1-correctness.md`,
  `evidence/review9/f5-attempt1-security.md`.

- **F5 phase gate: CLOSED (2026-09-01, owner sign-off).** Integration battery
  on a clean clone of `099c470`: 776/0 debug, pack 19/19, ReDoS 11/11, load
  14/14 (honest gate p99 0.839 ms), smoke-harness 63/63, structural
  no-sync-write gate 3/3, containment intact. Evidence:
  `evidence/review9/f5-integrator-check.md`. 9×P2 follow-ups registered
  (key-file creation race window folded into F6 builder scope).

F6 opens; F6–F9 remain under Review 9 containment.

- **F6.A fail-closed control-plane auth (R9-5 P0) + HMAC-only allowlist
  (R9-7 P1) + F5 key-file hygiene: CLOSED/PASS (2026-09-02, attempt 2; panel
  2/2 + attempt-2 re-verification).** `admin_token: None` = CLOSED control
  plane (401 on every `/api/*`, loopback included — the fix-plan's literal
  F6.1 mandate); `cerberus init` generates a 256-bit CSPRNG token into a
  0600 config; Host/Origin allowlist fails closed (19 rebinding shapes
  403'd live); `X-Cerberus-Bypass` requires the admin token in ALL modes
  (the F4 injection vector is dead); allowlist persists HMAC fingerprints
  only (store-level write gate; raw values destroyed by boot migration).
  Attempt-1's P1 (control-plane writes regressed config.yaml to 0644) was
  closed in attempt 2 with a unified 0600 write helper. Evidence:
  `evidence/f6/r9-auth-and-allowlist.md`,
  `evidence/review9/f6a-attempt1-correctness.md`,
  `evidence/review9/f6a-attempt1-security.md`,
  `evidence/review9/f6a-attempt2-verification.md`.

- **F6.B Appendix B CLI surface + parity matrix (R9-6 P1): CLOSED/PASS
  (2026-09-02, attempts 2/3/3b; re-verification).** 26 new CLI commands
  (independent inventory: 0 missing / 0 invented in-MVP), 42-row
  API↔CLI↔dashboard parity matrix with a CI-runnable router-derived parity
  test (mutation-proven non-vacuous). Attempt-1's P1 (PUT /api/config
  accepted `admin_token:null` → persistent lockout) closed across attempts
  2/3/3b: the unified fail-closed predicate rejects REMOVED, EMPTY, and
  WHITESPACE-PADDED token encodings on both write paths (live-reproduced:
  5/5 shapes → 400, plane survives); config mutations now emit honest
  audit events. Process note recorded verbatim: attempt-3 briefly shipped a
  clippy regression that a pipe-masked gate hid — caught by the spot
  verifier, evidence corrected. Evidence:
  `evidence/f6/r9-cli-parity.md`, `evidence/f6/parity-matrix.md`,
  `evidence/review9/f6b-attempt1-correctness.md`,
  `evidence/review9/f6b-attempt1-security.md`,
  `evidence/review9/f6b-attempt2-verification.md`,
  `evidence/review9/f6b-attempt3-verification.md`.

- **F6 phase gate: CLOSED (2026-09-02, owner sign-off).** Integration battery
  on a clean clone of `d378939`: 864/0 debug, clippy un-piped exit 0, pack
  19/19, ReDoS 11/11, load 14/14 (honest gate p99 1.726 ms; one documented
  contention tail on the phone_list probe re-run-passed serially), smoke
  harness 69/69, live token-shape closure (5/5 → 400), containment intact.
  Evidence: `evidence/review9/f6-integrator-check.md`.

- **F7 pack-format / pack-signing / auto-update re-verification: CLOSED/PASS
  (2026-09-03, round 3 after 2 documented fix rounds).** Round 1 found 1×P1
  (split ENV_LOCK mutexes over the same process-global env → nondeterministic
  workspace suite, 2/5 exit-101) + 1×P2 (packs update verified in-memory
  bytes while the rebuild read disk → dishonest operator report). Attempt 1
  fixed the lock (shared `cli_api::tests::ENV_LOCK`; 5×865/865) but the
  verifier caught that its disk-verification fix parsed `name@ver` against a
  name-keyed map (regression: healthy packs reported "0/1 verified;
  DEACTIVATED"). Attempt 2 aligned `verify_installed` with
  `manifest.versions_by_pack[name].active` (the rebuild's own source) and
  added the missing coverage. Round 3: PASS with zero findings — signing at
  boot, no-trust-root fail-closed, rollback integrity, Pro gate, wire v2,
  honest packs-update contract live both directions, determinism 4×865/865.
  Evidence: `evidence/f7/r9-reverification.md` (rounds 1–3 + both fixes).

- **F7 phase gate: CLOSED (2026-09-03, owner sign-off).** Evidence:
  `evidence/f7/r9-reverification.md`; candidate `738da62` on
  `r9-remediation` (pushed). R2-3 (dual trust-root test locks) registered as
  non-blocking follow-up.

F8 opens; F8–F9 remain under Review 9 containment.

- **F8 release architecture + tap + packaging (R9-3/R9-4/R9-15): CLOSED/PASS
  (2026-09-03, attempt 2 after one verification FAIL).** Replacement
  workflows (`release-v2.yml`, `version-bump-v2.yml`, `notify-tap-v2.yml`)
  inert under the `review9_f8_pending` guard: version bump opens a PR (no
  workflow writes to main), publish runs on tags of MERGED commits only
  (`verify_tag_merge.sh` — 8/8 attack vectors refused, unmerged/cherry-pick
  tags fail closed), tap PR automation with real SHA256SUMS (fail-closed
  without `TAP_PR_TOKEN`), REAL clean-install `brew install` gate passed
  (isolated prefix, real sha, `brew test`), deb/rpm built by the workflow
  with mandatory GPG, winget real `InstallerSha256` fail-closed, signing
  mandatory with no unsigned fallback, actionlint installed and clean
  (G0 residual closed). Attempt 1 failed verification with a P0 (the
  release-assembly dataflow dead-ended before `gh release create`: sums
  never merged for deb/rpm, merge-multiple collisions, upload-glob misses,
  asset-pattern omissions) — attempt 2 rebuilt the canonical SHA256SUMS
  assembly with a committed simulation proving the exact 17-asset list,
  both-directions fail-closed, independently re-verified. Evidence:
  `evidence/f8/r9-release-and-tap.md`,
  `evidence/review9/f8-attempt1-verification.md`.

- **F8 phase gate: CLOSED (2026-09-03, owner sign-off).** The G0 containment
  lift (flipping the replacement workflows live) is an owner action gated on
  the F9 close + remediation-branch merge. Frozen workflows remain
  byte-untouched. P2 notes: identical-duplicate-lines gate hardening
  suggestion; real-runner-only behaviors (Windows quirks, real rpm build,
  notarization secrets) documented as post-lift validation items.

F9 opens — the final gauntlet (security review, ReDoS fuzz, honest load
test, failsafe, docs) including the registered R9-21 repair; F9 under
Review 9 containment until its gate + GA sign-off.

- **F9.A JSON key-name context asymmetry (R9-21): CLOSED/PASS (2026-09-04,
  attempt 1 built inline; round-2 verification PASS).** The decision view
  for JSON bodies is now the flat-text scan ("all textual content", §4.2)
  UNION one authoritative per-leaf scan — the SAME pass the redaction
  splices (the F3.1/F3.2 one-scan-pass model extended); unspliceable
  cross-leaf redact findings fail closed; the allowlist is authoritative on
  every surface. adv5b closed live (block 403 / redact, never 200-raw);
  adv5 documented as regex-boundary semantics (no divergence). 868/0 debug,
  honest gate p99 1.219 ms, fingerprint unchanged. Round-1's reviewer
  fabricated its evidence table and self-retracted — preserved as
  `evidence/review9/f9a-attempt1-verification-VOID.md`; the round-2 battery
  ran inline with provenance. Evidence: `evidence/f9/r9-json-key-context.md`,
  `evidence/review9/f9a-attempt1-verification-r2.md`.

- **F9 final gauntlet: CLOSED/PASS (2026-09-05, owner sign-off — GA-ready).**
  - security-review: 133 live cross-phase attacks (break-glass scope
    escapes, allowlist 3-surface consistency, vault×bypass interplay,
    120-request adversarial flood) — zero raw secrets across upstream/
    logs/SQLite/events API; R9-5/R9-7/R9-16 re-attacked live and holding;
    all 7 residual follow-ups confirmed documented
    (`evidence/f9/security-review-r9.md`).
  - redos-fuzz 11/11 · load-test 14/14 (honest HTTP gate p99 0.84–1.73 ms
    across rounds vs strict 5.0 ms; fingerprint unchanged) · failsafe
    fail-policy matrix re-verified · docs synced through F5/F6.
  - **F9 phase gate: CLOSED (owner sign-off 2026-09-05).** Evidence:
    `evidence/f9/integration-gate-r9.md`. The Review 9 invalidation
    register is fully re-verified; GA readiness declared. The G0 lift
    (workflow flip, merge to main, first PR-based tag release) is an owner
    action, gated on nothing further.

  Process notes preserved: one reviewer fabrication + self-retraction
  (VOID record); ~7 sub-agent transport failures covered by inline
  orchestrator batteries with explicit provenance; one mid-build file
  corruption recovered via git. All phase gates carry owner sign-offs
  (2026-08-31 → 2026-09-05).

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
