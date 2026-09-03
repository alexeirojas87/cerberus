# Evidence Pack — F7 / R9-remediation re-verification (independent)

- **Candidate:** commit `c7f357429415ded3919870ebf320e17ebc024587` on branch `r9-remediation` (pushed; tree clean)
- **Worktree:** `/var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/f7-reverify` (detached HEAD at the candidate; `git status --short` empty; `git diff --check` exit 0)
- **Date:** 2026-09-02/03 (America/New_York, live session)
- **Host:** macOS 15.x (Darwin 25.5.0, arm64, Apple T6041)
- **Toolchain:** rustc 1.97.1 (8bab26f4f 2026-07-14), cargo 1.97.1
- **Reviewer:** independent adversarial re-verifier (no builder overlap); no code/test/threshold edits made anywhere
- **Prior status:** F7 PASS invalidated by the Review 9 containment register (`evidence/gauntlet/index.md` marks all prior F1–F9 PASS as `SUPERSEDED / INVALIDATED BY REVIEW 9`). This pack is the independent re-verification.
- **Scope note:** F6.B extended surface (packs enable/disable/update commands, updater manifest/verify path) is in scope per the re-verification order.

## Commands run

| # | Command (verbatim, cwd = worktree unless noted) | Exit | Result |
|---|---|---|---|
| 1 | `git -C /Users/alexeirojas/Work/Personal/Cerberus worktree add --detach …/f7-reverify c7f3574` | 0 | worktree created at candidate |
| 2 | `rtk cargo test -p cerberus-packs --all-targets` | 0 | `cargo test: 87 passed (2 suites, 0.19s)` (68 lib + 19 integration; raw re-run: `68 passed; 0 failed` + `19 passed; 0 failed`) |
| 3 | `rtk proxy cargo test -p cerberus-packs --test production_pack_pr -- --test-threads=1` | 0 | **19 passed; 0 failed** (0.41s) |
| 4 | `rtk proxy cargo test -p cerberus --test pack_cli_e2e --test pack_cli_via_api` | 0 | 3/3 + 4/4 passed |
| 5 | `rtk cargo test --workspace --all-targets` | 0 | `cargo test: 864 passed (29 suites, 54.34s)` — run A |
| 6 | `rtk proxy cargo test --workspace --all-targets` (piped capture) | 0 | 1 suite `FAILED. 232 passed; 1 failed` (run B — first flake observed) |
| 7 | `rtk proxy cargo test --workspace --all-targets > f7r-ws-full.log` | 0 | 29 suites, **864 passed; 0 failed** — run C (clean) |
| 8 | `rtk proxy cargo test --workspace --all-targets` × 2 (runs D, E) | 101 / 0 | run D **FAILED**: `cli_surface::tests::login_verifies_and_installs_signed_license` ("license installed 0600", cli_surface.rs:1217); run E clean |
| 9 | `rtk proxy cargo test -p cerberus --bin cerberus login_verifies_and_installs_signed_license` × 8 isolated | 0 ×8 | passes alone → inter-test race suspected |
| 10 | `rtk proxy cargo test -p cerberus --bin cerberus` × 6 | 101/0×5 | run 1 failed BOTH `license_wired_from_signed_file_at_boot` (daemon.rs:1476 "without trust root … fall back to Free") and `login_…` (cli_surface.rs:1212 `assert!(dest.exists())`) |
| 11 | `rtk proxy cargo test -p cerberus --bin cerberus -- license login` × 16 | 101 ×16 | **deterministic reproduction** of the pair race (failure variants: 1208 `Invalid argument (os error 22)`, 1212 `dest.exists()`, 1217 mode≠0600, daemon.rs:1476) |
| 12 | `rtk proxy cargo test -p cerberus --test pack_enable_disable_worker_e2e` | 0 | 1/1 passed (real-daemon worker round trip) |
| 13 | `rtk cargo build --release -p cerberus` | 0 | release binary for live battery |
| 14 | `rtk proxy cargo test -p cerberus-proxy --test smoke_harness` | 0 | **69/69** |
| 15 | `bash tests/smoke-test.sh` | 0 | 17/17 (shell smoke) |
| 16–40 | Live daemon battery (release binary, isolated HOME, port 18793) — see attack table below | — | see per-attack results |
| 41 | `shasum -a 256` of pack-crate files vs frozen blocks | 0 | see frozen-hash section |
| 42 | `git status --short` / `git diff --check` (worktree) | 0 | no modifications by reviewer |

## Live signing-at-boot battery (the v6 P0 class, attacked on a real release daemon)

Harness: release `target/release/cerberus start --port 18793`, isolated HOME per `pack_enable_disable_worker_e2e.rs` patterns; Pro license (Ed25519, local issuer) via `CERBERUS_LICENSE_PUBLIC_KEY` + `CERBERUS_LICENSE_PATH`; pack trust root via `CERBERUS_PACK_TRUST_ROOT`; signed packs generated with the harness key pattern ([7u8;32] license, [9u8;32] pack).

| # | Attack | Result | Evidence |
|---|---|---|---|
| L0 | Baseline: boot Pro+root, CLI `pack install` v1 (wire v2 bytes), scan | ✅ PASS | `pack installed (hot-reload): engine now has 16 rules`; manifest `f7r-pack@1.0.0: true` persisted; scan `flags: {"pack.f7r.marker": 1}`, action=block |
| L1 (2a) | Tamper **one byte** of the signed pack file on disk (`pack_f7r-pack-v1.0.0.json`, `F`→`G` inside the pattern, JSON still valid), restart daemon | ✅ PASS — DEACTIVATED + PERSISTED | `WARN packs: active pack f7r-pack@1.0.0 FAILED signature verification on boot; deactivating: signature verification failed: signature error: Verification equation was not satisfied`; manifest on disk now `"f7r-pack@1.0.0": false, versions_by_pack.active: ""`; scan detects NEITHER original nor tampered pattern; second restart: 0 deactivation warnings (no re-acceptance), `0 packs installed` |
| L2b (2b) | Healthy active manifest, restart **without** `CERBERUS_PACK_TRUST_ROOT` (Pro intact) | ✅ PASS — fail-closed 0 packs | `WARN packs: boot without trust root; loading NO packs (fail-closed)` + `WARN packs: no effective trust root (Free tier or root missing) — base engine, zero packs`; `0 packs installed`; engine back to 15 base rules; scan clean — **no unsigned fallback** |
| L2c (v6.1 P0 variant) | Trust root PRESENT but **Free tier** (no license) | ✅ PASS — zero packs | `tier=free` in log; same two fail-closed WARNs; `0 packs installed`; scan clean → the v6.1 license-gate bypass (`gated_by_pro(false)` → `PackTrustRoot::Disabled`) is closed live |
| L3a (2c-1) | Healthy rollback: install v1 → install v2 → `pack rollback` | ✅ PASS — active set reflects v1 | pre-rollback scan: V2 only; post-rollback: V1 only; manifest persisted `{"f7r-pack@1.0.0": true, "f7r-pack@2.0.0": false}`, `versions_by_pack.active: "1.0.0"` |
| L3b (2c-2) | Tamper the v1 file on disk **while it is the rollback target**, then `pack rollback` | ✅ PASS — no resurrection of unsigned bytes | rollback reports 15 rules (base); `WARN packs: active pack f7r-pack@1.0.0 FAILED signature verification …; deactivating` during the rollback rebuild; scan detects NOTHING (V1/V2/tampered all clean); manifest persisted both versions inactive; reboot → still `0 packs installed`, no resurrection |
| L4 | Pro gate without Pro (Free tier, trust root set): API + CLI | ✅ PASS | API: install/rollback/update/enable all `400 {"error":"… rule packs require a Pro license (open-core)…"}` (unified `require_pro_for_pack_ops`, worker arms); CLI (control-plane) identical refusals; CLI **local mode** (no daemon): `pack install aborted` / `pack rollback aborted` refusals; `packs disable` intentionally un-gated (documented: disable only reduces detection) and fails honestly with `pack 'f7r-pack' is not installed` in Free |
| L4+ | With Pro: enable/disable/update positives | ✅ PASS | disable → engine 15 rules, dataplane stops matching (`{}`); enable → 16 rules, detection returns; update → `1/1 signatures verified; engine hot-reloaded with 16 rules` |
| L5 | `packs update` **network isolation** (daemon started with `HTTP(S)_PROXY/ALL_PROXY=http://127.0.0.1:9`) | ✅ PASS — no network in the update path | update succeeded with all egress proxied to a dead sink; `lsof -a -p <pid> -i` shows **only** `TCP localhost:18793 (LISTEN)`, zero outbound sockets; static: `verify_installed` = local re-verify + rebuild + persist; `reqwest` exists only in `telemetry.rs` (opt-in telemetry, not the update path) |
| L5b | Tamper on disk + `packs update` | ⚠️ see P2 | pack WAS deactivated + persisted + dataplane clean (15 rules, scan `{}`), but the CLI message claimed `1/1 signatures verified` with no DEACTIVATED clause — see Finding 2 |
| L6 (wire v2) | Legacy/foreign request shapes vs `POST /api/packs/install` | ✅ PASS | `{"path":…}` → 400 `install by path retired (wire v1): the control plane does not open client paths; send the signed pack bytes in the 'pack' field (wire v2)`; `wire_version:1` → 400 `unsupported wire version: 1 (this binary speaks v2)`; `wire_version:3` → 400; `origin_name:"../evil/pack.json"` → 400 `origin_name must be a basename without path separators`; valid v2 byte transport works (L0). Unit gate: `wire.rs::legacy_path_request_is_rejected_explicitly` green in suites |

## Per-criterion verdicts

| Criterion | Verdict | Notes |
|---|---|---|
| `cerberus-packs --all-targets` (87) | ✅ PASS | 68 + 19, exit 0 |
| `production_pack_pr --test-threads=1` (19/19) | ✅ PASS | exit 0 |
| Pack CLI e2e (`pack_cli_e2e` 3/3, `pack_cli_via_api` 4/4) | ✅ PASS | exit 0 |
| `cargo test --workspace --all-targets` (864) | ❌ **FAIL (non-deterministic)** | 3/5 runs green at exactly 864/0/29 suites; 2/5 runs exit 101 on the F7/F6-licensing test pair — **P1 Finding 1** |
| smoke harness (`-p cerberus-proxy --test smoke_harness`) | ✅ PASS | **69/69** |
| smoke script (`tests/smoke-test.sh`) | ✅ PASS | 17/17 |
| Signing-at-boot (tampered pack deactivated + persisted) | ✅ PASS | L1 live attack |
| No-trust-root fail-closed (and Free-tier+root v6.1 variant) | ✅ PASS | L2b/L2c live attacks |
| Rollback integrity (v2→v1; tampered v1 not resurrected; persistence across reboot) | ✅ PASS | L3a/L3b live attacks |
| Pro gate unified (`require_pro_for_pack_ops`) API+CLI+local, Free refusals / Pro allowed | ✅ PASS | L4 (disable un-gated = documented design) |
| F6.B enable/disable/update + worker e2e + update path network-isolated | ✅ PASS | L5, worker e2e 1/1, dead-proxy + lsof evidence |
| Wire v2 (bytes, not path; `{path}`/v1/v3 rejected before the worker) | ✅ PASS | L6 live + unit tests |
| HMAC allowlist interplay (fingerprints only, no raw in pack format) | ✅ PASS | pack format (`RulePack` = metadata+rules, no allowlist section; `allowed_examples` carry only public test vectors, e.g. `default_pack.rs:90` `ghp_example_token_do_not_use_in_production`); user FP-allowlist persists as `hmac:`-prefixed SHA-256 fingerprints only (`docs/user-guide.md:107,133`; `ALLOWLIST_HASH_DOMAIN` domain separation at `cerberus-engine/src/engine.rs:1234-1258`; live scan returned `hashed_values: ["hmac:cd7e…"]`, never raw) |
| Frozen-hash integrity (pack-crate files) | ✅ PASS | see table below |

Frozen-hash re-computation at `c7f3574` (vs the latest active freeze per file):

| File | Latest freeze source | Frozen | Measured | |
|---|---|---|---|---|
| `crates/cerberus-packs/src/updater.rs` | `evidence/f6/r9-cli-parity.md:138` (F6 re-freeze) | `8c53af8f…64bf30` | `8c53af8f…64bf30` | ✅ |
| `crates/cerberus-packs/src/default_pack.rs` | `evidence/review9/f13-integrator-check.md:52` (F1.3; supersedes f12-attempt4/5/6 blocks, pre-R9-9-fix) | `66679c8a…5610` | `66679c8a…5610` | ✅ |
| `crates/cerberus-packs/tests/production_pack_pr.rs` | `evidence/review9/f13-integrator-check.md:54` | `33bf4c7a…e21` | `33bf4c7a…e21` | ✅ |
| `crates/cerberus/src/cli_pack.rs` | `evidence/f6/r9-cli-parity.md:369` (F6.B re-freeze) | `50a78de1…71a6` | `50a78de1…71a6` | ✅ |

`pack.rs`, `wire.rs`, `license.rs`, `telemetry.rs` have no frozen blocks (never frozen). `engine.rs` etc. are out of F7 scope per the re-verification order.

## Attack vectors tried (summary)

1. Single-byte on-disk tamper of a signed pack (content byte inside the signed JSON, file stays valid JSON) → boot restart → deactivated + persisted; dataplane refuses both original and mutated pattern. Repeated after rollback and via `packs update` — always fail-closed.
2. Boot with active manifest but no trust root → zero packs, no unsigned fallback.
3. Boot Free-tier with trust root present (v6.1 P0 bypass shape) → zero packs (`gated_by_pro`).
4. Rollback onto a tampered rollback-target file → verification failure at rebuild → deactivation + persistence; reboot does not resurrect.
5. Pro-gate probing via raw curl AND CLI (control-plane) AND CLI local mode, install/rollback/update/enable in Free → all refused with the unified message.
6. Wire-shape attacks: legacy `{"path":…}`, wire v1, wire v3, path-carrying `origin_name` → all 400 before the worker.
7. Network-isolation trap for `packs update` (dead proxies on the daemon + `lsof` socket audit) → no HTTP egress in the update path.
8. Full-suite parallelism attack on the test battery itself → found the P1 flake below.

## Findings

### P1 — Workspace suite is non-deterministic: dual `ENV_LOCK` race in the F7/F6-licensing tests
- **Where:** `crates/cerberus/src/daemon.rs:1064-1070` defines a **private** `static ENV_LOCK: Mutex<()>` inside its own `#[cfg(test)] mod tests`, while `crates/cerberus/src/cli_api.rs:295-302` defines `pub(crate) static ENV_LOCK` with the doc comment "Serializes ALL tests that mutate HOME/APPDATA/CERBERUS_* … Shared across modules … (a real race observed on F6.B)". `cli_surface.rs` uses the shared one; `daemon.rs` tests use their private one. The two locks do not serialize each other.
- **Effect:** `daemon::tests::license_wired_from_signed_file_at_boot` and `cli_surface::tests::login_verifies_and_installs_signed_license` concurrently mutate the same process-global env (`HOME`, `APPDATA`, `CERBERUS_LICENSE_PATH`, `CERBERUS_LICENSE_PUBLIC_KEY`). Observed failure modes across reproductions: `assert!(dest.exists())` (cli_surface.rs:1212), mode ≠ 0600 (cli_surface.rs:1217), `cannot install license: Invalid argument (os error 22)` (cli_surface.rs:1208), and `without trust root the daemon must fall back to Free` (daemon.rs:1476). Reproduction: `cargo test -p cerberus --bin cerberus -- license login` fails **16/16**; full `cargo test --workspace --all-targets` failed **2 of 5** runs with exit 101.
- **Impact:** the mandatory 864-test evidence criterion is not reproducibly green; CI/gauntlet evidence becomes a coin flip. The `daemon.rs:1476` symptom ("no trust root → Pro") is a **test-only artifact** of the race (the login test's cleanup re-installs a trust-root env var mid-test), NOT a product fail-open — disproven live by L2b/L2c (fail-closed boot with 0 packs in every no-root/Free configuration).
- **Fix direction (for FIX, not applied here):** make `daemon.rs` tests take `crate::cli_api::tests::ENV_LOCK` (delete the private static), or convert the env-touching tests to explicit parameter passing. One-line-class change.

### P2 — `packs update` reports "N/N signatures verified" while deactivating a pack that failed disk verification
- **Where:** `crates/cerberus-packs/src/updater.rs:700-733` (`verify_installed`): the per-pack verified/unverified `results` are computed against the **in-memory** `installed.pack_json`, but the subsequent `rebuild_active_set` re-loads pack files from **disk** and deactivates any that fail. After out-of-band disk tampering the two views diverge: the daemon log shows `FAILED signature verification …; deactivating`, the engine correctly reloads on base (15 rules), the manifest is persisted inactive — yet the command response was `packs update: 1/1 signatures verified; engine hot-reloaded with 15 rules` with no `DEACTIVATED after failed verification:` clause.
- **Impact:** operator-facing message diverges from the action taken (audit/observability defect). No security impact: unsigned bytes were never activated; deactivation + persistence + dataplane were all correct (verified live, L5b).
- **Secondary nit:** the deactivation WARN emitted by `rebuild_active_set` says "FAILED signature verification **on boot**" even when triggered from `rollback`/`packs update` — misleading provenance in logs.
- **Fix direction:** compute `results` from the post-rebuild state (or re-verify from disk in the results loop).

No P0 findings. No product-code fail-open was found in any attack.

## Final verdict

**FAIL** — per §8B ("VERIFY → FAIL: fails ≥1 criterion"): the mandatory `cargo test --workspace --all-targets` criterion cannot be demonstrated as reproducibly green (864/0 achieved in 3 of 5 independent runs; exit 101 in 2 of 5) due to the P1 dual-`ENV_LOCK` test race on the in-scope F7/F6-licensing surface. Every functional/security criterion of F7 (signing-at-boot, no-trust-root fail-closed, rollback integrity, Pro gate, F6.B enable/disable/update, wire v2, format hygiene, frozen hashes, 69/69 smoke harness, 19/19 production pack PR) **passed live adversarial verification**. The phase regains PASS after the P1 (and ideally the P2) is fixed and this battery is re-run to a stable green.

## Appendix — live-battery environment

- Fixture generator: throwaway cargo project at `/var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/f7r-fixtures` (path-dep on the worktree's `cerberus-packs`; license key seed `[7u8;32]`, pack key seed `[9u8;32]` — the harness pattern). Outputs under `/var/folders/…/opencode/f7r-live-home/`.
- Isolated homes: `f7r-live-home` (tamper battery), `f7r-noroot-home` (no-root + Free-variant), `f7r-roll-home` (rollback + F6.B positives + network isolation), `f7r-free-home` (Free Pro-gate). Port 18793; admin token `f7r-reverify-admin-token-0123456789`; trust root `fd172438…f618`; license root `ea4a6c63…d22c`.
- Daemon logs: `/var/folders/…/opencode/f7r-daemon-l0.log`, `…-l1.log`, `…-l1b.log`, `…-l2a.log`, `…-l2b.log`, `…-l2c.log`, `…-l3.log`, `…-l3b.log`, `…-l4.log`, `…-l5.log`; workspace logs `f7r-ws-full*.log`, `f7r-race-*.log`, `f7r-bin-*.log` in the same directory.
- All daemons terminated after the battery (`ps` count 0). Main repo untouched except this report file.

## FIX attempt 1 (orchestrator-executed builder fix, 2026-09-02)

**P1 (ENV_LOCK split):** `daemon.rs` tests had a private `ENV_LOCK` over the
same process-global env that `cli_api::tests::ENV_LOCK` (the lock created in
F6.B precisely because of this race class) already guards. The two license
tests raced on `HOME`/`APPDATA`/`CERBERUS_LICENSE_*`: pair failed 16/16 in
isolation; full workspace suite nondeterministic (2/5 exit-101). Fix: the
daemon test module now imports the shared `crate::cli_api::tests::ENV_LOCK`;
the private static and its `Mutex` import are gone. **Determinism proof:
5 consecutive full-workspace runs, 864/864 each, exit 0.**

**P2 (packs update report divergence):** `verify_installed` scored the
IN-MEMORY `pack_json` while the trailing `rebuild_active_set` re-loads from
DISK — out-of-band disk tampering produced the report "1/1 signatures
verified" while the rebuild deactivated the pack. Fix: `verify_installed`
now verifies the DISK bytes via the same `load_signed_from_dir(dir, name,
ver)` source the rebuild uses (missing disk file = unverified), so the
operator report matches the rebuild outcome by construction. The
deactivation WARN is flow-agnostic ("FAILED signature verification;
deactivating" — no longer claims "on boot"). Security outcome was already
correct (fail-closed); now the report is honest too.

**Verification:** clippy `--workspace --all-targets -D warnings` exit 0
(un-piped); `cerberus-packs` 87/87; `cerberus` 119/119; workspace 864/864 ×5.
