# Evidence Pack — F6.A — R9-5 control-plane auth hardening + R9-7 allowlist HMAC fingerprints (+ F5 P2 follow-ups)

- Unit: **F6.A** (builder) — R9-5 (P0, F6.1+F6.2), R9-7 (P1, F6.3), F5 F-1/F-2/F-3 hygiene
- Attempt: 1 · Branch: `r9-f6-attempt1` (worktree, base commit `f73928b` = `r9-remediation` HEAD)
- Builder: builder subagent (did not review) · Date: 2026-09-02 · Host: macOS arm64 (darwin)
- Toolchain: stable-aarch64-apple-darwin, rustc/clippy 1.97
- Returns to: **VERIFY** (§8B.5) — this is the builder pack; panel review happens next
- Scope discipline: only the semantics of these findings were changed; no threshold moved; MVP only.

---

## 0. Findings being closed (full text anchors)

- **R9-5 [CRÍTICO]** — "Control plane sin autenticación por defecto en loopback": `admin_token: None`
  left the control plane open; `POST /api/upstreams` hot-swaps upstreams; the provider key travels in
  `authorization` and a DNS-rebinding/CSRF page could steal it. `X-Cerberus-Bypass` honored without auth
  when no token (`proxy.rs:512-520` pre-fix).
- **R9-7 [ALTO]** — the allowlist persisted the RAW secret value in config.yaml and served it via API
  (`api.rs:662-671` pre-fix; matching by literal equality `proxy.rs:775-778` pre-fix). Violates §5
  "the raw value is never persisted".
- **F5 F-1/F-2/F-3** (authorized follow-ups) — key-file umask race + ignored chmod; unlogged corrupt-key
  repair; under-signalled ephemeral fallback.

---

## 1. Dev-mode semantics decision (EXPLICIT, per the finding text)

**`admin_token: None`/empty = the control plane is CLOSED, not open.** Rationale: the fix-plan F6.1
mandates "si falta token, mutation/data API responde 401 aun en loopback" and the finding's threat model
(a browser page driving a local control plane) admits no authenticated dev exception: with `None` there
is NO valid credential, so nothing can authenticate. The old contract ("None (dev mode/tests) → the
control plane is left open", `config.rs:45-46` pre-fix) WAS the R9-5 vulnerability and is gone.

- Every data `/api/*` route → **401** without a valid token, loopback included. Only the static
  dashboard HTML and `/health` stay public (neither serves data). Unknown `/api/*` paths 401 before
  reaching the 404 (no pre-auth oracle).
- **Dev usability**: `cerberus init` now generates a 256-bit CSPRNG admin token and persists it in
  `config.yaml` (written 0600 at creation, no umask window); the token is NOT printed to stdout/logs —
  the operator reads it from the config file and pastes it into the dashboard login card (existing
  flow: token only in browser memory/localStorage, sent via `X-Cerberus-Admin-Token`). `CERBERUS_ADMIN_TOKEN`
  env override > config.yaml (precedence unchanged). Non-loopback binds still REQUIRE ≥24-byte tokens
  at startup (review v4 rule unchanged, still refuses to start).
- Boot is loud when `None`: `warning: NO admin token configured — the control plane is CLOSED …` (daemon.rs:417).
- Data-plane bypass: same reading — with `None` there is no credential, so `X-Cerberus-Bypass` is REFUSED
  (proxy.rs:664-671), closing the F4-verified injection vector. With a token, the F2 review-v4 rule
  (only `X-Cerberus-Admin-Token`, never Bearer) is unchanged.

**Consequences honored and tested**: the smoke harness authenticates like the product (`api_client()` +
per-context token); `tests/smoke-test.sh` reads the init-generated token; every harness test that
legitimately broke under the new defaults was updated (63→67 tests).

## 2. Host/Origin allowlist (anti-rebinding) — config-driven per A.1

- New module `crates/cerberus-proxy/src/host_origin.rs`: exact allowlist, **no wildcards** (a wildcard/
  blank entry FAILS the build — fail-closed config, no silently-inert entries).
- Default policy (fail-closed): **loopback bind** → `localhost` / `127.0.0.1` / `[::1]` (with or without
  the real port; port-0 boots fall back to the bare-name comparison). **Non-loopback bind → NOTHING
  allowed by default** — the operator must name hostnames in the new config fields `allowed_hosts` /
  `allowed_origins` (`ProxyConfig`, config.rs:70-100). Public hostnames are configured explicitly, per
  fix-plan F6.1 "hostnames públicos configurados explícitamente, sin wildcards, en Mode A".
- Enforced on EVERY `/api/*` request BEFORE the auth gate (`api.rs:389 anti_rebinding_gate` wired at
  api.rs:455-462): rebound Host → 403; foreign/`null` Origin → 403; form-submittable "simple" content
  types (`text/plain`, urlencoded, multipart) on browser mutations → 403. CLI/curl without Origin keep
  working with a valid token. The installed policy is built once per boot (daemon from `config.listen`
  + config; every other producer gets the fail-closed default installed at `spawn_proxy`/`spawn_managed_proxy`,
  proxy.rs:272-277, 315-320).
- Deviation note (documented): fix-plan says "exigir application/json" for browser mutations; packs
  install (`POST /api/packs/install`) is a byte-upload route (Pro), so the implemented rule rejects the
  form-submittable simple types and lets the JSON routes enforce JSON parsing (they already 400 on
  non-JSON bodies). Effective browser shape is still `application/json`.

## 3. Token-gated bypass (F6.2) — all modes

- `proxy.rs:635-671`: `None =>` **refuse** (loud warn) instead of the old "dev mode: bypass open";
  `Some(expected)` keeps the F2 review-v4 rule: honored ONLY via `X-Cerberus-Admin-Token`, never
  `Authorization: Bearer` (the provider key travels in `Authorization`; the admin header is never
  forwarded upstream — proxy.rs:998).
- `POST /api/break-glass` (issue endpoint) sits behind the fail-closed auth gate: 401 without a valid
  token, in all modes.

## 4. HMAC-only allowlist (R9-7/F6.3)

- `crates/cerberus-engine/src/engine.rs:1246` — `ALLOWLIST_HASH_DOMAIN = "cerberus:allowlist:v1"`
  (the domain F5 reserved). Fingerprints are `domain_hash(installation_key, domain, trimmed_value)`
  (`crates/cerberus-proxy/src/allowlist.rs:39`), `hmac:` + 64 hex.
- **Write paths**: `POST /api/allowlist` converts raw→fingerprint at ingestion (api.rs:1417; requires
  the wired installation key, else 503); `PUT /api/policy`/`PUT /api/config` accept only
  fingerprint-shaped entries — `DetectionPolicy::validate()` REJECTS raw (detection_policy.rs:201-213,
  the **config-store write gate**); CLI allowlist commands do not exist in the MVP surface (R9-6 —
  nothing to gate; F6.4 owns the parity matrix).
- **Store write gate at the audit store (F5 F-4)**: `cerberus-store::write_event_async` validates every
  `hashed_values` entry — `hmac:` / `bypass-hash:` (both keyed) pass; unkeyed `sha256:` is REJECTED
  (`WriteOutcome::RejectedUnkeyed`, store.rs:126, 390-421, 765) before it can reach the database; the
  explicit `write_event_async_legacy` writer (store.rs:401) is the migration-tooling escape hatch and
  still refuses unknown schemes.
- **Matching**: the hot path computes the candidate's HMAC and compares fingerprints
  (proxy.rs:1103 `filter_with_allowlist`, json_redact.rs:132 `scan_multipart_regions`) — lazily-built
  HashSet + one HMAC per finding; unkeyed contexts (library tests only) filter NOTHING (fail-closed:
  the allowlist can never silently widen what passes).
- **Removal**: `DELETE /api/allowlist` accepts the raw value (computes its fingerprint) or the stored
  fingerprint; 404/ok responses echo the FINGERPRINT only (api.rs:1495-1530).
- **API responses never return raw values**; GET /api/allowlist + /api/policy return fingerprints.
- **Migration (smallest safe design, documented)**: legacy raw YAML entries are converted at daemon
  boot BEFORE policy validation (daemon.rs:167-215 `migrate_allowlist_to_fingerprints_persisting_to`),
  rewritten atomically to `config.yaml` at 0600; raw values are destroyed in place — **no raw backup
  file is kept** (deliberate deviation from the fix-plan's "backup + destroy after sign-off": a raw
  backup would itself violate the R9-7 invariant it protects; conversion is atomic + idempotent and the
  behavior is tested). Live boot verified: `allowlist migration (R9-7): 1 raw entry converted …`;
  config.yaml afterwards carries only `hmac:…`.
- **Key rotation**: fingerprints are key-bound; rotation invalidates them (documented, fail-closed —
  previously-allowed values are flagged again; re-add via the API). Tested.

## 5. F5 P2 follow-ups (F-1/F-2/F-3)

- **F-1** `crates/cerberus/src/audit_key.rs:176-231`: the tmp key file is created with
  `OpenOptions::create_new(true).mode(0o600)` (unix) — restrictive mode applied AT CREATION, no
  umask-derived 0644/0666 window, no post-hoc ignored chmod; every `Result` is handled (persistence
  failure → loud ephemeral fallback; stale tmp from a crashed boot removed first; failed rename cleans
  the tmp). Non-unix keeps exclusive creation (user-profile ACLs, documented).
- **F-2** audit_key.rs:53,65,84-105: corrupt key file ≠ first boot — new `KeySource::Regenerated`
  ("regenerated this boot (key file was corrupt — correlation with prior hashes lost)") + a loud warn
  path via `requires_loud_warning`.
- **F-3** daemon.rs:393 (`requires_loud_warning` → eprintln WARN + tracing::warn for
  Generated/Regenerated/Ephemeral) and init.rs:284 (dry-run `cerberus scan/test` discloses the
  ephemeral per-process key marker).

## 6. Acceptance → evidence

| # | Acceptance criterion | Evidence |
|---|---|---|
| 1 | All `/api/*` fail-closed 401 without valid token, loopback included; route matrix | `smoke_harness.rs:3605 r9_5_route_matrix_fail_closed` — 14 routes × no-token/wrong-token → 401; valid token → never 401; dashboard+health public. Live: tokenless `/api/events` → 401 |
| 2 | Host/Origin allowlist + rebinding attack tests; dashboard works with token | `host_origin.rs` (7 unit tests incl. `attacker.com`/evil-Origin/`null`/fail-closed non-loopback); `smoke_harness.rs:3704 r9_5_rebinding_attack_shapes_are_rejected` (raw-HTTP attacker.com Host → 403, evil/null Origin → 403, text/plain mutation → 403, loopback Host no-token → 401, loopback Host + token → 200); live rebound Host → 403 |
| 3 | Bypass requires token everywhere; F4 vector FAILS | proxy.rs:635-671 (refusal); `smoke_harness.rs:3782 r9_5_f4_injection_vector_bypass_without_token_is_refused` — unauthenticated bypass → 403 block, token-gated bypass still 200; smoke-test.sh TEST POINT 5a (mock-log leak check: payload never reaches the mock) |
| 4 | Raw never persisted; fingerprints end-to-end; grep-clean | `smoke_harness.rs:3835 r9_7_allowlist_fingerprints_end_to_end` (add → stored bytes are `hmac:` in config.yaml; API views carry fingerprints, no raw; hot path honors the fingerprint; rotation invalidates); store write-gate tests (store.rs:1035-1115); config-store gate test (config.rs raw → validate error); migration test (daemon.rs tests); live boot migration transcript (§4); grep audit below |
| 5 | Key-file hygiene F-1/F-2/F-3 | audit_key.rs:176-231 (`create_new`+`mode(0o600)`, exclusive-create test, stale-tmp test); Regenerated source + loud-warning matrix test; dry-run marker; daemon WARN |
| 6 | Full matrix green incl. honest HTTP gate | §7 below |

**Grep-clean audit (raw allowlist values)**: the only non-test `allowlist.push` in the product is
api.rs:1439 which pushes the FINGERPRINT; all other push sites are in `#[cfg(test)]` fixtures. API
responses echo fingerprints only (api.rs:1518/1528); the migration destroys raw values in place; live
smoke leak-check covers HOME tree + proxy log + mock log (3/3 inspected). The F5 store gate now makes
`sha256:` rows un-writable through the ordinary writer.

## 7. Verification matrix (all commands run in this worktree)

| Gate | Command | Result |
|---|---|---|
| fmt | `cargo fmt --all && cargo fmt --check` | clean |
| clippy | `rtk cargo clippy --workspace --all-targets -- -D warnings` | 0 warnings |
| workspace (debug) | `cargo test --workspace` | **804 passed, 0 failed** (776 base + 28 new) |
| smoke harness | `cargo test -p cerberus-proxy --test smoke_harness` | **67/67** (63 base updated + 4 new R9-5/R9-7) |
| pack | `cargo test --release -p cerberus-packs --test production_pack_pr` | **19/19** |
| redos | `cargo test --release --test redos_fuzz -- --test-threads=1` | **11/11**; `git diff f73928b -- tests/redos_fuzz.rs` = **0 bytes** (untouched) |
| load | `cargo test --release --test load_test` | **14/14** incl. `load_test_f3_3_honest_http_round_trip_gate` |
| smoke script | `bash tests/smoke-test.sh --port 18791` (release binary, tmp HOME) | **17/17 PASS** (14 prior + 3 new R9-5/F6.2 checks) — log `evidence/r0/smoke-test/smoke-run-20260902-100125.log` |
| release build | `rtk cargo build --release -p cerberus` | OK (live boot checks below) |
| `git diff --check` | whitespace/conflict markers | clean |
| redos_fuzz byte rule | `git diff` | file untouched (R9-16 rule preserved) |

**Live boot checks (release binary, isolated `$HOME`s)**:
1. init → `config.yaml` mode `-rw-------` (0600); boot → tokenless `/api/events` = 401; with token → 200;
   `Host: attacker.com` → 403; init report names the file, never prints the token.
2. Legacy config with `allowlist: [sk-LEGACY-RAW-SECRET-0001]` → boot logs
   `allowlist migration (R9-7): 1 raw entry converted to HMAC fingerprints (domain cerberus:allowlist:v1)…`
   and `config.yaml` afterwards contains only `hmac:b467537f…`.

## 8. Frozen SHA-256 (files touched by this unit, at commit time)

```
773aeb751170d6803f9b57c33414ef6eb489ae277073b46794c9ff7027187b74  crates/cerberus-engine/src/engine.rs
7e59debffbd0ca25934eb062c6a4f9d40a34912da8249a21361557466738b1ee  crates/cerberus-proxy/src/api.rs
c1c116475eab9e3ebf5d3321cd90d11dc8b16438efe12ddbc4a3ba025f0d79c4  crates/cerberus-proxy/src/config.rs
661ea81706f00a2603fdef030166daaf8cca99d0dab57d257bd9682c461dd98f  crates/cerberus-proxy/src/detection_policy.rs
51b0b81c3b3df26407a04f5a6d98607fad731b515517a5e1aedcdf8b55cb6b04  crates/cerberus-proxy/src/forward.rs
54bf628e1ef37d37f1d75e1d5fc6936dae0ec936b7f1914d234483806d087f22  crates/cerberus-proxy/src/json_redact.rs
6ce2d85d1b2475bef2d17f2abd3da77246b16b5739ccfd37150c5adc5a029d4e  crates/cerberus-proxy/src/lib.rs
a2ae1996ee187b8fa14f08326e95b0fb5fa1353edf511c0603a45907be1e4d28  crates/cerberus-proxy/src/proxy.rs
660f951c23c8abd3eeecaebeaa9c458bc97bdbda34aa01924e22d40bcbfb89e9  crates/cerberus-proxy/src/test_utils.rs
1884e35aadb4ae75586496f4038845601663c4147955722f49aaffaa4d0787fb  crates/cerberus-proxy/tests/smoke_harness.rs
cc1d14d23108818751ffdf314b90f6fd7e4d17f9b6d75ffe0715a072f4da6717  crates/cerberus-store/src/store.rs
10a538ecff84b42f2fd94575b637af00a4fa40577cbbc99a888e9f97e5adfcdf  crates/cerberus/src/audit_key.rs
ce0687f96877fd31dfb45ae2c2281ee7f5a6994926d58b889741ce5f7dca3121  crates/cerberus/src/daemon.rs
58267ab04e5c6e7375c595ea086aaa8b0f482f5be105a65a4628732a905d23d7  crates/cerberus/src/init.rs
75a647143fae07b4d26d3ae572ac833471394832320892ccf1a7cbb7835a79f8  docs/security-guide.md
6b857ad4c904640d1ae2f5afe8ae344ca34cbf3ec32ad1e80569c283b1e1477e  tests/smoke-test.sh
89eecf3eb5c3ebbeb16aac4a4e02e46e4ecf6351cd16f0ee969ddd34259b7f2b  crates/cerberus-proxy/src/allowlist.rs   (new)
a1e013333b19035be8fd22f28754df4700d729ad27c92948cd471ed4ee9959f1  crates/cerberus-proxy/src/host_origin.rs (new)
```

## 9. Known limits / risks for the panel

1. **Dev-mode UX delta**: a tokenless control plane is CLOSED — every data API answers 401. The
   mitigations are init-generated tokens + `CERBERUS_ADMIN_TOKEN`. Operators who hand-write configs
   without a token will see the boot WARN and 401s until they set one (documented in config.rs docs,
   security-guide.md, and the evidence).
2. **Non-loopback binds are now double fail-closed**: strong token (pre-existing) AND an explicit
   `allowed_hosts` list (new). A public deployment that only set a token but no `allowed_hosts` will
   get 403 on all `/api/*` until it names its hostnames — fail-closed by design (A.1), documented.
3. **Allowlist key rotation invalidates fingerprints** (documented; values must be re-added). The
   installation key is shared with the audit-hash key (one key per installation, F5 model).
4. **No raw backup on migration** (deviation from fix-plan F6.3's "backup + destroy after sign-off"):
   keeping a raw backup would violate the R9-7 invariant; the conversion is atomic, idempotent, loud,
   and the raw value is destroyed in place. If the YAML persist fails at boot, the migration stays
   in-memory and a warn is printed (the raw file remains on disk in that failure case — the operator
   is told to fix persistence).
5. **Key-None contexts**: library contexts without `with_audit_hash_key` cannot evaluate allowlist
   fingerprints (filter inert, fail-closed) and cannot add (API 503). The product always keys; tests
   that exercise the allowlist wire the key explicitly.
6. **`scan_multipart_regions`/`filter_with_allowlist` hot-path cost**: one HMAC-SHA256 per finding
   (findings are few; set lookup O(1)); within the closed p99 budget (load 14/14 incl. the honest
   HTTP round-trip gate still passes).
7. The dashboard UI copy already said "Values are hashed before storage" (dashboard.html:843); the
   allowlist tab now lists fingerprints. No HTML change was needed (CSP hash recomputed dynamically).

## 10. Builder verdict

All acceptance criteria are implemented and verified by running code (unit + HTTP-level + live release
boots + smoke script with the adapted F4 vector). No threshold moved; no prior finding's semantics
changed beyond R9-5/R9-7/F5-F-1/2/3 as authorized. **Returns to VERIFY** for the §8B panel.