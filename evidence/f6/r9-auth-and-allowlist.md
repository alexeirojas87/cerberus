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
---

## FIX attempt 2

- **Trigger**: attempt 1 (`40283eb`) passed both panel lenses on the security core; the correctness
  lens registered one P1 (blocking, pre-gate) + P2s, the security lens P2-1/P3-1, and fix-plan F6.1
  mandates session-scoped dashboard credentials. This attempt closes those items ONLY —
  findings-preserving, no threshold moved, no security semantic touched.
- **Candidate**: branch `r9-f6-attempt2` (worktree off `40283eb`); not pushed.

### Item 1 — P1 (blocking): `persist_config` regressed config.yaml 0600 → 0644 after any control-plane write

- **Root cause**: `persist_config` (was api.rs:836–846) wrote `config.yaml.tmp` with plain
  `std::fs::write` (umask → 0644) and renamed it over the 0600 file — no mode enforcement, and the
  tmp itself carried the admin token at umask perms during the write→rename window. Empirically
  confirmed by the lens: one `PUT /api/config` → `100644`, and re-init could not repair it.
- **Fix**: new shared helper `write_config_file_0600` + `write_tmp_0600`
  (`crates/cerberus-proxy/src/api.rs:847,867`) with the F5 F-1 discipline: stale-tmp removal, then
  `OpenOptions::create_new(true).mode(0o600)` (mode applied AT CREATION on unix — no umask window),
  then atomic rename; every `Result` handled (tmp removed on any failure; the previous file is left
  untouched). `persist_config` (api.rs:895) now delegates to it, so EVERY mutation that persists
  (PUT /api/config, PUT /api/policy, POST /api/allowlist, upstream CRUD) leaves config.yaml at 0600,
  regardless of the prior mode.
- **Tests**: `persist_config_keeps_0600_on_an_existing_file` (api.rs:2279 — 0600 fixture → stays
  0600 + no tmp residue) and `persist_config_creates_the_file_at_0600` (api.rs:2318 — from-scratch
  creation at 0600); live-flow harness `config_put_persists_yaml_at_0600`
  (smoke_harness.rs:1395 — real daemon, PUT /api/config over a 0600 fixture → stat 0600); live
  release-binary check: init → PUT /api/config → `stat` = `100600` (was `100644` at attempt 1).

### Item 2 — P2: migration `atomic_write_config` wrote the tmp at umask default before chmod

- **Root cause**: `atomic_write_config` (daemon.rs:212–227 at attempt 1) wrote the tmp with
  `fs::write` (umask) and only then `set_permissions` — the final file was 0600, but the tmp briefly
  existed at umask perms (same class as the P1, shorter window).
- **Fix**: the function (daemon.rs:216) now delegates to the SAME shared helper — one writer, one
  discipline; the migration persist path creates its tmp at 0600 from birth.
- **Test**: `atomic_write_config_enforces_0600_on_result` (daemon.rs:1061 — 0644 fixture →
  rewritten 0600, no tmp residue); the pre-existing migration test
  (`allowlist_migration_converts_raw_entries_and_persists_fingerprints`) still passes unchanged.

### Item 3 — P2-1 (security lens): re-init over a non-0600 config kept 0644 and the report lied "mode 0600"

- **Root cause**: `write_config_0600` (init.rs:139–156 at attempt 1) opened the FINAL path with
  `.create(true).truncate(true).mode(0o600)` — the mode applies only at creation, so re-init over an
  existing 0644 file kept it 0644 while the report asserted "(mode 0600, R9-5)".
- **Fix**: (a) `write_config_0600` (init.rs:146) delegates to the shared tmp+rename helper — a
  re-init now REPLACES the file with a 0600-created tmp, repairing the mode; (b) the report is
  truthful: `actual_mode_note` (init.rs:154) stats the written file and prints its REAL octal mode
  (`mode 0600` on unix; a non-numeric note when the platform has no unix mode or the stat fails).
- **Test**: `reinit_over_non_0600_config_enforces_0600_and_tells_the_truth` (init.rs:462 — seed a
  0644 config, re-init → file 0600, old token rotated, report claims `mode 0600` and the file IS
  0600); live release-binary check: `chmod 644 config.yaml` → `cerberus init` → mode `100600`,
  report prints `mode 0600, R9-5` truthfully (attempt 1: mode stayed 0644 with the same claim).

### Item 4 — P2 (fix-plan F6.1): dashboard persisted the admin token in `localStorage`

- **Root cause**: fix-plan F6.1 mandates "credencial solo en memoria/session scope"; the dashboard
  stored the token in `localStorage` (survives browser restarts on the operator's disk).
  dashboard.html:1098,1121,1138,1152.
- **Fix**: switched all four sites to `sessionStorage` (same `TOKEN_KEY`, same login/logout flow);
  a comment marks the plan mandate. CSP script hash is derived from the served HTML at runtime, so
  it self-adapts (verified live: served CSP sha256 matches the edited `<script>`; zero
  `localStorage.` API calls remain in the served HTML).
- **Test**: full smoke harness 69/69 (dashboard HTML/CSP/token-absence tests green post-edit); live
  dashboard served with a matching CSP hash. (No harness test asserted the storage backend; the
  behavioral proof is the live CSP/served-script match + unchanged login flow.)

### Item 5 — P3-1 (security lens): malformed JSON on authenticated POST /api/upstreams dropped the connection

- **Root cause**: `handle_post_upstreams` mapped the serde error with `?` (`format!(...)` into the
  handler's `Err(String)`), so hyper logged "error from user's Service" and closed the connection
  (curl `HTTP=000`) instead of answering. Trivial and isolated (every other parse arm already
  returns 400), so fixed rather than documented.
- **Fix**: parse arm returns `400 {"status":"error","error":"invalid upstream payload: …"}` via the
  standard `invalid_config_response` (api.rs:1075–1077).
- **Tests**: harness `upstream_post_malformed_json_answers_400_not_connection_drop`
  (smoke_harness.rs:1457 — live HTTP: the response arrives (a drop fails the test), 400 + JSON
  error body); live release-binary check: malformed POST → `HTTP 400` + JSON error (was `HTTP 000`).

### What deliberately did NOT move

- No threshold, rule, route semantics, auth/allowlist/rebinding behavior, or attempt-1 finding
  judgment was altered. `tests/redos_fuzz.rs` and all attempt-1 security semantics are byte/behavior
  preserved. The only init behavioral delta is the mandated one: re-init now repairs the file mode
  (and the in-place write became an atomic tmp+rename — strictly safer; a symlinked config.yaml is
  now replaced rather than written through, the safer behavior for a credential file).
- Attempt-1 residuals accepted by the panel lenses remain registered: data-plane Host/Origin gate
  out of scope (P2 observation), P3-2 timing note (informational), re-init UX note (wholesale
  config replace).

## FIX attempt 2 — Builder matrix (all run in the isolated worktree)

| # | Gate | Command | Result |
|---|---|---|---|
| 1 | fmt | `rtk cargo fmt --all -- --check` | clean |
| 2 | clippy | `rtk cargo clippy --workspace --all-targets -- -D warnings` | 0 warnings |
| 3 | workspace debug | `rtk cargo test --workspace --all-targets` | **810 passed, 0 failed** (26 suites; 804 + 6 new) |
| 4 | production pack | `rtk cargo test -p cerberus-packs --test production_pack_pr` | **19/19** |
| 5 | redos (frozen rule) | `cargo test --release --test redos_fuzz -- --test-threads=1` | **11/11** (file untouched) |
| 6 | load (release, serial) | `cargo test --release --test load_test -- --test-threads=1` | **14/14** incl. `load_test_f3_3_honest_http_round_trip_gate` (7.52 s) |
| 7 | smoke harness | `cargo test -p cerberus-proxy --test smoke_harness` | **69/69** (67 + 2 new) |
| 8 | smoke script | `bash tests/smoke-test.sh --port 18955` (release binary) | **17/17 PASS, Fail: 0** |
| 9 | **live 0600 check** | release binary, isolated `$HOME`: init → start → GET+PUT `/api/config` → `stat config.yaml` | PUT 200 → **`100600`** (attempt 1: `100644`) |
| 10 | live re-init check | `chmod 644 config.yaml` → `cerberus init` | mode **`100600`**, report `mode 0600, R9-5` (truthful) |
| 11 | live P3-1 check | malformed-JSON POST /api/upstreams + token | **HTTP 400** + JSON error (was HTTP 000) |
| 12 | live dashboard check | GET /api/dashboard → sha256(CSP) vs served `<script>` | **match**; 0 `localStorage.` calls |
| 13 | whitespace | `rtk git diff --check` | clean (exit 0) |

New tests: `persist_config_keeps_0600_on_an_existing_file`, `persist_config_creates_the_file_at_0600`
(api.rs), `atomic_write_config_enforces_0600_on_result` (daemon.rs),
`reinit_over_non_0600_config_enforces_0600_and_tells_the_truth` (init.rs),
`config_put_persists_yaml_at_0600`, `upstream_post_malformed_json_answers_400_not_connection_drop`
(smoke_harness.rs).

## FIX attempt 2 — Frozen SHA-256 (files touched by this fix)

```
e61579a0a91c62b28422c1d32302e409fa5de25e64c8e29e4cc0b8999fea3a1c  crates/cerberus-proxy/dashboard.html
7c2a7879ee69ed04e8da66b70bf09b6c6293c3eefd8dd4cc4e61545fe50fa467  crates/cerberus-proxy/src/api.rs
f6d6cb708e292171c2b064dc8eb62bba55f59a411f5bff1b35fa401ef64fe44e  crates/cerberus-proxy/tests/smoke_harness.rs
63a48344801d83825580cdc8f4ad5d36a247dd99842fe561fc876f447aba5d12  crates/cerberus/src/daemon.rs
2c2c1757aaa0a69670312e81c940913b0e099d196fc803240ca2ba0e6cd9b2d9  crates/cerberus/src/init.rs
```

(All other attempt-1 frozen hashes are unchanged; this fix touched exactly the five files above.)

## FIX attempt 2 — Risks for re-verification

1. **tmp name unification**: the shared helper names the tmp `<path>.tmp` for every writer
   (attempt 1 used the same effective name for both config writers: `config.yaml.tmp`), so on-disk
   artifacts are unchanged; a stale tmp is now removed before the exclusive create (loudly, no
   silent reuse). Re-verification should confirm no `<path>.tmp` residue in operator trees.
2. **init write is now replace-atomic**: inode is replaced instead of truncated in place. Any
   external process holding an open fd to the old config.yaml keeps reading the old inode until
   reopen — operationally irrelevant for init (single-user, pre-start), but noted for completeness.
3. **Truthful mode claim**: on unix the report derives the mode from the file (will print e.g.
   `mode 0644` if some future regression reintroduces one — the claim can no longer lie); on
   non-unix platforms no numeric claim is made.
4. **sessionStorage UX delta**: the dashboard token now dies with the tab — operators must re-paste
   the token in each new tab/browser session (the intended fix-plan trade: credential never
   persisted to disk).
5. **P3-1 400 body shape**: `{"status":"error","error":"invalid upstream payload: …"}` mirrors the
   PUT /api/config parse-arm shape; any client keying on connection-drop behavior (none known)
   would now see a clean 400.

## FIX attempt 2 — Builder verdict

All five fix items are implemented and proven (unit tests, live HTTP harness tests, and live
release-binary checks including the mandated PUT → stat = 0600 check). The full builder matrix is
green with zero failures and no threshold or semantic moved. **Returns to VERIFY** for the §8B
panel; the P1 is closed pre-gate.
