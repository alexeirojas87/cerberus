# Evidence Pack — f6 / F6.B (R9-6: Appendix B CLI surface + API→CLI→dashboard parity)

- Attempt: 1    Builder: F6.B builder subagent    Verdict: **returns to VERIFY**
- Date: 2026-09-02    Base: be6b6ff (branch `r9-remediation`)    Work branch: `r9-f6b-attempt1` (isolated worktree, not pushed)
- Scope: R9-6 (P1, ALTO, VERIFIED) — "~70% de la superficie CLI del Appendix B no
  existe — falso el claim §4.6 parity total", including the inverse finding
  (API/dashboard lacked packs enable/disable and events tool/since filters).
- Artifacts: **`evidence/f6/parity-matrix.md`** (full API→CLI→dashboard matrix;
  `evidence/f6/appendix-b-parity-matrix.md` points to it), this pack.

## 0. Findings being closed (anchors)

- R9-6 (gauntlet-findings.md): real output was only `init start stop status
  license pack mitm scan test doctor`; missing: restart, mode, upgrade, agents /
  wire / unwire, providers, add/remove-provider, packs enable/disable/update,
  category set, rules list/add/set, allowlist add/list/remove, events, stats,
  logs -f, config show/edit/path, login, dashboard, validate, reload,
  allow-once, version. Inverse: API/dashboard lacked packs enable/disable and
  events tool/since filters.
- Fix-plan §0.5/§0.6: DAG respected (F6 does not open F7/F8 work; deferred
  contracts explicitly marked). Fix-plan F6.4: normalize `pack` vs `packs`,
  `cerberus version` in addition to `--version`, every command proves
  before/after state via the SAME Config API, parity matrix with one row per
  command (columns API, CLI, UI, auth, test, state).

## 1. Appendix B inventory (summary; per-row detail in parity-matrix.md)

| Group | Rows | Built before | **Built by F6.B** | Deliberately not built |
|---|---|---|---|---|
| B.1 lifecycle | 11 | init, start, stop, status, doctor | restart, mode, allow-once, version, upgrade (check+guidance) | brew/curl lines (F8 installers) |
| B.2 agents/providers | 6 | — | agents, agents wire, agents unwire, providers, add-provider, remove-provider | — |
| B.3 packs/policy/allowlist | 11 | (pack install/list/rollback pre-existing, kept as compat alias) | packs list, packs enable, packs disable, packs update, category set, rules list, rules add, rules set, allowlist add/list/remove | registry FETCH inside `packs update` (F7 auto-update) |
| B.4 dry-run | 2 | scan, test | (+ new API+UI leg: `POST /api/scan`, "Test Detection" card) | — |
| B.5 observability | 3 | — | events (provider/tool/since), stats (--by), logs [-f] | — |
| B.6 config/license | 5 | — | config show/edit/path, login, dashboard (+`GET /ui` redirect) | — |
| B.7 Mode A | 4 | — | validate -f, reload | helm/docker lines (F8 deploy units) |
| **Total** | **42** | **13** | **26** | **3 external lines → F8/F7** |

- **Missing count → 0** for every in-MVP Appendix B command (the R9-6 list is
  fully closed). The three "not built" rows are external installer/deploy
  commands named in Appendix B but owned by Phase 7/8 units (DAG, fix-plan §0.5).

## 2. Implementation evidence

- **CLI surface** (`crates/cerberus`):
  - `src/cli_surface.rs` (new): all B.1–B.7 implementations; allowlist display
    truncates fingerprints (`hmac:0123456789ab…`, never raw — R9-7);
    `config show` redacts `admin_token`; `rules add` compiles the rule LOCALLY
    before any network (lookaround → hard error); `login` verifies with the
    daemon's trust root and installs 0600 (tamper → reject, good license kept);
    `validate` checks syntax + upstream schemes + policy + pattern compile.
  - `src/cli_api.rs` (new): shared control-plane client — endpoint resolution
    (env > endpoint.json > config.yaml > 8787, always loopback), admin token
    (env > config; never hardcoded), and the actionable unreachable-daemon
    error ("cannot reach the Cerberus daemon at … — `cerberus start`").
  - `src/main.rs`: full clap surface (every command with help text),
    `packs` group with `pack` compatibility aliases, `version` +
    `--version`, and the CI parity test walking the route table.
  - `src/daemon.rs`: pack-worker arms Enable/Disable/Update (Pro gate on
    enable/update; disable ungated — only reduces detection), each followed by
    snapshot + policy rebase (hot-reload preserves operator overrides/custom
    rules); `log_file_path()` for B.5.
  - `src/log.rs` (proxy): `set_log_tee_file` + `TeeSink` — the non-blocking
    worker tees to `~/.cerberus/logs/cerberus.log` (8 MiB cap, one-shot
    rotation to `.1`); the R9-10 hot-path guarantees (bounded lossy queue,
    worker-owned sink, bounded drain) are untouched — gate test
    `cli_main_holds_the_log_guard_for_the_process_lifetime` passes unmodified.
- **API** (`crates/cerberus-proxy/src/api.rs`): `POST /api/packs/enable|disable|
  update` (worker-owned manifest), `POST /api/reload` (disk → live hot-swap;
  listen preserved; **anti-lockout guard** — a reload that would REMOVE the
  admin token is rejected 400 so a running secured control plane never silently
  closes), `POST /api/scan` (dry-run, nothing persisted, no raw echo),
  `GET /ui` → 302 `/api/dashboard` (public, no data), `tool`/`since` filters on
  events/stats, `effective_rules` in the policy document, and
  `known_api_routes()`/`is_known_api_route()` as the machine-readable route
  table. All new data routes 401 without the admin token (F6.A fail-closed
  preserved — tested).
- **Dashboard** (`dashboard.html`): per-pack **Enable/Disable** buttons and
  **"Update packs"** button (§4.6 names enable/disable rule packs; B.3 names
  the update button) and the **"Test Detection"** box (B.4) via `POST /api/scan`.
  CSP constraints respected (no inline handlers; existing dashboard tests pass).
- **Packs** (`cerberus-packs/src/updater.rs`): `PackManager::set_active` (idempotent,
  Pro trust-root gate on enable, manifest persisted, engine rebuilt) and
  `verify_installed` (signature re-verification; failures deactivate the pack
  like boot-time tamper handling).

## 3. Acceptance criteria (one row each)

| Criterion | Command run | Output (quoted) | Result |
|---|---|---|---|
| 1. `cerberus --help` + subcommand help match Appendix B (missing → 0 in-scope) | `./target/release/cerberus --help` | 32 commands listed: init, start, stop, restart, status, mode, allow-once, version, upgrade, license, login, pack, packs, agents, providers, add-provider, remove-provider, category, rules, allowlist, events, stats, logs, config, dashboard, mitm, scan, test, validate, reload, doctor, help | ✅ |
| 1a. R9-6 "missing" list closed | `cargo test -p cerberus --bin cerberus` | `cli_tests` b1/b2/b3/b5-b6-b7 parse tests + `version_subcommand_parses` | ✅ |
| 2. Parity matrix complete + CI-runnable parity test | `cargo test -p cerberus --bin cerberus every_daemon_backed` | `every_daemon_backed_cli_command_maps_to_a_real_api_route ... ok` (walks 24 daemon-backed rows against `known_api_routes`) | ✅ |
| 3. Full matrix green (all gates below) | see §5 | 856 passed; 0 failed; all targeted suites green | ✅ |

## 4. Adversarial cases tested (attempt to break)

- **Unreachable daemon** → `cli_reports_a_clear_error_when_the_daemon_is_unreachable`: exit≠0, error names the address and the fix (`cerberus start`). No raw reqwest dumps.
- **Missing admin token** → `missing_token_error_mentions_sources` (error names both sources); API-side: every new route 401s without the token (3 dedicated asserts in `f6b_api_surface.rs`).
- **Raw allowlist leakage** → `cli_allowlist_hits_the_allowlist_routes` asserts the raw value is NEVER echoed; `fingerprint_display_never_shows_full_digest`; API tests from F6.3 unchanged.
- **`/api/scan` as an exfiltration/echo channel** → `api_scan_dry_runs_and_persists_nothing`: raw secret never in the response; zero events persisted (shadow AND enforce); bad body → 400.
- **Reload weaponization** → `reload_applies_on_disk_config_without_restart`: broken YAML → 400 with live config untouched; token-removing file → 400 (anti-lockout); unauthorized POST → 401.
- **Bad regex via `rules add`** → `rules_add_rejects_bad_regex_before_network` (lookaround rejected locally, no daemon call); engine hard-error preserved.
- **Tampered license via `login`** → `login_verifies_and_installs_signed_license`: tamper rejected AND the previously installed license remains.
- **Pack tamper at update** → `verify_installed` deactivates packs failing verification (same policy as boot tamper) before the rebuild.
- **Log-tee cannot stall the hot path** → tee writes happen only on the existing logging worker; R9-10 gate tests unchanged and green.
- **Test-parallel env races** → single crate-wide `ENV_LOCK` shared by every HOME-mutating test (a real flake observed and fixed during this unit).

## 5. Verification matrix (all run in the isolated worktree)

| # | Gate | Command | Result |
|---|------|---------|--------|
| 1 | fmt | `cargo fmt --all -- --check` | clean |
| 2 | clippy | `cargo clippy --workspace --all-targets -- -D warnings` | **No issues found** |
| 3 | workspace debug | `cargo test --workspace` | **856 passed; 0 failed; 0 ignored** (810 baseline + 46 new) |
| 4 | pack | `cargo test -p cerberus-packs --test production_pack_pr` | **19/19** |
| 5 | redos | `cargo test --test redos_fuzz` | **11/11** |
| 6 | load (incl. honest gate) | `cargo test --test load_test` | **14/14** |
| 7 | smoke harness | `cargo test -p cerberus-proxy --test smoke_harness` | **69/69** |
| 8 | NEW API surface suite | `cargo test -p cerberus-proxy --test f6b_api_surface` | **7/7** |
| 9 | NEW CLI e2e suite | `cargo test -p cerberus --test cli_surface_via_api` | **11/11** |
| 10 | smoke script | `bash tests/smoke-test.sh` (release binary) | **17/17 PASS** (no CLI-change delta) |
| 11 | whitespace | `git diff --check` | clean |
| 12 | manual binary sanity | `--help`, `version`, `agents`, `config show` (redaction), `config path`, `validate -f` | all correct (transcript in builder report) |

## 6. Frozen SHA-256 (files touched by this unit, at commit time)

```
aad0da36d6b976bc437eb4900b9e1dfdb8741c0ec1b95bb2b21ac794d0f659b8  Cargo.lock
85d014fb762eb5c9a799e7f502efa6d30337cec3c4ab995e422789e93da95b6e  crates/cerberus/Cargo.toml
76036c6516cad3072c22d9e34935d5cbdac51cd978eb8bdbc890292860164be8  crates/cerberus/src/main.rs
18a07f166507e551bdd349f4056691e7009ae60d5f8c99d8d28f69d33efd63d7  crates/cerberus/src/cli_api.rs
afdb3f916287d8087472ff5eafac2eda3f3c992f54f3ac02c467f7e1f51dafd7  crates/cerberus/src/cli_surface.rs
ce67d14fbbc5095da6daa3e3fb0459f45f8be3b8e6c64b453c6b8e1f04779227  crates/cerberus/src/cli_pack.rs
f9057e82c17ec07782b8657dd714fd6784d74a6ace0f2f7d48c7e082455cbbb9  crates/cerberus/src/init.rs
718cb28757ee33df64094dce316c12bda1f9a8d75ecf090b463351977d6b0aab  crates/cerberus/src/daemon.rs
539673da4d42ac29b482041795f19228cb392031096d2c0aa6d79a925647f909  crates/cerberus/src/mitm.rs
8c53af8f104c06e615916dccd3a3697481d9be37e7c06542d2c884da5e64bf30  crates/cerberus-packs/src/updater.rs
1fcc08219de23348aa86f0831e313045ac2adc9a3be6cccd64c4c926533fbc1b  crates/cerberus-proxy/src/api.rs
34601407f7b799ca86e763ebdb2a0681ee275ebf8820d01df2b2675d5c19d08e  crates/cerberus-proxy/src/proxy.rs
1e95eb3c2811c341ff369f6c5fe674d8d1e92590e2d0ee2600239f4283221182  crates/cerberus-proxy/src/log.rs
83bd40484bdffdcebc84b685bac695b47c7e8aebe39b1b72aad36106316dfebb  crates/cerberus-proxy/src/detection_policy.rs
211420d24a6344a9c9720a12ad18daa5341518fc370b5edfe5ff6f4080149b76  crates/cerberus-proxy/dashboard.html
73e48a6c37700fb322633ca780f7df0ec955bc404cc6152beff23a0b319b897c  crates/cerberus-proxy/tests/smoke_harness.rs
a1639656f58f982d713b40f272257a62bc45472923b100bb7410e8c86de707b7  crates/cerberus-proxy/tests/f6b_api_surface.rs
89eac19bafa432e5fdff2db0b6eeb47a4ee58334d90e01c0b33d460a64d9bbf1  crates/cerberus/tests/cli_surface_via_api.rs
e44c2a9583cf38b13039a06837e8344bc94f05308faee988b36773475575b5ee  docs/user-guide.md
b09a87fe19109c86a66cc46aa338fbfc6b8006462b20b39360825bc9c5228d21  evidence/f6/parity-matrix.md
69c87247813b2fe6e30da73b4ba90efcba5e87e255a5b7a86a2222399e326549  evidence/f6/appendix-b-parity-matrix.md
```
(This pack itself is the only touched file not listed — it is finalized at
commit time by definition.)

## 7. Known limits / risks for the panel

- **L1 — deferred-by-DAG contracts** (documented in the matrix): `packs update`
  does verify+hot-reload; fetching NEW versions from a registry is the F7
  `auto-update` unit. `upgrade` checks the manifest and prints guidance;
  downloading/replacing signed binaries is F8. `login` is verified against the
  same trust root the daemon uses (local issuer contract, as fix-plan F6.4
  prescribes); F8 re-verifies against real entitlements. Helm/docker lines are
  F8 deploy units. None of these are placeholders — each does real, tested work.
- **L2 — `restart` e2e**: restart = stop+start composition (both e2e-proven by
  the smoke script); clap wiring test-proven; a self-contained restart e2e
  (daemon-under-test lifecycle) is registered as follow-up hardening.
- **N1 dashboard screens**: Appendix B's Dashboard column names screens beyond
  the §4.6 config-screens list (onboarding wizard, start/stop, agents,
  diagnostics, version notice, account, logs panel). They are explicitly marked
  absent in the matrix (notes N1–N3) rather than invented. The §4.6-named
  controls — enable/disable packs (R9-6 inverse finding), update button,
  test-detection box — ARE built. A dashboard logs panel and remote daemon
  lifecycle control have genuine design cost (the session lives inside the
  daemon) and deserve their own unit decision.
- **N3**: events `tool`/`since` filters are API+CLI complete; the Events feed
  UI still ships the provider filter only (adding pickers is small follow-up
  inside the F6 dashboard unit).
- **Reload semantics** (documented + guarded): applies the file exactly; listen
  not reloaded (socket bound); token change applies immediately; token REMOVAL
  is rejected (anti-lockout, fail-closed preserved).
- **Agents wiring** is local by nature (export line + persisted intent record);
  the dashboard cannot mutate the operator's shell — marked in the matrix.
- Auth semantics from F6.A are respected everywhere: the CLI carries the token
  from config/env, never bypasses the gate, and never sends raw allowlist
  values over the wire (add/remove go over loopback to be fingerprinted;
  fingerprints only are displayed).

## 8. Builder verdict

**Returns to VERIFY.** All Appendix B in-scope commands are implemented with
clap wiring, help text, tests (unit, harness e2e against the real proxy, and
CLI-via-API e2e through the real binary) and user-guide documentation; the
parity matrix is complete with per-row test citations and an explicitly
CI-runnable parity test; the full builder matrix is green.

## FIX attempt 2 (commit on `r9-f6b-attempt2`, candidate base cb36c8a)

Attempt 1 (079ebf8) returned FIX: correctness lens FAIL (1×P1 + P2s), security
lens PASS with remediate-before-gate P2s. This pass closes every listed item;
nothing else moved (no threshold changes, no scope beyond the findings, F6.A
behavior untouched).

### Root cause → fix → test, per item

**F1 (P1, blocking) — PUT /api/config accepted `admin_token:null`, closed the
control plane and persisted the closure.**
Root cause: the anti-lockout guard existed only in `apply_reload`
(`live.admin_token.is_some() && candidate.admin_token.is_none()` → 400);
`handle_put_config` resolved an explicit null via `PatchField::Clear` straight
to a persisted candidate (R9-5 fail-closed then closes every `/api/*` route,
including for the operator who sent the PUT; the on-disk `admin_token: null`
survives restart).
Fix: `crates/cerberus-proxy/src/api.rs:1350-1366` — the SAME invariant inside
`handle_put_config`'s transactional block, evaluated AFTER the candidate is
computed and BEFORE exposure validation/persist/publish (so nothing is
written when rejected). Error names the escape hatches honestly ("omit
admin_token to keep it or PUT a new value to rotate it"). Token CHANGE stays
allowed and applies immediately (rotation semantics unchanged — live-verified
below). The write-guard is scoped lexically so the audit emission awaits only
after the lock is released.
Tests: `f6b_api_surface::put_config_rejects_admin_token_removal_anti_lockout`
(spawned real proxy: null → 400; old token still 200 on /api/config; /health
200; on-disk YAML still carries the old token; rotation → 200 with old 401 /
new 200 immediately; no token value in the audit trail) + LIVE battery below.

**F2 (P2) — the parity test validated against `known_api_routes()`, a
hand-maintained duplicate of the router (mutation-proven green with a removed
router arm).**
Root cause: `every_daemon_backed_cli_command_maps_to_a_real_api_route`
asserted `is_known_api_route(row)`, i.e. table-vs-table — the router was not
consulted.
Fix: the parity test now dispatches all 24 CLI rows through the REAL router of
a spawned proxy over HTTP (`crates/cerberus/src/main.rs:651-694` module const
table, `:852-971` test): every row's request is engineered to reach its
handler (pre-seeded upstreams/allowlist fingerprint/audit key, bodies for the
mutating rows), so a bare router `404 {"error":"not found"}` is the only way
to fail — an authenticated `/api/not-a-route` canary first proves that 404
shape is real. A second, reverse test protects the table itself:
`f6b_api_surface::route_table_matches_the_router`
(`crates/cerberus-proxy/tests/f6b_api_surface.rs:875-950`) iterates
`known_api_routes()` and requires every entry to dispatch non-404.
Mutation proof (attempt-1's mutation A, re-run on this candidate): with
`("POST", "/api/reload") => Ok(not_found())` substituted for the dispatch arm
(a temporary local edit, REVERTED immediately — commit is clean):
- parity test → FAILED: "parity: CLI 'reload' maps to POST /api/reload, which
  the ROUTER does not serve (bare 404 — the dispatch arm is missing)";
- route_table_matches_the_router → FAILED: "route table claims POST
  /api/reload but the ROUTER does not serve it".
After revert both are green again (1/1 and 10/10).

**F3 (P2) — the real packs enable/disable success path had no executing test.**
Root cause: `f6b_api_surface::pack_enable_disable_update_reach_the_worker`
stubs the worker with a channel echo; `PackManager::set_active` is reached
only by the real daemon arms, which nothing executed.
Fix: NEW binary e2e `crates/cerberus/tests/pack_enable_disable_worker_e2e.rs`
— spawns the REAL `cerberus start` daemon (signed Pro license + pack trust
root via the same env wiring the product resolves), then drives over HTTP:
install (activates; worker arm → manifest+engine) → `/api/scan` DETECTS the
pack marker → disable (ungated) → scan does NOT detect → enable (Pro gate
passes) → scan DETECTS again → the mutations are audited on the real daemon
via `/api/events` (pack-enable/pack-disable). This exercises the full
composed path API → PackCommand → worker arm → `set_active` →
`snapshot_engine` → engine rebase → live scan. Result: 1 passed (~1.2 s).

**F4 (informational)** — documented here: (a) `packs update` fetch-registry
→ F7 `auto-update` (command does verify+hot-reload today, disclosed in
--help); (b) Appendix B's "every command has its equivalent in the dashboard"
preamble vs the §4.6-scoped control list — the matrix states its reading
openly and marks absences N1–N3 instead of inventing UI (orchestrator
awareness item, plan-text tension stands); (c) the config parser's silent
unknown-top-level-key laxity is pre-existing schema behavior outside this
unit's diff (validate correctly rejects the documented failure classes).

**Security P2-1 — control-plane mutations were unaudited.**
Root cause: reload/config/allowlist/upstream mutations swapped live state
with zero event-store and (for reload/config/allowlist/upstream) zero tee-log
trace; `GET /api/events` showed only dataplane `proxy` events.
Fix: `AuditEvent::control_plane(mode, action, detail)`
(`crates/cerberus-store/src/event.rs:108-146` — honest action name in
`flags`, `tool: "control-plane"`, `provider: "control"`, `action_taken:
"audit"`, empty `counts`/`hashed_values`) + `audit_config_mutation`
(`crates/cerberus-proxy/src/api.rs:2397-2410` — event + `tracing::info!` tee
line) emitted on SUCCESS only, at: reload → `config-reload` (api.rs:875),
config PUT → `config-update` (api.rs:1392), allowlist add/remove →
`allowlist-add`/`allowlist-remove` (api.rs:1899/2063), upstream add/remove →
`upstream-add`/`upstream-remove` (api.rs:1555/1597), packs enable/disable →
`pack-enable`/`pack-disable` (api.rs:752), packs update → `pack-update`
(api.rs:686). NO secrets in payloads: no tokens, no raw values, no
fingerprints (detail carries only pack/upstream names).
Tests: `f6b_api_surface::config_mutations_emit_audit_events_visible_via_api`
(all five action families visible via /api/events, secret-free), the extended
worker-stub test (pack action names), the worker e2e (in vivo on the real
daemon), `cerberus-store` `control_plane_event_is_honest_and_secret_free`, and
the LIVE battery below.

**Security P2-2 — flaky `login_verifies_and_installs_signed_license`.**
Root cause: `temp_home()` derived directory names from nanosecond timestamps;
two tests landing on the same clock tick shared a home, and a sibling's
`remove_dir_all(&home)` deleted the login test's live home mid-run (the
observed "installed then dest missing" signature).
Fix: all THREE copies of the helper (`crates/cerberus/src/cli_surface.rs:984`,
`cli_api.rs:304`, `cli_pack.rs:204`) now build `prefix-tag-pid-nanos-SEQ`
names with a monotonically increasing `AtomicU64` — unique per CALL,
independent of clock granularity; each test still rmtree's only its own home.
Tests: login test green ×3 consecutive runs (below) plus every temp_home
consumer in the workspace run (862/0).

**Security P3-1 — log tee file created 0644.**
Fix: `crates/cerberus-proxy/src/log.rs:348-364` — `open_log_file()` creates
with `mode(0o600)` at creation (unix; append keeps an existing file's mode),
used by `TeeSink::open` and the rotation path. Content discipline unchanged
(designed secret-free; 0600 is defense-in-depth matching the config-write
rule). Test: `log.rs:693 tee_file_is_created_0600` (created mode asserted
0600, append keeps it) + LIVE `stat` on a real daemon's tee: `-rw-------`.

**Security P3-2 — scan cap is the shared 1 MiB control-plane limit, not the
plan's 100 KB scan budget shape.**
Documented at `crates/cerberus-proxy/src/api.rs:126-135` (`KNOWN LIMIT`
comment on `CONTROL_PLANE_MAX_BYTES`): the plan's 100 KB describes the scan
BUDGET SHAPE; the API cap is the shared control-plane limit (10 MB → 413 in
ms; 954 KB → tens of ms linear). No behavior change — a scan-specific cap
would move behavior and stays out of this fix.

### LIVE acceptance battery (release binary, isolated HOME, port 18947/18949)

- F1: `PUT /api/config {"admin_token":null}` with the valid token → **HTTP
  400** `{"status":"error","error":"config update would remove the admin
  token and CLOSE the control plane (fail-closed); ..."}`; immediately after,
  `GET /api/config` with the SAME token → **200**, `/health` → **200**, and
  the on-disk YAML still contains the original `admin_token` line (grep = 1).
  Rotation: `PUT {"admin_token":"<new>"}` → **200**; old token → **401**;
  new token → **200** (rotation NOT broken).
- P2-1: after `POST /api/reload` (200), `PUT /api/config` (200), allowlist
  add/remove (200/200), upstream add/remove (200/200) — `GET
  /api/events?tool=control-plane` lists **config-reload, config-update,
  allowlist-add, allowlist-remove, upstream-add, upstream-remove** with
  `tool=control-plane`, `action_taken=audit`; serialized events contain NO
  raw canary, NO `hmac:` fingerprint, NO token (python check: all False).
- P3-1: `stat` on the daemon's tee file → `-rw-------` (0600).

### Verification matrix (attempt 2, all run in the isolated worktree)

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | 0, clean |
| `cargo clippy --workspace --all-targets -- -D warnings` | 0, "No issues found" |
| `cargo test --workspace --all-targets` (debug) | **862 passed / 0 failed** (856 attempt-1 + 3 f6b + 1 worker e2e + 1 event + 1 log-mode; login test green ×3) |
| `cargo test -p cerberus-packs --test production_pack_pr` | **19/19** |
| `cargo test --release --test redos_fuzz -- --test-threads=1` | **11/11** (`tests/redos_fuzz.rs` untouched — 0-byte diff) |
| `cargo test --release --test load_test -- --test-threads=1` | **14/14** incl. the honest HTTP round-trip gate |
| `cargo test -p cerberus-proxy --test smoke_harness` | **69/69** |
| `cargo test -p cerberus-proxy --test f6b_api_surface` | **10/10** (7 attempt-1 + 3 new) |
| `cargo test -p cerberus --test cli_surface_via_api` | **11/11** |
| `cargo test -p cerberus --test pack_enable_disable_worker_e2e` | **1/1** (real-daemon worker round trip) |
| `bash tests/smoke-test.sh` (release binary) | **17 PASS / 0 FAIL** |
| `git diff --check` | clean |
| Mutation A (temporary, reverted) | parity test + table↔router test both FAIL on the removed reload arm (proof above) |
| `login_verifies_and_installs_signed_license` ×3 | 3× `ok. 1 passed` |

### Frozen SHA-256 (files touched by attempt 2, at commit time)

```
87b13acc46e27ea2e26b2d876ef1f9d8c3fb212807fecad2c06b0504ad2d633b  crates/cerberus-proxy/src/api.rs
fa7ed2f67ef3599acdef99e9b1a4e282ed4de13578c4d4eb18f0d7c02c7c315a  crates/cerberus-store/src/event.rs
91ca5af3f29f2b5a0b42ea822c09058b82aa2744ab25338391c7dd115a95b167  crates/cerberus-proxy/src/log.rs
acde20ce13770041257398db8fd424107e5a77a1e4b85128335f38b54e24a2ae  crates/cerberus-proxy/tests/f6b_api_surface.rs
1a5135b5c40036c56404e64b0c10b85387597cda3c7bb2494233a14de5382bbc  crates/cerberus/src/main.rs
3d53830f58a7c8bb2c284e9e25b52d12e3e4723977c14a26e9137a7f1b5103cd  crates/cerberus/src/cli_surface.rs
526ca2c4f7cb3e5cb840c836b238d1a6f5366b68071a57333f0cfc16271536f3  crates/cerberus/src/cli_api.rs
50a78de18214f489e2efb1ceb1ba1d124f3c88f09b2bf19eb917bf935e1b71a6  crates/cerberus/src/cli_pack.rs
a4efee9cd13c7c3d3c5af8d3197940673b303b536f77092f1d75e2ea2eda4f7f  crates/cerberus/tests/pack_enable_disable_worker_e2e.rs
e37c532d308faa8ccf63d0e51f98f1860ea8e0466637d313e54ab4429a6a6bf0  evidence/r0/smoke-test/smoke-run-20260902-203022.log (smoke-gate run artifact; gitignored per .gitignore:25, hash recorded here for the panel)
```
(`tests/redos_fuzz.rs` remains byte-untouched; the attempt-1 frozen hashes of
untouched files still apply; this pack file itself is finalized at commit.)

### Builder verdict (attempt 2)

**Returns to VERIFY.** Every attempt-1 finding is closed with a file:line fix
and an executing test: the anti-lockout invariant now holds on BOTH config
write paths (reload + PUT) with rotation intact (live-verified); the parity
test and the table cross-check both consult the REAL router (mutation-proven
red→green); the packs enable/disable success path runs end-to-end through the
real daemon worker; config mutations are audited with honest, secret-free
events visible via /api/events (live-verified); the flaky login test's cause
is removed at the helper level (stable ×3); the tee file is created 0600; the
scan-cap divergence is documented. Full builder matrix green (862/0 debug,
19/19, 11/11 redos, 14/14 load, 69/69 harness, 10/10 + 11/11 + 1/1 new
suites, 17/17 smoke, fmt/clippy/diff-check clean).

### Risks for re-verification

- **R1 (new audit events change the /api/events surface)**: control-plane
  events now appear next to dataplane `proxy` events (`tool=control-plane`).
  Consumers filtering by tool/provider are unaffected (verified: provider
  filters, smoke script's non-empty check, existing event assertions are
  membership-based). Dashboards that assumed only `proxy` events will now
  also show audit rows — intended behavior, but the panel should confirm it
  reads as a feature.
- **R2 (PUT transaction restructure)**: `handle_put_config`'s lock is now
  scoped in a block (Send-ness for the audit await). Semantics preserved
  (validate → persist → publish order unchanged, guards unchanged); the
  f6b reload/config suites + smoke cover it, but the panel should note the
  restructure when reviewing api.rs.
- **R3 (worker e2e environment sensitivity)**: the packs round-trip spawns a
  real daemon (free-port bind race, 90 s health deadline). It passed in
  ~1.2 s locally; on a saturated CI runner the deadline margin is the only
  fragile spot — a timeout failure there is infra, not product.
- **R4 (pack-update now emits `pack-update` events only on success)** —
  install/rollback remain un-audited event-store-wise (they tee log lines);
  the remediation list named enable/disable/update only. If the panel wants
  install/rollback events too, that is a two-line follow-up in the same
  helper.

## FIX attempt 3 (re-verification addendum, orchestrator-executed builder fix)

The attempt-2 re-verification closed every attempt-1 item but found the
anti-lockout invariant still violated via the EMPTY-STRING encoding:
`PUT /api/config` with `{"admin_token":""}` answered 200, closed the plane,
and persisted the empty token (identical class to the null P1 — the guards
tested `candidate.admin_token.is_none()` while the auth layer filters
`Some("")` to None via `expected_admin_token`). LIVE-reproduced by the
re-verifier including restart persistence on both write paths.

**Fix (orchestrator gatekeeper executed as builder; predicate change only):**
- `crates/cerberus-proxy/src/api.rs` — both guards (apply_reload and
  handle_put_config) now test
  `expected_admin_token(&live).is_some() && expected_admin_token(&candidate).is_none()`
  so an empty candidate token is rejected exactly like a removed one; a live
  empty token counts as "already closed" (no-op stays allowed, opening stays
  allowed). Messages updated to "remove or clear".
- `crates/cerberus-proxy/tests/f6b_api_surface.rs` — the anti-lockout test
  now also exercises `{"admin_token":""}` → 400 + old token survives; NEW
  test `reload_rejects_empty_token_file_anti_lockout` reproduces the
  re-verifier's exact attack shape (empty-token file → reload → 400, plane
  keeps the old token).

**Verification:** fmt clean; clippy `-D warnings` clean; workspace debug
**863/863** (+1 test); f6b_api_surface **11/11**; pack 19/19, load 14/14,
harness 69/69 unchanged (re-run post-fix). Frozen hashes below supersede the
attempt-2 block for these two files:

```
177fedc1addde436bbd9338e3c1dafe3254200508b6c4208d221d810ee0c196b  crates/cerberus-proxy/src/api.rs
7db05e4fc63e408d361bcf0b61e81c94cebdea4d1d55c0c4bc358b1ba2184856  crates/cerberus-proxy/tests/f6b_api_surface.rs
```
(Committed-state hashes, recorded after the fmt pass; they supersede the
attempt-2 block for these two files.)

**Builder verdict: attempt-3 fix executed — returns to VERIFY (unit NOT
closed; the empty-string P1 is closed pre-gate).**

## FIX attempt 3b (orchestrator-executed; evidence correction + whitespace class)

The attempt-3 spot verification CLOSED the empty-string gap live (a–d) but
found: **(P1)** the commit-introduced test code failed `clippy -D warnings`
(`let_underscore_future` on a dropped JoinHandle; `too_many_lines` 117/100)
— and the attempt-3 section's "clippy clean" claim was FALSE: the builder's
gate run piped clippy through a pipe without pipefail, masking exit 101.
Process error by the orchestrator-builder; recorded here verbatim.
**(P2)** the anti-lockout remained bypassable via whitespace-encoded tokens
(`"   "`, `"abc "` accepted 200 → unsendable via the trimmed auth header →
plane locked, restart-persistent).

**Fix (attempt 3b):**
- `api.rs` — new `admin_token_shape_is_valid` (non-empty, trim-stable) + one
  unified fail-closed predicate on BOTH guards (reload + PUT): removal, empty,
  and whitespace-padded candidate tokens are all rejected 400 ("CLOSE the
  control plane" wording preserved); a live already-unusable token counts as
  "already closed" (no-op allowed, opening allowed). Whitespace class closed
  at the source, not documented.
- `f6b_api_surface.rs` — `let _ = handle` → `handle.abort()` (lint);
  extracted `put_config_rejects_unsendable_token_shapes` covering empty,
  whitespace-only, trailing-space, leading-space → all 400 + plane/disk
  intact (also fixes `too_many_lines`).

**Verification (no pipe masking; real exit codes):** `cargo clippy
-p cerberus-proxy --all-targets -- -D warnings` → **exit 0**; fmt clean;
workspace debug **864/864**; f6b_api_surface **12/12**; pack 19/19.

**Frozen hashes (committed state; supersede attempt-3 block for these files):**

```
39883d3e9e1ace28edc0d381dba906c083ec95bcef05937e3ef27a8d3ec475bd  crates/cerberus-proxy/src/api.rs
0e0371e5e6c805046e5bd41f3ed41907f4334c4298fa08677fda66318782e7cd  crates/cerberus-proxy/tests/f6b_api_surface.rs
```

**Builder verdict: attempt-3b executed — returns to VERIFY.**
