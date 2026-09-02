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
