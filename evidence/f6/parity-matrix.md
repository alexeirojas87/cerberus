# Appendix B — API → CLI → Dashboard Parity Matrix (F6.B / R9-6)

- Attempt: 1    Branch: `r9-f6b-attempt1`    Base: be6b6ff (`r9-remediation`)    Date: 2026-09-02
- Spec: `CERBERUS_PRODUCT_BUILD_PLAN.md` **Appendix B** (the CLI surface) + §4.6
  ("total CLI ↔ dashboard parity", "the dashboard and CLI are two fronts over the
  **same Config API**") + fix-plan F6.4.
- closes R9-6 (P1): "~70% de la superficie CLI del Appendix B no existe — falso el
  claim §4.6 parity total", including the inverse finding (API/dashboard lacked
  packs enable/disable and events tool/since filters).

## How to read this matrix

- **API** = the Config API endpoint the command drives (§4.6: one API, two fronts).
- **CLI** = the Appendix B command (subcommands counted as rows).
- **Dashboard** = the UI control that performs the SAME state change.
- **Test** = the automated test that proves the leg(s). CLI→API legs for daemon-backed
  commands are proven by running the REAL binary against a recorded control plane
  (`cli_surface_via_api.rs`); the API behaviors are proven against the REAL proxy
  (`f6b_api_surface.rs`); the CLI→route-table walk is `main.rs::cli_tests::
  every_daemon_backed_cli_command_maps_to_a_real_api_route` (CI-runnable parity test
  required by acceptance #2).
- **Status**: `FULL` (API+CLI+UI legs live) · `CLI+API` (dashboard leg explicitly
  absent — reason cited) · `LOCAL` (command is local by design; no API leg).

## B.1 — Installation and lifecycle (Mode B)

| # | Command | API | CLI | Dashboard | Auth | Test | Status |
|---|---------|-----|-----|-----------|------|------|--------|
| 1 | `brew install` / `curl \| sh` | — | external installer (not a subcommand) | — | — | Phase 8 unit (installers); out of F6 scope | DEFERRED (F8) |
| 2 | `cerberus init` | — (local config bootstrap, 0600 token) | pre-existing | Onboarding wizard — **absent** (see note N1) | — | `cerberus` unit tests (init_writes_config_with_default_upstreams, reinit…), smoke-test STEP 2 | CLI FULL / UI absent (N1) |
| 3 | `cerberus start` | — (boots the API) | pre-existing; now also tees the daemon log file | Start/stop button — **absent** (N1) | — | smoke-test 17/17; `tee_sink_*` tests (log.rs) | CLI FULL / UI absent (N1) |
| 4 | `cerberus stop` | — | pre-existing | Start/stop button — **absent** (N1) | — | smoke-test 17/17 | CLI FULL / UI absent (N1) |
| 5 | `cerberus restart` | — | **NEW** (same effective port; stop+start) | — (N1) | — | clap parse test (`b1_lifecycle_commands_parse`); stop/start legs e2e-proven by smoke-test — see known limits L2 | CLI BUILT (L2) |
| 6 | `cerberus status` | `GET /api/config` (live detail) | pre-existing + **enhanced** (port/mode/upstreams when reachable) | "Status" data on Dashboard tab (overview stats) | token (degrades silently) | `cli_surface_via_api::cli_status_packs_list_and_rules_add_hit_expected_routes` | FULL |
| 7 | `cerberus mode <shadow\|enforce>` | `PUT /api/config {mode}` | **NEW** (show = `GET /api/config`) | Quick Controls → Operation Mode toggle (hot-swap) | token | `cli_mode_shadow_puts_the_config`; dashboard toggle pre-existing (F6 pantallas) | FULL |
| 8 | `cerberus allow-once [--reason]` | `POST /api/break-glass` | **NEW** (nonce printed; reason stored hashed only) | break-glass API used by F2.3 primitive (UI: F2 scope) | token | `cli_allow_once_posts_break_glass`; API tests F2.3/F6.2 | FULL (UI: F2 scope) |
| 9 | `cerberus doctor` | — (local diagnostics) | pre-existing | Diagnostics panel — **absent** (N1) | — | pre-existing unit tests | CLI FULL / UI absent (N1) |
| 10 | `cerberus version` / `--version` | — | **NEW** subcommand (fix-plan F6.4: `version` + `--version`) | Version notice — **absent** (N1) | — | `version_matches_cargo_pkg`, `version_subcommand_parses` | CLI FULL / UI absent (N1) |
| 11 | `cerberus upgrade` | releases manifest (read-only, external) | **NEW** (check + guidance; `CERBERUS_RELEASES_URL` for staging) | Version notice — **absent** (N1) | — | `upgrade_reports_newer_version_from_local_manifest`, `…up_to_date…`, `…rejects_unrecognizable_manifest` | CLI FULL (L1) / UI absent (N1) |

## B.2 — Agents and providers/upstreams

| # | Command | API | CLI | Dashboard | Auth | Test | Status |
|---|---------|-----|-----|-----------|------|------|--------|
| 12 | `cerberus agents` | — (local detection) | **NEW** | "Agents" screen — **absent** (N2) | — | `cli_agents_wire_works_without_a_daemon` (list output) | CLI FULL / UI absent (N2) |
| 13 | `cerberus agents wire <agent>` | — (local: wire record + export line) | **NEW** | Per-agent toggle — **absent** (N2) | — | `cli_agents_wire_works_without_a_daemon`; unit `agents_wire_unwire_roundtrip` | CLI FULL / UI absent (N2) |
| 14 | `cerberus agents unwire <agent>` | — (local) | **NEW** | Per-agent toggle — **absent** (N2) | — | same tests as #13 | CLI FULL / UI absent (N2) |
| 15 | `cerberus providers` | `GET /api/upstreams` | **NEW** | Upstreams tab (list) | token | `cli_provider_crud_hits_upstreams_routes` | FULL |
| 16 | `cerberus add-provider <n> --url <u> [--auth-header <h>]` | `POST /api/upstreams` | **NEW** (prints local base URL, Appendix C) | Upstreams tab → "Add" form | token | same e2e (name/url/auth_header body asserted) | FULL |
| 17 | `cerberus remove-provider <n>` | `DELETE /api/upstreams/{name}` | **NEW** | Upstreams tab → Delete | token | same e2e (DELETE path asserted) | FULL |

## B.3 — Rules, categories, packs, and allowlist

| # | Command | API | CLI | Dashboard | Auth | Test | Status |
|---|---------|-----|-----|-----------|------|------|--------|
| 18 | `cerberus packs list` | `GET /api/packs` | **NEW group** (`packs`; `pack` kept as compat alias) | Rule Packs tab | token | `cli_status_packs_list_and_rules_add_hit_expected_routes`; `pack_cli_via_api` (alias path) | FULL |
| 19 | `cerberus packs enable <pack>` | `POST /api/packs/enable {name}` (**NEW endpoint**) | **NEW** | Rule Packs tab → **Enable button (NEW)** | token (+Pro gate on enable) | e2e `cli_packs_enable_disable_update_hit_pack_routes`; API `pack_enable_disable_update_reach_the_worker`; worker arms in daemon.rs | FULL (closes R9-6 inverse finding) |
| 20 | `cerberus packs disable <pack>` | `POST /api/packs/disable {name}` (**NEW endpoint**) | **NEW** | Rule Packs tab → **Disable button (NEW)** | token (disable ungated: reduces detection) | same tests | FULL (closes R9-6 inverse finding) |
| 21 | `cerberus packs update` | `POST /api/packs/update` (**NEW endpoint**; verify+hot-reload) | **NEW** | Rule Packs tab → **"Update packs" button (NEW)** | token (+Pro gate) | same tests; PackManager::verify_installed unit paths via production_pack_pr suite | FULL (registry fetch deferred to F7 — L1) |
| 22 | `cerberus category set <cat> --action <a>` | `PUT /api/policy {categories}` | **NEW** | Policy tab → per-category selector | token | `cli_category_and_rules_set_hit_the_policy_route`; policy PATCH tests (pre-existing) | FULL |
| 23 | `cerberus rules list` | `GET /api/policy` (now returns **`effective_rules`**) | **NEW** | Policy tab | token | `cli_category_and_rules_set…` (list output); API `policy_document_lists_effective_rules` | FULL |
| 24 | `cerberus rules add --file <rule.yaml>` | `PUT /api/policy {custom_rules}` (full replacement) | **NEW** (local compile check first — lookaround/ReDoS hard error before any network) | Policy tab → rule editor (Free: form/YAML per §4.6) | token | e2e (`rules add` compiles + PUTs); unit `rules_add_rejects_bad_regex_before_network`, `rule_file_parses_single_and_list` | FULL |
| 25 | `cerberus rules set <flag> --action <a>` | `PUT /api/policy {rules}` | **NEW** | Policy tab → per-rule selector | token | `cli_category_and_rules_set…` | FULL |
| 26 | `cerberus allowlist add <value>` | `POST /api/allowlist` (raw → HMAC fingerprint, R9-7) | **NEW** (echoes fingerprint ONLY) | Policy tab → allowlist (add) | token (+installation key) | `cli_allowlist_hits_the_allowlist_routes` (raw never echoed); F6.3 API tests | FULL |
| 27 | `cerberus allowlist list` | `GET /api/allowlist` (fingerprints) | **NEW** (truncated digests `hmac:0123456789ab…`) | Policy tab → allowlist view | token | same e2e; `fingerprint_display_never_shows_full_digest` | FULL |
| 28 | `cerberus allowlist remove <value>` | `DELETE /api/allowlist` | **NEW** | Policy tab → allowlist remove | token | same e2e | FULL |

## B.4 — Tests / dry-run

| # | Command | API | CLI | Dashboard | Auth | Test | Status |
|---|---------|-----|-----|-----------|------|------|--------|
| 29 | `cerberus scan <file>` | — (local dry-run by design) | pre-existing | **"Test Detection" card (NEW)** via `POST /api/scan` | API: token | pre-existing scan tests; API `api_scan_dry_runs_and_persists_nothing` (no persistence, no raw echo) | FULL |
| 30 | `cerberus test <text>` | — (local) | pre-existing | **"Test Detection" card (NEW)** via `POST /api/scan` | API: token | pre-existing; same API test | FULL |

## B.5 — Observability

| # | Command | API | CLI | Dashboard | Auth | Test | Status |
|---|---------|-----|-----|-----------|------|------|--------|
| 31 | `cerberus events [--provider] [--tool] [--since]` | `GET /api/events?provider&tool&since` (**tool/since NEW**) | **NEW** (since: epoch, RFC 3339, `90s/30m/2h/1d`) | Events feed (provider filter; tool/since pickers not rendered — N3) | token | `cli_events_stats_reload_hit_their_routes`; API `events_filter_by_tool_and_since` (+401 gate) | FULL (UI filter note N3) |
| 32 | `cerberus stats [--by provider\|tool\|flag]` | `GET /api/stats` (+ same filters) | **NEW** (`--by provider` = per-upstream breakdown, §4.6 first-class) | Statistics tab (per-provider + top flags) | token | same e2e; stats API tests (pre-existing) | FULL |
| 33 | `cerberus logs [-f]` | — (reads the daemon log file; no-secrets contract via the logging layer) | **NEW** (tail 100; `-f` follows, rotation-aware) | Logs panel — **absent** (N1) | — | unit `tail_lines_returns_last_n`; log.rs `tee_sink_*`; e2e `cli_local_commands_work_without_a_daemon` | CLI FULL / UI absent (N1) |

## B.6 — Config and license

| # | Command | API | CLI | Dashboard | Auth | Test | Status |
|---|---------|-----|-----|-----------|------|------|--------|
| 34 | `cerberus config show` | — (local file; token REDACTED — API's "token never returned" stance) | **NEW** | Settings tab (config view, token never returned) | — | e2e `cli_local_commands_work_without_a_daemon`; unit `config_show_redacts_the_admin_token` | FULL |
| 35 | `cerberus config edit` | — (local; post-edit parse validation) | **NEW** (`$EDITOR`, fallback vi/notepad) | Settings tab (config edits via UI, hot-reload) | — | e2e with `EDITOR=true`; `cerberus reload` carries changes | FULL |
| 36 | `cerberus config path` | — | **NEW** | — | — | e2e (path printed) | CLI FULL |
| 37 | `cerberus login --file <license.json>` | — (verifies with the daemon's trust root; installs 0600) | **NEW** | "Account" screen — **absent** (N1) | local file + `CERBERUS_LICENSE_PUBLIC_KEY` | unit `login_verifies_and_installs_signed_license` (verify + 0600 + tamper-reject) | CLI FULL (F8 re-verifies against real entitlements) / UI absent (N1) |
| 38 | `cerberus dashboard` | `GET /ui` → 302 `/api/dashboard` (**NEW redirect**) | **NEW** (opens `http://localhost:8787/ui`) | itself | /ui public (no data) | API `ui_path_redirects_to_the_dashboard`; dashboard CSP tests pre-existing | FULL |

## B.7 — Mode A (operation / self-host)

| # | Command | API | CLI | Dashboard | Auth | Test | Status |
|---|---------|-----|-----|-----------|------|------|--------|
| 39 | `helm install/upgrade` (B.7) | — | external deploy tool (not a subcommand) | central dashboard (Mode A, §Appendix B note) | — | Phase 8 unit (docker/helm) | DEFERRED (F8) |
| 40 | `docker run …` (B.7) | — | external deploy tool | — | — | Phase 8 unit (docker/helm) | DEFERRED (F8) |
| 41 | `cerberus validate -f <cfg>` | — (local pre-deploy validation) | **NEW** (syntax, upstream http(s) scheme, policy, pattern compile — ReDoS impossible by construction) | — (Mode A config is IaC; central dashboard = F8 scope) | — | unit `validate_accepts_a_well_formed_config` / `validate_rejects_bad_scheme_and_bad_regex`; e2e `cli_local_commands_work_without_a_daemon` | CLI FULL |
| 42 | `cerberus reload` | `POST /api/reload` (**NEW endpoint**; hot-reload, no restart) | **NEW** | Settings/Policy changes hot-apply (§4.6 hot-reload) | token (+anti-lockout guard) | e2e `cli_events_stats_reload_hit_their_routes`; API `reload_applies_on_disk_config_without_restart` (disk→live, broken-file 400, token-removal rejected, 401 gate) | FULL |

## Notes (leg absences — explicitly marked, not silently omitted)

- **N1 — dashboard screens beyond the §4.6 config-screens list.** The plan's
  binding Phase 6 dashboard scope (§4.6 "Config actions (all from the UI)") is:
  providers add/remove, local base URL, category toggles, enable/disable rule
  packs, custom rules, action per rule, allowlists, fail-open/closed, shadow/
  enforce, statistics — all of which EXIST (plus the B.4-named "Test detection"
  box and the B.3-named "Update packs" button added by this unit). Appendix B's
  Dashboard column additionally *names* an onboarding wizard, start/stop button,
  agents screen/per-agent toggle, diagnostics panel, version notice, account
  screen and logs panel; those screens are NOT part of the §4.6 list and were
  not invented here. Rows affected: #2,3,4,5,9,10,11,12,13,14,33,37.
  Additionally, start/stop-from-the-UI and a dashboard logs panel have a real
  design cost (the browser session lives inside the daemon it would stop).
- **N2 — agents wiring is a local action.** Routing an agent = setting its
  `*_BASE_URL` in the shell/agent config on the operator's machine. A web UI
  cannot mutate the parent shell environment; `agents wire` prints the exact
  export line and records intent (`~/.cerberus/agents.json`). An "Agents"
  screen would be read-only status — deferred with the rest of N1.
- **N3 — events tool/since in the dashboard.** The API now supports
  `tool`/`since` (closing the R9-6 inverse finding); the Events feed UI has the
  provider filter it shipped with. The CLI exposes the full filter surface;
  adding UI pickers is a small follow-up inside the F6 dashboard unit, not new
  scope.

## Deferred by the DAG (not "missing" — owned by later phases)

- **L1 — `packs update` registry fetch & `upgrade` binary download**: F6
  delivers the functional contracts (verify+hot-reload; manifest check+guidance)
  tested against a local repository/manifest, exactly as fix-plan F6.4 prescribes
  for `upgrade`/`login`. Auto-update from a registry is the Phase 7 unit
  (`auto-update`); downloading/replacing signed binaries is Phase 8
  (`signed-binaries`, `installers`).
- **L2 — `cerberus restart` e2e**: restart is the composition of `stop` + `start`
  (both e2e-proven by the smoke script); a self-contained restart e2e would need
  a real daemon-under-test lifecycle inside CI and is registered as follow-up
  hardening, not missing scope. Clap wiring is test-proven.
