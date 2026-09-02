# F6.B Attempt 1 — CORRECTNESS lens (independent adversarial review)

- **Unit**: F6.B / R9-6 — Appendix B CLI surface + API→CLI→dashboard parity matrix
- **Candidate**: commit `079ebf8` (parent `be6b6ff`, branch `r9-remediation`), 22 files, +4811/−327
- **Reviewer**: independent correctness lens, attempt 1, fresh worktree at
  `/var/folders/.../opencode/f6b-attempt1-correctness` (detached at `079ebf8`)
- **Date**: 2026-09-02
- **Blindness**: the sibling lens report (`f6b-attempt1-security.md`) was never opened.

---

## 1. Commands run (verbatim, with exit codes)

| # | Command (from the worktree) | Exit | Result |
|---|---|---|---|
| G1 | `rtk cargo fmt --all -- --check` | 0 | clean |
| G2 | `cargo clippy --workspace --all-targets -- -D warnings` | 0 | "No issues found" |
| G3 | `cargo test --workspace --all-targets` | 0 | **856 passed / 0 failed / 0 ignored** (matches builder's 856; tally re-computed from all `test result:` lines) |
| G4 | `cargo test -p cerberus-packs --test production_pack_pr` | 0 | **19/19** |
| G5a | `cargo test --release --test load_test -- --test-threads=1` | 0 | **14/14**, incl. `load_test_f3_3_honest_http_round_trip_gate` |
| G5b | `cargo test -p cerberus-proxy --test smoke_harness` | 0 | **69/69** |
| G5c | `bash tests/smoke-test.sh` (release binary) | 0 | **17 PASS** (17 individual PASS lines + summary) |
| T1 | `cargo test -p cerberus-proxy --test f6b_api_surface` | 0 | **7/7** |
| T2 | `cargo test -p cerberus --test cli_surface_via_api` | 0 | **11/11** |
| T3 | `cargo test -p cerberus --bin cerberus every_daemon_backed_cli_command_maps_to_a_real_api_route` | 0 | 1/1 (walks 24 daemon-backed rows) |
| T4 | **MUTATION A**: removed `("POST","/api/reload")` arm from `handle_api_request` (router), table left intact → rerun T3 | 0 | **parity test still PASSES with the route gone from the router** (finding F2) |
| T5 | Under mutation A: `cargo test -p cerberus-proxy --test f6b_api_surface reload_applies_on_disk_config_without_restart` | test FAILED | real-router suite **does** catch the vanished route (mitigation exists, but not in the parity test) |
| T6 | `git checkout -- crates/cerberus-proxy/src/api.rs` (revert mutation) + rerun T3 | 0 | worktree clean, parity test green again |
| L1–L14 | Live harness: `cerberus init` → `cerberus start --port 18901`; hand-driven CLI commands against the live daemon (see §4) | 0/1 as expected | see §4 |
| T7 | `git diff --check` | 0 | whitespace clean |

All live-harness commands were run with an isolated `HOME`, a random init token
(64 hex chars, 0600 config), the daemon on `127.0.0.1:18901`, and
`X-Cerberus-Admin-Token` headers; every command and status code is quoted in §4.

---

## 2. Per-criterion verdicts

| Criterion | Verdict | Evidence |
|---|---|---|
| 1. `cerberus --help` + subcommand help match Appendix B (in-MVP missing = 0, invented = 0) | **PASS** | §3: independent inventory diff = 0 missing / 0 invented; 32 top-level commands; all subcommand groups (packs/category/rules/allowlist/config/agents) complete with help text |
| 1a. The 3 deferred lines are genuinely external/phase-owned, not dodged MVP commands | **PASS** | §3: brew/curl → F8 `installers(brew/curl/…)`; helm/docker → F8 `docker/helm`; registry-fetch **inside** `packs update` → F7 `auto-update` (command itself IS built: verify + hot-reload; help text discloses the deferral) |
| 2. Parity matrix complete + CI-runnable parity test walking all daemon-backed commands | **PASS with finding** | 24 rows walked (T3); **BUT** the test validates against a hand-maintained duplicate table, not the router — mutation A proved a removed router arm leaves it green (finding F2, P2) |
| 3. Full gates green (fmt/clippy/tests/pack/load/smoke) | **PASS** | §1: all gates exit 0; 856/0; 19/19; 14/14; 69/69; 17 PASS |
| 4. New e2e suites green (f6b_api_surface 7/7, cli_surface_via_api 11/11) | **PASS** | T1/T2 |
| 5. Daemon-backed commands hand-driven against a live daemon | **PASS** | §4: packs disable/enable (honest errors incl. Free-tier Pro gate), category set (merge + persist proven), events `--since/--tool/--provider` discriminating real traffic, `config edit` round-trip + `cerberus reload` hot-apply; no-daemon errors exit 1 with actionable message, no panic |
| 5b. `packs enable/disable` real success path | **PASS with finding** | Honest error gates verified live; but no test executes `set_active`/the real worker arms (API test stubs the worker) — finding F3, P2 |
| 6. Reload anti-lockout: token-removal rejected 400, token-change accepted + applies | **FAIL (P1)** | §4.6: reload guard works exactly as claimed (400 on removal, live config preserved; change applies immediately). **PUT /api/config has NO such guard**: explicit `"admin_token": null` → 200, control plane closes (all `/api/*` 401), and `admin_token: null` is persisted to disk, so the closure survives restart. The evidence pack's invariant ("a running secured control plane never silently closes") is false on this path |
| 7. CLI auth model: token from config/env, no unauthenticated access, no hardcoded/logged token, no raw allowlist | **PASS** | §4.7–4.9: 9 routes → 401 without token; CLI without token source refuses with actionable error (exit 1); token absent from daemon log and sources; allowlist add/list/remove carry fingerprints only (disk shows `hmac:488d…`, display truncated `hmac:3e64deea7519…`) |
| 8. `known_api_routes()` derived from vs duplicated next to the router | **FAIL (P2, F2)** | `known_api_routes()` is a static duplicate of the `match` in `handle_api_request` (doc comment: "Keep in sync"); mutation A proved the parity test cannot detect a removed route |

---

## 3. Appendix B — independent inventory diff

Reviewer's own enumeration from `CERBERUS_PRODUCT_BUILD_PLAN.md` Appendix B
(B.1: 11 rows, B.2: 6, B.3: 11, B.4: 2, B.5: 3, B.6: 5, B.7: 5 → **43 rows**, of
which 4 are external-tool lines: brew/curl, helm install, helm upgrade, docker run).
Counting nuance vs the builder: the plan's B.7 table lists `helm install` and
`helm upgrade` as separate rows; the builder merged them (their 42 = my 43 − 1).
No command is lost by that merge.

| Appendix B item | In binary? | Notes |
|---|---|---|
| brew/curl installer (B.1) | external (correctly not a subcommand) | → F8 `installers(brew/curl/…)` — genuine external-tool line |
| init, start, stop, restart, status, mode, allow-once, doctor, version, upgrade | ✅ all present | restart = NEW (stop+start); version + `--version` agree (`0.1.2`); upgrade checks a manifest and prints guidance (binary download = F8 `signed-binaries`) |
| agents, agents wire, agents unwire | ✅ | wire prints the export line, records `~/.cerberus/agents.json`; local by design (a web UI cannot mutate the shell) |
| providers, add-provider, remove-provider | ✅ | `GET/POST/DELETE /api/upstreams`; add prints the local base URL (Appendix C) |
| packs list/enable/disable/update | ✅ | `pack` kept as compat alias (plan F6.4); enable/update Pro-gated, disable ungated |
| category set, rules list/add/set, allowlist add/list/remove | ✅ | all live-verified (§4) |
| scan, test | ✅ | pre-existing CLI; NEW `POST /api/scan` + "Test Detection" card |
| events --provider/--tool/--since, stats --by, logs -f | ✅ | CLI help matches B.5 exactly (stats takes only `--by`, per spec) |
| config show/edit/path, login, dashboard | ✅ | show redacts the token (`***redacted***`); `/ui` → 302 `/api/dashboard` |
| helm install / helm upgrade / docker run (B.7) | external | → F8 `docker/helm` — genuine external-tool lines |
| validate -f, reload | ✅ | both live-verified |
| **In-MVP commands missing** | **0** | — |
| **Invented beyond spec** | **0** | `license`, `pack` (alias), `mitm`, `help` all pre-date this unit (R9-6's own "before" list includes license/pack/mitm) |

**Deferred-lines check (task a)**: all three deferrals map to real later-phase
units and none is an MVP command dodged. The only nuance is `packs update`: the
command exists and does real work (signature re-verification + hot-reload, e2e-
and unit-tested); only fetching NEW versions from a registry is deferred to F7
`auto-update`, disclosed in `--help` and matrix L1. Accepted.

---

## 4. Parity spot-check results (task b — 13 rows sampled, all live)

Live harness: daemon on `127.0.0.1:18901`, admin token via header, real traffic
generated through the data plane.

| Matrix row | API leg (curl, live) | CLI leg (live binary) | Dashboard leg | Verdict |
|---|---|---|---|---|
| #7 mode | `PUT /api/config` live: rotate accepted (200), old token 401, new token 200 — applies immediately | `mode` / `mode enforce` live | mode toggle present in dashboard.html | FULL ✓ |
| #18 packs list | `GET /api/packs` → `{"status":"ok","message":"0 packs installed"}` | `packs list` live | Rule Packs tab | FULL ✓ |
| #19/20 packs enable/disable | `POST` live → honest 400s ("not installed", "Pro license") + f6b test proves worker wiring (stub) + 401 gate | live (same honest errors, exit 1) | Enable/Disable buttons (`btn-enable-pack`/`btn-disable-pack` → `/api/packs/enable|disable`) | FULL ✓ (success-path coverage gap = F3) |
| #21 packs update | `POST /api/packs/update` live → 400 not-installed | live | "Update packs" button → `/api/packs/update` | FULL ✓ |
| #22 category set | `GET /api/policy` after → `{'secrets':'block'}`, then `{'pii':'warn','secrets':'block'}` (merge, not replace) | `category set secrets --action block` / `pii --action warn` (hot-reload applied) | per-category selector present | FULL ✓ |
| #23–25 rules list/add/set | `GET /api/policy` shows `effective_rules` (15) | `rules add --file` (compiles, PUTs), `rules list` shows `custom.reviewer_rule`, `rules set … --action allow` | rule editor (Free form/YAML) | FULL ✓ |
| #26–28 allowlist | 401 without token; add→fingerprint; disk stores `hmac:488dc964…` (never raw); remove → `allowlist: []` | add echoes `hmac:488dc9649738…` only (raw never echoed); list truncated; remove works | allowlist UI present | FULL ✓ |
| #29/30 scan/test | `POST /api/scan` live → `{"action":"block","flags":{"secret.openai_api_key":1},"hashed_values":["hmac:b9eb…"]}`, **0 events persisted** | pre-existing `scan`/`test` | "Test Detection" card → `/api/scan` | FULL ✓ |
| #31 events | `GET /api/events?provider&tool&since` live: after a real blocked send → 1 event; `--tool proxy` → 1; `--tool curl` → 0; `--provider anthropic` → 0 (filters discriminate) | `events --since 5m/30m/1h`, `--tool`, `--provider` all live | Events feed w/ provider filter (tool/since pickers not rendered — N3, honestly disclosed) | FULL (N3 note) ✓ |
| #32 stats | `GET /api/stats?provider=openai` → `{"total":1,"by_provider":[{"openai":…}]}` | `stats --by provider` → "openai 1 events"; `--by flag` → top flag | Statistics tab | FULL ✓ |
| #34–36 config show/edit/path | local | show redacts token; path correct; `config edit` (scripted EDITOR flipped enforce→shadow) → valid → `cerberus reload` → live mode `shadow` (true hot round-trip) | settings/config view (pre-existing) | FULL ✓ |
| #38 dashboard | `GET /ui` → **302** `/api/dashboard`; `/api/dashboard` serves HTML | `dashboard` opens the URL | itself | FULL ✓ |
| #42 reload | `POST /api/reload` live: broken file → 400 + live untouched; token-removing file → **400**; token-changed file → 200, applies immediately (old token 401, new 200, mode applied) | `reload` live | settings edits hot-apply (§4.6) | FULL ✓ (PUT-side gap = F1) |

**UI-absent rows (task b, second half)** — the 11 rows marked CLI-FULL/UI-absent
(#2,3,4,9,10,11,12,13,14,33,37) name screens from Appendix B's Dashboard column
(onboarding wizard, start/stop, agents screen, diagnostics, version notice,
account, logs panel). None of these is in §4.6's binding "Config actions (all
from the UI)" list (providers add/remove, base URL, category toggles, pack
enable/disable, custom rules, action per rule, allowlists, fail policy,
shadow/enforce, statistics — **all present**, plus the B.3 update button and B.4
test box). The absences are plan-justified (not invented, not dodged), each
explicitly marked N1/N2 rather than claimed. Caveat noted in F5: Appendix B's
preamble literally promises "every command has its equivalent in the dashboard";
the shipped parity claim rests on the §4.6-list reading. Reasonable, but the
orchestrator should be aware the two plan texts disagree.

---

## 5. Findings

### F1 — P1: Anti-lockout guard missing on `PUT /api/config`; explicit token removal closes the control plane and persists `admin_token: null` (live-reproduced)

- **Repro (live harness)**: `PUT /api/config` with body `{"admin_token":null}`
  and the valid token → **HTTP 200** `{"status":"ok","requires_restart":false,"message":"config updated"}`.
  Immediately after, the **same valid token** on `GET /api/config` → **401**.
  `data plane /health` still 200. **The on-disk config was rewritten to
  `admin_token: null`**, so a restart boots with the control plane CLOSED
  (R9-5 fail-closed semantics) — the lockout survives `cerberus restart`, and
  the reload error's own advice ("keep admin_token in the file or restart the
  daemon") does not recover this state; the operator must hand-edit the YAML.
- **Mechanism**: `ConfigPatch::PatchField::Clear` (pre-existing) resolves an
  explicit `null` to delete; `validate_control_plane_exposure` only requires a
  token for non-loopback listens, so the loopback candidate passes, is persisted,
  and published. The NEW guard added by this commit exists only in
  `apply_reload` (verified: `git show be6b6ff` has 0 hits for the guard, 5 for
  `PatchField`).
- **Why it matters**: the evidence pack claims "a reload that would REMOVE the
  admin token is rejected 400 so a running secured control plane never silently
  closes" — the invariant is real for reload and false for the sibling route on
  the SAME Config API that the dashboard and CLI are documented as fronts over.
  The review spec for this unit explicitly expected PUT token-removal → 400.
- **What is NOT broken**: security posture stays fail-CLOSED (no data exposure —
  every data route 401s for everyone, including the operator); no CLI command or
  dashboard control triggers it (only a hand-crafted authenticated PUT with
  explicit null); token CHANGE via PUT and via reload both apply immediately
  (verified live). This is an availability/guard-consistency defect, not a
  confidentiality break.
- **Suggested fix (small)**: apply the same guard in `handle_put_config`
  (reject `PatchField::Clear` for `admin_token` when the live config has one —
  or route null through the same 400 path), and do not persist the nulled field.

### F2 — P2: The CI parity test validates against a duplicated route table, not the router (mutation-proven)

`every_daemon_backed_cli_command_maps_to_a_real_api_route` (main.rs:804) walks
24 rows and asserts each against `is_known_api_route()`, which reads the static
`known_api_routes()` table — a hand-maintained copy of the `match` arms in
`handle_api_request` (api.rs:608–639), kept in sync only by a doc comment.
**Mutation A** (remove the `("POST","/api/reload")` router arm, table intact):
parity test **passes** while the real router 404s the route. The same mutation
fails `f6b_api_surface::reload_applies_on_disk_config_without_restart` (verified),
so live drift on exercised routes is caught incidentally — but by other suites,
not by the parity test whose stated job is "keeps the CLI↔API legs of every row
honest". No live drift exists today (all 24 table entries have matching router
arms — verified by reading `handle_api_request` 1:1). Suggested fix: a
table-vs-router cross-check (e.g. for every table entry, a request must not 404)
or derive the table from the dispatch.

### F3 — P2: The real `packs enable/disable` success path has no executing test

`PackManager::set_active` (the actual manifest state change) is called only by
the real daemon worker arms (daemon.rs:624/644), and no test executes either:
`f6b_api_surface::pack_enable_disable_update_reach_the_worker` stubs the worker
(a channel echo), no unit test calls `set_active`, and `production_pack_pr`
measures pack content quality, not activation. My live harness verified the
honest failure gates (not-installed 400, Free-tier Pro-gate 400) but could not
reach a success round-trip without a signed Pro license + installed pack. The
component pieces are tested (Pro gate test, `verify_installed` via pack suites);
the composed path API→worker→`set_active`→engine-rebuild is not.

### F4 — P2 (informational, no action blocking): documented deferrals and plan-text tension

(a) `packs update` registry-fetch → F7, disclosed in `--help`/matrix L1 — the
command does real work today. (b) Appendix B's preamble ("every command has its
equivalent in the dashboard") is satisfied only under the §4.6-scoped reading;
the builder marks every absence (N1/N2/N3) instead of inventing UI — acceptable,
but the plan texts disagree and the matrix states its reading openly. (c) The
config parser silently ignores unknown top-level keys (a file with `rules:`
instead of `policy.custom_rules:` parses as 0 custom rules and `validate` calls
it VALID) — pre-existing schema laxity, outside this unit's diff; validate
correctly rejects lookarounds, un-compilable patterns under the documented
`policy.custom_rules` key, and non-http(s) schemes (all live-verified; note
`(a+)+$` is correctly accepted — Vectorscan is linear-time, so nested
quantifiers are not a ReDoS vector by construction).

---

## 6. Final verdict

**FAIL** (returns to FIX). The unit's core delivery is real and verified: the
Appendix B surface is complete (independent inventory diff: 0 missing in-MVP
commands, 0 inventions; the three deferrals map to genuine F7/F8 external-tool
and auto-update units, with `validate`/`reload`/`packs update` honestly built),
all hard gates pass on my own runs (fmt clean; clippy clean; **856/0** workspace
debug; 19/19 pack PR; 14/14 release load incl. the honest HTTP gate; 69/69
harness; 17 PASS smoke; 7/7 + 11/11 new suites), the parity matrix rows I
sampled (13, exceeding the required 8) behave as claimed on all three legs
against a live daemon, the auth model holds (401 everywhere without the token,
fingerprints-only allowlist, no token leakage), and the CLI degrades with
actionable errors. However, one P1 blocks a PASS: the commit's own anti-lockout
invariant — "a running secured control plane never silently closes" — is
implemented on the reload path only; `PUT /api/config` accepts an explicit
`"admin_token": null` (200), immediately closes every data route (401 with the
previously-valid token), **and persists `admin_token: null` to disk**, so the
closure survives the very restart the system's own error message recommends —
reproduced live end-to-end. Two P2s (parity test checks a duplicated table
rather than the router — mutation-proven; untested real enable/disable success
path) round out the picture. Fix F1 (extend the guard to `PUT /api/config`),
ideally address F2/F3 in the same pass, and return to VERIFY.

---

*Commands and outputs quoted in this report were executed by the reviewer in the
detached worktree; live-harness artifacts (daemon logs, editor script) live under
`/var/folders/.../opencode/`. No file in the main repo was modified except this
report.*
