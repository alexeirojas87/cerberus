# Evidence Pack — Gauntlet v6.1: loop adversarial Codex + OpenCode cerrado

- **Fecha de recheck final:** 2026-08-21 (America/New_York)
- **Checkout:** `HEAD 09612f2142b8ab4e7655da6682231b2548e78bef` + working tree actual, sin commit
- **Orquestación:** Orca Run `run_a64b51716aba`; workers exclusivamente **Codex** y **OpenCode**. No se usó Claude en la revisión/fix/recheck v6.1.
- **Resultado:** **PASS técnico v6.1 — 0 P0 / 0 P1 del MVP**. Pendiente visto bueno humano de fase conforme a §8B.7.

## Fase 9 — Hardening y GA (cerrada 2026-08-22)

- **Commits:** `c327527` (feat F9) → `c684591` (fix P1 flake load_test, loop del gauntlet)
- **Revisores adversariales:** Codex (gate inicial: FAIL P1 flake) + OpenCode (recheck: PASS)
- **Evidence:** `evidence/f9/{redos-fuzz,load-test,failsafe,security-review,docs,integration-gate}.md` + `evidence/review8/{codex-f9-gate,codex-f9-findings,opencode-f9-findings}.md`

| Unidad F9 | Veredicto |
|-----------|-----------|
| security-review | ✅ PASS |
| redos-fuzz (pack real, 13 reglas incl. multiline) | ✅ PASS |
| load-test (pack real, release p99 2.6 ms) | ✅ PASS |
| failsafe (secure-by-default + proxy-level + 5 clases error) | ✅ PASS |
| docs (user/operator/security con F4/F8) | ✅ PASS |

### Gates finales F9 (commit `c684591`)
| Comando | Resultado |
|---------|-----------|
| `cargo fmt --all -- --check` | ✅ 0 |
| `cargo clippy --workspace --all-targets -- -D warnings` | ✅ 0 |
| `cargo test --workspace --all-targets` (debug) ×3 | ✅ 596/0 ×3 reproducible |
| `cargo test --release --workspace --all-targets` ×2 | ✅ 596/0 ×2 |
| `python3 tools/simulate.py` | ✅ 29/0 |

### Cambios structurales F9
- Pack por defecto (13 reglas) movido a `cerberus-packs/src/default_pack.rs` como fuente única de verdad; CLI y tests consumen el mismo pack (sin drift).
- redos-fuzz + load-test ahora fuzzean/benchmarkean el pack real (no copia inline) — cumple "redos-fuzz(todos los packs)" del plan §8B.6.
- failsafe extendido con secure-by-default + proxy pipeline + 5 clases de error heterogéneo.
- Fix flake env-race release (`pid_path`/`config_dir` toman ENV_LOCK).
- Fix P1 flake load_test debug: budget p99 es gate de release (plan §5); debug sólo techo patología 30×.
- Docs actualizados con F4/F8 (MITM opt-in, Windows winget, feedback, telemetry, Helm, packs Ed25519).

## Estado del MVP (consolidado tras F9)

**Todas las fases del DAG §8 (F0→F9) cerradas con PASS técnico.**

- F0 (spike-escaneo, spike-proxy, scaffold+CI, presupuesto-latencia) ✔
- F1 (motor: rule-loader, regex-compiler, validators, multiline, entropy, constraints, corpus) ✔
- F2 (redacción in-place, reversible-vault, action-precedence, break-glass, feedback-hook) ✔
- F3 (reverse-proxy-core, agnostic-decoder, schema-adapters, shadow/enforce, fail-policy, healthcheck+logs) ✔
- F4 (local-daemon, cerberus-init, default-packs, mitm-opt-in, windows-support, dev-feedback-ux) ✔
- F5 (sqlite-store, event-schema, async-writer, retención, garantía-no-leak) ✔
- F6 (config-api, stats-por-proveedor, pantallas-config, fp-triage-1click, paridad-CLI↔dashboard) ✔
- F7 (pack-format, firma-de-packs, auto-update) ✔
- F8 (installers, binarios-firmados, licensing/entitlements, docker/helm, telemetría-opt-in) ✔
- **F9 (security-review, redos-fuzz, load-test, failsafe, docs) ✔**

**Post-GA (backlog)** — fuera del MVP por contrato (AGENTS.md):
- PII contextual por NER/NLP (futurible Pro)
- Escaneo de respuestas en streaming (SSE)
- Hooks nativos por herramienta
- Escaneo de tool-calls / MCP
- Decodificación antes de escanear (base64/hex/URL-encoded)
- Endpoint Prometheus + export SIEM (Pro)
- Reporting compliance (Pro)
- Alertas Slack/Teams/webhook (Pro)
- Detección de tamper / heartbeat (Pro)
- SDK embebible (FFI Python/Node/Go)
- Política por proveedor/ruta

## Loop v6.1 (previo a F9)

| Paso | Agente | Evidence | Resultado |
|---|---|---|---|
| Gate inicial completo | Codex | `evidence/review7/codex-gate.md` | PASS: 534/0 debug+release, sim 29/29, PR determinista, p99 1.412 ms |
| Review adversarial inicial | OpenCode | `evidence/review7/opencode-findings.md` | **FAIL: 1 P1** — dashboard enviaba `{path}` wire v1 y el API wire v2 lo rechazaba con 400 |
| FIX loop | Codex | `evidence/f6/dashboard-pack-wire-v2-v61-fix.md` | Selector `type=file`, bytes UTF-8 acotados, `{wire_version,pack}`, sin ruta local; cota compartida y evidencia histórica aclarada |
| Gate recheck desde cero | Codex | `evidence/review7/codex-gate-recheck.md` | **PASS**: 534/0 debug+release, sim 29/29, SHA PR idéntico, p99 peor 1.169 ms |
| Findings recheck desde cero | OpenCode | `evidence/review7/opencode-findings-recheck.md` | **PASS: 0 P0 / 0 P1**; sin regresiones en config/policy/packs/store/daemon/CSP |

El FAIL inicial se conserva como evidencia histórica. Su addendum posterior no cambia el dictamen original; los dos rechecks finales viven en archivos nuevos.

## Hallazgos v6.1 cerrados

| Área | Cierre verificado |
|---|---|
| Config/control-plane | `ConfigView` nunca expone `admin_token`; PATCH omitir/null/read-only correcto; no-loopback revalidado antes de persistir/publicar; carga de config inyectable y determinista |
| F6 policy | categorías/overrides, custom rules y allowlist persisten en YAML, sobreviven reopen y hacen hot-swap del dataplane preservando las actions base |
| Packs/F7 | trust root explícito y Pro-gated al boot; wire v2 transporta bytes; `{path}` se rechaza antes del worker; policy y packs se rebasan bajo lock sin carrera |
| Dashboard packs | archivo local leído con `File.arrayBuffer` + `TextDecoder` fatal; request exacta `{wire_version:2,pack}`; sin `path`/`origin_name`; CSP continúa sin `unsafe-inline` |
| Store/daemon | no admisión post-cierre, deadline único enqueue+ACK, drenaje ordenado, drops/errores honestos y shutdown graceful |
| Determinismo | workspace y release 534/0; sim 29/29; PR SHA `969e84903ef58e72a7d706e2d50ab938c35d0c2c5851b5f40f64736355114d2e`; recall 94.3%, precision 89.2% |

## Gates finales v6.1

| Gate | Resultado independiente final |
|---|---|
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --workspace --all-targets -- -D warnings` | PASS, 0 warnings |
| `cargo test --workspace --all-targets` | PASS, **534 / 0** |
| `cargo test --release --workspace --all-targets` | PASS, **534 / 0** |
| `python3 tools/simulate.py` | PASS, **29 / 0** |
| `cargo test -p cerberus-packs --all-targets` | PASS, **59 / 0** |
| CLI packs (`pack_cli_e2e`, `pack_cli_via_api`) | PASS, **3 / 0** y **4 / 0** |
| Load release | PASS, 7 / 0; peor p99 **1.169 ms** |
| Precision/recall x2 | PASS; SHA idéntico |
| `git diff --check` | PASS |

## Riesgo residual y gate de fase

- P2 no bloqueantes documentados por OpenCode: endurecer `deny_unknown_fields` del envelope, descriptor `endpoint.json` stale, margen conservador del envelope JSON y sanitización adicional de `metadata.name/version`. Ninguno abre rutas del cliente, relaja auth/trust-root o rompe el MVP; permanecen explícitos en `evidence/review7/opencode-findings-recheck.md`.
- F4 (MITM opt-in) y F8 (distribución) **no se han ejecutado en este Run**. El contrato del repositorio obliga a detenerse en este gate y pedir visto bueno antes de abrir la siguiente fase.

---

## Antecedente: Gauntlet v6 (reviews 1–6)

- **Fecha:** 2026-08-21
- **Método:** 7 subagentes de cierre (wave1: P0 firmas / store drops / evidence; wave2: CLI→API / Pro-gate / paridad F6 / XSS) + **integración** (gates) + **2 revisores adversarios** en worktrees separados → **loop** (1 FAIL re-cerrado en el modo local de pack_rollback) → **re-verificación adversarial de los 2** en worktrees de commits de loop.
- **Dictamen final: 7/7 hallazgos PASS (gate PASS + findings PASS tras recheck).**

## Revisiones (worktrees aislados)
| Revisor | Commit | Evidence | Veredicto |
|---|---|---|---|
| gate v6 | `31c14cd` | `evidence/review6/v6-gate.md` | PASS (fmt/clippy 0; debug 454; release 454; sim 29/29) |
| findings v6 | `31c14cd` | `evidence/review6/v6-findings.md` | 6/7 PASS + **1 FAIL (#6)** |
| gate recheck | `12bc776` | `evidence/review6/v6-gate-recheck.md` | PASS (debug/release **455**, sim 29/29, packs 46, PR sha estable) |
| findings recheck | `12bc776` | `evidence/review6/v6-findings-recheck.md` | **#6 → PASS** (pack_rollback local Pro-gated + tests) |

## Los 7 hallazgos v6 → estado
| # | Hallazgo | Fix | Dictamen revisor |
|---|---|---|---|
| 1 | **P0** packs sin verificar firma al boot | `rebuild_active_set(trust_root)` + `extract_with_root`; tamper→desactivar+persistir; sin root→fail-closed 0 packs | PASS |
| 2 | CLI no conectado a hot-reload | `cli_pack.rs`: pack install/rollback/list = cliente HTTP del daemon vivo (x-cerberus-admin-token); fallback local sin daemon | PASS |
| 3 | store confirma durabilidad tras drops | `flush`/`close` reportan drops nuevos (dropped_acknowledged); barrier en spawn_blocking | PASS |
| 4 | F6 paridad CLI/UI | PUT config persiste YAML; GET config no filtra token (`admin_token_configured`); CRUD `/api/upstreams` autenticado | PASS |
| 5 | XSS dashboard | DOM+textContent sin innerHTML dinámico; chips por closure; CSP en head; token nunca en DOM | PASS |
| 6 | Pro-gate /api/packs | `require_pro_for_pack_ops` unificado: worker(install+rollback), CLI local(install+rollback), boot omite packs en Free | **FAIL→PASS** (loop cerrado en `12bc776`) |
| 7 | Evidence no reproducible | SHA real documentado; index v6 sin contradicción v4 | PASS |

## Gates (rechecks independientes sobre `12bc776`)
| Comando | Resultado |
|---|---|
| `cargo fmt --all -- --check` | ✅ 0 |
| `cargo clippy --workspace --all-targets -- -D warnings` | ✅ 0 |
| `cargo test --workspace --all-targets` | ✅ 455 passed / 0 ff |
| `cargo test --release --workspace --all-targets` | ✅ 455 passed / 0 ff |
| `python3 tools/simulate.py` | ✅ 29 PASS / 0 FAIL |
| `cargo test -p cerberus-packs --all-targets` | ✅ 46 passed |
| PR determinista (sha) | ✅ `969e8490…` estable |

## Estado fases (honest)
- F1 (motor) ✔ PR por instancia/spans; gates 90/85; determinista
- F2 redacción ✔ JSON-safe + fail_policy
- F3 proxy ✔ auth default-secure, TLS, límites, routing, fail-policy
- F5 store ✔ durabilidad real (bounded/drops/err/cierre)
- F6 control-plane/UI ✔ (paridad API, persistencia YAML, CRUD upstreams, XSS, CSP)
- F7 packs/licensing ✔ (firma al boot, hot-reload real same engine, rollback durable, CLI→API, Pro-gate completo)

## Apertura F4/F8 (2026-08-21) — cerrada con revisores adversariales
| Área | Implementado | Revisión |
|---|---|---|
| **F4 — Windows** | `platform.rs` (APPDATA/_exe_), `stop_process_graceful`, `tasklist`, CI matrix 3-OS (`ci.yml`), embed en init | `evidence/review7/f4-adversarial.md` PASS |
| **F4 — Feedback dev** | `feedback_ux.rs` (notify-rust + stderr fallback) watch activo en daemon tras block/redact/warn, rate-limit 1/s, solo flag+hash | idem PASS |
| **F4 — Cero-config** | `init` escribe upstreams openai/anthropic por defecto | idem PASS |
| **F4 — MITM opt-in** | `forward.rs` CONNECT+TLS allowlist exacta, CA create_new validada (symlink/perms/>1MiB), fail-closed antes de bind, wiring `cerberus mitm` | idem PASS (19/19 forward, mitm_cli e2e) |
| **F8 — installers** | `tools/release/*` (build_release tar/zip+SHA256), install.sh checksum, brew.rb+fill, deb/rpm, winget **zip** (+winget-fix), release.yml | `evidence/review7/f8-adversarial.md` PASS* y `f8-winget-fix.md` PASS |
| **F8 — Helm** | `deploy/helm/cerberus` chart Modo A (configmap 0.0.0.0:8080, secret admin, required, tests health) | idem PASS |
| **F8 — Telemetría opt-in** | `telemetry.rs` POST HTTP real (reqwest blocking, 5s timeout, silencioso), install_id uuid persistente, nunca secretos | idem PASS |

\* F8: el único FAIL (winget .msi) entró al loop y quedó **re-cerrado** apuntando al `.zip` real de la pipeline (`f8-winget-fix.md` PASS).

**Gates F4/F8**: build workspace OK; debug/release `cargo test --workspace --all-targets` ✅ (582→583 suite completa); clippy -D 0; fmt 0; sim 29/29; pipeline release e2e (real `dist/cerberus-0.1.0-macos-aarch64.tar.gz` + SHA256SUMS + zip windows). `helm` no local → templates YAML parseados.

**Deuda documentada (no bloqueante):**
- `show_feedback` (engine) sin caller de producción — el feedback real va por `feedback_ux.rs` (a eliminar en limpieza).
- Windows real: cross-compile/taskkill requiere CI (local no tiene target).
- winget `InstallerSha256` es placeholder → el CI debe inyectar el sha real de SHA256SUMS antes del PR a winget-pkgs.
- MSI nativo (WiX) queda como nota; el installer publicable es el `.zip` (winget soporta zip).

Commits F4/F8: `a04a84d` (implementación) → `winget fix` pendiente de commit.
