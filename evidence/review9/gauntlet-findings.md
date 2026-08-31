# Evidence Pack — review9 / full-project gauntlet
- Attempt: 1    Reviewers: 5 adversarial subagents (build/CI, security, plan-compliance, performance, test-quality) + integrator spot-checks    Verdict: **FAIL** (release-gating findings present)
- Date: 2026-08-26    HEAD: fccd9e4 (branch docs/fix-install-commands, tree clean)

## Method
Panel independiente por dominio (§8B.3 high-risk panel). Cada hallazgo abajo está marcado
VERIFIED (comando + salida citada o file:line comprobado por el integrador) o SUSPECTED.
Nada aquí es "looks good" / "parece que".

---

## CRÍTICOS (bloquean release / violan decisiones cerradas)

### R9-1 [CRÍTICO, VERIFIED] Hot-path JSON redaction ~8-13x sobre el presupuesto p99 cerrado (3–5 ms)
- Estructura comprobada por integrador:
  - `crates/cerberus-proxy/src/json_redact.rs:77` — `engine.scan_with_context(s, body_text)` **por cada hoja string del JSON** (37 hojas → 37 scans del cuerpo completo como contexto).
  - `crates/cerberus-engine/src/engine.rs:270-271` — `Regex::new(&ml)` de patrones multiline (PEM/id_rsa/env_block) **recompilado en cada scan**.
  - `crates/cerberus-engine/src/entropy.rs:87-90` — `Regex::new` del alternado de keywords de entropía **recompilado en cada scan** (llamado desde engine.rs:286).
  - Doble parse JSON (json_redact.rs:54) + `to_lowercase()` del cuerpo por candidato (`constraints.rs:43`).
- Medición del revisor de rendimiento (probe HTTP con proxy real, enforce, default pack, n=100, M-series, release): redact JSON 37-hojas 50 KB → **p50 37.4 ms / p99 38.9 ms (max 67.4)**; redact texto plano 50 KB → p99 2.4 ms; upstream directo p99 1.13 ms.
- Presupesto plan §5 (decisión CERRADA §9 #2): p99 < 3–5 ms para prompts ≤ 50 KB.

### R9-2 [CRÍTICO, VERIFIED] El gate de latency no mide el camino dominante y el presupuesto fue inflado sin Evidence Pack
- `tests/load_test.rs:102,119,141,159` miden solo `engine.scan()` in-process; `load_test_decode_and_scan` usa payloads plain-text (rama Text del decoder); `load_test_scan_and_redact` llama `apply_redaction` directo — **ningún test hace round-trip HTTP ni toca la ruta JSON por-hoja de R9-1**.
- Commit `f1cdab9` subió `P99_BUDGET_MS` 7→15 ms (3–5x sobre el presupuesto cerrado); techo debug = 450 ms (`load_test.rs:44`). `grep '15 ms' evidence/` → 0 hits; `evidence/f9/load-test.md:36` sigue afirmando "Release sigue enforcing 5 ms" (evidencia podrida).
- CI load-test nunca corre en Windows (`ci.yml:66-68`), pese a §8B.4 "CI matrix" para cross-platform.

### R9-3 [CRÍTICO, VERIFIED] Release pipeline roto en main; la distribución quedó parada
- `gh run list --workflow=release.yml`: run **32616242426 (main) = failure**; log: `GH006: Protected branch update failed for refs/heads/main … [remote rejected] main -> main (protected branch hook declined)`. Jobs build/release skipped; `gh release list` → lo último es v0.1.2.
- Causa estructural (SUSPECTED permanente): el job bump-commitea y hace push a main protegida con 7 checks requeridos con `[skip ci]` → el push nunca puede satisfacer la protección.

### R9-4 [CRÍTICO, VERIFIED] Homebrew tap roto: la promesa "one-command install" (§5) no funciona
- `contrib/homebrew/cerberus.rb:4-11`: versión fijada en **0.1.0** con `sha256 "0000…"` **`# Placeholder`** en las 4 plataformas. README (`brew install alexeirojas87/cerberus/cerberus`) → el install falla la verificación de checksum siempre.

### R9-5 [CRÍTICO, VERIFIED] Control plane sin autenticación por defecto en loopback → el proveedor clave/rota puede ser secuestrado desde un navegador
- `config.rs:180` default `admin_token: None`; `config.rs:45-46` (doc): "When it is None … the control plane is left open"; `api.rs:272-279` solo gatea `if let Some(expected)`. Sin validación Origin/Host/CORS en rutas de escritura (`POST /api/upstreams` api.rs:817-860 acepta cualquier url, hace swap en caliente `*live = candidate`).
- Consecuencia: una página web del dev (DNS-rebinding/CSRF sobre `http://127.0.0.1:8787`) puede re-dirigir un upstream a `http://evil` y el proxy reenvía el header `authorization` (api key del proveedor) verbatim (`proxy.rs:693-704`).
- `X-Cerberus-Bypass` sin auth cuando no hay token (`proxy.rs:512-520`). Mitigación existente: bind no-loopback exige token fuerte (`proxy.rs:153` + test `non_loopback_listener_requires_strong_admin_token`), el caso vulnerable es el default Mode B.

### R9-6 [ALTO, VERIFIED] ~70% de la superficie CLI del Appendix B no existe — falso el claim §4.6 "parity total"
- Salida real: `./target/release/cerberus --help` → solo `init start stop status license pack mitm scan test doctor`; `cerberus version` → `error: unrecognized subcommand`.
- Faltan: restart, mode, upgrade, agents/wire/unwire, providers, add/remove-provider, packs enable/disable/update, category set, rules list/add/set, allowlist add/list/remove, events, stats, logs -f, config show/edit/path, login, dashboard, validate, reload, allow-once.
- Inversamente, la API/dashboard carece de packs enable/disable y filtros events tool/since (SUSPECTED sin evidencia UI).

## ALTOS

### R9-7 [ALTO, VERIFIED] Allowlist persiste el valor secreto RAW en config.yaml y lo sirve por API
- Matching por igualdad con el literal (`proxy.rs:775-778`); persistido por API (`api.rs:662-671`); `GET /api/allowlist` sin auth (R9-5) lo devuelve. Viola §5 "the raw value is never persisted".

### R9-8 [ALTO, VERIFIED] Zeroization nunca implementada y vault reversible (decisión cerrada §9 #4, Phase 2) es código muerto
- `zeroize`/`secrecy` en ningún Cargo.toml; workspace `unsafe_code = "forbid"` (Cargo.toml:34). `Vault` sin ningún caller fuera de `vault.rs`/`lib.rs` (grep crates/cerberus-proxy, crates/cerberus → 0 hits); `Vault::clear` (vault.rs:127-130) no limpia memoria. `evidence/f2/reversible-vault.md` lo marca BUILT — evidencia falsa vs código.
- Mismo patrón break-glass CLI: `BreakGlass` (break_glass.rs) sin callers fuera de sus tests; `allow-once` no existe en CLI.

### R9-9 [ALTO, VERIFIED] Precision/Recall se mide sobre un product distinto del que se shippea
- `precision_recall_test.rs:31` carga `test-rules.json` (11 rules c/ credit_card y entropy); el default_pack tiene 13 rules, **sin credit-card ni entropy rule** (`pii.email_address`/`pii.phone_number`). El FP/FN del pack real (§5) nunca se midió.
- Test `negative_files_no_false_positives` (precision_recall_test.rs:658-679) **no tiene assert** (solo eprintln WARNING). Comentarios "verified: 94.3%/89.2%" (L551-553) no coinciden con la corrida real: 93.9%/88.6%; categoría alta-entropía 71.4% precisión.

### R9-10 [ALTO, VERIFIED] Logging síncrono a stdout en la hot path
- `proxy.rs:627` → `log_security_event` (INFO/WARN) con subscriber `fmt().init()` (log.rs:71-74): sin `with_writer(non_blocking)` en el repo; un pipe/log redirect lento bloquea el worker (patrón §1.4 que el plan prohíbe repetir).

## MEDIOS

### R9-11 [MED, VERIFIED] Shadow/enforce es global-only; §4.7 exige "globally **and per provider**" (config.rs:109-125 `UpstreamConfig` sin campo mode; 0 hits de per-provider en código y evidencia).
### R9-12 [MED, VERIFIED] `fail_mode: closed-on-critical` (default recomendado §4.1 y ejemplo A.1) no existe: solo `enum FailPolicy { Open, Closed }` (config.rs:100-106); el YAML de A.1 no parsea. Default real: Closed total.
### R9-13 [MED, VERIFIED] Multipart no se decodifica/escanea (§4.2 lo lista en MVP): `decoder.rs:21-26` solo `Json|Text`; 0 hits de multipart en proxy+engine.
### R9-14 [MED, VERIFIED] "<100KB vs hundreds of patterns <1ms" (§5) nunca validado con el pack shippeado: default_pack = 13 rules/14 patterns; el 0.6 ms de `evidence/f0/budget-validation.md` usó 300 patterns sintéticos del spike.
### R9-15 [MED, VERIFIED] Empaquetado vs Phase 8: sin MSI (packaging/winget/README.md:4 "future note"), manifests winget congelados en 0.1.0, `packaging/deb|rpm` existen pero release.yml nunca los build (grep deb → 0), binarios publicados sin firmar cuando faltan credenciales (release.yml:26), Intel macOS dropeado (163ba24…161387a).
### R9-16 [MED, VERIFIED] Hashes SHA-256 sin salt por defecto de los secretos (`engine.rs:119-120`, `daemon.rs:133`; HMAC opt-in) → secretos de baja entropía recuperables offline desde `hashed_values` (`store.rs:696,715`); `redos_fuzz.rs:24` MAX_SCAN_TIME_MS=250 (50-83x el target) subido sin evidencia (163ba24).
### R9-17 [MED, VERIFIED] smoke-test con checks podridos: `tests/smoke-test.sh:237-244` HTTP_CODE sale del exit-status de curl (no del código de respuesta); `:312` el leak-check grephea un archivo log con typo (`cerberus-smock-$PORT.log`, inexistente) → "clean" siempre; `:141` fallo de init tragado por `|| true`. Estos alimentan la evidencia de no-leak (r0/f9).
### R9-18 [MED, VERIFIED] Gobernanza §8B rota: `evidence/gauntlet/index.md` congelado en 09612f2; 35 commits después (incluidas dos subidas de presupuesto) sin Evidence Pack.
### R9-19 [LOW] `crates/cerberus-core/` crate stub muerto (engine_version() retorna literal "0.1.0", test auto-afirmado, 0 dependientes). Feature::Dashboard/Alerts (license.rs:104-121) jamás chequeado fuera de license.rs — gating Pro casi inerte (R9-20 [LOW] `expected_auth: header` de A.1 no se parsea; la impl usa `auth_header`).

## LO LIMPIO (verificado, para balance)
Sin pre-decode base64/hex (fuera de MVP respetado); firma de packs mandatory en todos los install paths (pack.rs:110-144, updater.rs:421); telemetry default off sin datos sensibles (telemetry.rs:59,75-90); TLS upstream validado sin bypasses; ReDoS imposible por diseño (solo crate `regex`, lookaround = error duro engine.rs:171-174) y redos_fuzz sí cubre DEFAULT_PACK_JSON; audit store SQLite bounded + drop-on-full (nunca bloquea la request); caps de body (64 MiB); baseline local fmt/clippy/build/test PASS (~596 tests, 0 fallos, 0 ignored); `#[ignore]` = 0.

## Root-cause común
1) Los gates de verificación miden el camino fácil (scan in-process / corpus alterno / tap con placeholder) y no el camino que se shippea (JSON por-hoja, default_pack real, brew install real). 2) Cuando un gate falló, se subió el umbral en vez de arreglar el código (f1cdab9, 163ba24), sin §8B loop. 3) Features cerradas del plan quedaron como código muerto con evidencia "PASS" (vault, BreakGlass).
