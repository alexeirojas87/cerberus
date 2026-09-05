# Plan de remediación — Review 9 / release blockers

- Estado inicial: **FAIL; release freeze activo**.
- Fuente de verdad: `CERBERUS_PRODUCT_BUILD_PLAN.md`, especialmente §4, §5, §8, §8B, §9 y Appendix B.
- Alcance: solo requisitos MVP y fallos que bloquean una aceptación ya cerrada.
- Fuera de alcance: NER, streaming response scanning, base64/hex/url decoding, alertas y demás Post-GA; también higiene no bloqueante como `cerberus-core` o deduplicaciones cosméticas.

## 0. Correcciones al diagnóstico y reglas de ejecución

1. R9-1 se divide en dos afirmaciones:
   - **VERIFIED:** regex multiline y entropy se recompilan durante cada scan; JSON redaction hace un scan por hoja y normaliza repetidamente el contexto completo.
   - **NEEDS REPRODUCTION:** el valor 38.9 ms p99 no se puede cerrar como VERIFIED hasta archivar comando, probe, salida raw, hardware, SHA y configuración.
2. R9-4 se reemplaza por el problema comprobado: la fórmula local está podrida, pero el tap público tiene v0.1.1 con SHA reales. El bloqueo es **tap atrasado respecto de v0.1.2 + automatización sin evidencia + ausencia de clean-install gate**, no “checksum placeholder hace imposible todo brew install”.
3. Se remediarán R9-1/2/3/5/6/7/8/9/10/11/12/13/14/15/17/18/20 y la distribución corregida de R9-4. R9-16 entra solo por hashes recuperables; el timeout de fuzz no se equipara arbitrariamente al presupuesto p99.
4. Se invalida cualquier PASS previo de una unidad reabierta. No se edita un Evidence Pack viejo para hacerlo parecer vigente: se crea un intento nuevo con el SHA exacto.
5. Se respeta el DAG: **F1 → F2 → F3 → F4 → F5 → F6 → F7 → F8 → F9**. Una fase no empieza ni se declara verde hasta que la anterior tiene todos sus units PASS, Evidence Packs y revisión de integración.
6. Al cerrar cada fase: detener ejecución y pedir sign-off del owner. No se mueve ningún umbral ni se elimina ningún requisito cerrado para obtener PASS.
7. Cada unit usa builder y reviewer distintos. Latencia, detección, memoria y seguridad requieren panel correctness/security/performance y mayoría para PASS. Tras 3 intentos fallidos: ESCALATE.

## G0 — Contención antes de tocar código

### G0.1 Congelar publicación

- Desactivar temporalmente la publicación automática de releases; mantener disponibles las releases existentes.
- No crear tags GA ni actualizar taps/manifests hasta que F9 pase.
- Abrir un tracking checklist con cada unit y su Evidence Pack esperado.

### G0.2 Poner la evidencia en estado honesto

- Marcar los PASS afectados de F1–F9 como `SUPERSEDED/INVALIDATED BY REVIEW9` sin borrar su historia.
- Registrar HEAD, rama, toolchain, OS/arquitectura y hashes de packs/corpora para cada nueva corrida.
- Conservar `evidence/review9/gauntlet-findings.md` como informe de descubrimiento, no como sustituto de los Evidence Packs por unit.

### Gate G0

- Release workflow incapaz de publicar accidentalmente.
- Índice de evidencia identifica claramente qué PASS están invalidados.
- Owner aprueba el alcance y autoriza abrir F1.

---

## F1 — Detection engine y métricas del producto real

### F1.1 Precompilación del engine

**Implementación**

- Compilar en `EngineBuilder::build()` todos los patrones multiline y almacenarlos en `CompiledEngine`; ningún `Regex::new` queda en `scan*()`.
- Compilar una sola vez el detector de keywords de entropy, como campo del engine o estático inmutable.
- Mantener el comportamiento de prefijos, solapamientos, validators, actions y findings.

**Pruebas/evidencia**

- Test que pruebe que construir el engine compila y que N scans no vuelven a compilar.
- Suite completa del engine, multiline y entropy.
- Perfil before/after con flamegraph o contador equivalente que pruebe la desaparición de `Regex::new` del hot path.
- Evidence Pack: `evidence/f1/r9-regex-compiler.md`.

### F1.2 Pack shippeado y precision/recall honesto

**Implementación**

- Separar dos harnesses:
  - unit-features puede seguir usando `test-rules.json`;
  - product-gate debe cargar exactamente `DEFAULT_PACK_JSON`/artefacto firmado que se distribuye y registrar su SHA-256.
- Incorporar credit-card + Luhn porque el plan exige PII estructurada y paridad migrada, no para enseñar al test.
- Convertir generic entropy en configuración de producto explícita o documentar y probar su condición virtual; no duplicar detectores.
- Hacer que el corpus negativo falle con asserts; eliminar porcentajes escritos a mano y generar el reporte desde la corrida.
- Medir precision/recall por categoría y por flag, no solo el agregado.

**Decisión requerida antes del gate**

- §5 no fija números exactos por categoría. El owner debe confirmar los thresholds; 90% recall / 85% precision actuales son una propuesta, no una decisión cerrada.

**Decisión del owner — 2026-08-27:** confirmados recall `>= 90%` y precision `>= 85%` tanto por categoría como por flag. Los agregados son informativos y no pueden compensar ni ocultar el fallo de una categoría o flag evaluable.

**Pruebas/evidencia**

- Positivos, negativos, allowedExamples, contextKeywords, Luhn y entropy.
- Reporte machine-readable con TP/FP/FN, corpus version/hash y pack version/hash.
- Evidence Pack: `evidence/f1/r9-production-pack-pr.md`.

### F1.3 Throughput del engine

- Benchmark release de 100 KB contra el default pack y la máxima combinación de packs MVP soportada, con cientos de patterns y fingerprint estable.
- Warm-up, al menos 1,000 muestras, runner controlado y resultados p50/p95/p99.
- Gate cerrado: scan de 100 KB / cientos de patterns `< 1 ms` según §5. Si falla, FIX o ESCALATE; no cambiar el umbral.
- Evidence Pack: `evidence/f1/r9-engine-throughput.md`.

### Gate F1 — STOP + sign-off

- F1.1–F1.3 PASS independientes.
- Integrador reproduce P/R y benchmark desde checkout limpio.
- Solo entonces se abre F2.

---

## F2 — Redaction, vault, zeroization y break-glass

### F2.1 JSON redaction correcta y eficiente

**Implementación**

- Parsear JSON una sola vez en el pipeline.
- Precalcular una sola representación normalizada del contexto para `contextKeywords`.
- Mantener el scan por hoja tras F1.1 y perfilarlo primero. Solo si sigue fuera de presupuesto, introducir batching con mapa explícito `buffer offset → leaf + decoded offset` o parser que preserve source spans.
- Nunca aplicar offsets del JSON raw directamente sobre `serde_json::Value`: escapes Unicode, claves, strings repetidos y límites entre hojas deben conservar semántica.

**Casos obligatorios**

- JSON 50 KB con 1, 37 y ≥1,000 hojas; limpio, redact, block y warn.
- Keyword en otra hoja; claves que parecen secretos; strings escapados; Unicode; valores repetidos; arrays/objetos anidados; JSON inválido y fallback text.
- El upstream recibe JSON válido y ningún secreto block/redact llega raw.
- Evidence Pack: `evidence/f2/r9-json-redaction.md`.

### F2.2 Vault reversible real y memory hygiene

**Implementación**

- `reversible_redaction` sigue opt-in y default false, como decisión cerrada §9 #4.
- Vault limitado al ciclo de vida request/response, con capacidad/TTL; no global ilimitado ni IDs predecibles `v1`.
- Valores secretos en contenedores `Zeroizing`/`SecretString` o equivalente; evitar clones; zeroize al consumir, expirar, clear y Drop.
- Un-redaction solo para respuestas no-streaming soportadas en MVP; streaming permanece fuera de alcance y debe fallar/documentarse sin filtrar.
- Nada del vault se persiste ni se loggea.

**Pruebas/evidencia**

- Round-trip local opt-in, default irreversible, aislamiento entre requests, expiración/cap, token no adivinable, no disk/log leak y prueba observable de zeroization de buffers poseídos.
- Code review específico de copias de secretos y Drop paths.
- Evidence Pack: `evidence/f2/r9-reversible-vault-zeroization.md`.

### F2.3 Allow-once/break-glass real

- Implementar primitive server-side autenticada: nonce criptográfico, TTL corto, scope explícito y consumo atómico exactamente una vez bajo concurrencia.
- El bypass por header y el futuro CLI comparten la misma auditoría; sin admin token válido no hay bypass.
- Guardar razón truncada/hasheada, nunca raw si puede contener secretos.
- Tests: válido, ausente, expirado, replay, dos requests concurrentes, provider equivocado y evento auditado.
- Evidence Pack: `evidence/f2/r9-break-glass.md`.

### Gate F2 — STOP + sign-off

- Redaction JSON, vault/zeroization y break-glass PASS.
- Revisor de seguridad reproduce no-leak, replay y memory-lifecycle cases.
- Solo entonces se abre F3.

---

## F3 — Proxy completo y presupuesto HTTP real

### F3.1 Decoder MVP completo

- Añadir multipart/form-data con boundary parsing bounded, scan/redaction solo de partes textuales y preservación exacta de binarios/metadatos.
- Casos: múltiples partes, filename/Content-Type, boundary malformado, body truncado, secreto cruzando chunks y límite de tamaño.
- Evidence Pack: `evidence/f3/r9-multipart-decoder.md`.

### F3.2 Policy operacional

- Añadir `mode: shadow|enforce` por `UpstreamConfig`, con fallback al global.
- Añadir `FailPolicy::ClosedOnCritical` y hacerlo default conforme §4.1/Appendix A; conservar `open` y `closed` configurables.
- Parsear de forma compatible los nombres del Appendix A (`expected_auth`/`auth_header`) o corregir formalmente un único wire name.
- Tests de matriz provider × mode × severity × engine failure.
- Evidence Pack: `evidence/f3/r9-provider-mode-fail-policy.md`.

### F3.3 Gate de latencia end-to-end

**Harness obligatorio**

- Binario release, proxy HTTP real → mock upstream, y baseline directo al mismo mock.
- Alternar corridas direct/proxy para evitar drift; conexiones y concurrencia documentadas; warm-up; ≥2,000 muestras por escenario.
- Reportar `p99(proxy)`, `p99(direct)`, su diferencia y, si se instrumenta, p99 interno del handler. Conservar histogramas/raw samples.
- Escenarios: text y JSON 50 KB, 1/37/≥1,000 hojas, clean/redact/block, shadow/enforce, default pack y máxima combinación MVP.
- Logging activado y prueba adicional con sink lento/cola saturada.
- Referencia de producto en runner/hardware controlado; CI compartido puede tener regression guard separado, pero nunca sustituye el gate oficial.

**Criterio cerrado**

- Proxy overhead p99 `< 5.0 ms` para prompts ≤50 KB. `tests/load_test.rs` vuelve a 5 ms para el criterio aplicable; los microbench scan-only quedan etiquetados como tales.
- Si falla: volver a F1/F2/F3 FIX o ESCALATE; prohibido elevar 5 ms.
- Evidence Pack: `evidence/f3/r9-http-latency.md` y actualización explícita de la evidencia F9 que quedó stale.

### Gate F3 — STOP + sign-off

- F3.1–F3.3 PASS.
- Panel correctness/security/performance reproduce proxy transcript y benchmark; mayoría requerida.
- Solo entonces se abre F4.

---

## F4 — Cerberus Local seguro y cross-platform

### F4.1 Bootstrap de credenciales

- `cerberus init` genera admin token y claves HMAC con CSPRNG antes de levantar el listener.
- Persistencia atómica con permisos mínimos; usar keychain/credential store cuando esté disponible y fichero separado `0600` como fallback documentado.
- Primer start sin credenciales genera/persiste de forma segura o falla cerrado; jamás arranca API mutable abierta.
- Rotación conserva migración explícita y auditable.

### F4.2 Lifecycle, agents y feedback

- Completar `restart`, `agents`, `agents wire/unwire`, status real y feedback de block/redact conforme Appendix B/F4.
- Windows/macOS/Linux: init, start, status, restart, stop y wire/unwire sin depender de rutas HOME incorrectas.

### F4.3 Smoke test sano

- Quitar `|| true` de init.
- Capturar HTTP real con `curl -o ... -w '%{http_code}'` y asertar body/status.
- Corregir `smock`→`smoke`; enumerar todos los logs/store inspeccionados y fallar si falta un archivo esperado.
- Añadir cleanup determinista y `set -euo pipefail` sin ocultar errores.

### Gate F4 — STOP + sign-off

- Clean-home transcript en macOS, Linux y Windows.
- Dev recibe feedback; raw secret ausente en upstream/log/disk.
- Evidence Packs: `evidence/f4/r9-secure-init.md`, `r9-local-lifecycle.md`, `r9-smoke.md`.
- Solo entonces se abre F5.

---

## F5 — Audit/logging no bloqueante y hashes resistentes

### F5.1 Logging fuera del hot path

- `tracing_appender::non_blocking` o equivalente con cola bounded y modo lossy para no bloquear requests.
- Mantener `WorkerGuard` durante toda la vida del proceso y flush bounded en shutdown.
- Evitar construir `flags/categories/hashes` si el nivel está deshabilitado.
- Contador/aviso agregado de mensajes descartados, sin secretos.
- Test con writer bloqueado y cola saturada: la request sigue dentro del presupuesto.

### F5.2 Audit hashes keyed por default

- HMAC-SHA256 versionado con clave por instalación, normalización estable y domain separation distinta de allowlist/bypass.
- Env override solo para operación explícita/test; no default silencioso.
- Migración de hashes previos sin pretender re-hashear valores raw ya descartados; documentar el cambio de deduplicación.
- Verificar que valores de baja entropía no son recuperables con una tabla de SHA-256 simple.

### Gate F5 — STOP + sign-off

- Writer lento/saturado no bloquea hot path; SQLite sigue bounded/drop-on-full.
- Grep de logs/DB/config demuestra cero secretos raw.
- Evidence Packs: `evidence/f5/r9-nonblocking-logging.md`, `r9-keyed-audit-hashes.md`.
- Solo entonces se abre F6.

---

## F6 — Control plane, allowlist y paridad CLI/dashboard

### F6.1 Auth fail-closed y anti-rebinding

- Todos los `/api/*` que sirven datos o mutan estado exigen admin token; solo dashboard HTML estático y health quedan públicos.
- Si falta token, mutation/data API responde 401 aun en loopback.
- Validar `Host`/authority contra una allowlist exacta: loopback + puerto real en Mode B; hostnames públicos configurados explícitamente, sin wildcards, en Mode A.
- Para mutaciones browser: validar Origin same-origin o contra una allowlist exacta de Mode A, exigir `application/json`, rechazar content types simples y no habilitar CORS amplio.
- CLI/curl sin Origin siguen permitidos únicamente con token válido.
- Validar URL/scheme de upstream y preservar la exclusión de admin headers al forward.
- Definir el login del dashboard sin token en URL ni HTML: prompt/bootstrap local y credencial solo en memoria/session scope; probar que refresh/logout no la filtra a logs o terceros.

**Adversarial tests**

- DNS-rebinding Host, Origin extranjero, `text/plain` simple POST, preflight, token ausente/incorrecto, Authorization del proveedor y admin token separados.
- PoC cambia upstream antes del fix y queda bloqueado después; el provider Authorization nunca llega al host atacante.
- Evidence Pack: `evidence/f6/r9-control-plane-security.md`.

### F6.2 Bypass protegido

- `X-Cerberus-Bypass` se ignora/rechaza cuando no existe token configurado o el request no presenta `X-Cerberus-Admin-Token` válido.
- Authorization del proveedor nunca autentica bypass ni se sobrescribe.
- Reusar y probar la primitive one-shot de F2.3.

### F6.3 Allowlist sin raw secrets

- Persistir fingerprints `hmac-sha256:v1:<digest>` con normalización y domain-separated installation key.
- Matching y remove computan el HMAC del candidato; respuestas API nunca devuelven el literal original.
- Definir representación UI segura (flag/label opcional + digest truncado), ya que un hash no permite reconstruir `list`.
- Migración idempotente: distinguir raw legado de formato versionado, convertir bajo lock, persistir atómicamente, backup con permisos mínimos y destruirlo tras sign-off explícito.
- Tests de add/list/remove, restart, duplicate, key rotation, config/disk/log leak y fixtures legados.
- Evidence Pack: `evidence/f6/r9-hmac-allowlist.md`.

### F6.4 Matriz Appendix B: API → CLI → dashboard

- Crear `evidence/f6/appendix-b-parity-matrix.md` con una fila por comando y columnas API, CLI, UI, auth, test y estado.
- Dividir builders por unidades, no un mega-cambio:
  1. lifecycle/version/upgrade/mode/allow-once;
  2. agents/providers;
  3. packs/categories/rules/allowlist;
  4. events (`provider/tool/since`), stats (`provider/tool/flag`) y logs `-f`;
  5. config/login/dashboard/validate/reload;
  6. UI equivalente y hot-reload para cada acción.
- Normalizar `pack` vs `packs` con alias de compatibilidad y completar `cerberus version` además de `--version`.
- Cada comando debe probar estado antes/después mediante la misma Config API y tener equivalente UI verificable.
- Para `upgrade` y `login`, F6 entrega el contrato funcional probado contra repositorio/issuer local; F8 vuelve a verificarlos contra artefactos y entitlements reales. No se aceptan comandos placeholder.

### Gate F6 — STOP + sign-off

- PoCs CSRF/DNS rebinding/exfiltration bloqueados.
- Allowlist no contiene raw values en config/API/logs.
- 100% de filas del Appendix B aplicables al MVP en PASS, con screenshots/transcripts y hot-reload.
- Integrador contrasta API, CLI, dashboard y YAML sobre el mismo estado.
- Solo entonces se abre F7.

---

## F7 — Packs: revalidación tras cambiar el engine

- Ejecutar firma, install, update, rollback y hot-reload de todos los packs MVP contra el nuevo `CompiledEngine`.
- Todos pasan el mismo fuzz y benchmark; registrar pack hashes y cantidad de rules/patterns.
- Confirmar que el pack usado por P/R y el distribuido son byte-identical.
- Evidence Pack: `evidence/f7/r9-pack-integration.md`.

### Gate F7 — STOP + sign-off

- Pack signing/update/rollback PASS con integración independiente.
- Solo entonces se abre F8.

---

## F8 — Release, installers, firmas y entitlement gating

### F8.1 Flujo compatible con rama protegida

- El version bump entra mediante PR y todos los required checks; el release workflow nunca hace push a `main`.
- Publicación disparada por tag `v*` sobre commit ya mergeado.
- Validar antes de build: tag semver == versión de `crates/cerberus/Cargo.toml` == lock/package metadata.
- Todos los jobs hacen checkout del tag/SHA del evento, no `main` mutable.
- Probar workflow con dry-run/no-publish y luego release candidate explícita.

### F8.2 Artefactos e integridad requeridos

- Construir brew/curl, `.deb`, `.rpm`, winget/MSI y artefactos macOS/Linux/Windows que §8 exige.
- Firmas verificables: macOS codesign/notarization, Windows Authenticode y firma detached verificable para binarios/paquetes Linux.
- Credencial ausente = FAIL/ESCALATE; no publicar unsigned con una nota.
- Generar SHA256SUMS desde los artefactos finales firmados.

### F8.3 Tap Homebrew real, sin doble fuente podrida

- Hacer del template generado la única fuente o añadir drift test que impida que `contrib/homebrew/cerberus.rb` diverja del tap.
- Reparar `notify-tap`/repository_dispatch, autenticarlo y esperar a que el tap actualice la misma versión y SHA.
- Gate real: `brew install alexeirojas87/cerberus/cerberus`, `brew test`, `cerberus --version` y checksum sobre máquinas limpias soportadas; no `grep -v 0000`.

### F8.4 Licensing/entitlements

- Conectar capabilities Pro a los paths reales correspondientes sin bloquear funciones Free prometidas.
- Tests Free/Pro/expired/invalid/offline y `login`; dashboard y CLI muestran el mismo entitlement.

### Gate F8 — STOP + sign-off

- Install logs y signature verification en macOS, Linux y Windows.
- Tag/release/tap/manifests/versiones consistentes y artefactos descargables.
- Pro correctamente gated, Free intacto.
- Evidence Packs: `evidence/f8/r9-tag-release.md`, `r9-installers-signing.md`, `r9-homebrew-live-install.md`, `r9-entitlements.md`.
- Solo entonces se abre F9.

---

## F9 — Gauntlet final de producto

### F9.1 Baseline reproducible

- `cargo fmt --check`.
- `cargo clippy --workspace --all-targets -- -D warnings`.
- `cargo build --release --workspace`.
- `cargo test --workspace --all-targets` en macOS/Linux/Windows.
- Smoke, failsafe y fuzz sin `|| true`, archivos inexistentes ni thresholds ocultos.

### F9.2 Panel adversarial

Cinco revisores independientes:

1. build/CI/release/installers;
2. seguridad/control plane/no-leak/zeroization;
3. plan-compliance/CLI-dashboard/MVP scope;
4. performance/HTTP p99/slow sink;
5. detection/P-R/fuzz/packs.

Cada reviewer entrega comando exacto, salida raw, SHA, ambiente y criterio. `could not run` = FAIL.

### F9.3 Verificación cruzada del integrador

- Reejecutar una muestra material de cada dominio desde checkout limpio.
- Comprobar que Evidence Packs corresponden al HEAD/tag candidato y no citan outputs de commits previos.
- Contrastar release assets/tap/manifests contra hashes descargados.
- Emitir `evidence/review9/final-gauntlet.md` con una fila por acceptance criterion y enlaces a raw artifacts.

### Gate final — STOP + sign-off de release

Solo se permite crear/publicar el tag GA cuando:

- todas las unidades F1–F9 tienen PASS vigente;
- cada fase tiene integration PASS y sign-off del owner;
- p99 producto `<5 ms`, P/R del pack real cumple thresholds aprobados y todos los PoCs de seguridad fallan de forma segura;
- instalación y firma están verificadas en los tres OS;
- no quedan críticos/altos abiertos ni evidencia stale.

## Orden resumido y ruta crítica

```text
G0 freeze/evidence
  → F1 engine + production P/R
  → F2 redaction + vault + break-glass
  → F3 proxy/multipart/policy + HTTP p99
  → F4 secure local bootstrap + cross-platform smoke
  → F5 non-blocking audit/logging + keyed hashes
  → F6 control-plane security + HMAC allowlist + total parity
  → F7 pack revalidation
  → F8 protected-tag release + installers/signing/tap/gating
  → F9 adversarial panel + integrator
  → owner release sign-off
```

No hay carriles paralelos entre fases. Dentro de una fase solo pueden ejecutarse units en paralelo si no comparten archivos/contratos y el integrador confirma que no adelantan trabajo de una fase dependiente.
