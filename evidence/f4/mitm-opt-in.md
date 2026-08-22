# Evidence Pack — F4/mitm-opt-in

- Fecha: 2026-08-21
- Intento: 6 — FIX loop del P1 de admisión/shutdown reproducido por el review Codex
- Builder/verificación ejecutada: Orca task `task_0d3e85ca25d6`
- Veredicto del FIX focalizado: **PASS del builder**
- Gate Gauntlet: **pendiente de nueva verificación independiente**; este FIX no cierra la unidad ni reemplaza las evidencias de los revisores

## Evidencia del FIX loop — intento 6

| Punto corregido/diagnosticado | Comando ejecutado | Salida citada | Resultado |
|---|---|---|---|
| Reproducción con el test original de 128 sockets y backlog implícito de Tokio/mio (128) | loop `rtk cargo test -p cerberus-proxy connection_limit_covers_active_connect_tunnels_and_recovers_capacity` ×50 | `BASELINE_SUMMARY runs=50 failures=2`; iteración 37: `CONNECT 60/128 ETIMEDOUT`, snapshot `accepted=permits_acquired=jobs_enqueued=jobs_started=60`, `permits_available=68`; iteración 38: índice 117 y 11 permisos libres | ❌ reproducido |
| Hipótesis backlog | `TcpSocket::listen(256)` + mismo test original ×100 | `FIX_SUMMARY runs=100 failures=5` (35/37/67/74/80); en cada fallo `accepted == permits == enqueued == started == índice` y quedaban permisos | ❌ backlog 256 por sí solo no resuelve el loop; no era la causa del ETIMEDOUT |
| Causa validada y test corregido sin ocultar cobertura | lifecycle repetible reserva 112 permits en proceso y ejercita 16 CONNECT reales; stress separado abre 128 CONNECT reales simultáneos con `Barrier` | el fallo siempre ocurre antes de `accept`, nunca por límite/jobs; reducir sólo el churn por corrida elimina el patrón: lifecycle `100/100`, mientras el stress nominal real pasa `10/10` | ✅ |
| Admisión nominal real y backlog explícito | `rtk cargo test -p cerberus-proxy nominal_connect_capacity_is_admitted_under_concurrent_stress` ×10 | `STRESS_SUMMARY runs=10 failures=0`; por corrida `accepted=permits_acquired=jobs_enqueued=jobs_started=active_tunnels=128`, `permits_available=0`; al cerrar, 128 permisos disponibles | ✅ |
| Barrera determinista `send(job) → encolado/no iniciado → shutdown` | `rtk cargo test -p cerberus-proxy shutdown_drains_a_tunnel_job_enqueued_before_it_can_start` ×50 | `SHUTDOWN_SUMMARY runs=50 failures=0`; pre-shutdown `enqueued=1`, `started=completed=0`, `active=1`, 127 permisos; post-shutdown `started=completed=1`, `active=0`, 128 permisos y EOF | ✅ |
| Forward/MITM focal | `rtk cargo test -p cerberus-proxy forward::tests --no-fail-fast`; `rtk cargo test -p cerberus --bin cerberus mitm::tests` | `20 passed, 155 filtered out`; `8 passed, 48 filtered out` | ✅ |
| Suite proxy | `rtk cargo test -p cerberus-proxy --no-fail-fast` | `175 passed (3 suites)` | ✅ |
| Suite binario/daemon | `rtk cargo test -p cerberus --no-fail-fast` | `69 passed (5 suites)` | ✅ |
| Workspace | `rtk cargo test --workspace --no-fail-fast` | corrida final: `585 passed (33 suites, 40.96s)` | ✅ |
| Build/fmt/clippy | `rtk cargo build --workspace --locked`; `rtk cargo fmt --all -- --check`; `rtk cargo clippy --workspace --all-targets -- -D warnings`; `rtk git diff --check` | build exit 0; fmt/diff-check sin salida; clippy `No issues found` | ✅ |

### Causa y diseño comprobable del intento 6

- La instrumentación `índice/accept/permits/jobs` descartó el owner loop: en todos los ETIMEDOUT, el último índice aceptado coincidía exactamente con permits adquiridos, jobs encolados e iniciados, y quedaban entre 4 y 97 permits. El SYN fallido nunca alcanzó `listener.accept()`.
- El test anterior creaba 130 sockets loopback por proceso y el loop adversarial los repetía sin pausa. En macOS ese churn acaba sufriendo throttling/presión TCP local y devuelve ETIMEDOUT aunque el listener y sus permits estén sanos. Los A/B con backlog 256, `SO_REUSEADDR`, zero-linger y puertos fuente fijos siguieron fallando alrededor de las iteraciones 23/37; esos experimentos temporales se retiraron. El A/B que sí elimina el fallo es separar lifecycle repetible (18 conexiones reales por corrida, 100/100) de admisión nominal (128 reales concurrentes, 10/10).
- El listener de producción sí queda endurecido con `TcpSocket::listen(256)`, margen explícito mayor que `MAX_CONNECTIONS=128`. No se atribuye falsamente a este cambio el arreglo del loop; el stress concurrente demuestra que admite los 128 nominales.
- `ForwardTestState` es sólo `cfg(test)` y registra accepts, permits y estados enqueued/started/completed. La barrera pausa el branch receptor del canal sin sleeps; shutdown cierra el receiver, señala cancelación, drena conexiones, arranca el job ya encolado dentro del `JoinSet` y espera su finalización. No queda job detached.
- Se eliminó `ForwardState::tunnel_done`, estado muerto que no tenía lecturas ni participaba en el drain.

### Estado Gauntlet del intento 6

- Este es un Evidence Pack del builder/fixer. El P1 reproducido queda corregido y verificado localmente, pero la unidad **no se declara cerrada**.
- Falta un re-review adversarial independiente que repita los comandos y emita su propio PASS/FAIL. Los archivos de evidencia de revisores permanecen intactos.

## Evidencia histórica del segundo FIX — intento 5

| Punto corregido | Comando ejecutado | Salida citada | Resultado |
|---|---|---|---|
| PEM estricto: un único `CERTIFICATE`, una única `PRIVATE KEY`, sólo whitespace fuera; rechaza duplicados/chain/tags incorrectos/garbage/DER/random/non-CA | `rtk cargo test -p cerberus-proxy ca_loader_consumes_exactly_one_pem_block_and_rejects_garbage` + `... ca_loader_rejects_non_ca_and_cross_algorithm_mismatches` | ambos PASS; suite `forward::tests`: `18 passed, 155 filtered out` | ✅ |
| Mismatch de clave, incluido EC-cert/RSA-key y RSA-cert/EC-key; comparación de SPKI DER completa | mismos tests + `mismatched_ca_pair_fails_closed_before_listener_bind` | fixture RSA válida como control; ambos cruces devuelven `does not match`; mismatch falla con puerto ocupado antes del bind | ✅ |
| `status`, `enable` y config efectiva del daemon rechazan material extra antes de arrancar | `rtk cargo test -p cerberus --bin cerberus mitm::tests` | `8 passed, 48 filtered out`; `strict_ca_material_is_rejected_by_status_enable_and_daemon_runtime` PASS | ✅ |
| CA importada no se re-firma: `rcgen 0.14.9` usa `Issuer::from_ca_cert_der` y leaf `CertificateParams::signed_by` | `rtk cargo tree -i rcgen --locked` + suite TLS | una sola versión `rcgen v0.14.9`; TLS CONNECT firmado por la identidad persistida PASS | ✅ |
| Toolchain/lock | `rtk rustc --version`; `rtk cargo info rcgen@0.14.9`; `rtk cargo metadata --locked --no-deps --format-version 1`; `rtk cargo tree -i x509-parser --locked` | Rust `1.97.1`; rcgen declara MSRV `1.88`; repo/CI usa `stable`; lock resuelve `rcgen 0.14.9` y una única `x509-parser 0.18.1` | ✅ |
| Límite real durante toda la vida del CONNECT/TLS/HTTP; 129.º no recibe 200 y capacidad vuelve al liberar uno | `rtk cargo test -p cerberus-proxy connection_limit_covers_active_connect_tunnels_and_recovers_capacity` ×20 | `20/20`: cada corrida `1 passed`; sin sleeps | ✅ |
| Shutdown cancela cliente estancado antes de ClientHello y supervisa túneles hasta finalizar | `rtk cargo test -p cerberus-proxy shutdown_cancels_connect_stalled_before_client_hello` ×20 | `20/20`: cada corrida `1 passed`; `shutdown(500 ms)` devuelve `Ok` y el socket queda EOF | ✅ |
| Shadow CONNECT+TLS: pass-through byte-a-byte + evento sin secreto | `rtk cargo test -p cerberus-proxy connect_tls_` ×10 | `10/10`, cinco E2E TLS por corrida; shadow recibió body original y `events.len() == 1`, `no_raw_values == true` | ✅ |
| JSON inválido y fallo real de redacción bajo Closed/Open | mismo filtro ×10 | Closed → 502 y upstream sin request; Open → 200 y upstream recibe body original; respuestas/audit no contienen valores crudos | ✅ |
| Suite proxy | `rtk cargo test -p cerberus-proxy --no-fail-fast` | `173 passed (3 suites)` | ✅ |
| Suite binario/daemon | `rtk cargo test -p cerberus --no-fail-fast` | re-run limpio: `69 passed (5 suites)` | ✅ |
| Workspace | `rtk cargo test --workspace --no-fail-fast` | `583 passed (33 suites, 38.84s)` | ✅ |
| Build/fmt/clippy | `rtk cargo build -p cerberus-proxy -p cerberus --locked`; `rtk cargo fmt --all -- --check`; `rtk cargo clippy -p cerberus-proxy -p cerberus --all-targets -- -D warnings`; `rtk git diff --check` | build exit 0; fmt/diff-check sin salida; clippy `No issues found` | ✅ |
| Presupuesto p99 | `rtk proxy cargo test --release --test load_test -- --nocapture` | `7 passed`; peor p99 `1.313 ms` (decode+scan), resto `0.667–1.086 ms`, presupuesto `<5 ms` | ✅ |

### Diseño comprobable del intento 5

- El loader recorta sólo whitespace exterior, exige los delimitadores exactos y consume el primer end marker como final del archivo; cualquier byte no-whitespace, segundo bloque o tag distinto falla.
- El X.509 único debe tener `BasicConstraints CA:TRUE`. La clave única debe ser PKCS#8 `PRIVATE KEY` soportada por el backend ring de rcgen. Se compara `SubjectPublicKeyInfo.raw` del certificado con `PublicKeyData::subject_public_key_info()` de la clave, incluidos `AlgorithmIdentifier` y bit string.
- `LocalCa` ya no contiene un `Certificate` reemitido ni llama `self_signed` al importar. Contiene `Issuer<'static, KeyPair>` creado directamente desde el DER persistido; sólo las leaf efímeras se generan y firman.
- Cada accept adquiere un `OwnedSemaphorePermit`. Un CONNECT válido lo toma de la conexión y lo guarda en `TunnelGuard`; un request inválido lo conserva hasta cerrar esa conexión. Así no existe doble conteo ni liberación al terminar el upgrade Hyper.
- Los túneles se entregan por canal al `JoinSet` propietario del listener. El shutdown cierra el canal, señala cancelación, drena conexiones, agenda jobs ya encolados y espera todos los túneles; TLS accept selecciona señal de shutdown y timeout de 10 s.
- Se mantienen los controles previos: listener loopback, authority exacto, CONNECT sólo a 443, destino fijado por allowlist, `DirectUpstream` impide exposición del control plane y ninguna operación confía la CA automáticamente.

### Observaciones del Gauntlet

- La primera corrida de `rtk cargo test -p cerberus --no-fail-fast` tuvo un fallo aislado fuera del cambio en `platform::tests::process_alive_true_for_current_process`; el test focal pasó 10/10 inmediatamente y la suite completa posterior pasó `69/69`. La corrida workspace posterior también pasó `583/583`.
- Se eliminó `.scratch/mitm-recheck` (156 KiB) tras confirmar en el re-review OpenCode que era HOME/material temporal de esa revisión; contenía únicamente CAs/logs/probe del reviewer, no datos de usuario. No existía `.tmp-f4*`.
- Los archivos de evidencia de revisores no se editaron. El siguiente paso obligatorio es un VERIFY adversarial fresco según §8B; hasta entonces el gate sigue pendiente.

## Evidencia histórica del FIX — intento 4

| P1 corregido | Comando ejecutado | Salida citada | Resultado |
|---|---|---|---|
| Certificado CA A + clave privada CA B se rechazan en `validate_ca_files` y en `spawn_forward_proxy` antes del bind | `rtk cargo test -p cerberus-proxy mismatched_ca_pair_fails_closed_before_listener_bind` | `1 passed, 166 filtered out (2 suites, 0.05s)` | ✅ |
| Límite de conexiones sincronizado por `watch`, sin `sleep(50 ms)` | `rtk cargo test -p cerberus-proxy connection_limit_drops_excess_client` | `1 passed, 166 filtered out (2 suites, 0.04s)` | ✅ |
| Regresión focalizada forward completa | `rtk cargo test -p cerberus-proxy forward::tests` | `12 passed, 155 filtered out (2 suites, 0.08s)` | ✅ |
| Caminos CLI MITM que consumen `validate_ca_files` | `rtk cargo test -p cerberus mitm` | `6 passed, 42 filtered out (4 suites, 0.02s)` | ✅ |
| Calidad | `rtk cargo clippy -p cerberus-proxy -p cerberus --all-targets -- -D warnings` | `No issues found` | ✅ |
| Formato | `rtk cargo fmt --all -- --check` | exit 0, sin diff | ✅ |

## Criterios de aceptación

| Criterio | Comando ejecutado | Salida citada | Resultado |
|---|---|---|---|
| Forward proxy CONNECT/TLS + certificados por host firmados por CA | `rtk cargo test -p cerberus-proxy forward::tests` | `12 passed, 155 filtered out` | ✅ |
| Allowlist exacta; deniega subdominio, puerto distinto de 443 y HTTP plano | mismo comando | casos `connect_rejects_unlisted_host_wrong_port_and_plain_http` PASS | ✅ |
| Redacción antes del upstream, target fijado por CONNECT y sin exposición de `/api/*` local | mismo comando | `connect_tls_redacts_before_forwarding_and_audit_has_no_raw_secret` PASS; el upstream de captura recibió el body redactado aunque el request interior usó `/api/stats` y `Host: attacker.invalid` | ✅ |
| Block fail-closed sin secreto en la respuesta | mismo comando | `connect_tls_uses_host_certificate_and_blocks_without_leaking_secret` PASS (`403`, secreto ausente) | ✅ |
| CA sólo por acción explícita, sin overwrite/trust automático | mismo comando + `rtk cargo test -p cerberus mitm` | `12 passed`; `6 passed` dentro de la suite de `cerberus` (config ausente → disabled/None, CA create-new) | ✅ |
| Clave privada y material CA defensivos | mismo comando | 0600 en Unix; permisos 0644, symlink, missing CA, archivos >1 MiB y cert/key de CAs distintas fallan antes del bind | ✅ |
| Reverse proxy sigue default y config MITM disabled no puede bloquearlo | `rtk cargo test -p cerberus mitm::tests` | config ausente no crea/require CA; config disabled inválido se sanea y produce `None` | ✅ |
| Integración CLI/daemon y shutdown drenado | `rtk cargo test -p cerberus` | `48 passed (4 suites)` | ✅ |
| Regresión completa proxy | `rtk cargo test -p cerberus-proxy` | `166 passed (3 suites)` | ✅ |
| Calidad | `rtk cargo clippy -p cerberus-proxy -p cerberus --all-targets -- -D warnings` | `No issues found` | ✅ |
| Formato | `rtk cargo fmt --all -- --check` | exit 0, sin diff | ✅ |
| Build optimizado | `rtk cargo build -p cerberus --release` | `Finished release profile` | ✅ |
| Presupuesto hot-path p99 < 5 ms | `rtk proxy cargo test --release --test load_test -- --nocapture` | 7/7 PASS; peor p99 observado `0.857 ms` (100 KiB clean), scan+redact `0.795 ms` | ✅ |
| CLI deja inequívoco el opt-in | `rtk proxy ./target/release/cerberus mitm --help` | `init-ca` dice `NO la instala ni confía`; `enable` exige hosts; `trust-instructions` sólo imprime pasos | ✅ |

## Casos adversariales probados

- `CONNECT api.hardcoded.test:443` + TLS confiando únicamente la CA temporal → handshake PASS y certificado SAN válido para ese host.
- Body con `SUPERSECRET-12345678` y regla `block` → HTTP 403; el secreto no aparece en la respuesta.
- Body con `TOKEN-12345678` y regla `redact` → upstream local recibe body distinto y sin token crudo; evento de auditoría pasa `no_raw_values`.
- Request TLS interior intenta `Host: attacker.invalid` → no se reenvía ese Host y el destino continúa fijado por el authority autorizado del CONNECT.
- Request TLS interior usa `/api/stats` → se envía al upstream autorizado; no alcanza el control plane local.
- Subdominio no allowlisted, `CONNECT :8443` y request forward HTTP plano → 403/400/405 respectivamente, sin túnel.
- Listener no-loopback, allowlist vacía, wildcard, IP, URL, credenciales/path/port y más de 64 hosts → validación rechaza.
- CA ausente, clave legible por grupo/otros o ruta symlink → arranque fail-closed antes de escuchar.
- Certificado de CA A combinado con clave privada de CA B → comparación SPKI falla tanto en validación como en spawn; el test mantiene el puerto ocupado para demostrar que el error de mismatch ocurre antes de intentar bind.
- Más de 128 conexiones simultáneas → límite por semaphore; el test espera una marca `watch` emitida por el accept loop al adquirir los 128 permits, sin sleeps ni carreras temporales.
- Shutdown → cierra admisión y notifica/cancela túneles antes de cerrar el audit store.

## Diseño/archivos

- `crates/cerberus-proxy/src/forward.rs`: CA, validación, certificados por host, CONNECT/TLS, límites y lifecycle.
- `crates/cerberus-proxy/src/proxy.rs`: destino directo inyectado por el CONNECT; reutiliza scan/redact/fail-policy/audit sin aceptar target desde headers internos.
- `crates/cerberus/src/mitm.rs`: estado/config opt-in, comandos de CA/enable/disable/status e instrucciones manuales.
- `crates/cerberus/src/main.rs`: CLI `cerberus mitm ...`.
- `crates/cerberus/src/daemon.rs`: listener forward opcional junto al reverse default y shutdown coordinado.

## Límites y gaps declarados

- La nueva verificación independiente exigida por §8B sigue pendiente; este artefacto documenta el FIX y evidencia reproducible del builder, no cierra el gate de unidad.
- En esta máquina sólo está instalado el target `aarch64-apple-darwin`; la matriz macOS/Linux/Windows pertenece también a la unidad F4 `windows-support` y no se ejecutó aquí. Rustls/rcgen son portables; en Windows la clave hereda la DACL del perfil del usuario, mientras Unix se valida explícitamente a 0600.
- No se modifica ningún trust store. Confiar la CA y configurar `HTTPS_PROXY` en la tool son pasos humanos deliberados; una tool que ignore ambos sigue siendo la limitación documentada por el plan.
- No se llamó a proveedores externos: las pruebas TLS usan upstreams locales deterministas y una ruta bloqueada que nunca debe salir a red.
- Gap de tooling: TokenSave 7.8.1 marcó `unwrap()` dentro de `#[cfg(test)] mod tests` como `in_test: false` aun con `exclude_tests=true`. Conviene abrir un issue en <https://github.com/aovestdipaperino/tokensave> describiendo esa clasificación; quitar primero cualquier código sensible o propietario del reporte.
