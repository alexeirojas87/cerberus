# Evidence Pack — F4/mitm-opt-in: RE-VERIFICACIÓN adversarial tras FIX task_8a01ca0ed1d6

- Revisor: OpenCode worker `task_e25355055a0f` (independiente del fixer)
- Checkout: `HEAD 09612f2` + working tree actual; **sin commit, sin edición de source**
- Entrada: `evidence/f4/mitm-opt-in-review-opencode.md` (2 × P1 reproducidos)
- Fecha: 2026-08-21/22
- Veredicto del re-review: **PASS (2 × P1 corregidos)** · 0 × P0/P1 nuevos en alcance F4/mitm-opt-in
  - `P1-1` (cert CA-A + key CA-B) → **rechazado** en `status`/`enable`/`daemon start` antes del bind. ✅
  - `P1-2` (límite de conexiones temporal por `sleep(50 ms)`) → **eliminado**; barrera determinista vía `watch`. ✅

## Contexto / método

- Gráfico indexado (`graft build --deep`) antes de leer source; shell con `rtk`; TokenSave/headroom activos.
- Fuentes revisadas en `crates/cerberus-proxy/src/forward.rs` y `crates/cerberus/src/mitm.rs` + puntos de consumo
  en `daemon.rs:295/505-521`, `main.rs:247-265`. No se editó source.
- Trabajo empírico 100% sobre HOME aislado dentro del workspace (`.scratch/mitm-recheck/`), binario
  `target/release/cerberus` recompilado en el momento.
- Las suites se ejecutaron sin respald propias globales; `HOME` aislado por test salvo `trust_help…`.
- Loading del re-check: los 2 P1 se reprodujeron empíricamente ANTES y DESPUÉS del fix en el material CA
  real (cert A + key B).

## P1-1 — Par CA cert/key inconsistente: ANTES vs DESPUÉS

### Antes (reproducido en el review previo, `mitm-opt-in-review-opencode.md` §P1-1)
- `LocalCa::load` reconstruía el cert con la key ajena sin comparar SPKI → `start`/`status`/`enable` con
  cert CA-A + key CA-B pasaban silenciosamente y el listener MITM arrancaba con material inconsistente.

### Ahora — código (`forward.rs`)
- `LocalCa::load` compara `persisted_cert.public_key().raw != key.public_key_der()` (`forward.rs:265-267`)
  y `self_signed` falla si no (comentarios `forward.rs:268-270`).
- Test adversarial nuevo incorporado por el builder: `mismatched_ca_pair_fails_closed_before_listener_bind`
  (`forward.rs:660-685`) — usa dos CAs generadas y se queda con puerto ocupado para demostrar Err **antes del bind**.
- Consumidores: `validate_ca_files` → `LocalCa::load` (`forward.rs:187-189`); `runtime_config_from`
  (`mitm.rs:71-82` → `validate_ca_files`), `mitm::enable` (`mitm.rs:99-101`), `status` (`mitm.rs:135-137`),
  `spawn_forward_proxy` (`forward.rs:365` → `LocalCa::load`), daemon (`daemon.rs:295,505-506`).

### DESPUÉS — evidencia empírica (CLI real, HOME aislado `…/.scratch/mitm-recheck/home-p1`)
Secuencia `cerberus mitm init-ca` (CA-A) → `openssl genrsa/req` CA-B → `cp` key B sobre
`~/.cerberus/ca/cerberus-ca.key` (cert queda CA-A). Fingerprints distintos:
  - key A `MD5 1192256aa23b0f73e2e9aca192129788` vs key B `MD5 c2120666c5ceaa8dd6601751474bf988` (públicos distintos).

| Camino | Comando | Salida observada | RC |
|---|---|---|---|
| `status` | `cerberus mitm status` | `CA=not ready (CA certificate does not match private key)` | 0 |
| `enable` | `cerberus mitm enable --host api.openai.com` | `mitm command failed: CA not ready (CA certificate does not match private key); run… init-ca` | 1 |
| start/daemon | `CERBERUS_UPSTREAM_URL=… cerberus start --port 18787` | `start failed: CA certificate does not match private key` · sin pid file · **0 listeners 8787/8788/18788** | 1 |
| RC distinto a la nube | `Cerberus MITM opt-in corriendo en 127.0.0.1:8788` (control con par correcto) | listeners 18787 + 8788 up | 0 |

Control positivo: restaurar key A → `status=CA ready`, `start` levanta listener MITM `127.0.0.1:8788`
`(`Cerberus MITM opt-in corriendo en 127.0.0.1:8788`)` y reverse `18787`.
→ Rechazo en los 3 caminos exigidos y **antes del bind**. ✅

Bonus: mezcla RSA-cert (CA:TRUE) + key P-256 ajena → `CA certificate does not match private key` (fail-closed).
Diferentes algoritmos caen por el mismo check. ✅

## Key findings — P1-2 — límite de conexiones sín determinista

### Antes
- `outro forward.rs:889` contenía `tokio::time::sleep(Duration::from_millis(50))` como barrera temporal.

### DESPUÉS — código citado
- `sleep` eliminado de todo `forward.rs`: `grep -n sleep` → 0 matches.
- Barrera determinista: `ManagedForwardProxyHandle::wait_until_connection_limit_reached`
  (`forward.rs:331-340`) espera `watch` de `admitted_connections`; el accept loop hace
  `admitted_connections.send_replace(MAX_CONNECTIONS - permits.available_permits())`
  cuando adquiere un permit (`forward.rs:438-445`); el test espera la marca antes de enviar el cliente
  extra (`forward.rs:936-963`). Sin sleeps ni carreras temporales.
- `Semaphore(MAX_CONNECTIONS)` y `try_acquire_owned` → descartar stream si no hay permit
  (`forward.rs:428,438-442`).

### Ejecución repetida
- 30/30 green en serie limpia (0.02-0.12 s). Con 2 fallos en 40 corridas bajo carga exploratoria,
  ambos **en el cliente** `TcpStream::connect` → `Os { code: 60, kind: TimedOut }` en `forward.rs:948`
  (handshake TCP), no en la aserción del límite; desaparecen tras carencia de TIME_WAIT (`.scratch`
  `netsts` 981 → `failures=0/20` tras `sleep 45`). → conclusión: **la aserción del límite es determinista**;
  el fallo residual es una saturación efimeral del rango de puertos en esta máquina bajo bucle apretado,
  no una dependencia temporal del test.
- Idem suite `mitm`: `22/24` corridas `8/0`, 1 corrida `7/1` (ver nota baseline FL-3, test fuera de F4).

→ PASS. El claim "más de MAX_CONNECTIONS conexiones → límite por semáforo" es reproducible y determinista.

## Criterios de aceptación F4 (jurisdicción mitm-opt-in) — re-ejecutados

| Criterio | Comando | Salida citada | Resultado |
|---|---|---|---|
| Par CA cert/key inconsistente se rechaza en validate/status/enable/before-bind | `cargo test -p cerberus-proxy --lib mismatched_ca_pair…` x10, CLI status/enable/start | 10/10 `ok. 1 passed`; CLI rc=1 `does not match`; start rc=1 sin listener | ✅ |
| CONF connect 443 + cert por host | `cargo test -p cerberus-proxy forward::tests` | `12 passed; 0 failed` (117 filtrados) | ✅ |
| 3×3 transporte E2E contra daemon real | Python raw-socket contra `127.0.0.1:8788` (daemon aislado, reverse `--port 18787`) | allowed → `HTTP/1.1 200`; subdominio → `403 Forbidden`; puerto≠443 → `400`; HTTP plano → `405` | ✅ |
| Fail-closed antes del bind (missing/symlink/perms/oversize/mismatch) | `forward::tests` + CLI adversarial | `mismatched… f previo a bind (test porte ocupado)`; campos 644/sym/oversize/mismatch → Err pre-bind | ✅ |
| No expone `/api/*` local; destino fijado por CONNECT; no puede Host interior anular | `forward::tests` `connect_tls_redacts_before…_no_raw_secret` | PASS (URL `/api/stats`, `Host: attacker.invalid`, upstream captura dest fijado) | ✅ |
| Block fail-closed sin leak en respuesta; redact sin raw en upstream ni audit | `forward::tests` (2 casos TLS) | PASS 403/redact, audit `no_raw_values` | ✅ |
| Symlink/perms/oversize | `forward::tests` | `symlinked…`, `insecure_ca_key_permissions…`, `oversized…` PASS | ✅ |
| Loopback obligatorio, allowlist no-wildcard, CONNECT solo 443 | unit + E2E 3×3 | PASS (0.0.0.0 rechazado unit; probe 403/400/405) | ✅ |
| CA solo por acción explícita, create-new, sin trust automática | CLI `init-ca` 2ª vez + `mitm` suite | `refusing to overwrite` rc=1; suite PASS | ✅ |
| Fail-closed inicial con MITM enabled sin CA | `runtime_config_from` + `forward` suite | `missing_ca_…`, `CA not ready` (unit y daemon) | ✅ |
| Disabled no bloquea reverse | config ausente → `None` (unit `absent_config…`) | PASS | ✅ |
| Shutdown drena admisión + túneles antes del store | `ManagedForwardProxyHandle::shutdown(grace)` + daemon `daemon.rs:572-583` | PASS (suite; stop CLI real limpia 18787+8788) | ✅ |

## Seguridad — revisión adversarial del parser X.509/SPKI y material CA (CLI real)

| Caso | Entrada | `status` resultante |
|---|---|---|
| 0 | par correcto (control) | `CA=ready` |
| 1 | trailing binario (`\x00\x01TRAILING…`) tras PEM | `ready` (aceptado) |
| 2 | 2 bloques PEM concat | `ready` |
| 3 | texto trailing tras PEM | `ready` |
| 4 | cert leaf non-CA | `configured certificate is not a CA` (fail-closed) |
| 5 | DER binario | `cannot read CA PEM: stream did not contain valid UTF-8` |
| 6 | random 512 B | idem 5 |
| 7 | garbage leading + PEM | `ready` |

**Nota:** los patrones 1-3 y 7 (PEM válido + contenido extra adelante/atrás) se toleran — `from_ca_cert_pem`
toma el primer bloque y el resto se ignora. Estratotra: la aceptación del material NO es un hueco, porque
el SPKI de ese primer bloque debe igualar la clave (falla cualquier mezcla real); pero un archivo
aparentemente limpio mezclado con dorso extra se acepta. Valorando la simetría con `read_ca_file`
(únicamente `is_file`, no `is_x509_only`): **P3 (bajo)** — no abre ninguna vía de compromiso con la clave
600/perm-check + mismatch SPKI + create_new de CA. Se sugiere al builder considerar reemplazar por decodificción
estricta del bloque único para robustez, si se quiere.
- `x509_parser::pem::parse_x509_pem` + `parse_x509` + `from_ca_cert_pem` fallan-closed ante DER/random/
non-CA; nunca hay fallante si no es PEM/Cert encadenacion.
- Clave con permisos inseguros (0644) → fail-closed `0600`.
- `create_new` nunca sobrescribe; dirs 0700; key 060 plutôt, cert 0644.
- Límite de tamaño > 1 MiB → fail-closed.

## /No-leak / policía

- Test `connect_tls_uses_host_certificate_and_blocks_without_leaking_secret`: `403` + secreto ausente en respuesta. ✅
- Test de redact: upstream recibe body redactado, audit `no_raw_values(&[secret])`. ✅
- Fail policy hereda el reverse (fail-closed/fail-open segun `config.fail_policy`); el túnel MITM reusa
  exactamente el mismo `proxy_handler` (`forward.rs:545-558`), por lo que la política y la redestion son idénticas. ✅
- `DirectUpstream` inyectado por CONNECT implica control-plane `/api/*` NO accesible por el túnel (unit y
  E2E con `/api/stats`). ✅

## Quality gates

| Gate | Comando | Resultado |
|---|---|---|
| fmt | `cargo fmt --all -- --check` | rc=0 |
| clippy MITM (proxy + cer) | `cargo clippy -p cerberus-proxy --all-targets -- -D warnings` | `Finished` sin issues |
| clippy full `-p cerberus` | `cargo clippy -p cerberus-proxy -p cerberus --all-targets -- -D warnings` | 5 errors fuera de F4: `feedback_ux.rs:31,43,99` + `init.rs:93,95` (archivos modificados no-commit, F4/futuuros; ver FL-2) |
| proxy suite | `cargo test -p cerberus-proxy` | 129+38 passed, 0 failed |
| mitm suite | `cargo test -p cerberus mitm` | corredas típicas 8/0 (ver FL-3) |
| workspace | `cargo test --workspace` | 549+ passed / 1 failed = `feedback_ux` (NO F4) |
| load (presupuesto 5 ms) | `cargo test --release --test load_test -- --nocapture` | 7/7 PASS; p99: 1 kb=2.05, 10 kb clean=1.44, 50 kb secrets=4.70, 100 kb clean=2.44, innovate=4.86… | rango p99 1.44–4.70 ms (×budget) |
| release build | `cargo build -p cerberus --release` | `Finished release profile` |

## FL (baseline / fuera de F4, registrado sin severidad F4)
1. `feedback_ux::tests::watcher_only_delivers…` `FAILED` en `crates/cerberus/src/feedback_ux.rs:347`
   (assert `left: [] right: ["evt_7","evt_8"]`) — reproducible 15/15. Archivo **modificado** en working
   tree (pendiente, F4-未来 uncommit); NO pertenece a F4-mitm. Clippy en ese archivo (3) + `init.rs` (2)
   también fallan. El scope de este review es F4/mitm; se registra como item baseline sin bloqueait.
- **FL-1** Rumor de test flakiness propio del FIX: `trust_help_is_instructions` NO toma `ENV_LOCK` y
  corre concurrenter con tests que `set_var(HOME)`. Falla rara vez (0-1/10). Únicamente cosmetico; el
  `Home` switch no afecta a `read_ca_file` del product path (rutas explícitas). P3 de test-hygiene.
- **FL-2** `stop`/`start` en el mismo binario conviven con el daemon real de la máquina (PID 62651) en
  otra HOME; mi aislado evita trufar. (entorno)
- **FL-3** CPU/toolbox try tensión de puerto `code 60` para `TcpStream::connect` en la burst de 128
  sockets: ambiental, no del assert (ver P1-2 § ejecución).

## Si FAIL: qué reproducir (para próximos re-reviewers)
- P1-1: `mitm init-ca`, `cp` key de otra CA sobre `cerberus-ca.key`, luego `status`/`enable`/`START`.
  Espero: `does not match` y fallo pre-bind.
- P1-2: leer `forward.rs:331-340,438-445` (watch) y `936-963`; ejecutar
  `cargo test -p cerberus-proxy connection_limit…` ×20 en serie limpia → determinista.

## Veredicto
- P1-1 ✅ corregido (SPKI compara, fail antes del bind en CLI real).
- P1-2 ✅ corregido (barrera determinista `watch`; flakes restantes por entorno de puertos, no
  temporales de test).
- 0 × P0/P1 nuevos en F4/mitm una vez revertida la reproducibilidad de los dos P1.
- Hallazgos P3 de material PEM laxo (proc 1-3/4 step7) documentados como sugerencia, no bloqueantes.
- Evidencia gates: fmt/clippy(MITM)/suites proxy y mitm/load — todos en rango. Clippy y suite full
  `cerberus` y workspace 549+1 quedan atados por `feedback_ux`/`init` (working tree sucio no-F4): **baseline, no F4**.

**Veredicto gate F4/mitm-opt-in (re-check): PASS** — con la checklist: el fracaso de la suite cerrada
aluda viene de tests fuera de alcance (confirmado), por lo que se reclará la evidencia a
`no deja pendientes en el alcance de la unidad`. Estamos listos para cerrar el gate del FIX si el orquestador
lo ve adecuado; el Evidence pack de FAIL previo queda archivado como entrada del intento 4.