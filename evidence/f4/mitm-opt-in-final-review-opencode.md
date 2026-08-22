# Evidence Pack — F4/mitm-opt-in · VERIFY independiente adversarial (OpenCode worker)

- Fecha: 2026-08-21
- Rol: revisor independiente (worker Orca `task_de723f79c784`), revisión adversarial de seguridad — sólo lectura
- Base revisada: HEAD `a04a84d` (diff efectivo) + cambio NO committeado de `crates/cerberus-proxy/src/forward.rs` (test-only)
- Método: §8B Gauntlet — build → verificación con evidencia y salida citada → loop; sin edición de implementación, F8 ni evidencia ajena (`evidence/f4/mitm-opt-in.md` NO tocado)
- Veredicto: **PASS**

---

## Alcance del diff efectivo

### HEAD `a04a84d` (materia F4/MITM revisada)
- `crates/cerberus-proxy/src/forward.rs` (+1483): CA estricta, listener forward/MITM CONNECT+TLS, allowlist, semáforo 128, shutdown de túneles.
- `crates/cerberus/src/mitm.rs` (+523): CLI `mitm status/init-ca/enable/disable/trust-instructions`, config efectiva del daemon.
- `crates/cerberus/src/daemon.rs`: boot valida MITM y arranca `spawn_forward_proxy`; shutdown drena túneles.
- `crates/cerberus-proxy/tests/fixtures/f4-rsa-ca.pem` + `f4-rsa-ca-key.pem`: fixture RSA como control cross-algorithm.
- `crates/cerberus/src/main.rs`: subcomandos `Mitm` con help opt-in inequívoco.

### Cambio no committeado (`forward.rs`, 2+/1-)
`ca_loader_consumes_exactly_one_pem_block_and_rejects_garbage` sustituye el caso de prueba
"certificate chain" de `format!("{cert_text}\n{cert_text}")` (EC duplicado = redundante con el caso "duplicate certificate") por
`{cert_text}\n{rsa_cert_text}` (forward.rs:786). Ahora la cadena usa un certificado distinto (RSA), con lo que el caso
ejercita de verdad rechazo de un 2.º bloque distinto y no una mera duplicación.
Es test-only, no toca implementación. El resto del diff de F4 en el commit está sin cambios en el working tree.

---

## 1) PEM estricto: exactamente un CERTIFICATE + una PRIVATE KEY; rechazo de garbage/trailing, duplicado/chain, tag incorrecto, DER/random, non-CA y mismatch EC/RSA; import sin re-firma

### Código
- `strict_single_pem_block` exige la imagen **exacta** de inicio, un END marker único como fin físico, sin begin/end embebido en el body y **cero bytes no-whitespace después** del END:
  - `forward.rs:250-271` (inicio exacto `252-256`, no-END en el body `258-266`, si hay datos tras el bloque → `267-269` err "contains trailing data or multiple PEM blocks").
- Carga del par:
  - `forward.rs:278-306` (`LocalCa::load`): tira de `read_ca_file` (anti-symlink `226-228`, ≤1 MiB `229`, permisos clave 0600 `233-238`) → `strict_single_pem_block` para CERT+KEY → `parse_x509_pem` con `remainder.is_empty` (`283-287`).
  - `is_ca` exige `BasicConstraints CA:true` (`291-297`) → rechaza **non-CA**.
  - `KeyPair::from_pem` sólo PKCS#8 (`PRIVATE KEY`); `RSA PRIVATE KEY`/PKCS#1 no pasa.
  - **mismatch cross-algorithm**: comparación byte-a-byte de SPKi completa `persisted_cert.public_key().raw != key.subject_public_key_info()` (`299-300`) → rechaza EC-cert/RSA-key y RSA-cert/EC-key, incluido `AlgorithmIdentifier` y bit string.
- **Import sin re-firma**:
  - `LocalCa { issuer: Issuer<'static, KeyPair> }` (`273-274`) NO contiene un `Certificate` reemitido.
  - `forward.rs:302-303`: `Issuer::from_ca_cert_der(&certificate_der, key)` desde el DER **persistido** — una única `rcgen v0.14.9` en el lock.
  - Sólo `self_signed` en `generate_local_ca` (`forward.rs:165`) para una CA **nueva** (`create_new` rehúsa overwrite `144-146`); el import jamás re-emite/re-firma la CA persistida.
  - Las leaf efímeras se firman `signed_by(&leaf_key, &self.issuer)` (`forward.rs:319`); la CA persistida queda quieta.
- Fallos antes de activar el listener: `spawn_forward_proxy` carga `LocalCa::load` antes del `TcpListener::bind` (`forward.rs:405` y `421`); `crates/cerberus/src/mitm.rs:76` `validate_ca_files` antes del listener.

### Evidencia (reproducción)
- `rtk cargo test -p cerberus-proxy ca_loader_` → `2 passed, 171 filtered out`.
- `rtk cargo test -p cerberus-proxy mismatched_ca_pair_fails_closed_before_listener_bind` → `1 passed`.
- `rtk cargo test -p cerberus mitm::tests` → `8 passed` (incluye `strict_ca_material_is_rejected_by_status_enable_and_daemon_runtime`).
- Fixtures: `f4-rsa-ca.pem` (1 bloque, cert RSA CA), `f4-rsa-ca-key.pem` (1 bloque, PKCS#8 RSA) — verificado `grep -c BEGIN` = 1/1.
- `rtk cargo tree -i rcgen --locked` → única `rcgen v0.14.9` bajo `cerberus-proxy` (dev-dep `cerberus-hardening`). No existe camino de re-firma.

### Adversarial (casos que la suite cubre y pasan)
duplicado de cert, cadena cert+cert(RSA), garbage leading/trailing, tag incorrecto (`CERTIFICATE REQUEST`, `RSA PRIVATE KEY`), DER crudo, random bytes, non-CA (leaf self-signed `not-a-ca`), EC-RSA × 2 cruces, whitespace fuera del bloque permitido.

---

## 2) Límite 128 durante CONNECT/TLS/HTTP tras upgrade; 129 rechazado y capacidad recuperada

### Código
- `MAX_CONNECTIONS: usize = 128` (`forward.rs:44`).
- Semáforo de 128 en el listener (`forward.rs:471`): cada accept `try_acquire_owned` (`482`); al fallar, `drop(stream)` → reset del 129.º **sin servicio** (`483-485`).
- El permit NO se libera en el upgrade: CONNECT triunfa lo toma del `Mutex<Option<OwnedSemaphorePermit>>` (`570-576`) y lo mueve a `TunnelGuard { _permit }` (`586-591`), que vive en el job del túnel durante TODA la vida del túnel (upgrade → TLS handshake ≤10 s → HTTP interceptado) (`592-608`; `serve_intercepted` `624-680`).
- Conexiones no-CONNECT conservan el permit en el `Mutex` hasta cerrar la conexión (`526-551`) → nunca doble cuenta.
- `TunnelGuard::Drop` decrementa `active_tunnels` y restaura capacidad (`695-701`). No hay sleeps; sincronización por `watch`.

### Evidencia
- `rtk cargo test -p cerberus-proxy connection_limit_covers_active_connect_tunnels_and_recovers_capacity` **20/20** corridas (cada una `1 passed`).
- Test: 128 CONNECT activos todos `200` (`forward.rs:1411-1416`), `129.º` no recibe `200` ni servicio (`1418-1427`), tras `drop(held.pop())` se reabre exactamente 1 (`1430-1439`) → capacidad recuperada.

---

## 3) Shutdown cancela CONNECT con ClientHello estancado y espera túneles

### Código
- señal de shutdown (`serve_forward`): `tunnel_jobs.close()` + `tunnel_shutdown.send(true)` (L-509-510) y drena:
  - `connections` JoinSet (L-511-514) → la conexión cliente estancada se cierra (EOF) vía el `select` en `serve_forward_connection` (L-543-549).
  - jobs ya colados se vuelven a encolar (L-516-518) y `tunnels.join_next()` espera TODOS hasta que terminen (L-519-523).
- El tunnel job del CONNECT: si el shutdown llega mientras espera el upgrade o el ClientHello → `shutdown.changed()` corta con retorno limpio (`select` L-598-602).
- `ManagedForwardProxyHandle::shutdown` espera la task entera con `grace` y aborta sólo si se excede (`forward.rs:383-396`).

### Evidencia
- `rtk cargo test -p cerberus-proxy shutdown_cancels_connect_stalled_before_client_hello` **20/20**; el handler cierra el túnel con EOF dentro de la gracia (`forward.rs:1465-1471` devuelve socket `read==0`).
- Daemon: shutdown espera-forward `handle.shutdown(5 s)` antes de cerrar el reverse proxy y el store (daemon.rs:585-591).

---

## 4) E2E TLS shadow pass-through; evento sin raw; fail-policy Closed/Open para decode y redact

### Código
- Intercept TLS: `serve_intercepted` (L320-330 leaf firmada por la CA importada; ALPN http/1.1) → `proxy_handler` con `DirectUpstream { base = target_base, provider = host }` siempre inyectado (`forward.rs:656-660`).
- Flujo del engine en `proxy_handler`:
  - decode: contenido `application/json` + JSON inválido = «decode failed» → Closed ⇒ `502 {"error":"cannot decode"}`; Open ⇒ forward del body original intacto (proxy.rs:536-548).
  - scan: `engine_snap.scan` + allowlist (proxy.rs:552-562).
  - shadow: `shadow::apply_mode` (shadow.rs:65) pasa intacto; `final_bytes = body_bytes` cuando no es Enforce (proxy.rs:595-611).
  - redact: `redact_body` → `decide_redact_result`: Closed ⇒ `502 {"error":"redact failure",...}` sin secreto; Open ⇒ forward del body ORIGINAL (proxy.rs:420-436, 595-608).
  - eventos: `AuditEvent::from_findings` guarda sólo `flags` + `hashed_values` (`sha256:`) (event.rs:45-80); `no_raw_values` verifica que el JSON serializado no contiene ningún valor crudo (event.rs:84-87).
- Respuesta nunca contiene el secreto: asserts en los 4 E2E TLS tests.

### Evidencia
- `rtk cargo test -p cerberus-proxy connect_tls_` **10/10** corridas (5 E2E TLS por corrida):
  - `connect_tls_shadow_forwards_original_and_records_redacted_audit_event`: 200, `writes` body con secreto intacto al upstream, `events.len()==1`, `no_raw_values(&[secret])` (forward.rs:1189-1231).
  - `connect_tls_invalid_json_obeys_closed_and_open_fail_policy_without_audit_leak` (decode): Closed → `502` y upstream **sin** request; Open → `200` y upstream recibe body original; audit sin leak (L-1234-1288).
  - `connect_tls_redaction_failure_obeys_closed_and_open_fail_policy_without_leak` (redact): Closed → `502` sin forward; Open → `200` forward del body original; audit sin raw (L-1291-1358).
  - `connect_tls_redacts_before_forwarding_and_audit_has_no_raw_secret` (L-1096-1186): secreto `TOKEN-*` sale redacted al upstream, `attacker.invalid` NO reenvía, `/api/stats` interior llega al upstream NO al control plane.

---

## 5) Loopback, allowlist exacta, CONNECT:443, control plane no expuesto, no trust automática

### Código
- Loopback: `ForwardProxyConfig::new` rechaza cualquier `listen` no-loopback antes de arrancar (`forward.rs:76-78`); igual el config efectivo del daemon (`mitm.rs:214`) y el boot.
- Allowlist exacta: `normalize_allowed_hosts`/`normalize_host` — sin wildcard, sin IP, sin `localhost`, sin URL, sin puerto, FQDN con labels válidas, ≤64 hosts (`forward.rs:43,102-139`; test `allowlist_is_exact_normalized_and_rejects_unsafe_inputs` L:724-744).
- CONNECT autorizado solo a 443: `parse_connect_target` exige `port_u32 == 443` y normaliza el host (`forward.rs:616-622`), luego `tls_configs.get` / `targets.get` por el host allowlisted (`564-568`); el `Host:` interior NO se reenvía y el destino queda fijado por `DirectUpstream` (proxy.rs:690-695; test L:1096-1188).
- Control plane no expuesto: `/api/*` y `/health` sólo se sirven `direct_upstream.is_none()` (proxy.rs:451,461); por el túnel CONNECT/TLS `DirectUpstream` siempre existe → los paquetes van al upstream autorizado; request HTTP plano (no CONNECT) → `405` (`forward.rs:558`); subdominio/puerto no allowlisted → `403`; target malformado → `400`.
- No trust automática:
  - `init-ca` "NO la instala ni confía" (main.rs:95-96), `trust-instructions` "nunca modifica el trust store" (main.rs:108-109); implementa sólo pasos (`mitm.rs:260-281`) — no ejecuta `sudo`/`security`/`certutil`.
  - Ausencia de config = `enabled=false`; una CA existente jamás habilita el listener (`mitm.rs:71-81`, test `absent_config_is_disabled_and_does_not_create_files`).
  - `enable` exige hosts explícitos (`main.rs:100`) y CA validada antes (`mitm.rs:100-104`).

### Evidencia
- `rtk cargo test -p cerberus-proxy connect_rejects_unlisted_host_wrong_port_and_plain_http` → `1 passed` (403/400/405, sin túnel).
- `rtk cargo test -p cerberus mitm::tests` → `8 passed` (`enabled_config_rejects_empty_hosts_and_public_bind`, `absent_config_is_disabled_and_does_not_create_files`, `strict_ca_material_is_rejected_by_status_enable_and_daemon_runtime`, `enable_without_daemon_persists_for_next_start`, etc.).

---

## Calidad / integridad
- `rtk cargo fmt --all -- --check` → sin salida (**exit 0**, sin diff).
- `rtk git diff --check` → OK.
- `rtk cargo clippy -p cerberus-proxy -p cerberus --all-targets -- -D warnings` → `No issues found`.
- `rtk cargo test -p cerberus-proxy --no-fail-fast` → `173 passed (3 suites)`.
- `rtk cargo test -p cerberus --no-fail-fast` → `13 passed (5 suites)`.
- `rtk cargo test --workspace --no-fail-fast` → `583 passed (33 suites)`.

---

## Observaciones (documentadas aparte; ninguna es P0/P1 de F4)
1. **Flake por contención de máquina/IO (no lógica)**: al lanzar `cargo test -p cerberus-proxy` y `cargo test -p cerberus` **en paralelo**, 9 tests de `forward::tests`/`proxy::tests` fallaron con `Os { code: 60, TimedOut }` (`crates/cerberus-proxy/src/forward.rs:960,1054,1385,1406,1456` y `proxy.rs:1122`) — conectos TCP a 127.0.0.1 bajo carga fuerte (el test de límite abre 129 sockets a la vez). Reproducido: suite completa `173 passed` en re-runs consecutivos y con `--test-threads=1`; los tests sensibles pasan 20/20 y 10/10 en serie. No es defecto de lógica de F4; es entorno/IO.
2. **Nota de robustez (no viola la aceptación)**: una conexión que hace `connect()` y no envía nada retiene un permit mientras viva (sin idle-timeout en la conexión desnuda antes del CONNECT). El límite se respeta estrictamente y un 129.º recibe reset; pero 128 conexiones idle podrían bloquear nuevos CONNECT. El límite 128 se mantiene durante CONNECT/TLS/HTTP tal como exige la aceptación.
3. **Sin hallazgos de control**: el import no re-firma ni re-emite la CA (sólo `Issuer::from_ca_cert_der`), no hay confianza automática, el evento de auditoría no contiene valores crudos, el `Host` interior no se reenvía y `/api/*` no se sirve por el túnel MITM.

---

## Veredicto estricto

**PASS** — sin P0 ni P1 reales en el ámbito F4/mitm-opt-in. El build/evidencia satisface los 5 puntos de la tarea con reproducibilidad (20/20, 10/10, 173/173, 583/583) y calidad limpia (fmt/clippy). El único fallo observado (ETIMEDOUT bajo dos `cargo test` concurrentes) no se reproduce en aislamiento y es un artefacto de la carga del entorno; se documenta aparte y **no** impide el PASS.