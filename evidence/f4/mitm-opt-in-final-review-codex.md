# Evidence Pack — F4/mitm-opt-in (revisión final independiente Codex)

- Fecha: 2026-08-21
- Intento: revisión final independiente/adversarial
- Revisor: Codex worker `task_d3dd5c9af30a` (no builder)
- Alcance: F4 `mitm-opt-in`; sólo lectura de implementación, sin confiar en evidencia previa
- Veredicto estricto: **FAIL**

## Motivo del veredicto

La revisión encontró una falla de concurrencia reproducible en la prueba que debe demostrar que el límite declarado de 128 túneles CONNECT se alcanza y recupera capacidad. En dos ejecuciones repetidas e independientes, `TcpStream::connect` agotó el timeout del sistema antes de completar los 128 túneles (`forward.rs:1406`): una vez en la iteración 23 y otra en la 37. Aunque las suites aisladas y completas pasan en corridas únicas, §8B prohíbe cerrar una unidad cuando una prueba ejecutada falla; por disponibilidad y fiabilidad del listener bajo su carga nominal se clasifica **P1**.

## Hallazgos

### P1 — el listener no alcanza de forma determinista su capacidad nominal de 128 CONNECT

- Superficie causal auditada: admisión y adquisición de permiso en `crates/cerberus-proxy/src/forward.rs:471-491`; transferencia del permiso al job en `:570-613`; guard de liberación en `:688-700`.
- Reproductor:

  ```text
  rtk proxy sh -c 'for i in $(seq 1 30); do rtk echo "connection-limit iteration $i"; rtk cargo test -p cerberus-proxy forward::tests::connection_limit_covers_active_connect_tunnels_and_recovers_capacity -- --exact || exit 1; done'
  ```

- Resultado observado: 22 PASS y luego FAIL en iteración 23:

  ```text
  thread 'forward::tests::connection_limit_covers_active_connect_tunnels_and_recovers_capacity' panicked at crates/cerberus-proxy/src/forward.rs:1406:61:
  called `Result::unwrap()` on an `Err` value: Os { code: 60, kind: TimedOut, message: "Operation timed out" }
  test result: FAILED. 0 passed; 1 failed; ... finished in 8.16s
  ```

- Reproductor independiente de confirmación: el mismo loop con `seq 1 40`.
- Resultado observado: 36 PASS y luego el mismo FAIL en iteración 37, `forward.rs:1406`, tras 7.80 s.
- Impacto: la implementación/test de capacidad no demuestra de forma estable que `MAX_CONNECTIONS = 128` sea utilizable; el cliente puede sufrir timeout antes del límite administrado. No observé una fuga de `OwnedSemaphorePermit` ni un deadlock permanente, pero el fallo de disponibilidad es real y repetible y bloquea PASS.

## Revisión exacta de código

### PEM, identidad CA y SPKI

- `strict_single_pem_block` exige un único bloque con etiqueta exacta, rechaza bloques anidados/múltiples y cualquier dato no-blanco posterior (`forward.rs:250-270`).
- El certificado se parsea con comprobación de `remainder.is_empty()` (`:283-287`), se exige `BasicConstraints.ca` (`:288-297`) y la clave se parsea después del mismo contrato de bloque único (`:281-282`, `:298`).
- La correspondencia cert/clave compara el SPKI DER completo del certificado con `KeyPair::subject_public_key_info()` (`:299-301`), incluida la prueba cruzada EC↔RSA (`:855-881`).
- No se re-emite la CA: se importa el DER persistido directamente en `Issuer::from_ca_cert_der` (`:302-304`) y sólo se genera/firma el leaf por host (`:308-327`).
- La regresión de consumo completo prueba whitespace exterior permitido, certificado duplicado, cadena heterogénea EC+RSA, basura líder/cola, tags incorrectos, clave duplicada y DER crudo (`:778-851`).

Resultado de código: **PASS**.

### Ownership del permiso, upgrade y shutdown

- Cada socket aceptado obtiene un `OwnedSemaphorePermit` (`forward.rs:471-491`). En CONNECT válido se extrae una sola vez del `Arc<Mutex<Option<_>>>` (`:570-576`) y se captura en `TunnelGuard` antes de encolar (`:580-593`). El permiso permanece en el future aun si todavía está en cola; un fallo de `send` descarta el future/guard y libera el permiso (`:610-613`).
- El job selecciona entre `upgrade` y shutdown (`:594-607`); el handshake TLS también selecciona shutdown y tiene timeout de 10 s (`:631-650`); la conexión HTTP interceptada vuelve a seleccionar shutdown (`:668-679`).
- Al cerrar, el receptor deja de aceptar jobs, publica shutdown, espera todas las conexiones productoras, drena los jobs ya encolados al `JoinSet` y espera todos los túneles (`:509-523`). Si excede la gracia, el handle aborta la tarea raíz; al caer los `JoinSet` se abortan sus hijos (`:383-394`). No encontré jobs detached ni una ruta normal que pierda el permiso.
- La prueba pre-ClientHello pasó 50/50 repeticiones exactas. El código de drenaje de jobs encolados es coherente, pero no existe una prueba con barrera que fuerce exactamente `send(job)`→job aún en cola→shutdown; conviene añadirla en el FIX para cerrar esa carrera de manera determinista.

Resultado de código: **PASS**, con hueco de cobertura señalado; la prueba de capacidad asociada falla como se documentó arriba.

### E2E TLS, modos y no-leak

- La ruta MITM inserta `DirectUpstream` derivado del CONNECT autorizado (`forward.rs:652-665`). Por ello un path interno `/api/*` no entra al control plane: las rutas API/health sólo se atienden cuando la extensión no existe (`proxy.rs:445-470`). El upstream usa el destino autorizado y elimina `Host`, bypass y admin-token antes de reenviar (`proxy.rs:664-702`).
- Decode de JSON inválido: Closed devuelve 502 sin incluir input; Open evita el scan y reenvía el body original (`proxy.rs:533-563`). El E2E verifica 502/no upstream para Closed y 200/body original para Open, sin raw en respuesta/audit (`forward.rs:1234-1287`).
- Error de redacción: Closed devuelve 502 sin upstream; Open reenvía el original; ambos verifican ausencia de los dos secretos en respuesta/audit (`forward.rs:1291-1357`).
- Shadow reenvía exactamente el original y registra evento sin valor crudo (`forward.rs:1189-1230`); Enforce redacta antes del upstream, impide que `Host: attacker.invalid` cambie el destino y no filtra el secreto en auditoría (`:1096-1185`); Block devuelve 403 sin el secreto (`:1043-1092`).

Resultado: **PASS**.

### Opt-in CLI/daemon, loopback, allowlist, CONNECT:443 y no trust automático

- El daemon sólo construye configuración MITM si `mitm.json` está habilitado; CA existente por sí sola no activa nada (`crates/cerberus/src/mitm.rs:65-81`). El arranque consume esa configuración y mantiene reverse como default (`daemon.rs:290-296`, `:509-527`).
- CLI exige `--host`, persiste enable/disable y avisa de reinicio cuando el daemon ya vive (`main.rs:92-109`, `:242-265`; `mitm.rs:97-160`).
- `ForwardProxyConfig::new` rechaza listeners no-loopback y puerto cero (`forward.rs:75-90`); la allowlist admite sólo FQDN exactos sin wildcard/IP/URL/puerto (`:100-139`); CONNECT exige puerto explícito 443 y lookup exacto (`:553-622`); HTTP plano y targets no listados se rechazan (`:1361-1391`).
- `init-ca` sólo genera archivos y declara “NO confiada” (`mitm.rs:84-95`). El único uso de `security add-trusted-cert` está dentro del texto de instrucciones manuales (`:257-282`); búsqueda exhaustiva: 1 ocurrencia, ninguna ejecución automática.
- El shutdown del daemon cierra y drena primero forward/reverse y sólo después hace flush/close del audit store (`daemon.rs:583-620`).

Resultado: **PASS**.

## Gauntlet ejecutado

| Criterio | Comando | Salida observada | Resultado |
|---|---|---|---|
| Tests focalizados F4 | `rtk cargo test -p cerberus-proxy forward::tests::` ×3 | `18 passed, 155 filtered out` en 0.17 s, 0.19 s y 0.13 s | ✅ |
| Carrera de capacidad repetida | loop exacto de `connection_limit_covers_active_connect_tunnels_and_recovers_capacity` | FAIL reproducido en iteraciones 23 y 37, timeout en `forward.rs:1406` | ❌ P1 |
| Shutdown pre-ClientHello repetido | loop exacto ×50 | 50/50 PASS | ✅ |
| CLI/daemon integration repetida | `rtk cargo test -p cerberus --test mitm_cli_daemon` ×3 | `4 passed` en cada corrida | ✅ |
| Formato | `rtk cargo fmt --all -- --check` | exit 0, sin diff | ✅ |
| Clippy aplicable | `rtk cargo clippy --workspace --all-targets -- -D warnings` | `No issues found` | ✅ |
| Clippy all-features adicional | `rtk cargo clippy --workspace --all-targets --all-features -- -D warnings` | no ejecutable: falta `cmake` al compilar `vectorscan v0.1.0` | ⚠️ entorno; no adjudicado a F4 |
| Suite proxy | `rtk cargo test -p cerberus-proxy` | `173 passed` | ✅ |
| Suite daemon/CLI | `rtk cargo test -p cerberus` | `69 passed` | ✅ |
| Suite workspace | `rtk cargo test --workspace` | `583 passed, 33 suites` | ✅ |

## Casos adversariales cubiertos

- PEM con segundo certificado distinto, basura, tags incorrectos, DER crudo y mismatches EC↔RSA.
- CONNECT a subdominio no listado, puerto 8443 y HTTP plano.
- Path MITM `/api/stats` y `Host` interior atacante para intentar alcanzar/desviar el control plane.
- Shadow, enforce-redact, enforce-block, decode inválido Closed/Open y redaction error Closed/Open, comprobando respuesta, upstream y auditoría.
- Túnel detenido antes de ClientHello bajo shutdown repetido 50 veces.
- Saturación/recuperación de 128 permisos repetida hasta reproducir dos timeouts.

## FIX y re-verificación requeridos

1. Diagnosticar por qué `TcpStream::connect` puede expirar antes de completar los 128 CONNECT (instrumentar índice, backlog/accept y contadores de conexiones/jobs/permits) y corregir implementación o contrato de capacidad; no basta ampliar el timeout sin explicar el atasco.
2. Añadir una prueba determinista con barrera para la carrera `send(job)`→job encolado no iniciado→shutdown, verificando cierre, `active_tunnels == 0` y recuperación de todos los permisos.
3. Repetir al menos los dos loops que fallaron y exigir 100% verde, además de las suites/fmt/clippy anteriores.

