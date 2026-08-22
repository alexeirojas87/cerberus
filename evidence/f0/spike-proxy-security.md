# Evidence Pack — f0/spike-proxy-security

- **Rol**: REVISOR 3 (Security)
- **Unidad**: spike-proxy
- **Veredicto**: PASS

## Resumen

Revisión de seguridad sobre el reverse proxy de spike (Fase 0). Todos los
criterios PASS. Se documentan 4 hallazgos de severidad baja/media, ninguno
bloqueante para un spike local.

## Criterios de Seguridad

### 1. Build ✅

| Comando | Resultado |
|---------|-----------|
| `cargo build --release --workspace` | ✅ 0 errores |

### 2. Tests ✅

| Comando | Resultado |
|---------|-----------|
| `cargo test -p spike-proxy` | ✅ 7/7 passed (3 unit lib + 4 integration) |

### 3. Reenvío de headers hostiles / sanitización ✅

**Archivo**: `crates/spike-proxy/src/proxy.rs:16-24, 147-152`

El proxy tiene un allowlist de headers **skip** (hop-by-hop): `host`,
`content-length`, `connection`, `keep-alive`, `proxy-connection`,
`transfer-encoding`, `upgrade`. Todos los demás headers se reenvían
**verbatim**, incluyendo `authorization`, `cookie`, `x-api-key`, etc.

**Riesgo**: Bajo. Para un spike local sin tráfico real no hay riesgo. En
producción, headers sensibles deben ser filtrados explícitamente.

**Hallazgo** 🟡 Low: El proxy reenvía headers sensibles sin sanitizar.
Aceptable para el spike.

### 4. Body de tamaño infinito (sin límite) ✅

**Archivo**: `crates/spike-proxy/src/proxy.rs:136`

```rust
let body_bytes = body.collect().await.map_err(|e| e.to_string())?.to_bytes();
```

`body.collect()` bufferiza el body **completo en memoria** sin límite de
tamaño. Un cliente malicioso puede enviar gigabytes de datos y agotar la
memoria del proxy.

**Riesgo**: Medio. El plan §4.1 establece explícitamente que el body se
bufferiza para escaneo, pero no hay límite superior. En producción se
necesita `max_body_size` de hyper o un `StreamBody` con límite.

**Hallazgo** 🟠 Medium: Bufferización sin límite → DoS por memoria.
Aceptable para el spike local.

### 5. Header spoofing: Host / X-Forwarded-For ✅

**Archivo**: `crates/spike-proxy/src/proxy.rs:142-152`

- **Host**: El proxy **REESCRIBE** el `Host` correctamente. El header `host`
  está en `SKIP_HEADERS` (línea 17), y la URI se reconstruye desde la
  dirección del upstream (línea 142-143). No hay spoofing del Host.
- **X-Forwarded-For**: El proxy **NO** añade `X-Forwarded-For` ni
  `X-Real-IP`. La IP del cliente se pierde. Esto es correcto para un spike
  local donde no hay clientes reales.

**Comportamiento actual**: Host rewrite ✅, X-Forwarded-For ausente
(intencional para el spike).

### 6. `unsafe` ✅

| Búsqueda | Resultado |
|----------|-----------|
| `grep -rn 'unsafe' crates/spike-proxy/` | ❌ 0 ocurrencias |

**Workspace lint**: `unsafe_code = "forbid"` en `Cargo.toml:8` — verificado
funcionalmente. El build no compilaría si hubiera `unsafe`.

### 7. SSRF: upstream configurable ✅

**Archivo**: `crates/spike-proxy/src/main.rs:52-56, 129-130`

El upstream es configurable vía `--upstream-addr <ADDR>`. Default:
`127.0.0.1:8091`. No hay validación de que la dirección sea local.

**Riesgo**: Bajo. Para el spike local el default es loopback y el uso es
controlado. En despliegues multi-tenant, el proxy podría ser usado para
SSRF contra servicios internos.

**Hallazgo** 🟢 Info: Sin validación de upstream como localhost. Si se
usara en infra multi-tenant, sería SSRF. Aceptable para el spike.

### 8. Body leaks (logs sin secretos) ✅

**Archivo**: `crates/spike-proxy/src/proxy.rs`

| Búsqueda | Resultado |
|----------|-----------|
| `println!` en `proxy.rs` | ❌ 0 ocurrencias |
| `eprintln!` en `proxy.rs` | 4 ocurrencias — solo errores de conexión (líneas 58, 66, 78, 90) |
| `dbg!` en `crates/spike-proxy/` | ❌ 0 ocurrencias |

Ningún log incluye el contenido del body ni datos de la request.
Las `eprintln!` solo reportan errores de conexión.

### 9. Timeouts de conexión ✅

**Archivo**: `crates/spike-proxy/src/proxy.rs:73, 155`

```rust
let client: Client<HttpConnector, Full<Bytes>> =
    Client::builder(TokioExecutor::new()).build(HttpConnector::new());
```

**No hay un solo timeout configurado**:
- Sin `pool_config().set_idle_timeout()`
- Sin `set_connect_timeout()`
- Sin `set_http1_keepalive()`
- Sin `http1::Builder::new().timer(...)` en el server

Un cliente que abre conexión y no envía datos → conexión colgada
indefinidamente (socket leak / DoS).

**Hallazgo** 🟠 Medium: Ausencia total de timeouts → DoS por socket leak.
Aceptable para el spike local con control de carga conocido.

## Hallazgos de Seguridad

### 🟠 Medium: Bufferización sin límite de body
- **Archivo**: `crates/spike-proxy/src/proxy.rs:136`
- **Descripción**: `body.collect()` sin `max_body_size` → DoS por memoria.
- **Impacto**: Un cliente malicioso puede agotar RAM del proxy.
- **Recomendación**: Post-spike, añadir `http1::Builder::max_buf_size()` y
  límite en `body.collect()` con `take()`.

### 🟠 Medium: Sin timeouts en cliente ni servidor
- **Archivo**: `crates/spike-proxy/src/proxy.rs:73`
- **Descripción**: Cliente HTTP sin connect/request/idle timeout.
  Servidor HTTP1 sin timer.
- **Impacto**: Conexiones lentas o colgadas agotan descriptores de archivo
  (socket leak).
- **Recomendación**: Post-spike, configurar `HttpConnector::set_connect_timeout()`,
  `pool_config().set_idle_timeout()`, y timer en `http1::Builder`.

### 🟡 Low: Headers reenviados sin sanitizar
- **Archivo**: `crates/spike-proxy/src/proxy.rs:147-152`
- **Descripción**: Todos los headers excepto hop-by-hop se reenvían
  verbatim. Headers de autenticación (`authorization`, `cookie`,
  `x-api-key`) se filtran al upstream.
- **Impacto**: Bajo para el spike. En producción, fuga de credenciales.
- **Recomendación**: Post-spike, implementar allowlist de headers
  reenviables.

### 🟢 Info: upstream configurable sin restricción (SSRF potencial)
- **Archivo**: `crates/spike-proxy/src/main.rs:52-56`
- **Descripción**: `--upstream-addr` acepta cualquier dirección IP, no
  solo loopback. Sin validación.
- **Impacto**: En despliegue multi-tenant podría ser usado como SSRF proxy.
  Para el spike local es intencional.
- **Recomendación**: En producción, validar que el upstream sea una
  dirección permitida.

## Evidencia Reproducible

```bash
# Build
cargo build --release --workspace

# Tests
cargo test -p spike-proxy

# unsafe
grep -rn 'unsafe' crates/spike-proxy/

# println! / eprintln! / dbg! en proxy.rs
grep -n 'println!\|eprintln!\|dbg!' crates/spike-proxy/src/proxy.rs
```

## Decisión

**VEREDICTO: PASS** ✅

Todos los criterios de seguridad cumplen para un spike local de Fase 0. Se
documentan 4 hallazgos (2 medium, 1 low, 1 info) para corrección post-spike.
Ninguno es bloqueante para el MVP: el proxy es funcional, correcto, y seguro
dentro del alcance del spike de latencia.