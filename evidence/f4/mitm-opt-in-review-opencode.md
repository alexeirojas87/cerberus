# Evidence Pack — F4/mitm-opt-in: revisión adversarial independiente

- Revisor: OpenCode worker `task_1d54352f305e` (independiente del builder)
- Checkout: `HEAD 09612f2` + working tree actual, sin commit / sin edición de source
- Fecha: 2026-08-21/22
- Veredicto del revisor: **FAIL — 2 × P1 (0 P0, 0 P2 definitivos)**
- Veredicto previo del builder (no independiente): PASS (`evidence/f4/mitm-opt-in.md`)

Este artefacto **no** confirma el cierre del gate de la unidad: el veredicto va
al loop de FIX (§8B.3) con la reproducción `file:line` de ambos P1.

---

## Contexto / método

- Leídos `AGENTS.md`, `CERBERUS_PRODUCT_BUILD_PLAN.md` (F4 y §8B), evidence del builder.
- Revisado el diff completo del working tree pertinente a F4:
  `crates/cerberus-proxy/src/forward.rs` (nuevo, core), `proxy.rs`, `config.rs`,
  `crates/cerberus/src/mitm.rs`, `main.rs`, `daemon.rs`.
- Shell siempre con `rtk`; grafter/indexado antes de leer source.

## Criterios de aceptación (re-ejecutados, resultados honestos)

| Criterio | Comando ejecutado | Salida citada | Resultado |
|---|---|---|---|
| CONNECT/TLS + cert por host | `cargo test -p cerberus-proxy forward::tests` | `11 passed; 0 failed` | ✅ |
| Allowlist exacta (subdomain/port/plain-HTTP) | mismo | caso `connect_rejects_unlisted_host_wrong_port_and_plain_http` PASS | ✅ |
| Redacción antes del upstream + audit sin raw + destino fijado por CONNECT + no exposición de `/api` | `forward::tests` | `connect_tls_redacts_before_forwarding_and_audit_has_no_raw_secret` PASS (capturó body redactado con `Host: attacker.invalid` y path `/api/stats`) | ✅ |
| Block fail-closed sin secreto en respuesta | `forward::tests` | `connect_tls_uses_host_certificate_and_blocks_without_leaking_secret` PASS (403, sin secreto) | ✅ |
| CA sólo por acción explícita, create-new, sin overwrite/trust automático | CLI real + `cargo test -p cerberus mitm` | init-ca la 2ª vez → `refusing to overwrite` rc=1; suite 6 passed | ✅ |
| Clave 0600 / certificado presente | `ls -l` tras `mitm init-ca` | `-rw-------` key, `-rw-r--r--` cert | ✅ |
| Symlink / missing CA / >1 MiB fail-closed | `forward::tests` | `symlinked_ca_file_fails_closed`, `missing_ca_prevents_listener_from_binding`, `oversized_ca_file_fails_closed` PASS | ✅ |
| Fail-closed de arranque con MITM enabled sin CA | daemon real (HOME aislado) | `start` rc=1 `CA file unavailable`, **0 listeners** | ✅ |
| Disabled no bloquea reverse | daemon real | `MITM: disabled (default); reverse proxy only` + reverse healthy | ✅* |
| Loopback obligatorio | `ForwardProxyConfig::new('0.0.0.0:8788')` (test) + CLI `--listen 0.0.0.0:8788` | ambos rechazados | ✅ |
| 3×3 transporte: unlisted→403, wrong-port→400, plain→405; case y trailing-dot→200 | `nc` real contra daemon en listener forward | `HTTP/1.1 403 Forbidden`, `400 Bad Request`, `405 Method Not Allowed`, `200 OK` | ✅ |
| Lifecycle CLI/daemon stop | `cerberus start/stop` real | graceful; forward + reverse drenados | ✅ |
| Calidad | `cargo fmt --all -- --check` / `cargo clippy -p cerberus-proxy -p cerberus --all-targets -- -D warnings` | exit 0 en ambos | ✅ |
| Regresión workspace | `cargo test --workspace` | **549 passed / 0 failed** | ✅ |
| Build release | `cargo build -p cerberus --release` | `Finished release profile` | ✅ |
| p99 hot-path | `cargo test --release --test load_test -- --nocapture` | 7/7 PASS; peor p99 observado **1.316 ms** (< 5 ms) | ✅ |

\* salvo caso de fichero malformado — ver P3-1.

### Dos claims del builder comprobados sobre el código y en ejecución

- `validate_ca_files` **sí** detecta missing/symlink/permisos/oversize (se volvió
  a ejecutar). `validate_ca_files` NO detecta par cert/key inconsistente → **P1-1**.
- `connection_limit_drops_excess_client` sigue usando `sleep(50 ms)` →
  barrera temporal, no determinista → **P1-2**.

---

## P1-1 — `validate_ca_files` NO detecta un par CA cert/key inconsistente

**Lugar:** `crates/cerberus-proxy/src/forward.rs:187-189` (`validate_ca_files`)
→ `LocalCa::load` `forward.rs:251-264`, en concreto `forward.rs:260-262`:

```rust
let key = KeyPair::from_pem(&key_pem)...;
let certificate = params.self_signed(&key)...;  // NUNCA compara key vs cert
```

**Causa raíz (rcgen 0.13.2):** `CertificateParams::from_ca_cert_pem` extrae
sólo atributos (DN, SAN, usos, validez) y **pierde el public key original**
(`certificate.rs:225-270`, campo `subject_public_key_info` queda `Default`).
`self_signed(key)` re-construye el cert con `key_pair.public_key_der()`
(`certificate.rs:177-192`) y firma con la key pasada: **no existe ninguna
comparación** SPKI-cert vs SPKI-key. Un par con key ajena multiplica sin error.

**Reproducción empírica:**
1. `cargo run` en scratch `rcgen =0.13.2` (mismo pinned en Cargo.lock):
   - generar CA-A (certA/keyA) y CA-B (certB/keyB);
   - `from_ca_cert_pem(certA) + KeyPair::from_pem(keyB) + self_signed(keyB)`
     → **`Ok(570)`** y los leaf `signed_by` subsecuentes también `Ok`
     (control: par correcto también `Ok`).
2. Con el binario release y `HOME` aislado:
   - `cerberus mitm init-ca`, luego `cp` una key RSA ajena como `~/.cerberus/ca/cerberus-ca.key`;
   - `cerberus mitm status` → `CA=ready (not automatically trusted)`;
   - `cerberus mitm enable` → rc=0;
   - `cerberus start` → **bind del listener forward (18788) + "Cerberus MITM opt-in corriendo"** sin un solo error, aun con cert/key incompatibles.

**Impacto (fail-open de la validación prometida):** el arranque presenta un
túnel MITM cuyo certificado raíz efectivo (`LocalCa::load` re-firma con la key
que haya en disco) NO enrula a la anchor que el usuario recibió instrucciones
de confiar (`cerberus-ca.cert`). El listener "acepta" material corrupto en
lugar de fallar antes del bind, exactamente el caso que la evidencia declara
cubrir ("material CA defensivo … fallan antes del bind"), quedando el host
protegidamente en un estado funcionalmente roto y silencioso: peor que no
arrancar. La defensa solicitada por la tarea es explícita (detectar par
inconsistente) → **P1**.

**Fix exigido:** comparar `certSPKI == key.public_key_der()` (o verificar la
firma del cert con la key) dentro de `LocalCa::load` y `Err` antes del bind.
Test adversarial: cert/key de dos CAs distintas → `validate_ca_files` Err.

---

## P1-2 — prueba del límite de conexiones es temporal (sleep 50 ms)

**Lugar:** `crates/cerberus-proxy/src/forward.rs:889`:

```rust
tokio::time::sleep(Duration::from_millis(50)).await;  // barrera TEMPORAL
```

**Análisis de flake:** el test abre 128 CONNECTs, espera 50 ms "por si acaso"
y sólo luego asume que todos los permits ya fueron consumidos por el accept
loop. Si un host cargado no consume las 128 accepts dentro de esos 50 ms, el
cliente 129º toma un permit, `forward_connect` lo SIERVE y responde (405),
rompiendo el assert `read.is_err() || response.is_empty()` → **falso FAIL en
CI lenta**; y, aun sin fallar, 50 ms no garantizan la propiedad aserrada. No
existe ninguna barrera determinista (p.ej. un `Notify`/`watch` emitido por el
accept loop al alcanzar el límite). Es exactamente el caso que la tarea ordena
reprobar ("contiene/contuvo sleep(50 ms): si sigue siendo temporal/flaky →
FAIL P1"). Pasó 15/15 bajo carga artificialmente y en suite (0.08-0.15 s), pero
**el diseño del test es temporal**, no determinista.

**Fix exigido:** barrera determinista (notificación del accept loop
cuando quedan `MAX_CONNECTIONS` conexiones bajo permit, p.ej. `Notify`/`watch`)
o **retirar el claim** "más de 128 conexiones → límite por semaphore".

---

## Otros casos adversariales probados (negativos, todos PASS salvo notas)

- `CONNECT api.hardcoded.test.:443` y `CONNECT API.OPENAI.COM:443` → 200
  (normalización case + trailing dot), mientras `*` / otro puerto / HTTP plano
  → 400 / 400 / 405.
- Allowlist: se rechazan `*.x`, `https://host`, IPs, `localhost` (sin FQDN),
  `host:port`, credenciales, rutas y >64 hosts; duplicados deduplicados. IDNA
  Unicode se rechaza (fail-closed); punycode literal se acepta tal cual.
- Autoridad CONNECT vs Host interior: `parse_connect_target` usa SÓLO el
  authority del CONNECT (`forward.rs:489-495`); el `Host` del request TLS
  interior nunca altera el destino (`SKIP_HEADERS`, `proxy.rs:54-65`).
- Control-plane `/api/*` no expuesto por el túnel: `DirectUpstream` inyectado
  por CONNECT omite `api::is_api_path` (`forward.rs:511-517`, `proxy.rs:451-454`);
  verificado en el test de captura con `/api/stats`.
- Límites de body: el túnel hereda `max_body_bytes` (default 64 MiB) vía el
  mismo `ctx.config` (`proxy.rs:480`, `config.rs:74`); buffering acotado.
- fail-closed (redact-error → 502 sin secreto) y fail-open (forward del body
  original + warn) idénticos al dataplane reverse; cubiertos por `forward::tests`
  (falta un caso fail-open explícito del túnel MITM; la ruta y la política son
  las mismas → nota).
- Routing único al destino `443`: `target = https://{host}:443` y `CONNECT`
  sólo acepta `443`. Listener forward únicamente loopback. Shutdown: el guard
  de tunnels (`TunnelGuard`) decrementa y drena antes del cierre del store;
  el daemon cierra forward ANTES del store (`daemon.rs:572-583`).
- Daemon E2E completo en `/tmp` con `HOME` aislado: bind 18788, 403/400/405,
  health reverse OK, stop graceful, fail-closed cuando MITM enabled sin CA y
  disabled no enciende 18788.

## NFR aplicables

- p99 hot-path: peor 1.316 ms (presupuesto 3-5 ms) → ✅ (path reverse/
  scan+redact; el path CONNECT/TLS no tiene bench propio declarado).
- No-leak: los tests de auditoría y block no filtran el raw en respuesta ni
  en evento → ✅ (casos ejecutados).
- `fmt` / `clippy -D warnings` / release: 0 issues → ✅.

## Notas no bloqueantes (P2/P3)

1. **mitm.json malformado bloquea el daemon** (incluso con intención de
   `enabled=false`): `load_config_from` propaga el error de parse
   (`serde_json::from_str`, `mitm.rs:160`) y daemon.rs:295 hace `?`.
   El claim "disabled no puede bloquear reverse" sólo vale para JSON
   estructuralmente válido con campos inválidos (el unit lo prueba y el daemon
   lo reproduce). Tratar un JSON malformado como `disabled` sería opcional. P3.
2. TOCTOU entre `symlink_metadata` y `File::open` en `read_ca_file`
   (`forward.rs:220-234`); mismo usuario. P3.
3. Dev-mode (sin admin token) honra `X-Cerberus-Bypass` también en el túnel
   (`proxy.rs:502-531`), igual que el reverse: escape hatch documentado. P3 nota.
4. Windows: sin validación explícita de DACL de la clave (documentado por el
   builder, en línea con la evidencia). P3 nota.

## Si FAIL: qué falla y cómo reproducirlo

- **P1-1 (`validate_ca_files`):**
  1. `cerberus mitm init-ca`;
  2. sobrescriba `ca/cerberus-ca.key` con la clave de OTRA CA
     (`openssl genrsa` + `openssl req -x509`);
  3. `cerberus mitm status` muestra `CA=ready`;
  4. `cerberus start` levanta el listener MITM sin error.
     (Además: repro rcgen del scratch en §P1-1.)
- **P1-2:** leer `forward.rs:889`; la aserción del límite depende de
  `sleep(50 ms)` sin marca de sincronización del accept loop.

→ Requiere FIX (barrera determinista + SPI-mismatch) y re-verificación
   independiente con este artefacto como entrada. Veredicto: **FAIL**.