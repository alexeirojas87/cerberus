# Evidence Pack — F4/mitm-opt-in (segundo VERIFY de seguridad post-fix)

- Intento: 2 post-fix
- Revisor: Codex independiente (`task_61a8e49ecd79`), distinto del builder/fixer
- Fecha: 2026-08-21 (America/New_York)
- Estado revisado: `main` en `09612f2` más el worktree compartido sin commit; `crates/cerberus-proxy/src/forward.rs` es parte del diff F4 y sigue untracked.
- Alcance: review-only. No se editó source ni se hizo commit; este Evidence Pack es el único archivo creado.
- **Veredicto: FAIL** — dos P1 reproducidos: el loader acepta PEM adicional/trailing y el límite de 128 conexiones se evade con túneles CONNECT activos.

## Fuente de verdad y método §8B

Se contrastó la unidad con `CERBERUS_PRODUCT_BUILD_PLAN.md:115-131` (MITM sólo opt-in y sin confianza automática), `:443-462` (F4) y `:554-672` (Gauntlet: evidencia ejecutada, revisión adversarial, Evidence Pack y gate). No se asumió válida evidencia F4 previa.

El orden aplicado fue build → tests focalizados → reproducciones adversariales → gates de calidad → veredicto. Los harnesses adversariales se compilaron desde stdin a `/tmp`, se ejecutaron y borraron; no dejaron source ni artefactos en el repositorio.

## Criterios de aceptación

| Criterio | Comando/evidencia ejecutada | Salida citada | Resultado |
|---|---|---|---|
| Default reverse; MITM sólo por opt-in explícito; nunca confiar CA automáticamente | `rtk cargo test -p cerberus --bin cerberus mitm::tests -- --nocapture` + review `crates/cerberus/src/mitm.rs:67-125,224-246` | `5 passed, 38 filtered out`; config ausente/deshabilitada da `None`; `init-ca`, `enable` y las instrucciones de trust son acciones separadas | ✅ PASS |
| Certificado persistido y private key deben corresponder a nivel SPKI y rechazar algoritmos incompatibles | `rtk cargo test -p cerberus-proxy mismatched_ca_pair_fails_closed_before_listener_bind -- --nocapture` + repro certA/keyB inline | `1 passed`; `certA_keyB=Err("CA certificate does not match private key")` | ✅ PASS parcial: la comparación usa el SPKI DER completo (`forward.rs:254-266`), que incluye AlgorithmIdentifier; falta un caso automatizado RSA↔EC |
| Aceptar exactamente un certificado y una clave; rechazar bloques PEM extra y trailing no-whitespace | Harness inline contra `validate_ca_files` | `duplicate_pem_plus_trailing=Ok(())` | ❌ **FAIL P1-01** |
| No re-firmar silenciosamente la CA persistida | Review `crates/cerberus-proxy/src/forward.rs:251-272` | Tras parsear el cert persistido, ejecuta `params.self_signed(&key)` en `:268-270` y usa ese certificado sustituto para firmar leafs | ❌ **FAIL P1-01** |
| Todo material/config inválido falla antes de cualquier bind | Review `crates/cerberus/src/daemon.rs:296,503-507`, `crates/cerberus/src/mitm.rs:67-82`, `forward.rs:361-395`; test certA/keyB | `runtime_config()` llama `validate_ca_files` en `mitm.rs:76` antes de `spawn_managed_proxy`; `spawn_forward_proxy` vuelve a cargar CA antes de su `TcpListener::bind` | ✅ PASS |
| Sólo loopback, `CONNECT host:443`, allowlist DNS exacta; sin Host override, plain HTTP ni SSRF directa | `rtk cargo test -p cerberus-proxy forward::tests -- --nocapture` + review `forward.rs:70-134,492-572` | `12 passed, 155 filtered out`; subdominio, puerto 8443 y HTTP plano rechazados; Host interno se elimina y el destino queda fijado por el CONNECT autorizado | ✅ PASS |
| TLS real usa leaf del host; block/redact ocurren antes de upstream; control-plane no queda expuesto; auditoría no contiene secreto crudo | Mismo suite focalizado; tests `connect_tls_uses_host_certificate...` y `connect_tls_redacts...` (`forward.rs:757-900`) | TLS confiando sólo la CA local; block `403`; redacción cambia body upstream; `/api/stats` interno se envía al upstream fijo, no al API local; `no_raw_values` verdadero | ✅ PASS |
| Fail policy y límites de body se conservan en la ruta MITM | `rtk cargo test -p cerberus-proxy` + review del camino común `proxy.rs:440-754` | `167 passed (3 suites)`; `DirectUpstream` entra al mismo decode/scan/redact/fail-policy y límites de request/response | ✅ PASS funcional; falta integración MITM específica de shadow/fail-open (P2-02) |
| Máximo de conexiones/túneles realmente activos y test determinista sin sleeps | Test existente repetido 10 veces + harness de 160 CONNECT | 10/10: `1 passed` en 0.03–0.07 s, pero el adversarial imprimió `active_connect_tunnels_admitted=160` con `MAX_CONNECTIONS=128` | ❌ **FAIL P1-02** |
| Shutdown cierra admisión y cancela/drena túneles, incluso cliente estancado antes de TLS | Harness CONNECT sin ClientHello + review `forward.rs:343-356,492-572` | `shutdown_with_stalled_tls_client=Err("forward proxy drain exceeded 200 ms")` | ⚠️ P2-01 |
| Quality gates razonables | build, fmt, clippy, crates y workspace (ver abajo) | Todos verdes: workspace `554 passed` | ✅ PASS, pero no compensa los P1 funcionales |

## Hallazgos

### P1-01 — El loader acepta material PEM ambiguo/trailing y re-firma una CA sustituta

**Evidencia de código**

- `crates/cerberus-proxy/src/forward.rs:254` recibe `(remainder, pem)` de `parse_x509_pem`, pero enlaza el remainder como `_` y nunca exige que esté vacío/sea sólo whitespace.
- `forward.rs:259` pasa el texto completo a `CertificateParams::from_ca_cert_pem` y `:264` a `KeyPair::from_pem`.
- En rcgen 0.13.2, ambos terminan en `pem::parse` (`certificate.rs:199`, `key_pair.rs:177` del source de la dependencia). `pem` 3.0.6 busca un bloque y no exige que sea el único contenido; `parse_many` es una API distinta.
- `forward.rs:265-266` sí compara el SPKI DER del cert persistido con `key.public_key_der()`, por lo que certA/keyB se rechaza correctamente.
- Después de esa comparación, `forward.rs:268-270` ejecuta `params.self_signed(&key)`. El objeto issuer usado en `server_config_for` no es el certificado persistido sino una reemisión in-memory que puede omitir extensiones no reconstruidas por rcgen. No sobrescribe el archivo, pero sí viola el requisito explícito de no re-firma silenciosa.

**Reproducción ejecutada**

Se compiló desde stdin un harness enlazado contra el `libcerberus_proxy.rlib` recién construido. El harness:

1. generó CA A y CA B con `generate_local_ca`;
2. llamó `validate_ca_files(certA, keyB)`;
3. anexó al cert A una segunda copia completa del bloque CERTIFICATE y `TRAILING-MALICIOUS-BYTES`;
4. anexó a key A una segunda copia completa del bloque PRIVATE KEY y los mismos bytes trailing;
5. llamó de nuevo `validate_ca_files(certA, keyA)`.

Comando ejecutado (source Rust pasado por heredoc; binario temporal eliminado al final):

```bash
rtk proxy zsh -lc 'rtk proxy rustc --edition=2021 -L dependency=target/debug/deps \
  --extern cerberus_proxy=target/debug/libcerberus_proxy.rlib \
  -o /tmp/cerberus-f4-pem-repro-bin - <<RS
use std::fs::{self, OpenOptions};
use std::io::Write;
use cerberus_proxy::forward::{generate_local_ca, validate_ca_files, CaPaths};
fn paths(base: &std::path::Path, name: &str) -> CaPaths {
    let dir = base.join(name);
    CaPaths { cert: dir.join("ca.pem"), key: dir.join("ca.key") }
}
fn main() {
    let base = std::env::temp_dir().join(format!("cerberus-f4-pem-repro-{}", std::process::id()));
    let a = paths(&base, "a");
    let b = paths(&base, "b");
    generate_local_ca(&a).unwrap();
    generate_local_ca(&b).unwrap();
    let mismatch = CaPaths { cert: a.cert.clone(), key: b.key.clone() };
    println!("certA_keyB={:?}", validate_ca_files(&mismatch));
    let cert = fs::read(&a.cert).unwrap();
    let key = fs::read(&a.key).unwrap();
    let mut cert_file = OpenOptions::new().append(true).open(&a.cert).unwrap();
    cert_file.write_all(b"\n").unwrap();
    cert_file.write_all(&cert).unwrap();
    cert_file.write_all(b"\nTRAILING-MALICIOUS-BYTES\n").unwrap();
    let mut key_file = OpenOptions::new().append(true).open(&a.key).unwrap();
    key_file.write_all(b"\n").unwrap();
    key_file.write_all(&key).unwrap();
    key_file.write_all(b"\nTRAILING-MALICIOUS-BYTES\n").unwrap();
    println!("duplicate_pem_plus_trailing={:?}", validate_ca_files(&a));
    fs::remove_dir_all(&base).unwrap();
}
RS
rtk proxy /tmp/cerberus-f4-pem-repro-bin
rtk proxy rm /tmp/cerberus-f4-pem-repro-bin'
```

Salida exacta:

```text
certA_keyB=Err("CA certificate does not match private key")
duplicate_pem_plus_trailing=Ok(())
```

**Impacto**

El mismo archivo puede tener identidades distintas para consumidores que elijan first/last/all PEM block. Eso convierte el material CA en una entrada ambigua, impide una política de identidad única verificable y acepta explícitamente trailing malicioso. En un componente MITM que posee una CA confiada, se clasifica P1.

**Corrección y regression test requeridos**

- Parsear el archivo completo y exigir exactamente un bloque `CERTIFICATE` y exactamente un bloque de clave privada soportada; sólo whitespace puede quedar fuera del bloque.
- Rechazar tipo PEM incorrecto, bloque duplicado, cert chain, bytes prefijo/sufijo y algoritmos no soportados/incompatibles.
- Comparar SPKI DER del X.509 único contra SPKI derivado de la clave única.
- Evitar construir el issuer mediante `self_signed` del material importado; usar una representación de issuer/import de CA que conserve el certificado persistido, o hacer explícito y comprobable el contrato si la versión de rcgen obliga a cambiar.
- Tests mínimos: certA/keyB; EC cert/RSA key; RSA cert/EC key; cert+cert; key+key; cert+garbage; key+garbage; bloques con orden invertido; cert no-CA; todos deben fallar antes de bind.

### P1-02 — `MAX_CONNECTIONS=128` no limita túneles CONNECT activos

**Evidencia de código**

- El permit se adquiere por socket aceptado en `crates/cerberus-proxy/src/forward.rs:438` y queda dentro de la tarea `serve_forward_connection` (`:445-448`).
- `serve_forward_connection` usa Hyper `with_upgrades()` (`:470-490`). Tras completar el upgrade CONNECT, esa tarea termina y su `_permit` se libera.
- `forward_connect` incrementa `active_tunnels` y lanza el túnel en un `tokio::spawn` separado (`:492-519`), sin mover el permit ni adquirir otro.
- El test `connection_limit_drops_excess_client` (`:937-963`) retiene 128 sockets mudos, antes de CONNECT. Su barrera `watch` es determinista y no usa sleep, pero prueba el recurso equivocado.

**Reproducción ejecutada**

Un harness async público creó el proxy, abrió secuencialmente 160 sockets, envió en cada uno `CONNECT api.allowed.test:443`, esperó el `HTTP/1.1 200` y mantuvo todos abiertos sin enviar ClientHello.

Comando ejecutado (los hashes son los artefactos reportados por `rtk proxy cargo build -p cerberus-proxy --message-format=json` en esta corrida):

```bash
rtk proxy zsh -lc 'rtk proxy rustc --edition=2021 -L dependency=target/debug/deps \
  --extern cerberus_proxy=target/debug/libcerberus_proxy.rlib \
  --extern cerberus_engine=target/debug/deps/libcerberus_engine-5ea3cd0b153fc145.rlib \
  --extern tokio=target/debug/deps/libtokio-1a59be4580944237.rlib \
  -o /tmp/cerberus-f4-limit-repro-bin - <<RS
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use cerberus_engine::{engine::EngineBuilder, redact::RedactOptions};
use cerberus_proxy::{
    api::ApiContext,
    config::ProxyConfig,
    forward::{generate_local_ca, spawn_forward_proxy, CaPaths, ForwardProxyConfig},
    proxy::ProxyContext,
};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream};
async fn read_head(stream: &mut TcpStream) -> String {
    let mut out = Vec::new();
    let mut byte = [0u8; 1];
    while !out.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.unwrap();
        out.push(byte[0]);
    }
    String::from_utf8_lossy(&out).into_owned()
}
fn main() {
    tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap().block_on(async {
        let base = std::env::temp_dir().join(format!("cerberus-f4-limit-repro-{}", std::process::id()));
        let ca = CaPaths { cert: base.join("ca.pem"), key: base.join("ca.key") };
        generate_local_ca(&ca).unwrap();
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let listen = probe.local_addr().unwrap();
        drop(probe);
        let cfg = ForwardProxyConfig::new(listen, &["api.allowed.test".to_string()], ca).unwrap();
        let shared = Arc::new(RwLock::new(ProxyConfig::default()));
        let engine = EngineBuilder::new(&[]).build().unwrap();
        let ctx = Arc::new(ProxyContext {
            config: shared.clone(),
            engine: Arc::new(RwLock::new(Arc::new(engine))),
            redact_options: RedactOptions::default(),
            api: ApiContext::new(shared),
            last_upstream: Arc::new(Mutex::new(None)),
        });
        let (addr, handle) = spawn_forward_proxy(cfg, ctx).await.unwrap();
        let mut tunnels = Vec::new();
        for index in 0..160usize {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream.write_all(b"CONNECT api.allowed.test:443 HTTP/1.1\r\nHost: api.allowed.test:443\r\n\r\n").await.unwrap();
            let head = read_head(&mut stream).await;
            assert!(head.starts_with("HTTP/1.1 200"), "CONNECT {index}: {head}");
            tunnels.push(stream);
        }
        println!("active_connect_tunnels_admitted={}", tunnels.len());
        drop(tunnels);
        println!("shutdown_after_drop={:?}", handle.shutdown(Duration::from_secs(2)).await);
        std::fs::remove_dir_all(&base).unwrap();
    });
}
RS
rtk proxy /tmp/cerberus-f4-limit-repro-bin
rtk proxy rm /tmp/cerberus-f4-limit-repro-bin'
```

```text
active_connect_tunnels_admitted=160
shutdown_after_drop=Ok(())
```

El valor esperado era como máximo 128; se admitió 25% más y el código no impone otro límite, por lo que no hay techo real.

El test existente se repitió diez veces sin sleeps:

```text
1..10: cargo test: 1 passed, 166 filtered out
duración por corrida: 0.03–0.07 s
```

**Impacto**

Un proceso local no privilegiado puede mantener un número arbitrario de túneles, tareas, handshakes TLS y buffers. Loopback reduce el atacante a la máquina local, pero no reduce el agotamiento de recursos del daemon ni protege otros usuarios/procesos locales; P1 para el listener de una CA MITM.

**Corrección y regression test requeridos**

- Hacer que el permit sobreviva toda la vida de la conexión/túnel. Al aceptar CONNECT, moverlo a `TunnelGuard` (o aplicar un segundo semáforo explícito a túneles sin doble conteo).
- Supervisar las tareas de túnel; no dejarlas detached del `JoinSet` del listener.
- Regression sin sleeps: abrir exactamente `MAX_CONNECTIONS` CONNECT que reciban 200 y queden retenidos por una barrera; esperar una señal interna de `active_tunnels == MAX_CONNECTIONS`; comprobar que el siguiente cliente se cierra/rechaza sin recibir servicio; liberar la barrera y comprobar admisión posterior. Repetir varias veces.

### P2-01 — Un cliente estancado antes del ClientHello no observa shutdown

`serve_intercepted` espera `acceptor.accept(...).await` en `forward.rs:539` antes de crear el `select!` contra shutdown (`:557-570`). Un CONNECT que nunca manda TLS queda fuera de la cancelación cooperativa. La tarea de túnel, además, fue creada con `tokio::spawn` y no pertenece al `JoinSet`.

Repro ejecutado: abrir CONNECT, recibir 200, no mandar ClientHello y llamar `shutdown(200 ms)`.

```text
shutdown_with_stalled_tls_client=Err("forward proxy drain exceeded 200 ms")
```

El grace mantiene el shutdown acotado, por eso se clasifica P2 y no un tercer P1. Debe hacerse `select!` de TLS accept contra cancelación y timeout, y conservar handles de todas las tareas para abort/drain real.

### P2-02 — Faltan integraciones MITM específicas de shadow/fail-policy

Los tests TLS cubren enforce block y enforce redact, y el camino común `proxy_handler` tiene tests de shadow/fail-open/fail-closed. No existe un test CONNECT+TLS que demuestre shadow pass-through intacto + evento ni JSON inválido bajo ambas fail policies. §8B.4 pide el transcript de red en shadow. Es deuda de cobertura, no evidencia de un fallo funcional adicional.

## Auditoría de controles solicitados

- **Opt-in/control de confianza:** PASS. Ausencia/deshabilitado nunca abre listener y Cerberus sólo imprime instrucciones manuales.
- **Loopback/control plane:** PASS. `ForwardProxyConfig::new` rechaza no-loopback; `DirectUpstream` evita que `/api/*` dentro del TLS interceptado se enrute al API local.
- **Allowlist/DNS/SSRF:** PASS para el threat model del MVP. Host DNS exacto normalizado, puerto fijo 443, destino derivado sólo del allowlist, HTTPS con WebPKI/SNI; Host y URI internos no pueden escoger otro authority. Queda el riesgo operacional normal de DNS/CA pública para un dominio que el usuario autorizó explícitamente.
- **No-leak:** PASS en los casos ejecutados. Block response y audit no contienen el secreto; redacción cambia el body antes de upstream; logs de seguridad usan flags/categorías/hashes.
- **Fail policy:** PASS por camino común; default `FailPolicy::Closed`. Fail-open sigue siendo una decisión explícita de config y puede reenviar original por contrato.
- **Límites de payload/response:** PASS por camino común (`build_buffered` y `collect_resp_body`).
- **Conexiones/shutdown:** FAIL/P2 según los hallazgos anteriores.

## Comandos y salidas de quality gates

```text
$ rtk cargo build -p cerberus-proxy -p cerberus
cargo build (0 crates compiled)
Finished `dev` profile ... in 0.31s

$ rtk cargo fmt --all --check
(sin salida, exit 0)

$ rtk cargo clippy -p cerberus-proxy -p cerberus --all-targets -- -D warnings
cargo clippy: No issues found

$ rtk git diff --check
(sin salida, exit 0)

$ rtk cargo test -p cerberus-proxy forward::tests -- --nocapture
cargo test: 12 passed, 155 filtered out (2 suites, 0.09s)

$ rtk cargo test -p cerberus-proxy
cargo test: 167 passed (3 suites, 0.45s)

$ rtk cargo test -p cerberus --bin cerberus
cargo test: 39 passed (1 suite, 4.56s)

$ rtk cargo test --workspace
cargo test: 554 passed (32 suites, 37.67s)
```

## Veredicto §8B / retorno al loop

**FAIL.** Los gates verdes no prueban los dos invariantes que fallaron adversarialmente. Según §8B.1–8B.3, la unidad vuelve a FIX y requiere otro VERIFY independiente después de:

1. parser PEM de consumo completo + identidad CA sin re-firma silenciosa;
2. permit que abarque toda la vida del túnel y regression determinista de CONNECT activo;
3. cancelación/supervisión de handshake/túneles durante shutdown;
4. integraciones TLS de shadow y fail-policy.
