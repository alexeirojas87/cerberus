# Evidence Pack — f6/dashboard-pack-wire-v2-v61-fix

- Intento: FIX 1
- Fecha: 2026-08-21
- Checkout: CURRENT, sin commit
- Veredicto: **PASS**

## Fallo reproducido (before)

La revisión adversarial v6.1 registró el body exacto anterior en
`evidence/review7/opencode-findings.md`: `dashboard.html:543-551` tomaba el
texto de `pack-path` y ejecutaba
`sendJson('POST', '/api/packs/install', { path })`. En el mismo checkout,
`PackInstallRequest::parse_body` rechaza esa forma como
`LegacyPathRequest`, y el test HTTP
`pack_install_wire_v2_accepts_bytes_and_never_opens_legacy_path` demuestra
respuesta 400 antes de encolar el comando al worker. Por tanto el FAIL previo
era reproducible y no una inferencia visual.

## Cambio (after)

- `crates/cerberus-proxy/dashboard.html:108-109`: el panel usa
  `<input type="file" id="pack-file">`; no solicita ni promete una ruta. El
  navegador valida archivo presente/no vacío, aplica `MAX_PACK_BYTES`
  (`dashboard.html:523-524,546-558`), lee `arrayBuffer()` y decodifica UTF-8
  con `TextDecoder(..., { fatal: true })` (`:565-566`). Construye el request
  exacto en `:575` y lo envía en `:578`: `{ wire_version: 2, pack }`. No manda
  `input.value`, `origin_name` ni otro dato con semántica de ruta local.
- Los errores por archivo vacío, oversize, UTF-8 inválido, rechazo del daemon y
  fallo de conexión producen mensajes accionables en `packs-msg` mediante
  `textContent`.
- La CSP continúa sin `unsafe-inline`: el script sigue siendo un único bloque
  cuyo hash se deriva del mismo `include_str!` servido; no se añadieron
  handlers inline.
- `crates/cerberus-packs/src/wire.rs:39-47` expone
  `MAX_PACK_BODY_BYTES = 1 MiB` y deriva
  `MAX_PACK_BYTES = (MAX_PACK_BODY_BYTES - 1024) / 2` (523,776 bytes). El
  parser y el colector HTTP comparten la cota del body.
- `crates/cerberus-proxy/src/api.rs:2251-2302` amplía el test de contrato
  existente: si
  reaparece `path` dentro de `installPack`, falta el selector file, cambian las
  constantes/shape wire v2 o el body representativo deja de ser aceptado por
  `PackInstallRequest::parse_body`, la suite falla. El test de
  `api.rs:1690-1698` comprueba la invariante
  `2·MAX_PACK_BYTES + 1024 <= CONTROL_PLANE_MAX_BYTES`; la cota compartida se
  conecta en `api.rs:59,101`.

## Criterios de aceptación y gates

| Criterio | Comando ejecutado | Salida citada | Resultado |
|---|---|---|---|
| Selector file, sin `{path}`, shape wire v2 aceptada por `parse_body` y CSP sin handlers inline | `cargo test -p cerberus-proxy dashboard_html_has_no_inline_event_handlers` | `1 passed; 154 filtered out`; exit 0 | ✅ |
| Parser wire y cotas | `cargo test -p cerberus-packs wire` | `8 passed; 51 filtered out`; exit 0 | ✅ |
| API HTTP acepta bytes y rechaza path antes del worker | `cargo test -p cerberus-proxy --test smoke_harness pack_install_wire_v2_accepts_bytes_and_never_opens_legacy_path` | `1 passed; 37 filtered out`; exit 0 | ✅ |
| CLI sigue enviando contenido wire v2 | `cargo test -p cerberus --test pack_cli_via_api` | `4 passed`; exit 0 | ✅ |
| Build workspace | `cargo build --workspace` | `Finished dev profile`; exit 0 | ✅ |
| Formato | `cargo fmt --all -- --check` | sin diff; exit 0 | ✅ |
| Lints estrictos | `cargo clippy --workspace --all-targets -- -D warnings` | `No issues found`; exit 0 | ✅ |
| Workspace completo | `cargo test --workspace` | **`534 passed`** (32 suites, 36.87 s); exit 0 | ✅ |
| Higiene del diff | `git diff --check` | sin errores; exit 0 | ✅ |

Las cifras 474, 485 y 532 de documentos anteriores son resultados reales de
corridas anteriores y se conservan como tales. La cifra final del checkout
v6.1 verificado en esta unidad es **534 passed / 0 failed**.

## Casos adversariales

- Sin archivo seleccionado → no hay request y la UI pide seleccionar uno.
- Archivo vacío u >523,776 bytes → no hay request y la UI muestra la cota.
- Bytes no UTF-8 → `TextDecoder` fatal aborta antes de la red.
- Regresión a cualquier identificador `path` dentro de `installPack` → falla
  el test de contrato estático.
- Request legacy con un archivo real visible para el servidor → HTTP 400 y el
  worker no recibe un segundo comando (smoke existente).
- Body representativo producido por la shape del dashboard →
  `PackInstallRequest::parse_body` devuelve `Ok`.

## P2-4 — descriptor stale

No se amplió el alcance con este P2. Existe `process_alive` en
`cli_pack.rs`, pero su rama Windows considera vivo cualquier `tasklist` con
stdout no vacío y no ofrece una comprobación fiable de identidad ante reuso
de PID; por tanto no es la comprobación segura y cross-platform exigida para
reutilizarla aquí. Corregirla exigiría diseño y matriz macOS/Linux/Windows,
fuera del fix MVP del P1. No bloquea: el descriptor sólo selecciona un puerto
loopback, el CLI no abre rutas ni relaja auth, una entrada rancia falla cerrada
al conectar, y el shutdown graceful ya elimina `endpoint.json`.

## Gate

Todos los criterios ejecutables de esta unidad están en PASS y el flujo UI
produce un body aceptado por `PackInstallRequest::parse_body`. Este Evidence
Pack cierra la unidad del fix; el gate de fase/integración sigue perteneciendo
al coordinador según §8B.7.
