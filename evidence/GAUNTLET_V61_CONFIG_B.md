# Gauntlet v6.1 — unidad `config-api` (builder B)

Rama: `gauntlet-v61-config-b`. **Sin commits** (working tree).

## Archivos modificados (sólo los 3 del alcance)

| Archivo | Δ |
|---|---|
| `crates/cerberus-proxy/src/api.rs` | +1144/-… (DTOs, transaccionalidad, F6, CSP, 20 tests unitarios) |
| `crates/cerberus-proxy/dashboard.html` | +391 (paneles F6, sin handlers inline, fix `admin_token_configured`) |
| `crates/cerberus-proxy/tests/smoke_harness.rs` | +463 (8 tests HTTP reales) |

No se tocaron `daemon.rs`, `store.rs`, `updater.rs`, `cli_pack.rs`, `config.rs` ni `Cargo.toml`.

## 1. DTO `ConfigPatch` / `ConfigView` separados

- **`ConfigView`** (`GET /api/config`): DTO propio sin campo `admin_token`. Ya no se
  redacta a mano sobre el JSON de `ProxyConfig` — el secreto **no existe** en el tipo,
  así que no puede filtrarse por olvido. Expone el derivado `admin_token_configured`.
- **`ConfigPatch`** (`PUT /api/config`): semántica de patch, **todo campo ausente se
  preserva**.
  - `admin_token` omitido ⇒ token vivo intacto; `null` explícito ⇒ se borra.
    Modelado con `PatchField<T>` (`Absent` / `Clear` / `Set`), que distingue los tres
    estados del JSON en el tipo.
  - `admin_token_configured` se acepta en el body y se **ignora**: es de sólo lectura y
    no puede activar/desactivar la autenticación.
  - `deny_unknown_fields`: un typo (`admin_tokens`) es 400, no un silencio.
  - Efecto colateral bueno: `PUT {"mode":"shadow"}` ya no borra los `upstreams`.
- `ConfigPatch::apply` construye el `ProxyConfig` campo a campo ⇒ si `config.rs` gana un
  campo, **falla la compilación** en vez de perderlo en silencio.

## 2. Revalidación de exposición antes de persistir

`validate_control_plane_exposure` espeja la regla de `proxy::check_listen_security`
(`listen` no-loopback ⇒ token ≥ `ADMIN_TOKEN_MIN_BYTES` = 24) pero se aplica **antes** de
tocar memoria o disco: una config que el daemon rechazaría al arrancar tampoco se puede
guardar. `listen_is_loopback` es **safe-by-default**: lo que no resuelve a IP loopback
literal (ni `localhost`) se trata como público.

## 3. Persistencia transaccional desde la perspectiva en memoria

Orden nuevo, con el lock de escritura tomado durante toda la operación:

```
candidato = patch.apply(vivo) → validar (400) → persistir YAML (500) → publicar en memoria
```

Antes se aplicaba en memoria y *luego* se escribía: un fallo de disco dejaba la config
viva divergiendo del YAML (el 500 decía literalmente "updated in memory but not
persisted"). Ahora, si la validación o el disco fallan, **la config viva no cambió**.
Misma transacción aplicada a `POST /api/upstreams` y `DELETE /api/upstreams/{name}`.

## 4. Test HTTP real GET → PUT (requisito explícito)

`config_get_then_put_over_http_preserves_the_admin_token` (smoke_harness, proxy real +
reqwest): GET autenticado (sin el token en el body) → PUT reenviando ese body verbatim +
un cambio → 200 → el cambio se aplicó → **GET y PUT sin token siguen en 401** → el YAML
persistido conserva el token.

## 5. F6 MVP en API + dashboard

| Pieza | API | UI |
|---|---|---|
| Packs | `GET /api/packs`, `POST /api/packs/install`, `POST /api/packs/rollback` (ya existían) | panel: estado, seleccionar archivo local y transportar su contenido firmado por wire v2, rollback; nunca promete instalar por ruta |
| Providers | `GET/POST /api/upstreams`, `DELETE /api/upstreams/{name}` | alta/baja + `auth_header` real (antes mostraba `u.enabled`, que la API nunca devuelve) |
| Categorías/actions | `GET/PUT /api/policy` | tabla + selector de acción |
| Reglas propias | `GET/PUT /api/policy` (`rules`) | tabla + override por regla |
| Allowlist | `GET/POST/DELETE /api/allowlist` | listar / añadir / quitar (triage FP 1-click) |

Acciones válidas = las del Apéndice A.1 (`allow|warn|redact|block`); el overlay se siembra
con `secrets: redact`, `pii: warn` (del plan, no inventadas). `PUT /api/policy` valida
**todas** las entradas antes de aplicar ninguna; `null` en un valor borra la entrada.
`/api/policy` y `/api/allowlist` pasan por el mismo gate de auth del control plane.

## 6. CSP efectiva en cabecera, sin `unsafe-inline`

- La CSP se emite en la **cabecera** `Content-Security-Policy` (`frame-ancestors` sólo
  aplica ahí; en `<meta>` se ignora). Se eliminó el `<meta>` para que no se desincronice.
- **Sin `unsafe-inline`**: el asset servido es único, así que sus bloques inline se
  autorizan por `sha256`, calculado del **mismo `include_str!` que se envía** ⇒ hash y
  contenido no pueden divergir. SHA-256 + Base64 implementados en `api.rs` (Rust seguro)
  para no añadir dependencias al crate; verificados contra los vectores de FIPS 180-4 /
  RFC 4648 y **cross-check contra `hashlib` de Python** sobre el HTML real:
  `script-src 'sha256-hZ5nCIn1Br/gdUo6HR6AREyzq5GVQAxiSzlp3dKEW58='` (idéntico).
- Los 3 `onclick=` del HTML pasaron a `addEventListener` (habrían necesitado
  `'unsafe-hashes'`). Un test vigila que no vuelvan.
- Política final: `default-src 'none'; script-src 'sha256-…'; style-src 'sha256-…';
  connect-src 'self'; img-src 'self' data:; font-src 'none'; base-uri 'none';
  form-action 'none'; frame-ancestors 'none'; object-src 'none'`, más
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy:
  no-referrer`, `Cache-Control: no-store`.
- Bug arreglado: la UI leía `cfg.admin_token` (clave que la API nunca devuelve), así que
  siempre decía "no configurado".

## 7. Resultados

La tabla siguiente conserva la **corrida original** de esta unidad (485 tests);
no se presenta como el estado final del checkout. La revalidación integral tras
los fixes v6.1 posteriores es `cargo test --workspace` → **534 passed, 0
failed** (2026-08-21); ver
`evidence/f6/dashboard-pack-wire-v2-v61-fix.md`.

```
cargo test -p cerberus-proxy         128 passed, 0 failed   (92 lib + 36 smoke_harness)
cargo test --workspace               485 passed, 0 failed   (32 suites)
cargo clippy --workspace --all-targets   0 issues  (pedantic+nursery+cargo en deny)
cargo fmt --all -- --check               clean
```

28 tests nuevos: 20 unitarios en `api.rs` + 8 HTTP en `smoke_harness.rs`.
Casos adversariales cubiertos: `admin_token_configured:false` no apaga la auth; mover
`listen` a `0.0.0.0` borrando el token es 400 y no escribe el YAML; token de 23 bytes es
400 y de 24 pasa; fallo de escritura deja la config viva intacta; acción de política
inválida no aplica ninguna entrada del patch; hostname no resoluble se trata como público.

## 8. Riesgos y límites

1. **El overlay de política vive en memoria y no llega al motor.** `categories`/`rules`
   se exponen y editan con paridad CLI↔UI, pero no se serializan al YAML ni cambian la
   detección: `ProxyConfig` (config.rs) no tiene esos campos y `config.rs` estaba fuera
   del alcance de esta unidad. La API lo declara (`"persisted": false`) y la UI lo avisa
   en pantalla. **Wirearlo a `ProxyConfig` + engine es trabajo pendiente de F6/F1.**
   Lo mismo aplica a `allowlist`, que ya era in-memory antes de este cambio.
2. **`deny_unknown_fields` en `ConfigPatch`** es un cambio de contrato: un cliente que
   mande claves extra pasa de 200 a 400. Verificado que hoy sólo `smoke_harness` y el
   dashboard consumen `PUT /api/config`.
3. **`listen_is_loopback` es safe-by-default**: un `listen` con hostname (p.ej.
   `proxy.internal:8080`) se considera público y exige token ≥ 24 bytes. Es más estricto
   que antes; deliberado, pero puede sorprender a quien use hostnames.
4. **La CSP por hash es frágil ante ediciones del HTML por otra vía**: cualquier cambio en
   el bloque inline recalcula el hash automáticamente (mismo `include_str!`), pero un
   `onclick=`/`style=` nuevo se rompería en el navegador. Hay un test que lo detecta; la
   alternativa robusta (servir `dashboard.js` como asset aparte con `script-src 'self'`)
   exige un archivo nuevo, fuera del alcance de esta unidad.
5. **`requires_restart` sigue siendo informativo**: el `listen` nuevo se persiste y se
   publica en memoria, pero el socket vivo no se rebindea (comportamiento previo, no
   modificado).
6. **`DELETE /api/upstreams` no revalida la exposición** (a propósito: quitar un upstream
   no puede abrir el control plane). Asimetría intencional con el POST.
