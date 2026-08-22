# F8 — Notas: Helm (Modo A) + Telemetría opt-in real

> Gate: Fase 8 — distribución y arranque de confianza.
> Alcance: `deploy/helm/cerberus/` (chart Helm Modo A) y `crates/cerberus-packs/src/telemetry.rs`.
> y `crates/cerberus-packs/src/telemetry.rs` (telemetría opt-in con envío HTTP real).

## 1. Chart Helm `deploy/helm/cerberus/`

Despliega el daemon Cerberus en modo A (self-host del reverse proxy frente a
flota de agentes) en Kubernetes.

- `Chart.yaml` — `name: cerberus`, `version: 0.1.0`, `apiVersion: v2`.
- `values.yaml` — defaults alineados con la config real del producto:
  - `image.repository/tag/pullPolicy` → `ghcr.io/alexeirojas87/cerberus:0.1.0`.
  - `replicaCount: 1`, `service.type: ClusterIP`, `service.port: 8787`
    (`targetPort: 8080` = puerto real del proceso).
  - `config.mode: enforce`, `config.failPolicy: closed`,
    `config.retentionDays: 90`, `config.admin.*`, `config.upstreams` con
    openai/anthropic/gemini/default (mismo layout que `cerberus init`),
    `config.telemetry.*` (OFF por defecto), `ingress.enabled: false`.
  - `serviceAccount`, `podSecurityContext`, `securityContext` con
    `readOnlyRootFilesystem: true` (los writes van al emptyDir de
    `/root/.cerberus`).
  - `environment` → bloque env del pod con `{{- range ... }}` /
    `{{ $v | quote }}`.
- `templates/configmap.yaml` — materializa `config.yaml` con `listen:
  0.0.0.0:<targetPort>`, `mode`, `fail_policy`, `health_path`, `upstreams`
  (vía `toYaml .Values.config.upstreams | nindent 6` — nindent 6 obligatorio,
  ver gotcha abajo), `retention_days` y `telemetry`.
- `templates/deployment.yaml` —
  - `args: ["start", "--port", "8080"]` (sobreescribe el CMD del Dockerfile).
  - env `CERBERUS_LISTEN_HOST=0.0.0.0`.
  - env `CERBERUS_ADMIN_TOKEN` vía `valueFrom.secretKeyRef` al Secret del chart.
  - env `CERBERUS_TELEMETRY_ENDPOINT` (derivado de `config.telemetry.endpoint`).
  - monta `/root/.cerberus/config.yaml` (configMap, `subPath`, `readOnly`) +
    emptyDir en `/root/.cerberus` para runtime (packs, audit, `install_id`).
  - liveness/readiness sobre `/health` en el puerto `http`.
- `templates/secret.yaml` — `kind: Secret` tipo `Opaque` con
  `admin-token` (`b64enc`).
  - **Gate fail-closed**: si `config.admin.enabled=true` (default) y
    `config.admin.token` está vacío, `helm install/template` FALLA con
    `required`. El patrón correcto es asignar a variable
    (`{{- $tok := required "..." .Values.config.admin.token -}}`); si
    `required` se escribe suelto, **volca el token como primera línea del
    manifest** y rompe el YAML.
  - **Por qué es obligatorio en K8s**: el listener se bindea a `0.0.0.0`
    (no-loopback) y `cerberus-proxy` exige un admin token de >= 24 bytes para
    arrancar en interfaces no-loopback (review v4 #1) — sin token el pod
    termina en CrashLoopBackOff.
- `templates/service.yaml` — `ClusterIP`, `8787 -> 8080`.
- `templates/ingress.yaml` — condicional `ingress.enabled`, `ingressClassName`,
  tls y anotaciones.
- `templates/NOTES.txt` — paso 1 configurar `CERBERUS_ADMIN_TOKEN`, luego
  `helm test`, port-forward y var de agente, y aviso de telemetría opt-in.
- `templates/tests/cerberus-health.yaml` — hook `test` con
  `curlimages/curl` → `curl /health` contra el Service.
- `values-prod.yaml` — ejemplo productivo: ingresos + tls + anotaciones,
  `resources` (250m/256Mi — 1/512Mi), telemetría OFF.
- `.helmignore`.

### Comandos de validación

```bash
helm lint deploy/helm/cerberus \
  --set 'config.admin.token=$CERBERUS_ADMIN_TOKEN'
helm template cerberus deploy/helm/cerberus \
  --set 'config.admin.token=$CERBERUS_ADMIN_TOKEN'
# con perfil productivo
helm template cerberus deploy/helm/cerberus -f deploy/helm/cerberus/values-prod.yaml \
  --set 'config.admin.token=$CERBERUS_ADMIN_TOKEN'
helm install cerberus deploy/helm/cerberus \
  --set "config.admin.token=$CERBERUS_ADMIN_TOKEN"
helm test cerberus
kubectl port-forward svc/cerberus 8787:8787
```

Nota de dureza: se validó con `helm 3.16.4` (sin helm en la máquina, se bajó a
`/tmp` para la verificación) + pyyaml `safe_load_all` sobre el render completo.

### Gotchas encontrados

1. **`required` vierte su valor al stream**: `{{- required "msg" $x }}` imprime `$x` como
   primera línea → YAML inválido. Siempre: `{{- $x := required "msg" $x }}`.
2. **`indent` vs base del bloque `|-`**: en un bloque `config.yaml: |-` la base
   de indentación es 4; `{{ toYaml ... | indent 4 }}` deja las claves de los
   hijos al MISMO nivel que `upstreams:` (parsea como `upstreams: None` + claves
   hermanas). Usar `nindent 6`.
3. Chart.yaml con `description` sin comillas y con `:` rompe el lint -> comillas
   el campo.

## 2. Telemetría opt-in real (`cerberus-packs`)

`crates/cerberus-packs/src/telemetry.rs` + `Cargo.toml`.

### Forbidden to regress

- `TelemetryConfig::default().enabled == false` (opt-in; sigue el build plan).
- El payload SOLO contiene métricas anónimas: `version`, `os`, `rule_count`,
  `event_count`, `uptime_secs`, `license_tier`, `install_id`.
  **NUNCA** rutas locales, flags, findings/valores hasheados, tokens, PII.
  `privacy_policy()` lo documenta y el test `payload_has_no_secrets_fields` lo
  blinda (assert del set exacto de claves + barrido de "secretos").

### Cambios

- `send(payload)` → POST HTTP real **solo cuando** `enabled=true` **y** hay
  endpoint (config o `CERBERUS_TELEMETRY_ENDPOINT` no vacío). Sin esas dos
  condiciones: **cero tráfico**, log y `Ok`.
- Fallos de red/HTTP/timeout → log `warn` y `Ok(()` (la telemetría nunca
  bloquea ni rompe el daemon). Timeout fijo de 5s.
- `send_background()` → dispara en `std::thread` para no bloquear al daemon.
- `install_id` → uuid v4 persistido en `~/.cerberus/install_id`
  (env de override interno `CERBERUS_INSTALL_ID_DIR` para tests).
  Usa el crate `uuid` (está en el lock); HTTP con `reqwest` *blocking*
  (`default-tls`, mismo que ya usa el workspace — `ureq` no está en el lock
  y requeriría descarga nueva).
- Deps añadidas a `cerberus-packs`: `reqwest` (blocking/default-tls) y `uuid`.

### Tests

`telemetry_disabled_no_http`, `payload_has_no_secrets_fields`,
`id_default_persistent_in_tmp`, `send_simulated_fail_ok_when_disabled` +
`telemetry_enabled_posts_to_endpoint` (mock TCP que comprueba que SÍ se hace un
POST con el payload), `telemetry_enabled_without_endpoint_skips_http`,
`telemetry_enabled_http_failure_is_ok` (fallo silencioso), `env_endpoint...`,
`install_id_is_persistent`, `privacy_policy_not_empty`.

## 3. Verificación (resultados)

| Comando | Resultado |
|---|---|
| `helm lint . --set config.admin.token=...` | 0 failed |
| `helm template . --set ...` (defaults) | renders 5 docs; `config.yaml` parsea OK (nindent) |
| `helm template . -f values-prod.yaml --set ...` | Ingress+TLS+resources OK |
| `helm template .` (sin token) | FALLA (required) — fail-closed |
| `cargo test -p cerberus-packs --all-targets` | 65 passed |
| `cargo clippy -p cerberus-packs --all-targets -- -D warnings` | no issues |
| `cargo fmt -p cerberus-packs --check` | no diffs |

## 4. Obligaciones de lanzamiento (pseudo-requisitos)

- Publicar la imagen (`ghcr.io/alexeirojas87/cerberus`) y actualizar
  `values.yaml`/`values-prod.yaml` con el tag/digest correcto (el chart usa
  placeholder `0.1.0`).
- El endpoint de telemetría `https://telemetry.cerberus.dev/v1/ping` es
  sintético de producto: para self-host total el operador apunta
  `config.telemetry.endpoint` a su propio endpoint o deja `enabled=false`.
- Prueba real en cluster (kind/minikube): `helm install` con el token,
  port-forward y evaluación del flujo mono–agente, y `helm test`.