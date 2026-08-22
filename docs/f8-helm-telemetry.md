# F8 — Notes: Helm (Mode A) + real opt-in telemetry

> Gate: Phase 8 — distribution and trust bootstrap.
> Scope: `deploy/helm/cerberus/` (Mode A Helm chart) and `crates/cerberus-packs/src/telemetry.rs`.
> and `crates/cerberus-packs/src/telemetry.rs` (opt-in telemetry with real HTTP send).

## 1. Helm chart `deploy/helm/cerberus/`

Deploys the Cerberus daemon in mode A (self-hosted reverse proxy in front of a fleet
of agents) on Kubernetes.

- `Chart.yaml` — `name: cerberus`, `version: 0.1.0`, `apiVersion: v2`.
- `values.yaml` — defaults aligned with the product's real config:
  - `image.repository/tag/pullPolicy` → `ghcr.io/alexeirojas87/cerberus:0.1.0`.
  - `replicaCount: 1`, `service.type: ClusterIP`, `service.port: 8787`
    (`targetPort: 8080` = the process's real port).
  - `config.mode: enforce`, `config.failPolicy: closed`,
    `config.retentionDays: 90`, `config.admin.*`, `config.upstreams` with
    openai/anthropic/gemini/default (same layout as `cerberus init`),
    `config.telemetry.*` (OFF by default), `ingress.enabled: false`.
  - `serviceAccount`, `podSecurityContext`, `securityContext` with
    `readOnlyRootFilesystem: true` (writes go to the emptyDir at
    `/root/.cerberus`).
  - `environment` → pod env block with `{{- range ... }}` /
    `{{ $v | quote }}`.
- `templates/configmap.yaml` — materializes `config.yaml` with `listen:
  0.0.0.0:<targetPort>`, `mode`, `fail_policy`, `health_path`, `upstreams`
  (via `toYaml .Values.config.upstreams | nindent 6` — nindent 6 is mandatory,
  see gotcha below), `retention_days`, and `telemetry`.
- `templates/deployment.yaml` —
  - `args: ["start", "--port", "8080"]` (overrides the Dockerfile CMD).
  - env `CERBERUS_LISTEN_HOST=0.0.0.0`.
  - env `CERBERUS_ADMIN_TOKEN` via `valueFrom.secretKeyRef` to the chart's Secret.
  - env `CERBERUS_TELEMETRY_ENDPOINT` (derived from `config.telemetry.endpoint`).
  - mounts `/root/.cerberus/config.yaml` (configMap, `subPath`, `readOnly`) +
    emptyDir at `/root/.cerberus` for runtime (packs, audit, `install_id`).
  - liveness/readiness on `/health` over the `http` port.
- `templates/secret.yaml` — `kind: Secret` of type `Opaque` with
  `admin-token` (`b64enc`).
  - **Fail-closed gate**: if `config.admin.enabled=true` (default) and
    `config.admin.token` is empty, `helm install/template` FAILS with
    `required`. The correct pattern is to assign it to a variable
    (`{{- $tok := required "..." .Values.config.admin.token -}}`); if
    `required` is written loose, **it dumps the token as the first line of the
    manifest** and breaks the YAML.
  - **Why it's mandatory in K8s**: the listener binds to `0.0.0.0`
    (non-loopback) and `cerberus-proxy` requires an admin token of >= 24 bytes
    to start on non-loopback interfaces (review v4 #1) — without a token the pod
    ends up in CrashLoopBackOff.
- `templates/service.yaml` — `ClusterIP`, `8787 -> 8080`.
- `templates/ingress.yaml` — conditional `ingress.enabled`, `ingressClassName`,
  tls and annotations.
- `templates/NOTES.txt` — step 1 set `CERBERUS_ADMIN_TOKEN`, then
  `helm test`, port-forward and the agent env var, and an opt-in telemetry notice.
- `templates/tests/cerberus-health.yaml` — `test` hook with
  `curlimages/curl` → `curl /health` against the Service.
- `values-prod.yaml` — production example: ingress + tls + annotations,
  `resources` (250m/256Mi — 1/512Mi), telemetry OFF.
- `.helmignore`.

### Validation commands

```bash
helm lint deploy/helm/cerberus \
  --set 'config.admin.token=$CERBERUS_ADMIN_TOKEN'
helm template cerberus deploy/helm/cerberus \
  --set 'config.admin.token=$CERBERUS_ADMIN_TOKEN'
# with the production profile
helm template cerberus deploy/helm/cerberus -f deploy/helm/cerberus/values-prod.yaml \
  --set 'config.admin.token=$CERBERUS_ADMIN_TOKEN'
helm install cerberus deploy/helm/cerberus \
  --set "config.admin.token=$CERBERUS_ADMIN_TOKEN"
helm test cerberus
kubectl port-forward svc/cerberus 8787:8787
```

Hardness note: validated with `helm 3.16.4` (no helm on the machine, downloaded to
`/tmp` for verification) + pyyaml `safe_load_all` over the full render.

### Gotchas found

1. **`required` spills its value into the stream**: `{{- required "msg" $x }}`
   prints `$x` as the first line → invalid YAML. Always: `{{- $x := required "msg" $x }}`.
2. **`indent` vs the base of a `|-` block**: in a `config.yaml: |-` block the
   indentation base is 4; `{{ toYaml ... | indent 4 }}` leaves the child keys at the
   SAME level as `upstreams:` (parses as `upstreams: None` + sibling keys). Use
   `nindent 6`.
3. Chart.yaml with an unquoted `description` containing `:` breaks lint → quote
   the field.

## 2. Real opt-in telemetry (`cerberus-packs`)

`crates/cerberus-packs/src/telemetry.rs` + `Cargo.toml`.

### Forbidden to regress

- `TelemetryConfig::default().enabled == false` (opt-in; follows the build plan).
- The payload ONLY contains anonymous metrics: `version`, `os`, `rule_count`,
  `event_count`, `uptime_secs`, `license_tier`, `install_id`.
  **NEVER** local paths, flags, findings/hashed values, tokens, or PII.
  `privacy_policy()` documents this and the test `payload_has_no_secrets_fields`
  guards it (asserts the exact set of keys + a sweep for "secrets").

### Changes

- `send(payload)` → a real HTTP POST **only when** `enabled=true` **and** there is
  an endpoint (config or non-empty `CERBERUS_TELEMETRY_ENDPOINT`). Without those two
  conditions: **zero traffic**, log, and `Ok`.
- Network/HTTP/timeout failures → `warn` log and `Ok(())` (telemetry never blocks
  or breaks the daemon). Fixed 5s timeout.
- `send_background()` → fires in a `std::thread` so as not to block the daemon.
- `install_id` → uuid v4 persisted at `~/.cerberus/install_id`
  (internal override env `CERBERUS_INSTALL_ID_DIR` for tests).
  Uses the `uuid` crate (already in the lockfile); HTTP via *blocking* `reqwest`
  (`default-tls`, same as the workspace already uses — `ureq` is not in the lockfile
  and would require a new download).
- Deps added to `cerberus-packs`: `reqwest` (blocking/default-tls) and `uuid`.

### Tests

`telemetry_disabled_no_http`, `payload_has_no_secrets_fields`,
`id_default_persistent_in_tmp`, `send_simulated_fail_ok_when_disabled` +
`telemetry_enabled_posts_to_endpoint` (mock TCP that verifies a POST with the
payload IS made), `telemetry_enabled_without_endpoint_skips_http`,
`telemetry_enabled_http_failure_is_ok` (silent failure), `env_endpoint...`,
`install_id_is_persistent`, `privacy_policy_not_empty`.

## 3. Verification (results)

| Command | Result |
|---|---|
| `helm lint . --set config.admin.token=...` | 0 failed |
| `helm template . --set ...` (defaults) | renders 5 docs; `config.yaml` parses OK (nindent) |
| `helm template . -f values-prod.yaml --set ...` | Ingress+TLS+resources OK |
| `helm template .` (no token) | FAILS (required) — fail-closed |
| `cargo test -p cerberus-packs --all-targets` | 65 passed |
| `cargo clippy -p cerberus-packs --all-targets -- -D warnings` | no issues |
| `cargo fmt -p cerberus-packs --check` | no diffs |

## 4. Release obligations (pseudo-requirements)

- Publish the image (`ghcr.io/alexeirojas87/cerberus`) and update
  `values.yaml`/`values-prod.yaml` with the correct tag/digest (the chart uses the
  `0.1.0` placeholder).
- The telemetry endpoint `https://telemetry.cerberus.dev/v1/ping` is a synthetic
  product endpoint: for full self-hosting the operator points
  `config.telemetry.endpoint` at their own endpoint or leaves `enabled=false`.
- Real test in a cluster (kind/minikube): `helm install` with the token,
  port-forward, and evaluation of the single-agent flow, plus `helm test`.
