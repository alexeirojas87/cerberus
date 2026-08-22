# Cerberus — Operator Guide

## Architecture

```
Client/Agent ──► Cerberus Proxy ──► LLM Provider
                    │
                    ├── Detection Engine (regex RE2-like, linear time)
                    ├── Redaction Engine (block/redact/warn/allow)
                    ├── Audit Store (SQLite local)
                    ├── Config API + Dashboard (localhost)
                    ├── Dev Feedback (desktop notify, rate-limited)
                    ├── MITM Forward Proxy (opt-in, allowlisted hosts)
                    └── Telemetry (opt-in, anonymous only)
```

## Deployment

### Docker (Modo A — server-side)
```bash
docker run -d \
  --name cerberus \
  -p 8787:8787 \
  -v $(pwd)/cerberus.yaml:/root/.cerberus/config.yaml \
  cerberus/cerberus
```

### Docker Compose
```bash
docker-compose up -d
```

### Helm (Modo A — Kubernetes)
```bash
helm install cerberus deploy/helm/cerberus \
  --set config.listen=0.0.0.0:8080 \
  --set adminToken.create=true
```
The chart ships a ConfigMap (default `0.0.0.0:8080`), a Secret for the admin
token, and a readiness probe on `/health`. Values are validated; missing
required values fail at `helm install` (not at runtime).

### Configuration file
Default location: `~/.cerberus/config.yaml` (or `%APPDATA%\cerberus\` on Windows).
Override with `CERBERUS_CONFIG` env var.

```yaml
listen: 127.0.0.1:8787
mode: enforce
fail_policy: closed
upstreams:
  anthropic:
    url: https://api.anthropic.com
  openai:
    url: https://api.openai.com
health_path: /health
telemetry:
  enabled: false
```

### Platform notes
- **macOS/Linux:** config dir is `~/.cerberus/`; PID file at
  `~/.cerberus/cerberus.pid`; daemon stopped gracefully via PID.
- **Windows:** config dir is `%APPDATA%\cerberus\`; process management uses
  `tasklist`/`taskkill`; the same binary ships as a `.zip` (winget supports
  `InstallerType: zip`).

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check (status, version, mode, upstream count) |
| `/api/config` | GET | Current configuration (admin token never returned) |
| `/api/config` | PUT/PATCH | Update configuration (hot-swap, no restart) |
| `/api/upstreams` | GET/POST/PUT/DELETE | CRUD upstreams (admin-auth) |
| `/api/events` | GET | Audit events (flags + hashes, never raw) |
| `/api/stats` | GET | Aggregated stats by provider with top flags |
| `/api/allowlist` | POST | Add to allowlist (FP triage, 1-click) |
| `/api/dashboard` | GET | HTML dashboard (CSP-protected, no inline scripts) |
| `/api/packs` | GET/POST/DELETE | Install/rollback signed rule packs (Pro) |

## MITM Forward Proxy (opt-in)

For agents that don't honor `*_BASE_URL` overrides, Cerberus can intercept
egress TLS via a locally-generated CA. This is **opt-in** and **fail-closed**:

- `cerberus mitm init` generates a CA under `~/.cerberus/ca/` (or
  `%APPDATA%\cerberus\ca\` on Windows).
- `cerberus mitm enable <host>` adds an exact host to the allowlist
  (CONNECT + TLS allowlist is exact, no wildcards).
- The proxy refuses to bind if the CA cert/key are missing, mismatched, or
  tampered — verified before listener creation, not after.
- Only allowlisted hosts are intercepted; all other CONNECTs are refused.

## Logging

Logs are written to stderr with structured fields:
- `event_type` — Type of security event
- `action_taken` — block/redact/warn
- `finding_count` — Number of findings
- `flags` — Rule flags that fired
- `hashes` — SHA-256 hashes only (never raw values)
- `mode` — shadow/enforce
- `tier` — free/pro

## Monitoring

- Health check endpoint for load balancers
- Stats API for Prometheus integration (coming in Pro)
- Audit events stored in SQLite for compliance
- Telemetry (if enabled) sends anonymous metrics only — see Security Guide
  for the full privacy policy and the exact payload schema.
