# Cerberus — Security Guide

## Threat Model

Cerberus protects against **accidental leakage** of secrets and PII in prompts
sent to LLM providers. It operates on the **egress path** from the client/agent
to the provider.

### In Scope
- API keys, tokens, and credentials in prompt text
- PII (emails, phone numbers) in messages
- Accidental inclusion of `.env` or config values
- High-entropy secrets near indicative keywords
- Multiline blocks: PEM private keys, SSH keys, `.env` dumps

### Out of Scope (MVP)
- Malicious insider bypassing Cerberus (mitigated by break-glass audit trail)
- Provider-side data breaches (Cerberus cannot control what happens at the provider)
- Streaming response scanning (post-MVP)
- Binary/multipart payloads (post-MVP)

## Security Guarantees

### 1. Zero Leak of Secrets
- **Never persisted:** Raw secret values are never written to disk or logs
- **Hashed only:** All stored values are SHA-256 hashed
- **Not logged:** Secret values excluded from all log output
- **Not in telemetry:** Telemetry payload (if enabled) contains only anonymous
  metrics — never secrets, PII, findings, flags, or hashes
- **Not in feedback:** Desktop notifications show flag + hash, never raw value
- **Memory hygiene:** Values released after scan (Rust ownership model)

### 2. No ReDoS
- Rust `regex` crate uses a linear-time matching engine (RE2-like)
- No backtracking = no catastrophic ReDoS
- All patterns in the default pack (13 rules) verified with adversarial
  fuzzing, including multiline PEM/.env patterns (see `tests/redos_fuzz.rs`)

### 3. Fail-Closed by Default
- If the engine fails, the request is rejected (`FailPolicy::default() = Closed`)
- Fail-open available for availability-sensitive deployments
- The MITM forward proxy fails closed **before** binding the listener if the
  CA material is missing/mismatched/tampered — no passive interception
- Configurable per deployment

### 4. Break-Glass Audit Trail
- `cerberus allow-once` bypasses blocks with recorded reason
- Every bypass is logged with timestamp, reason, and flags bypassed
- Enables incident response without blocking productivity

### 5. MITM Opt-In & Scoped
- MITM interception is **opt-in** (`cerberus mitm init` + `mitm enable`)
- The CONNECT allowlist is **exact-match** (no wildcards); non-allowlisted
  hosts are refused
- The CA is generated locally (`create_new` semantics, refuses to overwrite)
- The proxy refuses to start if the CA cert/key pair doesn't match or is
  tampered (verified before listener bind)

### 6. Telemetry Privacy
Telemetry is **opt-in and disabled by default**. The exact payload is defined
and tested in `cerberus_packs::telemetry`:

**Collected (anonymous only):**
- Cerberus version and OS
- Rule count and aggregate event counts
- Uptime and installation age
- A random persistent installation ID (UUID, never tied to identity)

**Never collected:**
- Raw secrets, PII, or any content
- Scan findings, flags, or hashed values
- User names, emails, system paths, or prompt data

Disable at any time via `config.yaml`:
```yaml
telemetry:
  enabled: false
```

## Data Flow

```
┌──────────┐     ┌──────────┐     ┌──────────┐
│  Agent   │────►│ Cerberus │────►│ Provider │
│ (LLM)    │     │  Proxy   │     │ (API)    │
└──────────┘     └────┬─────┘     └──────────┘
                      │
                      ▼
              ┌──────────────┐
              │  Audit Store │
              │  (SQLite)    │
              │  hashes only │
              └──────────────┘
```

1. Agent sends request → Cerberus intercepts
2. Body is decoded (JSON/text) and scanned
3. Findings are produced: matched patterns + hashed values
4. Actions applied: block (403), redact (replace token), or pass through
5. Only hashes/counts are stored; raw values are discarded
6. Redacted request is forwarded to provider
7. (Optional) Dev feedback: desktop notification with flag + hash, rate-limited

## Configuration Security

- Default config is restrictive (fail-closed, enforce mode)
- Config file should have restricted permissions (`chmod 600`)
- The admin token is never returned by `GET /api/config` (only
  `admin_token_configured: bool`); set it via env or the config file
- API endpoint should not be exposed to untrusted networks
- Dashboard serves on localhost only by default; CSP forbids inline scripts

## Rule Pack Security (Pro)

- Signed packs use Ed25519 signatures verified against a trust root at boot
- A pack with an invalid/tampered signature is **deactivated and persisted**
  (fail-closed), never silently loaded
- Without a trust root, the engine boots with 0 packs (fail-closed)
- Hot-reload reuses the same engine validation path (no bypass via reload)
