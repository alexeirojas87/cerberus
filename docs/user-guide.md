# Cerberus — User Guide

## Installation

### macOS (Homebrew)
```bash
brew install cerberus
```

### Linux / macOS (curl | sh)
```bash
curl -fsSL https://get.cerberus.dev | sh
```

### Windows (winget)
```powershell
winget install cerberus
```
Alternatively, download the `.zip` from the releases page, verify the SHA256
against `SHA256SUMS`, and extract `cerberus.exe` to a directory on your `PATH`.

### Docker
```bash
docker run -p 8787:8787 cerberus/cerberus
```

## Quick Start

### 1. Initialize
```bash
cerberus init
```
This auto-detects installed agents (Claude Code, Codex, opencode, pi) and creates
`~/.cerberus/config.yaml` with the default configuration (OpenAI + Anthropic
upstreams, enforce mode, fail-closed).

### 2. Start the daemon
```bash
cerberus start
```
The proxy listens on `127.0.0.1:8787`.

### 3. Configure your agent
Set the `*_BASE_URL` environment variable for your agent:
```bash
# Claude Code
export CLAUDE_CODE_BASE_URL=http://127.0.0.1:8787

# opencode
export OPENCODE_BASE_URL=http://127.0.0.1:8787

# Codex
export CODEX_BASE_URL=http://127.0.0.1:8787
```

### 4. Test it works
```bash
cerberus test "my api key is sk-abcDEFghijklmnopqrstuvwxyz1234"
# → Detects the secret and reports it (flag + keyed HMAC-SHA256 hash, never the raw value)
```

### 5. (Optional) Enable MITM interception
For agents that don't honor `*_BASE_URL` overrides, Cerberus can intercept
egress TLS via a local CA:
```bash
cerberus mitm init       # generates a local CA (~/.cerberus/ca/)
cerberus mitm enable api.openai.com  # allowlist exact host
cerberus mitm status
```
MITM is **opt-in and fail-closed**: it refuses to bind if the CA material is
missing/mismatched/tampered, and only intercepts hosts on the explicit allowlist.

## Commands

| Command | Description |
|---------|-------------|
| `cerberus init` | Auto-detect agents and create config |
| `cerberus start` | Start the local proxy daemon |
| `cerberus stop` | Stop the local proxy daemon |
| `cerberus status` | Show daemon status |
| `cerberus scan <file>` | Scan a file for secrets |
| `cerberus test <text>` | Test detection with inline text |
| `cerberus doctor` | System diagnostics (daemon PID, rule count, agents) |
| `cerberus mode <shadow\|enforce>` | Change operation mode |
| `cerberus mitm <init\|enable\|status>` | Manage MITM/forward proxy (opt-in) |
| `cerberus pack <install\|rollback\|list>` | Manage signed rule packs (Pro) |
| `cerberus license` | Show active license tier (Free/Pro) |

## Configuration

Edit `~/.cerberus/config.yaml`:

```yaml
listen: 127.0.0.1:8787
mode: enforce
fail_policy: closed
upstreams:
  openai:
    url: https://api.openai.com
  anthropic:
    url: https://api.anthropic.com
telemetry:
  enabled: false   # opt-in, off by default
```

### Modes
- **enforce** (default): Apply actions (block/redact)
- **shadow**: Scan and log only, never block

### Fail Policy
- **closed** (default): Reject request if engine fails
- **open**: Let request pass if engine fails

### Dev Feedback
When Cerberus blocks/redacts/warns, it shows a desktop notification
(macOS/Linux) with the flag and hash — never the raw secret. The watch is
rate-limited to 1/s and falls back to stderr if notifications are unavailable.

### Telemetry (opt-in)
Telemetry is **disabled by default**. If enabled, it sends only anonymous
metrics (version, OS, rule count, aggregate event counts, uptime, a random
persistent install ID). It **never** sends secrets, PII, findings, flags, or
hashes. See the full policy in the Security Guide.

### License Tiers
- **Free** (default): full detection engine, local daemon, default rule pack.
- **Pro**: signed rule packs with auto-update/rollback, advanced config.
  Activated via a signed license file (`CERBERUS_LICENSE_PATH` +
  `CERBERUS_LICENSE_PUBLIC_KEY`). Without a valid license, Cerberus falls back
  to Free (fail-open, no panic).
