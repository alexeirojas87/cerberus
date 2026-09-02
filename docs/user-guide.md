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

Every command below is the Appendix B surface of the product plan. The CLI and
the dashboard are two fronts over the **same Config API**: daemon-backed
commands send the admin token (`CERBERUS_ADMIN_TOKEN` env or `admin_token` in
`~/.cerberus/config.yaml`) and fail with an actionable error when the daemon
is unreachable.

| Command | Description |
|---------|-------------|
| `cerberus init` | Auto-detect agents and create config (generates the admin token) |
| `cerberus start` | Start the local proxy daemon (logs are also written to `~/.cerberus/logs/cerberus.log`) |
| `cerberus stop` | Stop the local proxy daemon |
| `cerberus restart` | Restart the daemon on the same port |
| `cerberus status` | Show daemon status (+ live mode/upstreams when reachable) |
| `cerberus mode <shadow\|enforce>` | Show or hot-change the operation mode |
| `cerberus allow-once [--reason <m>]` | Break-glass: lets the NEXT blocked send through (audited, hash-only) |
| `cerberus version` / `--version` | Print the version |
| `cerberus upgrade` | Check for a newer release and print the upgrade command |
| `cerberus login --file <license.json>` | Verify and install a signed Pro license (0600) |
| `cerberus license` | Show active license tier (Free/Pro) |
| `cerberus agents` | List detected agents and their wiring status |
| `cerberus agents wire <agent>` / `unwire <agent>` | Route / unroute an agent (prints the exact export line) |
| `cerberus providers` | List configured upstreams |
| `cerberus add-provider <name> --url <url> [--auth-header <h>]` | Register a custom upstream; prints the local base URL to paste |
| `cerberus remove-provider <name>` | Remove an upstream |
| `cerberus packs list` | List installed rule packs |
| `cerberus packs enable <pack>` / `disable <pack>` | Toggle a pack's rules in the live engine (hot-reload) |
| `cerberus packs update` | Re-verify installed signatures and hot-reload (registry auto-update lands with Phase 7) |
| `cerberus pack <install\|rollback\|list>` | Install / rollback signed packs (Pro); compatibility alias of `packs` |
| `cerberus category set <cat> --action <a>` | Set the action for a category (block/redact/warn/allow) |
| `cerberus rules list` | List effective rules (base + overrides + custom) |
| `cerberus rules add --file <rule.yaml>` | Validate a custom rule locally, then add it (hot-reload) |
| `cerberus rules set <flag> --action <a>` | Override the action of one rule |
| `cerberus allowlist add <value>` / `list` / `remove <value>` | Manage false positives (persisted as HMAC fingerprints only — raw values are never stored or echoed) |
| `cerberus events [--provider <p>] [--tool <t>] [--since <30m\|2h\|1d\|RFC3339\|epoch>]` | List filterable audit events |
| `cerberus stats [--by provider\|tool\|flag]` | Aggregate statistics; `--by provider` is the per-upstream breakdown |
| `cerberus logs [-f]` | Read the daemon log (no secrets); `-f` follows |
| `cerberus config show` | View the config file (admin token redacted) |
| `cerberus config edit` | Open `$EDITOR` on the config, then validate it |
| `cerberus config path` | Print the config file location |
| `cerberus dashboard` | Open the local UI (`http://localhost:8787/ui`) |
| `cerberus scan <file>` | Scan a file for secrets (local dry-run) |
| `cerberus test <text>` | Test detection with inline text (local dry-run) |
| `cerberus validate -f <config.yaml>` | Validate a config before deploying (syntax, upstream schemes, patterns) |
| `cerberus reload` | Hot-reload the on-disk config on the running daemon (no restart) |
| `cerberus doctor` | System diagnostics (daemon PID, rule count, agents) |
| `cerberus mitm <init\|enable\|status>` | Manage MITM/forward proxy (opt-in) |

Notes:

- **`cerberus reload`** applies the file exactly as it is on disk (Mode A IaC
  semantics). The listen address is NOT reloaded (the socket is already
  bound); a file that would remove `admin_token` is rejected so a running,
  authenticated control plane can never be silently closed — restart
  instead.
- **`cerberus agents wire`** records the routing and prints the export line
  (`export <AGENT>_BASE_URL=http://127.0.0.1:8787`); a CLI cannot mutate its
  parent shell's environment, so the export line IS the wiring action.
- **`cerberus allowlist`** never echoes raw values: entries are displayed as
  truncated fingerprints (`hmac:0123456789ab…`), because the raw value is not
  recoverable by design (R9-7).

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
