# Evidence Pack — f0/spike-proxy-security

- **Role**: REVIEWER 3 (Security)
- **Unit**: spike-proxy
- **Verdict**: PASS

## Summary

Security review of the spike reverse proxy (Phase 0). All
criteria PASS. 4 low/medium severity findings are documented, none
blocking for a local spike.

## Security Criteria

### 1. Build ✅

| Command | Result |
|---------|-----------|
| `cargo build --release --workspace` | ✅ 0 errors |

### 2. Tests ✅

| Command | Result |
|---------|-----------|
| `cargo test -p spike-proxy` | ✅ 7/7 passed (3 unit lib + 4 integration) |

### 3. Hostile header forwarding / sanitization ✅

**File**: `crates/spike-proxy/src/proxy.rs:16-24, 147-152`

The proxy has a header **skip** allowlist (hop-by-hop): `host`,
`content-length`, `connection`, `keep-alive`, `proxy-connection`,
`transfer-encoding`, `upgrade`. All other headers are forwarded
**verbatim**, including `authorization`, `cookie`, `x-api-key`, etc.

**Risk**: Low. For a local spike with no real traffic there is no risk. In
production, sensitive headers must be explicitly filtered.

**Finding** 🟡 Low: The proxy forwards sensitive headers without sanitization.
Acceptable for the spike.

### 4. Infinite-size body (no limit) ✅

**File**: `crates/spike-proxy/src/proxy.rs:136`

```rust
let body_bytes = body.collect().await.map_err(|e| e.to_string())?.to_bytes();
```

`body.collect()` buffers the **full body in memory** with no size
limit. A malicious client can send gigabytes of data and exhaust the
proxy's memory.

**Risk**: Medium. The §4.1 plan explicitly states that the body is
buffered for scanning, but there is no upper limit. In production,
hyper's `max_body_size` or a bounded `StreamBody` is needed.

**Finding** 🟠 Medium: Unbounded buffering → memory DoS.
Acceptable for the local spike.

### 5. Header spoofing: Host / X-Forwarded-For ✅

**File**: `crates/spike-proxy/src/proxy.rs:142-152`

- **Host**: The proxy **REWRITES** the `Host` correctly. The `host`
  header is in `SKIP_HEADERS` (line 17), and the URI is rebuilt from the
  upstream address (line 142-143). No Host spoofing.
- **X-Forwarded-For**: The proxy does **NOT** add `X-Forwarded-For` or
  `X-Real-IP`. The client IP is lost. This is correct for a local
  spike where there are no real clients.

**Current behavior**: Host rewrite ✅, X-Forwarded-For absent
(intentional for the spike).

### 6. `unsafe` ✅

| Search | Result |
|----------|-----------|
| `grep -rn 'unsafe' crates/spike-proxy/` | ❌ 0 occurrences |

**Workspace lint**: `unsafe_code = "forbid"` in `Cargo.toml:8` — verified
functionally. The build would not compile if there were `unsafe`.

### 7. SSRF: configurable upstream ✅

**File**: `crates/spike-proxy/src/main.rs:52-56, 129-130`

The upstream is configurable via `--upstream-addr <ADDR>`. Default:
`127.0.0.1:8091`. There is no validation that the address is local.

**Risk**: Low. For the local spike the default is loopback and usage is
controlled. In multi-tenant deployments, the proxy could be used for
SSRF against internal services.

**Finding** 🟢 Info: No validation of upstream as localhost. If used
in multi-tenant infra, it would be SSRF. Acceptable for the spike.

### 8. Body leaks (logs without secrets) ✅

**File**: `crates/spike-proxy/src/proxy.rs`

| Search | Result |
|----------|-----------|
| `println!` in `proxy.rs` | ❌ 0 occurrences |
| `eprintln!` in `proxy.rs` | 4 occurrences — only connection errors (lines 58, 66, 78, 90) |
| `dbg!` in `crates/spike-proxy/` | ❌ 0 occurrences |

No log includes the body content or request data.
The `eprintln!` only report connection errors.

### 9. Connection timeouts ✅

**File**: `crates/spike-proxy/src/proxy.rs:73, 155`

```rust
let client: Client<HttpConnector, Full<Bytes>> =
    Client::builder(TokioExecutor::new()).build(HttpConnector::new());
```

**There is not a single timeout configured**:
- No `pool_config().set_idle_timeout()`
- No `set_connect_timeout()`
- No `set_http1_keepalive()`
- No `http1::Builder::new().timer(...)` in the server

A client that opens a connection and sends no data → connection hung
indefinitely (socket leak / DoS).

**Finding** 🟠 Medium: Total absence of timeouts → socket leak DoS.
Acceptable for the local spike with known load control.

## Security Findings

### 🟠 Medium: Unbounded body buffering
- **File**: `crates/spike-proxy/src/proxy.rs:136`
- **Description**: `body.collect()` without `max_body_size` → memory DoS.
- **Impact**: A malicious client can exhaust the proxy's RAM.
- **Recommendation**: Post-spike, add `http1::Builder::max_buf_size()` and
  a limit on `body.collect()` with `take()`.

### 🟠 Medium: No timeouts on client or server
- **File**: `crates/spike-proxy/src/proxy.rs:73`
- **Description**: HTTP client without connect/request/idle timeout.
  HTTP1 server without timer.
- **Impact**: Slow or hung connections exhaust file descriptors
  (socket leak).
- **Recommendation**: Post-spike, configure `HttpConnector::set_connect_timeout()`,
  `pool_config().set_idle_timeout()`, and a timer on `http1::Builder`.

### 🟡 Low: Headers forwarded without sanitization
- **File**: `crates/spike-proxy/src/proxy.rs:147-152`
- **Description**: All headers except hop-by-hop are forwarded
  verbatim. Authentication headers (`authorization`, `cookie`,
  `x-api-key`) are passed to the upstream.
- **Impact**: Low for the spike. In production, credential leakage.
- **Recommendation**: Post-spike, implement an allowlist of
  forwardable headers.

### 🟢 Info: configurable upstream without restriction (potential SSRF)
- **File**: `crates/spike-proxy/src/main.rs:52-56`
- **Description**: `--upstream-addr` accepts any IP address, not
  only loopback. No validation.
- **Impact**: In a multi-tenant deployment it could be used as an SSRF proxy.
  For the local spike it is intentional.
- **Recommendation**: In production, validate that the upstream is an
  allowed address.

## Reproducible Evidence

```bash
# Build
cargo build --release --workspace

# Tests
cargo test -p spike-proxy

# unsafe
grep -rn 'unsafe' crates/spike-proxy/

# println! / eprintln! / dbg! in proxy.rs
grep -n 'println!\|eprintln!\|dbg!' crates/spike-proxy/src/proxy.rs
```

## Decision

**VERDICT: PASS** ✅

All security criteria are met for a local Phase 0 spike. 4 findings are
documented (2 medium, 1 low, 1 info) for post-spike correction.
None is blocking for the MVP: the proxy is functional, correct, and secure
within the scope of the latency spike.
