# Evidence Pack — Phase 3 / healthcheck-logs
- Attempt: 1    Reviewer: Builder    Verdict: PASS

## Acceptance criteria
| Criterion | Command executed | Output | Result |
|----------|-------------------|--------|-----------|
| `cargo test -p cerberus-proxy` | `cargo test -p cerberus-proxy` | 46 passed; 0 failed | ✅ |
| Healthcheck returns ok status | `test::health_status_is_ok` | Pass | ✅ |
| Healthcheck reflects shadow mode | `test::health_status_shadow` | Pass | ✅ |
| Health JSON is valid | `test::health_json_is_valid` | Pass | ✅ |
| /health path detected | `test::is_health_path_matches` | Pass | ✅ |
| Custom health path configurable | `test::custom_health_path` | Pass | ✅ |
| Upstream count in health | `test::upstream_count` | Pass | ✅ |
| Uptime increments | `test::uptime_increases` | Pass | ✅ |
| SecurityEvent levels correct | `test::security_event_levels` | Pass | ✅ |
| SecurityEvent messages | `test::security_event_messages` | Pass | ✅ |
| Log without secrets does not panic | `test::log_security_event_no_panic` | Pass | ✅ |
| Config YAML/JSON parse | `test::parse_yaml_minimal`, `test::parse_json` | Pass | ✅ |

## Adversarial cases tested
- Custom health path → used instead of /health
- Empty upstreams → count=0 in health
- Log with findings → only flags/hashes, never raw values
- Invalid config → clear error

## Applicable NFRs
- **Logs without secrets:** only flags, categories, hashes are logged. Never raw values.

## Files
- `crates/cerberus-proxy/src/health.rs`
- `crates/cerberus-proxy/src/log.rs`
- `crates/cerberus-proxy/src/config.rs`

## Deviations from plan
None. Healthcheck + logging without secrets + YAML/JSON config file.
