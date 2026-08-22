# Evidence Pack — Phase 4 / windows-support
- Attempt: 1    Reviewer: Builder    Verdict: PASS

## Acceptance criteria
| Criterion | Command executed | Output | Result |
|----------|-------------------|--------|-----------|
| `cargo test --workspace` | `cargo test --workspace` | 285 passed; 0 failed | ✅ |
| Config dir not empty on any platform | `test::config_dir_is_not_empty` | Pass | ✅ |
| Log dir under config dir | `test::log_dir_is_under_config` | Pass | ✅ |
| Daemon name without spaces | `test::daemon_name_has_no_spaces` | Pass | ✅ |

## Platform-specific paths
| Platform | Config dir | Binary name |
|------------|-----------|-------------|
| macOS | ~/.cerberus | cerberus |
| Linux | $XDG_CONFIG_HOME/cerberus or ~/.config/cerberus | cerberus |
| Windows | %APPDATA%/Cerberus | cerberus.exe |

## Files
- `crates/cerberus/src/platform.rs` (new)

## Deviations from plan
None. Cross-platform support with specific paths and detection.
