# Evidence Pack — F4/feedback-dev + zero-config + MITM wiring to the daemon

- Date: 2026-08-21
- Unit: F4 — connected dev feedback (desktop/CLI), zero-config (`cerberus init`),
  and `cerberus mitm enable|disable` talking to the daemon's state (real wiring).
- Builder/verification: opencode (deepseek-v4-flash), Gauntlet §8B flow.
- Verdict: **PASS** (within the repo; external breakage of `crates/cerberus-packs` reported, see §Limits).

## Deliverables and evidence

| # | Deliverable | How | Command | Quoted output |
|---|---|---|---|---|
| 1 | Connected dev feedback | In the daemon loop (`daemon.rs`, the `sleep(1s)` arm of `tokio::select!`) it drains `ApiContext.events`; each `block`/`redact`/`warn` event triggers `feedback_ux::send_dev_feedback`: macOS/Linux `notify-rust` (title "Cerberus blocked/redacted/warns", body flag+hash, NEVER the secret), rate ≤1 notif/sec, CLI line fallback to stderr; off-Unix the notification is a stderr line with an emoji | `rtk cargo test -p cerberus feedback_ux::tests` | `17 passed, 47 filtered out` (action selection, watermark without replay/trim, line without raw value, 1/sec rate) |
| 2 | Zero-config | `init.rs` writes EXPLICIT upstreams into `config.yaml` (`openai → https://api.openai.com`, `anthropic → https://api.anthropic.com`) → `cerberus start` boots without `CERBERUS_UPSTREAM_URL`; the guide no longer asks to export env | `rtk cargo test -p cerberus init::tests` | `init_writes_config_with_default_upstreams` PASS |
| 3 | MITM wired to the daemon | `cerberus mitm enable/disable`: checks `daemon::is_running()`; live daemon → persists config + prints "edit `~/.cerberus/mitm.json` and restart (`cerberus stop && cerberus start`)" (there is no hot `/api/mitm`: api.rs belongs to another agent); stopped daemon → writes config and announces it will apply on next boot | `rtk cargo test -p cerberus --test mitm_cli_daemon` and `-p cerberus mitm::tests` | 4 integration PASS (exit codes + messages without/with daemon), `enable_with_running_daemon_warns_restart_and_persists` PASS |
| 4 | Tests | Unit (feedback/rate-limit/watcher; mitm daemon-state) + real binary integration with isolated HOME and pid file of the live process | `rtk cargo test -p cerberus --all-targets` | `68 passed (5 suites)` |
| V | Build | — | `cargo build -p cerberus` | `Finished dev profile` (in isolated copy; see §6) |
| V | Clippy | — | `rtk cargo clippy -p cerberus --all-targets -- -D warnings` | `No issues found` |
| V | Fmt | — | `cargo fmt --all -- --check` (my 6 files) | 0 diffs; only unrelated diffs in `platform.rs`/`telemetry.rs` |

## Changes

- `crates/cerberus/src/feedback_ux.rs` — `send_dev_feedback`, `dev_feedback_line`, `is_dev_intervention`, `InterventionWatcher` (positional watermark with resync on trim), rate limit 1/sec, `notify_desktop` cfg(unix)=notify-rust / cfg(other)=stderr emoji, `emit_interventions` (async) for the daemon. Line and notification use ONLY flag + hash from the `AuditEvent` (never the raw value).
- `crates/cerberus/src/daemon.rs` — `emit_interventions` in the `sleep(1s)` arm of the graceful loop; `api_events` captured before moving `ctx` into the proxies; `is_running` → `pub(crate)`. Startup already reads `runtime_config()` (MITM at boot, no changes).
- `crates/cerberus/src/init.rs` — `init_config_yaml()` with explicit upstreams; corrected steps (zero env).
- `crates/cerberus/src/mitm.rs` — `enable`/`disable` now announce the persisted path; `enable_with_daemon_state`/`disable_with_daemon_state` + `daemon_restart_note()`.
- `crates/cerberus/src/main.rs` — `mitm enable|disable` dispatch uses `daemon::is_running()` and the state-aware helpers.
- `crates/cerberus/tests/mitm_cli_daemon.rs` — integration: status baseline, enable without CA (exit≠0), init-ca → enable → disable (exit 0), enable with fake live daemon (live pid) → restart note.
- `crates/cerberus/Cargo.toml` — no deps changes: `notify-rust` already exists on macos/linux; Windows without notif uses the `cfg` fallback.

## Adversarial cases

- Feedback line built with an event without flags/hashes → `unknown`/`sha256:n/a`, no panic.
- Watermark after trim of the 10k buffer (front trim) → resync without replay; repeating status with the same slice → 0 duplications.
- `mitm enable` with a fake live daemon → config is persisted anyway (effective on restart) AND warns of restart.
- `mitm enable` without CA → fails loudly with `init-ca`, exit ≠ 0, without touching `mitm.json`.
- Rate: 2nd immediate notification blocked; allowed after ≥ 1 s.

## Declared limits and gaps

- In the **real working tree** `cargo build --workspace` is BROKEN by in-progress work from another
  agent in `crates/cerberus-packs/` (`telemetry.rs` uses `reqwest`/`uuid` not declared in that
  `Cargo.toml` and a mistyped `is_root`/`OsString` signature in `updater`). Everything in this unit was
  verified in a **copy of the working tree** (rsync to `/var/folders/.../opencode/cerb-verify`)
  where only those deps were added, without touching the real packs files. Reported as unrelated; not reverted.
- `cerberus` (my crate) is clean against `-D warnings` and fmt; the unrelated fmt diffs remain in
  `platform.rs` and `telemetry.rs` (not touched).
- There is no hot `/api/mitm` and `cerberus-proxy/src/api.rs` is NOT touched (another agent, F6/XSS):
  MITM wiring is via config + restart, not via the control plane.
- Windows: `notify-rust` is not declared (already the case); the fallback prints to stderr. The Windows
  matrix was not run (only `aarch64-apple-darwin` installed), same as the F4 `windows-support` unit.
- No notification called external providers or exposed secrets (only event hashes).
