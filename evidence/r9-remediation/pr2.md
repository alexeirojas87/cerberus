# PR-2 Evidence Pack — review-findings-remediation (CLI surface: F2, F5) — branch `r9-remediation`, STRICT TDD
| Task | RED (written first, watched fail) | GREEN | REFACTOR |
|---|---|---|---|
| 2.1 print text | `cargo test -p cerberus --test cli_surface_via_api cli_allow_once` → FAILED: stdout `X-Cerberus-Bypass: n-123` bare, no `break-glass:` form, no admin note | 12 passed | none |
| 2.2 cli_surface.rs allow_once | same RED run | as above | — |
| 2.3 F2-no-bypass pin | approval/pinning (passed first run — data plane already correct per #447; genuine F2 RED = 2.1). F2-once/F2-replay already pinned by `test_break_glass_one_shot_end_to_end` steps 2–5, 7 (same exact header shape) | 1 passed | — |
| 2.4 unit (name shape) | `cargo test -p cerberus-proxy --lib f5_provider` → E0425 `upstream_name_shape_error` not found (test-first) | 1 passed (`--lib api` 44 ok) | fmt reflow only |
| 2.4/2.6 e2e (F5-route/default) | `cargo test -p cerberus-proxy --test smoke_harness f5_custom` → FAILED: `right upstream, prefix stripped: ` (empty myproj capture — silent misroute to default) | 1 passed; smoke `upstream` suite 8 ok | — |
| 2.5 api.rs | same RED runs | `path_prefix: Some(format!("/{name}"))` + 400 shape gate before mutation | — |

| Finding (obs #447) | Site | Fix |
|---|---|---|
| F2 allow-once prints bare nonce → replayable Legacy arm | `cerberus/src/cli_surface.rs` `allow_once` (:176–178 pre-fix) | prints exact `X-Cerberus-Bypass: break-glass:<nonce>` (data plane redeems only that prefix, proxy.rs:89) + explicit `X-Cerberus-Admin-Token` required note; bare nonce never printed |
| F5 advertised `/<name>` unroutable → 503 / silent default misroute | `cerberus-proxy/src/api.rs` `handle_post_upstreams` (:1567 pre-fix) | `path_prefix: Some(format!("/{name}"))` → resolve_route priority-1 longest-match (proxy.rs:1243, no resolve_route change); 400 name-shape BEFORE mutation via pure `upstream_name_shape_error` (single segment: no `/`, whitespace, `.`); F5-default pinned e2e phases 1+3 (GET /test → default, before and after the add) |

| Gate (2.8) | `cargo test --workspace` → 38× `test result: ok`, 0 FAILED (incl. smoke_harness 75, proxy lib 224→225, cli_surface_via_api 12); `make lint` → clippy clean (`Finished dev profile in 6.87s`); `cargo fmt --check` → clean |
| Commits | 7f5f7b3 (F2 print, 2.1–2.2) · b2f7344 (F2 pin, 2.3) · 0d401c9 (F5, 2.4–2.6) · this pack (2.7) |
