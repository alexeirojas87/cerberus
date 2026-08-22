# Gauntlet v6.1 — unit `config-api` (builder B)

Branch: `gauntlet-v61-config-b`. **No commits** (working tree).

## Modified files (only the 3 in scope)

| File | Δ |
|---|---|
| `crates/cerberus-proxy/src/api.rs` | +1144/-… (DTOs, transactionality, F6, CSP, 20 unit tests) |
| `crates/cerberus-proxy/dashboard.html` | +391 (F6 panels, no inline handlers, fix `admin_token_configured`) |
| `crates/cerberus-proxy/tests/smoke_harness.rs` | +463 (8 real HTTP tests) |

`daemon.rs`, `store.rs`, `updater.rs`, `cli_pack.rs`, `config.rs`, and `Cargo.toml` were not touched.

## 1. Separated `ConfigPatch` / `ConfigView` DTOs

- **`ConfigView`** (`GET /api/config`): its own DTO with no `admin_token` field. The
  JSON of `ProxyConfig` is no longer hand-redacted — the secret **does not exist**
  in the type, so it can't leak by oversight. Exposes the derived
  `admin_token_configured`.
- **`ConfigPatch`** (`PUT /api/config`): patch semantics, **every absent field is
  preserved**.
  - `admin_token` omitted ⇒ live token untouched; explicit `null` ⇒ it's cleared.
    Modeled with `PatchField<T>` (`Absent` / `Clear` / `Set`), which distinguishes
    the three JSON states in the type.
  - `admin_token_configured` is accepted in the body and **ignored**: it's read-only
    and cannot toggle authentication on/off.
  - `deny_unknown_fields`: a typo (`admin_tokens`) is a 400, not a silent ignore.
  - Good side effect: `PUT {"mode":"shadow"}` no longer wipes the `upstreams`.
- `ConfigPatch::apply` builds the `ProxyConfig` field by field ⇒ if `config.rs`
  gains a field, **compilation fails** instead of silently dropping it.

## 2. Exposure revalidation before persisting

`validate_control_plane_exposure` mirrors the rule in
`proxy::check_listen_security`
(non-loopback `listen` ⇒ token ≥ `ADMIN_TOKEN_MIN_BYTES` = 24) but is applied
**before** touching memory or disk: a config the daemon would reject at startup
can't be saved either. `listen_is_loopback` is **safe-by-default**: anything that
doesn't resolve to a literal loopback IP (not even `localhost`) is treated as
public.

## 3. Transactional persistence from the in-memory perspective

New order, with the write lock held for the whole operation:

```
candidate = patch.apply(live) → validate (400) → persist YAML (500) → publish to memory
```

Previously it was applied in memory and *then* written: a disk failure left the
live config diverging from the YAML (the 500 literally said "updated in memory but
not persisted"). Now, if validation or disk fails, **the live config didn't
change**. Same transaction applied to `POST /api/upstreams` and
`DELETE /api/upstreams/{name}`.

## 4. Real HTTP GET → PUT test (explicit requirement)

`config_get_then_put_over_http_preserves_the_admin_token` (smoke_harness, real
proxy + reqwest): authenticated GET (no token in the body) → PUT resending that
body verbatim + one change → 200 → the change applied → **GET and PUT without a
token still 401** → the persisted YAML retains the token.

## 5. F6 MVP in API + dashboard

| Piece | API | UI |
|---|---|---|
| Packs | `GET /api/packs`, `POST /api/packs/install`, `POST /api/packs/rollback` (already existed) | panel: status, select local file and transport its signed content via wire v2, rollback; never promises install-by-path |
| Providers | `GET/POST /api/upstreams`, `DELETE /api/upstreams/{name}` | add/remove + real `auth_header` (previously showed `u.enabled`, which the API never returns) |
| Categories/actions | `GET/PUT /api/policy` | table + action selector |
| Custom rules | `GET/PUT /api/policy` (`rules`) | table + per-rule override |
| Allowlist | `GET/POST/DELETE /api/allowlist` | list / add / remove (1-click FP triage) |

Valid actions = those in Appendix A.1 (`allow|warn|redact|block`); the overlay is
seeded with `secrets: redact`, `pii: warn` (from the plan, not invented).
`PUT /api/policy` validates **all** entries before applying any; `null` in a value
deletes the entry. `/api/policy` and `/api/allowlist` go through the same control
plane auth gate.

## 6. Effective CSP in header, no `unsafe-inline`

- The CSP is emitted in the **header**
  `Content-Security-Policy` (`frame-ancestors` only applies there; in `<meta>` it's
  ignored). The `<meta>` was removed so it can't drift out of sync.
- **No `unsafe-inline`**: the served asset is unique, so its inline blocks are
  authorized by `sha256`, computed from the **same `include_str!` that is served** ⇒
  hash and content can't diverge. SHA-256 + Base64 implemented in `api.rs` (safe
  Rust) to avoid adding dependencies to the crate; verified against the FIPS 180-4
  / RFC 4648 vectors and **cross-checked against Python's `hashlib`** on the real
  HTML:
  `script-src 'sha256-hZ5nCIn1Br/gdUo6HR6AREyzq5GVQAxiSzlp3dKEW58='` (identical).
- The 3 `onclick=` in the HTML became `addEventListener` (they would have needed
  `'unsafe-hashes'`). A test watches that they don't return.
- Final policy: `default-src 'none'; script-src 'sha256-…'; style-src 'sha256-…';
  connect-src 'self'; img-src 'self' data:; font-src 'none'; base-uri 'none';
  form-action 'none'; frame-ancestors 'none'; object-src 'none'`, plus
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy:
  no-referrer`, `Cache-Control: no-store`.
- Fixed bug: the UI read `cfg.admin_token` (a key the API never returns), so it
  always said "not configured".

## 7. Results

The table below preserves this unit's **original run** (485 tests);
it is not presented as the checkout's final state. The full revalidation after the
later v6.1 fixes is `cargo test --workspace` → **534 passed, 0 failed**
(2026-08-21); see
`evidence/f6/dashboard-pack-wire-v2-v61-fix.md`.

```
cargo test -p cerberus-proxy         128 passed, 0 failed   (92 lib + 36 smoke_harness)
cargo test --workspace               485 passed, 0 failed   (32 suites)
cargo clippy --workspace --all-targets   0 issues  (pedantic+nursery+cargo on deny)
cargo fmt --all -- --check               clean
```

28 new tests: 20 unit in `api.rs` + 8 HTTP in `smoke_harness.rs`.
Adversarial cases covered: `admin_token_configured:false` doesn't disable auth;
moving `listen` to `0.0.0.0` while deleting the token is a 400 and doesn't write
the YAML; a 23-byte token is a 400 and a 24-byte one passes; a write failure
leaves the live config intact; an invalid policy action applies no patch entry; an
unresolvable hostname is treated as public.

## 8. Risks and limits

1. **The policy overlay lives in memory and never reaches the engine.**
   `categories`/`rules` are exposed and edited with CLI↔UI parity, but are not
   serialized to YAML and don't change detection: `ProxyConfig` (config.rs) has no
   such fields and `config.rs` was outside this unit's scope. The API declares it
   (`"persisted": false`) and the UI warns on screen. **Wiring it into
   `ProxyConfig` + the engine is pending work for F6/F1.**
   The same applies to `allowlist`, which was already in-memory before this change.
2. **`deny_unknown_fields` on `ConfigPatch`** is a contract change: a client that
   sends extra keys goes from 200 to 400. Verified that today only `smoke_harness`
   and the dashboard consume `PUT /api/config`.
3. **`listen_is_loopback` is safe-by-default**: a `listen` with a hostname (e.g.
   `proxy.internal:8080`) is considered public and requires a token ≥ 24 bytes.
   It's stricter than before; deliberate, but may surprise anyone using hostnames.
4. **Hash-based CSP is fragile under HTML edits by another path**: any change to
   the inline block auto-recomputes the hash (same `include_str!`), but a new
   `onclick=`/`style=` would break in the browser. A test detects it; the robust
   alternative (serving `dashboard.js` as a separate asset with `script-src 'self'`)
   requires a new file, outside this unit's scope.
5. **`requires_restart` remains informational**: the new `listen` is persisted and
   published to memory, but the live socket isn't rebound (previous behavior,
   unmodified).
6. **`DELETE /api/upstreams` doesn't revalidate exposure** (on purpose: removing an
   upstream can't open the control plane). Intentional asymmetry with POST.
