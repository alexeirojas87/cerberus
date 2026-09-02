# F6.A — Independent Adversarial Review — SECURITY lens — attempt 1

- **Unit**: F6.A — R9-5 (P0) fail-closed control-plane auth + anti-rebinding + token-gated bypass; R9-7 (P1) HMAC-only allowlist; F5 F-1/F-2/F-3 key-file hygiene closure
- **Candidate**: commit `40283eb` on `r9-remediation` (parent `f73928b`) — detached worktree
- **Reviewer**: independent security lens (did not build; blind to the correctness lens)
- **Date**: 2026-09-02 · Host: macOS arm64 (darwin) · rustc/clippy 1.97 · release build `target/release/cerberus`
- **Method**: §8B — all gates re-run in a fresh worktree; adversarial battery executed against a **live release daemon** (isolated `$HOME`s, ports 18901–18906, mock upstream on 19901) with every attack recorded as request + response. "Couldn't run" = FAIL rule respected: nothing was skipped.

---

## 1. Commands run (verbatim, with exit codes)

| # | Command | Exit | Result |
|---|---|---|---|
| 1 | `git worktree add --detach …/f6a-attempt1-security 40283eb` (after removing a clean pre-existing checkout at the same path/commit) | 0 | fresh worktree @ `40283eb` |
| 2 | `rtk git diff --stat f73928b..40283eb` | 0 | 19 files, +2610/−211 (reviewed) |
| 3 | `rtk cargo clippy --workspace --all-targets -- -D warnings` | 0 | 0 warnings |
| 4 | `rtk cargo test --release --test redos_fuzz -- --test-threads=1 --nocapture` | 0 | **11/11** |
| 5 | `git diff f73928b..40283eb -- tests/redos_fuzz.rs \| wc -c` | 0 | **0 bytes** (untouched, R9-16 rule preserved) |
| 6 | `rtk cargo test -p cerberus-proxy` | 0 | **279 passed** (3 suites, 0 failed) |
| 7 | `rtk cargo test -p cerberus-store` | 0 | **27 passed** (2 suites, 0 failed) — incl. `write_gate_rejects_unkeyed_rows_*` |
| 8 | `rtk cargo test -p cerberus-packs --test production_pack_pr` | 0 | **19/19** |
| 9 | `rtk cargo test --release --test load_test` | 0 | **14/14** incl. the honest HTTP round-trip gate |
| 10 | `rtk cargo build --release -p cerberus` | 0 | release binary for the live battery |
| 11 | `HOME=$F6SEC/home ./target/release/cerberus init` | 0 | `config.yaml` **0600 at creation**; 64-hex token; **token absent from stdout** (grep 0) |
| 12 | live battery (curl + raw-socket Python client, `T-a*`, `R*`, `C*`, `D*` below) | 0 | all recorded |
| 13 | umask-000 concurrent boot (`umask 000; cerberus start` ×2, ports 18903/18904, same `$HOME`) | 0 | key file 0600, no tmp residue |
| 14 | corrupt-key boot (port 18905) | 0 | `Regenerated` + loud WARN |
| 15 | re-init over existing 0644 config (finding P2-1 evidence) | 0 | token rotated, mode stayed 0644 |
| 16 | env-override boot (port 18906, fresh `$HOME`) | 0 | `CERBERUS_ADMIN_TOKEN` > config verified; env token never logged |
| 17 | `git worktree remove …/f6a-attempt1-security` | 0 | worktree removed; main repo untouched except this report |

One boot attempt returned `start failed: Cerberus is already running. Use 'cerberus stop' first.` — the single-instance-per-`$HOME` guard working as designed (my harness reused a `$HOME`); re-run on a fresh `$HOME` succeeded. All reviewer test daemons were stopped afterwards (sibling-lens daemons on other ports were left untouched).

## 2. Per-criterion verdicts

| # | Criterion | Verdict | Evidence |
|---|---|---|---|
| G1 | clippy `-D warnings` clean | **PASS** | cmd 3 |
| G2 | redos_fuzz 11/11, file untouched | **PASS** | cmds 4–5 |
| G3 | proxy + store suites green | **PASS** | 279 + 27 passed (cmd 6–7) |
| G4 | production pack 19/19 | **PASS** | cmd 8 |
| 5a | Auth bypass vectors refused; fail-closed with `None` token | **PASS** | battery §3.1/§3.2 |
| 5b | Anti-rebinding exact allowlist, fail-closed shapes | **PASS** | battery §3.3 |
| 5c | Bypass token-gated in all modes; F4 vector dead; headers never forwarded | **PASS** | battery §3.4 |
| 5d | HMAC-only allowlist end-to-end; raw never persisted/served; migration destroys raw | **PASS** | battery §3.5 |
| 5e | F-1 umask race closed; F-2 corrupt-key loud; chmod `Result`s handled | **PASS** | battery §3.6 |
| 5f | 256-bit CSPRNG token; token never logged; config 0600 | **PASS** (one P2 edge → §4) | §3.7 + §4 |
| 5g | load 14/14 incl. honest HTTP gate | **PASS** | cmd 9 |

## 3. Live adversarial battery (release daemon, port 18901, tokenized; port 18902 tokenless)

### 3.1 Auth gate — bypass vectors (GET /api/events)

| Vector | Outcome |
|---|---|
| No token | **401** `{"error":"unauthorized"}` |
| Token in query `?token=<tok>` | **401** (query is never an auth channel) |
| Token in `Cookie` header | **401** |
| `Authorization: Bearer <wrong>` | **401** |
| `Authorization: Bearer <correct>` | **200** — API accepts Bearer by design (review v4 #2); the **data-plane bypass does NOT** (see §3.4) |
| `X-Cerberus-Admin-Token: <wrong>` | **401** |
| `X-Cerberus-Admin-Token: <correct>` | **200** |
| Case-variant header name `x-CeRbErUs-aDmIn-tOkEn` | **200** — HTTP header names are case-insensitive (hyper normalizes); correct semantics, not a bypass |
| Double `X-Cerberus-Admin-Token` (wrong first, right second) | **401** — first value wins → fail-closed |
| Double `X-Cerberus-Admin-Token` (right first) | **200** — consistent first-wins |
| Token padded with spaces | **200** — value trimmed (standard); internal whitespace/control chars cannot form a header value (hyper rejects at the parser) |
| `Bearer <wrong>` + `X-CAT <wrong>` | **401** |

**Route enumeration, unauthenticated**: `/api/config|events|stats|upstreams|policy|allowlist|packs|break-glass|packs/install|upstreams/anthropic|nonexistent|events/` → **all 401** (unknown `/api/*` 401s before the 404 — no pre-auth oracle). `/api/dashboard` → 200 static HTML only: token **absent** (grep 0), no upstream names (only generic UI copy). `/health` → 200 with `version`, `mode`, `upstream_count` (a count, not names) — by-design health shape. Paths *not* under `/api/` (`/api`, `/API/events`, `/version`, `/config`) fall through to the **data plane** and were verified to be proxied to the mock upstream (mock echo bodies confirm; no control-plane data served) — expected proxy behavior, not a gate bypass.

### 3.2 Raw-socket protocol shapes (gate order verified: Host/Origin **before** auth)

| Shape | Outcome |
|---|---|
| `Host: attacker.com` (the rebinding attack) | **403** host not allowed |
| `Host: 127.0.0.1:18901` / `localhost:18901` / `127.0.0.1` (no port) / `LOCALHOST:18901` / `[::1]:18901` | **401** — passes host gate, auth still enforced |
| `Host: 127.0.0.1.evil.com` | **403** |
| `Host: attacker.com:18901` | **403** |
| `Host: localhost.` (trailing dot) | **403** — exact match, fail-closed |
| `Host: xn--lcalhost-2ye.com` (punycode lookalike) | **403** |
| `Host: 0177.0.0.1` (octal-ish loopback) / `Host: 127.1` (short form) | **403** — alternate loopback encodings rejected |
| `Origin: null` | **403** |
| `Origin: http://attacker.com` | **403** |
| `Origin: https://allowed.com.evil.com` | **403** |
| `Origin: https://evil.com/allowed.com` | **403** |
| `Origin: http://127.0.0.1:18901@evil.com` (userinfo trick) | **403** |
| `Origin: https://127.0.0.1:18901` (scheme differs, same authority) | **401** — same-origin by authority (documented behavior) |
| HTTP/1.0 with **no Host** | **403** (empty authority is not allowlistable — fail-closed) |
| HTTP/1.1 with **no Host** | **403** |
| **Duplicate Host** (valid first) | **401** — hyper does not reject; first value wins; gate reads the first → fail-closed either way |
| Duplicate Host (attacker first) | **403** |
| Absolute-URI request line + valid `Host` | **401** — the gate binds on the Host **header**; browsers cannot emit absolute-form, and the request still targets this server's `/api/*` (auth applies) |
| Absolute-URI + attacker `Host` | **403** |
| `HEAD`/`OPTIONS` on gated route | **401** — no method-shaped exemption |

**Browser-mutation content-type rule** (POST /api/upstreams): `text/plain` → **403**; `application/x-www-form-urlencoded` → **403**; `multipart/form-data` → **403**; `application/json` unauth → **401** (reaches auth, as designed); JSON + valid token → **200**; `text/plain` **without** Origin (curl/CLI) + valid token → **200** (CLI shape preserved, as documented).

### 3.3 Bypass gating on the data plane (block-action AWS pattern; the literal `AKIAIOSFODNN7EXAMPLE` is deliberately inert — it is in the rule's `allowedExamples`, so `AKIAXXXXXXXXXXXXXXXX` was used)

| Vector | Response | Secret reached upstream? | Bypass/admin headers at upstream? |
|---|---|---|---|
| C1 no bypass (baseline) | **403 BLOCK** | no | — |
| C2 `X-Cerberus-Bypass` **unauthenticated** (the F4-injection vector) | **403 BLOCK** | **no** | — |
| C2' same on the **tokenless** daemon (mode `None`) | **403 BLOCK** + loud WARN `X-Cerberus-Bypass refused: no admin token is configured…` | **no** | — |
| C3 bypass + **wrong** admin token | **403 BLOCK** | no | — |
| C4 bypass + **Bearer** correct token | **403 BLOCK** (bypass requires `X-Cerberus-Admin-Token` specifically) | no | — |
| C5 bypass + correct `X-Cerberus-Admin-Token` | **200 PASS** (authenticated break-glass works) | yes (expected) | **NO** — `x-cerberus-bypass` and `x-cerberus-admin-token` both **absent** at the mock (F2 review-v4 stripping rule verified live) |

**Token model (documented)**: one installation admin secret; the **API** accepts it via `Authorization: Bearer` or `X-Cerberus-Admin-Token`; the **data-plane bypass** accepts it **only** via `X-Cerberus-Admin-Token`. Env override `CERBERUS_ADMIN_TOKEN` beats `config.yaml` (verified live: old config token → 401, env token → 200).

### 3.4 Allowlist fingerprints end-to-end (R9-7)

| Check | Outcome |
|---|---|
| `POST /api/allowlist {"value":"AKIAXXXXXXXXXXXXXXXX"}` | response carries **only** `{"fingerprint":"hmac:19fe4519…"}` — raw never echoed |
| `GET /api/allowlist` / `GET /api/policy` | fingerprints only |
| `config.yaml` bytes | raw value **0 occurrences**; exactly one `hmac:<64hex>` entry |
| Dataplane with the allowed value (no bypass) | **200**, secret reaches upstream — fingerprint matching works hot-path |
| Control: different secret | **403 BLOCK** — allowlist does not widen beyond the exact value |
| `PUT /api/policy` raw entry | **400** `allowlist entries must be HMAC fingerprints… (R9-7)` |
| `PUT /api/policy` unkeyed `sha256:` entry | **400** (same gate) |
| `PUT /api/config` raw injection | **400** — `unknown field 'allowlist'` (deny-unknown-fields; the config route cannot carry it at all) |
| `DELETE /api/allowlist` with the raw value | **200** echoing the **fingerprint** only; unknown value → **404** echoing a fingerprint only |
| **Migration** (legacy raw planted in `config.yaml`, reboot) | boot log: `allowlist migration (R9-7): 1 raw entry converted to HMAC fingerprints (domain cerberus:allowlist:v1); raw values are no longer persisted anywhere`; config rewritten `hmac:c0504f59…` only, **raw destroyed in place**, mode restored **0600**, raw absent from boot logs; migrated value honored on the dataplane afterwards |
| **Store write gate** (unit, 27/27 incl. gate tests) | ordinary writer rejects `sha256:`/unknown schemes (`RejectedUnkeyed`); explicit legacy writer still refuses unknown schemes; live audit rows observed keyed (`hashes=["hmac:8f4bab…"]` in the daemon log) |
| **Attacker reading `config.yaml`** | learns nothing about allowed values (HMAC fingerprints keyed by the installation key — R9-7's point holds) |

**Residual (accepted, documented — not a defect)**: an allowlist is inherently observable at the dataplane — an unauthenticated data-plane client can probe whether a *specific* value is allowlisted by sending it and observing 403 vs 200 (verified: allowed passes, non-allowed blocks). With the admin token, `DELETE` 200/404 is a post-auth membership oracle. This is inherent to enforcement (the R9-7 invariant — raw never persisted/served — is what was closed); a shape-valid but foreign-domain `hmac:` entry is accepted by the shape gate and is inert (it cannot collide with a real fingerprint).

### 3.5 Key-file hygiene (F-1/F-2/F-3)

| Check | Outcome |
|---|---|
| F-1 recreation: `umask 000` + **two concurrent boots** (ports 18903/18904, same `$HOME`, no key file) | `audit-hmac-key` created **0600** (`-rw-------`), **zero** `.tmp-*` residue, both daemons serving, both printed the loud `generated + persisted this boot` WARN |
| F-1 code | `OpenOptions::create_new(true).mode(0o600)` at creation (unix), stale-tmp removal, every `Result` handled (write/rename failure → tmp cleaned → ephemeral fallback) — reviewed in `audit_key.rs` |
| F-2: corrupt key file (`not-a-valid-hex-key!!`) → boot | loud line + WARN: `regenerated this boot (key file was corrupt — correlation with prior hashes lost)`; file repaired at 0600 (64 hex + `\n`) |
| F-3 | `requires_loud_warning` matrix unit-tested; dry-run ephemeral marker present in `init.rs` (code-reviewed) |

### 3.6 Token generation & logging (R9-5 support)

- `init` token: **64 lowercase hex = 256 bits** from `getrandom` (`generate_admin_token`, `init.rs` — code-verified; 32 CSPRNG bytes).
- `config.yaml` written **0600 at creation** (verified live, first init).
- Token **never logged**: grep of `init.out`, both daemon logs, and the mock log → **0 hits**. Env-override token → 0 hits in its daemon log.
- Boot with `None` token: loud `warning: NO admin token configured — the control plane is CLOSED …` (verified on port 18902; tokenless `/api/events` → **401**, `/health` → 200, rebinding gate still 403, F4 bypass refused).

### 3.7 Timing side-channel on token comparison (task item) — judged, documented

`api::constant_time_eq` short-circuits on **length** and its xor-accumulate loop is not hardened against compiler transformations. For this deployment the material is: 256-bit CSPRNG token, uniform 64-hex length (length leak = zero information), no early-exit on content, and network jitter orders of magnitude above the loop. **Verdict: P3 / informational — not exploitable; do not churn now** (a `subtle`-style constant-time primitive would close it cosmetically).

## 4. Findings

### P2-1 — `cerberus init` re-run over an existing non-0600 `config.yaml` writes a fresh admin token into the file **without enforcing 0600**, and its report falsely claims mode 0600
- **Reproduced live**: `chmod 644 config.yaml` → `cerberus init` → token rotated (new 64-hex value) → file mode **still `-rw-r--r--`** while the report prints `written to … (mode 0600, R9-5)`.
- **Cause**: `write_config_0600` (`init.rs`) uses `.create(true).truncate(true).mode(0o600)` — the mode applies only at creation; the F-1 `create_new` discipline was not extended to the re-init path, and there is no "already initialized" guard in `run_init`.
- **Impact**: a token credential can end up world-readable on re-init after an editor/older-version file; the tool's own output asserts otherwise (config lie).
- **Fix direction (follow-up, not a reopen)**: after write, `fchmod`/`set_permissions` unconditionally (or refuse re-init), and make the report reflect reality. Everything else in F-1's scope is closed.

### P3-1 — Malformed JSON on authenticated mutation routes drops the connection instead of 400
- Reproduced: `POST /api/upstreams` with `{}` + valid token → handler returns `Err` (serde map_err `?`) → hyper logs `error from user's Service` and closes the connection (curl `HTTP=000`). Daemon survives; unauthenticated callers get 401 before the handler. Robustness/UX only — no bypass, no leak; suggest mapping parse errors to 400 like the other failure arms do.

### P3-2 (informational) — timing side-channel, §3.7 above. Not exploitable for 256-bit tokens; documented, no action required now.

### Notes (no severity)
- hyper accepts duplicate `Host` (first value wins) and absolute-URI forms; the gate reads the first Host header and is fail-closed in every observed ordering — no bypass found.
- Concurrent first boots on one `$HOME` each persist a different key (last rename wins) — one process holds an in-memory key not on disk (operational nuance of the F-1 race; file mode invariant held; pre-existing semantics, not a regression).
- `ApiContext::ensure_host_origin` swallows `HostOriginPolicy::build` errors (`if let Ok`), but the product daemon builds the policy with `?` **before** spawning and fails the boot on wildcard/blank entries — the silent path is reachable only from library/test producers (documented in-code).
- `AKIAIOSFODNN7EXAMPLE` / `sk-EXAMPLE…` are inert by design (`allowedExamples` FP guards) — reviewers must not mistake them for detection failures (I initially did; verified against the pack source).

## 5. Final verdict

**PASS.** R9-5 (P0) is genuinely closed, not just asserted: the control plane is fail-closed in every mode I could attack — tokenless boot answers 401 on every data route with a loud boot warning; the F4 unauthenticated-bypass injection vector is dead in both tokenized and tokenless modes (403 + loud refusal); the bypass is token-gated exclusively through `X-Cerberus-Admin-Token` (Bearer is insufficient) and neither bypass nor admin headers ever reach the upstream (verified at a live mock); and the anti-rebinding allowlist rejected every hostile shape I threw at it — attacker hosts, subdomain/punycode/trailing-dot/alternate-encoding loopback lookalikes, `null` and evil Origins including userinfo and path tricks, missing/duplicate Host, HTTP/1.0, and absolute-URI forms — while loopback names, CLI curl shapes, and same-authority Origins still work. R9-7 is closed end-to-end: raw values are converted to keyed HMAC fingerprints at ingestion, rejected raw by the policy/config gates, destroyed in place by a loud idempotent migration, absent from config bytes, API responses, and logs, and still honored on the hot path; the store refuses unkeyed schemes at the writer. F-1/F-2/F-3 closed under a reproduced umask-000 concurrent-boot attack (0600 from creation, no tmp residue, loud regeneration). All four gates plus load 14/14 are green, and redos_fuzz is byte-identical to base. Two non-blocking findings are registered: **P2-1** (re-init writes a rotated token into a pre-existing non-0600 `config.yaml` while falsely reporting "mode 0600" — a follow-up fix in `init.rs`, creation-time 0600 itself is correct) and **P3-1/P3-2** (connection-drop on malformed JSON; cosmetic timing hardening). Neither reopens the unit; both should be tracked for F6 follow-up.

**Report path**: `evidence/review9/f6a-attempt1-security.md` (this file) — the only file created in the main repo.
