# Evidence Pack — F4.3 / R9-17 smoke-test hygiene (broken checks repaired)

- Attempt: 1    Builder: F4.3 builder (r9-f4-attempt1)    Verdict: **returns to VERIFY**
- Base: commit `67c3150` (branch `r9-remediation`), worktree `/var/folders/…/opencode/f4-attempt1-builder`, branch `r9-f4-attempt1`, tree clean at start
- Date: 2026-09-01    Toolchain: macOS (darwin), bash, python3, release build `cargo build --release --workspace` (219 crates, 39.8 s)
- Finding spec: `evidence/review9/gauntlet-findings.md` R9-17 [MED, VERIFIED] + fix-plan §F4.3
- Unit type: test/evidence hygiene — **zero product code touched** (single file: `tests/smoke-test.sh`)

## R9-17 (verbatim scope)

> `tests/smoke-test.sh:237-244` HTTP_CODE sale del exit-status de curl (no del código de
> respuesta); `:312` el leak-check grephea un archivo log con typo (`cerberus-smock-$PORT.log`,
> inexistente) → "clean" siempre; `:141` fallo de init tragado por `|| true`. Estos alimentan la
> evidencia de no-leak (r0/f9).

fix-plan §F4.3 adds: remove `|| true` from init; capture real HTTP with `curl -o … -w '%{http_code}'`
and assert body/status; fix `smock`→`smoke`; **enumerate all logs/store inspected and fail if an
expected file is missing**; deterministic cleanup; `set -euo pipefail` without hiding errors.

---

## Acceptance criteria (one row each)

| Criterion (from R9-17 + §F4.3) | Command / proof | Output | Result |
|---|---|---|---|
| AC1 — HTTP code from the real response status, explicitly asserted | `bash tests/smoke-test.sh --port 18787` (and 18788, 18790) | `HTTP response code: 200` → `PASS: P0-4/P0-5: CLEAN REQUEST forwarded successfully (HTTP 200)`; verdict line is an explicit `[ "$HTTP_CODE" = "200" ]` comparison on `-w '%{http_code}'` output | ✅ |
| AC1-neg — a non-200 response can no longer read as 200 | code path: blocked responses exit 0 in curl yet return 403; historical log `evidence/r0/smoke-test/smoke-run-20260817-173559.log` shows the old artifact: `NOTE: Proxy returned 200 but mock didn't record (timing?)` — that "200" was curl's exit status on a 403-blocked request. Repaired block derives `HTTP_CODE` solely from `-w '%{http_code}'` | old: hardcoded `"200"` on curl exit 0 → new: `HTTP_CODE=$(curl … -w '%{http_code}') || HTTP_CODE="000"` | ✅ |
| AC2 — body asserted together with status (§F4.3 "asertar body/status") | positive runs | `PASS: P0-4/P0-5: clean content echoed back by upstream (body passthrough intact)` (grep of the returned echo body) | ✅ |
| AC3 — `smock` typo gone; proxy log is a real per-run artifact | `grep -rn "smock" tests/ tools/` → no hits; daemon redirected to `/tmp/cerberus-smoke-${PORT}.log` (rm -f'd fresh each run) | leak-check names the real file it inspected: `No raw secret leaked in HOME tree, proxy log (/tmp/cerberus-smoke-18787.log), or mock log (…)` | ✅ |
| AC4 — mock log genuinely inspected (was: claimed in the pass message, never captured) | mock now launched with `CERBERUS_MOCK_LOG=/tmp/cerberus-smoke-mock-${MOCK_PORT}.log` (rm -f'd fresh); surface enumerated in the leak-check | positive runs: `3/3 surfaces present and inspected`; negative run: leak found IN the mock log (see Adversarial) | ✅ |
| AC5 — missing expected artifact fails the check (was: grep of missing file = silent "clean") | leak-check pre-pass enumerates `LEAK_SURFACES=("$TEST_HOME" "$DAEMON_LOG" "$MOCK_LOG")` and `fail_check`s any absent one before any grep runs | code + `bash -n` verified; absence path produces `❌ FAIL: Leak-check surface(s) missing — evidence would be vacuous: …` | ✅ |
| AC6 — init failure no longer swallowed; failed init fails the run | `INIT_RC=0; "$BINARY" init 2>&1 \| tee -a "$TEST_LOG" \|\| INIT_RC=$?` → `fail_check` + `FATAL` + `exit 1` (hard precondition, same style as daemon/mock) | `cerberus init` measured exiting 0 on success (probe + all positive runs) → no false abort; failure path aborts the run | ✅ |
| AC7 — no-leak checks genuinely run and genuinely fail on a violation | NEGATIVE test, leak injected through the real product (below) | `❌ FAIL: RAW SECRET FOUND in logs or data files!` + process exit **1** | ✅ |
| AC8 — no-leak checks pass on the real build | POSITIVE runs ×3 (ports 18787/18788/18790) | `✅ ALL: Smoke test PASSED`, 12 checks, exit **0** | ✅ |
| AC9 — grep errors cannot masquerade as "clean" | per-surface grep distinguishes rc=1 (no match) from rc≥2 (error → `fail_check "Leak grep errored … cannot certify no-leak"`) | code review + syntax check | ✅ |
| AC10 — deterministic cleanup; no hidden errors | cleanup trap additionally removes `DAEMON_LOG`/`MOCK_LOG`; logs rm -f'd before daemon/mock start (stale content can never feed a leak check); `set -euo pipefail` retained; the only remaining `|| true`s are the two legitimate grep-no-match guards in the old leak block (removed) and `free_port` (nothing-to-kill) | `rtk git diff --check` PASS | ✅ |

## Before / after of each broken check

### R9-17a — HTTP_CODE from curl exit status (old L236-244)

```bash
# BEFORE — "200" hardcoded whenever curl exited 0 (any completed transfer,
# including a 403/500 block response):
if curl -s -m 5 -o /tmp/cerberus-smoke-upstream-body.txt \
    -X POST "…" -H "Content-Type: application/json" \
    -d "$CLEAN_PAYLOAD" 2>/dev/null; then
    HTTP_CODE="200"
else
    HTTP_CODE="000"
fi
…
fail_check "P0-4/P0-5: CLEAN REQUEST NOT forwarded — exit code $HTTP_CODE"

# AFTER — real status, explicit comparison, body asserted too:
HTTP_CODE=$(curl -s -m 5 -o /tmp/cerberus-smoke-upstream-body.txt \
    -w '%{http_code}' \
    -X POST "…" -H "Content-Type: application/json" \
    -d "$CLEAN_PAYLOAD" 2>/dev/null) || HTTP_CODE="000"
if [ "$HTTP_CODE" = "200" ]; then
    pass_check "P0-4/P0-5: CLEAN REQUEST forwarded successfully (HTTP 200)"
else
    fail_check "P0-4/P0-5: CLEAN REQUEST NOT forwarded — HTTP response code $HTTP_CODE"
fi
if echo "$UPSTREAM_BODY" | grep -q 'hello'; then
    pass_check "P0-4/P0-5: clean content echoed back by upstream (body passthrough intact)"
else
    fail_check "P0-4/P0-5: clean content NOT echoed back by upstream (body passthrough broken)"
fi
```

Corroborating artifact: the 2026-08-17 run log contains `NOTE: Proxy returned 200 but mock didn't
record (timing?)` — that "200" was a 403 block response misread via exit status.

### R9-17b — leak-check grep of a typo'd, never-existing file (old L310-321)

```bash
# BEFORE — third surface can never match; "clean" always:
PROXY_LOG_LEAK2=$(grep -r "$RAW_SECRET" /tmp/cerberus-smock-${PORT}.log 2>/dev/null || true)
if [ -z "$LOG_LEAK" ] && [ -z "$PROXY_LOG_LEAK" ] && [ -z "$PROXY_LOG_LEAK2" ]; then
    pass_check "No raw secret leaked in HOME, proxy logs, or mock logs"
fi

# AFTER — enumerated surfaces, all must exist, every grep rc honored:
LEAK_SURFACES=("$TEST_HOME" "$DAEMON_LOG" "$MOCK_LOG")
#   DAEMON_LOG = /tmp/cerberus-smoke-${PORT}.log   ('smock'→'smoke', per-run, rm -f'd)
#   MOCK_LOG   = /tmp/cerberus-smoke-mock-${MOCK_PORT}.log  (CERBERUS_MOCK_LOG, rm -f'd)
for surface in "${LEAK_SURFACES[@]}"; do
    if [ ! -e "$surface" ]; then MISSING_SURFACES+=" …"; continue; fi   # missing = FAIL
    GREP_RC=0; HITS=$(grep -r "$RAW_SECRET" "$surface" 2>/dev/null) || GREP_RC=$?
    case: rc≥2 → fail_check (cannot certify no-leak); HITS non-empty → LEAK_HITS
done
# missing surfaces → fail_check("… evidence would be vacuous")
# LEAK_HITS non-empty → fail_check("RAW SECRET FOUND in logs or data files!") + hit dump
# else → pass_check("… — 3/3 surfaces present and inspected")
```

### R9-17c — init failure swallowed by `|| true` (old L141)

```bash
# BEFORE:
"$BINARY" init 2>&1 | tee -a "$TEST_LOG" || true

# AFTER — explicit exit code; failed init is a hard precondition that fails the run:
INIT_RC=0
"$BINARY" init 2>&1 | tee -a "$TEST_LOG" || INIT_RC=$?
if [ "$INIT_RC" -ne 0 ]; then
    fail_check "cerberus init exited with code $INIT_RC (was previously swallowed by '|| true')"
    echo "FATAL: init failed — aborting smoke test." | tee -a "$TEST_LOG"
    exit 1
fi
# (the pre-existing `~/.cerberus` directory check is kept as the follow-up assertion)
```

---

## Adversarial cases tested (attempt to break the checks)

### Negative test — leak injected through the REAL product → smoke FAILS (exit 1)

Leak vector (no product code modified, no fake file writes): the dev-mode data-plane bypass.
At this SHA the init-generated config has no admin token, so `X-Cerberus-Bypass: <reason>` is
honored unauthenticated (proxy.rs:610-637, "Dev mode: no token configured, bypass open") — the
documented R9-5 behavior, F6.2 pending. Verified in a pre-probe: secret payload → `403
{"error":"blocked"}` without the header; with the header → `200` and the mock's `/__cerberus__/last`
shows the RAW secret forwarded verbatim.

Fixtures (temp, untracked, **removed after the runs**; SHA-256 frozen below; recreation = copy
`tools/mock-server.py` + `tests/smoke-test.sh` and apply the two diffs quoted in Appendix A):

1. `tools/mock-server-leaky.py` — mock-server.py + logs every received request body into
   `CERBERUS_MOCK_LOG` (simulates a naive upstream that logs payloads).
2. `tests/smoke-test-negative.sh` — the fixed test with the leaky mock + one extra step after
   TEST POINT 3: `curl -H 'X-Cerberus-Bypass: smoke-negative-leak-injection' -d "$SECRET_PAYLOAD"`
   → raw secret crosses the real proxy → upstream → mock log.

Transcript (worktree `evidence/r0/smoke-test/smoke-run-20260901-192655.log`, console
`/tmp/f4-evidence/negative-fixed-console.log`, port 18791):

```
  ✅ PASS: P0-1: SECRET DETECTED (block or redact)
  [leak-injection] bypass response (truncated): {"mock": true, "echo": {"method": "POST", …
…
═══════════════════  STEP 8: TEST POINT 6 — Zero leak ═══════════════
  ❌ FAIL: RAW SECRET FOUND in logs or data files!

--- /tmp/cerberus-smoke-mock-61612.log ---
/tmp/cerberus-smoke-mock-61612.log:{"seq": 1, "logged_body": "{\"messages\":[{\"role\":\"user\",\"content\":\"OPENAI_API_KEY=sk-abc123def456ghi789jkl012mno345\"}]}"}
…
  Pass: 11
  Fail: 1
  ❌ FAIL: Smoke test has 1 failed checks
```

Process exit code measured without a pipe: **1**. The no-leak check names the leaking file and the
matching line; HOME tree, proxy log and audit store stayed clean (block/bypass events store hashes
only) — i.e. the mock-log surface, the one the old test faked, is what caught the leak.

### Vacuity control — OLD broken test, same leak → PASS (proves R9-17's "clean" siempre)

`tests/smoke-test-negative-old.sh` = verbatim `git show 67c3150:tests/smoke-test.sh` + the same
leaky mock + the same injection (port 18792; old run's mock log = default `/tmp/cerberus-mock.log`,
never set nor inspected by the old test):

```
  ✅ PASS: P0-1: SECRET DETECTED (block or redact)
  [leak-injection] bypass response (truncated): {"mock": true, …
…
  ✅ PASS: No raw secret leaked in HOME, proxy logs, or mock logs
  Pass: 11
  Fail: 0
```

Exit **0** — while, measured immediately after the run:

```
$ grep -c 'sk-abc123def456ghi789jkl012mno345' /tmp/cerberus-mock.log
1
{"seq": 1, "logged_body": "{\"messages\":[{\"role\":\"user\",\"content\":\"OPENAI_API_KEY=sk-abc123def456ghi789jkl012mno345\"}]}"}
```

The raw secret was present in that run's actual mock log; the old test reported "clean" because it
greps a typo'd path that never existed (`ls /tmp/cerberus-smock-*.log` → no matches) and never
captures the mock log at all. Same leak: old PASS / repaired FAIL.

### Positive runs — real build, isolated HOME, test ports (PASSES)

| Run | Port | Console capture | Verdict |
|---|---|---|---|
| 1 | 18787 | `/tmp/f4-evidence/positive-run1-console.log`, worktree `evidence/r0/smoke-test/smoke-run-20260901-192247.log` | exit 0, 12/12 |
| 2 | 18788 | `/tmp/f4-evidence/positive-run2-console.log`, `…smoke-run-20260901-192315.log` | exit 0, 12/12 |
| 3 (measured exit, no pipe) | 18790 | `/tmp/f4-evidence/positive-run3-console.log`, `…smoke-run-20260901-192645.log` | **exit 0**, 12/12 |

Key lines (runs 1–3 identical in shape):

```
  HTTP response code: 200
  ✅ PASS: P0-4/P0-5: CLEAN REQUEST forwarded successfully (HTTP 200)
  ✅ PASS: P0-4/P0-5: clean content echoed back by upstream (body passthrough intact)
  Response: {"error":"blocked","flag":"secret.openai_api_key"}        ← P0-1 (real 403 block)
  ✅ PASS: P0-6: /api/events returned events (non-empty)
  ✅ PASS: No raw secret leaked in HOME tree, proxy log (/tmp/cerberus-smoke-18787.log), or mock log (/tmp/cerberus-smoke-mock-61208.log) — 3/3 surfaces present and inspected
  ✅ ALL: Smoke test PASSED      (Pass: 12, Fail: 0)
```

---

## Verification matrix (builder gate battery)

| # | Gate | Command | Result |
|---|---|---|---|
| 1 | fmt | `rtk cargo fmt --all -- --check` | PASS (no output) |
| 2 | clippy | `rtk cargo clippy --workspace --all-targets -- -D warnings` | PASS — "No issues found" |
| 3 | tests (debug) | `rtk cargo test --workspace --all-targets` | **753 passed** (25 suites, 51.5 s), 0 failures — matches baseline 753 |
| 4 | production pack | `rtk cargo test -p cerberus-packs --test production_pack_pr` | **19 passed** (1 suite) |
| 5 | smoke end-to-end ×2 | positive runs 18787 + 18788 (plus a third with measured exit 0) | PASS ×2 (+1) |
| 6 | whitespace | `rtk git diff --check` | PASS |

Negative battery (beyond the matrix): injected-leak run → FAIL exit 1; old-test vacuity control →
PASS exit 0 with the leak demonstrably present. `bash -n` on all scripts: OK.

## Applicable NFRs

- Security (no-leak): repaired check now covers 3 enumerated, existence-checked surfaces; detection
  proven against a real end-to-end leak → ✅ (negative transcript above).
- Reliability: failed init / missing artifact / grep error each fail the run instead of passing
  vacuously → ✅.
- Latency: N/A for this unit (no product code touched; hot path untouched).

## If FAIL: what fails and how to reproduce it

N/A — builder verdict is **returns to VERIFY** with no failing criterion. Reproduction of the
negative case for the verifier: Appendix A.

## Real product bugs exposed by the repaired checks

- **None new.** Every repaired check passes against the real release build; the only failure ever
  produced was the deliberately injected leak.
- Corroboration (not a new finding): the injected-leak path exercises the already-verified R9-5
  behavior at this SHA — unauthenticated `X-Cerberus-Bypass` in dev mode forwards raw secrets
  upstream (F6.2 remediates). The smoke run surfaced it end-to-end exactly as the finding describes;
  per unit rules it was **not** fixed here (out of scope, F6.2's unit).

## Known limits / notes for the panel

1. The committed test's P0-1 curl still captures body only (no `-w '%{http_code}'`) — R9-17 lists
   L237-244 only; left untouched (scope discipline). Its assertion greps the response body and fails
   on empty, so it cannot false-pass a transport failure.
2. Pre-existing quirk, left untouched (outside R9-17's list): the post-P0-4 verification greps
   `'"echo"'` in `/__cerberus__/last`, a key that endpoint never returns → it can only print a NOTE,
   never a vacuous pass. Mock receipt is now genuinely asserted by the body-passthrough check (the
   echo body can only originate from the mock).
3. The mock's `CERBERUS_MOCK_LOG` (real mock) records request metadata, not bodies — with the real
   product it is an enumerated, existence-checked surface whose leak value shows up under broken
   upstreams (as the negative fixture demonstrates) or future proxy regressions that leak into it.
4. The negative fixture's bypass vector will need `X-Cerberus-Admin-Token` once F6.2 gates the
   bypass — a note for whoever re-runs Appendix A after F6, not part of the committed test.
5. `smoke-test.sh` remains bash/python3/lsof-based (macOS-oriented). Cross-platform clean-home
   transcripts belong to F4.2/windows-support, not this unit.
6. The script's cleanup frees ports by `lsof` match (pre-existing design); the `Killed: 9` job
   messages after exit are that trap's normal output and do not affect the exit code (measured).
7. Full console transcripts live in `/tmp/f4-evidence/` (host temp) and in the worktree's untracked
   `evidence/r0/smoke-test/smoke-run-2026090{1}-*.log` (the script's own persistence path). The
   negative-run transcripts contain the synthetic test secret by design (it is the detection proof).

## Frozen SHA-256 (final state)

| File | Status | SHA-256 |
|---|---|---|
| `tests/smoke-test.sh` | modified (committed) | `4be41c0c4eac759a7fea4efb3de43a7b19af1b78810dbf3011e410f09b07691c` |
| `evidence/f4/r9-smoke-test-hygiene.md` | added (this pack) | _self-reference impossible — final hash recorded in the commit body and the builder return_ |
| `tools/mock-server-leaky.py` | temp fixture, removed | `163da1209d584f4f20d5ffd041d750967516f43b049355e420309b7f7db1a1da` |
| `tests/smoke-test-negative.sh` | temp fixture, removed | `9a41f1382822e672879b4e24720ba5b6ffd42330f3e0295c9fd3e3639849def0` |
| `tests/smoke-test-negative-old.sh` | temp fixture, removed | `b6f4637b3758db35850366f5fa26016e15725c6cad857b2bc8b559464079ae13` |

## Builder verdict

**Returns to VERIFY.** All R9-17 items repaired inside the finding's scope; positive (real build,
×3) and negative (injected leak, exit 1) transcripts attached; old-test vacuity demonstrated live;
builder battery green (fmt/clippy/753 tests/19/19/smoke/diff-check). No product code changed, no
thresholds moved, no scope invented.

---

## Appendix A — negative-case reproduction (for the verifier)

From the repo/worktree root at the commit under review, with a release build present
(`cargo build --release --workspace`):

**1. Leaky mock fixture** — `cp tools/mock-server.py tools/mock-server-leaky.py`, then insert at
the end of `MockHandler._record()` (after the existing metadata `f.write(entry)` block, SHA-256 of
the produced file must equal `163da120…`):

```python
        # [R9-17 negative-test fixture ONLY — not committed] Deliberately
        # broken upstream: logs the FULL request body it receives, so a raw
        # secret that reaches the upstream (e.g. via an open data-plane
        # bypass) lands in the mock log — the leak surface the repaired
        # smoke-test leak-check must catch.
        try:
            with open(log_file, "a") as f:
                f.write(json.dumps({
                    "seq": request_count,
                    "logged_body": last_request.get("body", ""),
                }) + "\n")
        except OSError:
            pass
```

**2. Negative variant of the fixed test** — `cp tests/smoke-test.sh tests/smoke-test-negative.sh`,
then two edits (produced file SHA-256 `9a41f138…`):

- launch the leaky mock: `python3 tools/mock-server.py` → `python3 tools/mock-server-leaky.py`
- insert immediately after the P0-1 `if/else/fi` block:

```bash
# ── NEGATIVE TEST ONLY: LEAK INJECTION (not part of the committed test) ─
INJECT_RESULT=$(curl -s -m 5 -X POST "http://127.0.0.1:${PORT}/openai/v1/chat/completions" \
    -H 'Content-Type: application/json' \
    -H 'X-Cerberus-Bypass: smoke-negative-leak-injection' \
    -d "$SECRET_PAYLOAD" 2>/dev/null || echo "")
echo "  [leak-injection] bypass response (truncated): ${INJECT_RESULT:0:100}" | tee -a "$TEST_LOG"
```

**3. Run** (direct redirection so `$?` is the script's):

```bash
bash tests/smoke-test-negative.sh --port 18791 > console.log 2>&1; echo "exit=$?"
# expected: exit=1, "❌ FAIL: RAW SECRET FOUND in logs or data files!"
#           hit line under --- /tmp/cerberus-smoke-mock-<MOCK_PORT>.log ---
```

**4. Vacuity control (optional)** — repeat edits 1–2 on `git show 67c3150:tests/smoke-test.sh`
(leaky mock + same injection), run it, then observe: exit=0 with
`✅ PASS: No raw secret leaked in HOME, proxy logs, or mock logs` while
`grep -c 'sk-abc123def456ghi789jkl012mno345' /tmp/cerberus-mock.log` → `1`
(the old test never captures or inspects that file; it greps the never-existing
`/tmp/cerberus-smock-<PORT>.log` instead).

**5. Clean up** the three untracked fixture files afterwards.

Note: after F6.2 lands, step 2's injection curl must additionally carry the valid admin token
(`-H "X-Cerberus-Admin-Token: $TOKEN"`) or the bypass is (correctly) refused.
