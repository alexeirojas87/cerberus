# F4.3 Verification — R9-17 smoke-test broken checks repaired (attempt 1)

- Reviewer: independent adversarial verifier (did NOT build; verification by execution)
- Candidate: commit `389c95a` on `r9-remediation` (parent `67c3150`), inspected in detached worktree `/var/folders/…/opencode/f43-verify` (removed after verification)
- Date: 2026-09-01 · Protocol: §8B gauntlet, combined correctness+security verification, proportionate to P2 test-hygiene unit
- Finding spec: `evidence/review9/gauntlet-findings.md` R9-17 [MED, VERIFIED] + fix-plan §F4.3
- Builder pack: `evidence/f4/r9-smoke-test-hygiene.md` (incl. Appendix A, used as-is to recreate the negative-case fixtures)

**FINAL VERDICT: PASS** (2 P2 evidence-quality findings, non-blocking — see Findings)

---

## 1. Commands run (verbatim, with exit codes)

| # | Command (cwd = verification worktree) | Exit | Result |
|---|---|---|---|
| 1 | `git -C /Users/alexeirojas/Work/Personal/Cerberus worktree add --detach /var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/f43-verify 389c95a` | 0 | worktree created at 389c95a |
| 2 | `rtk cargo fmt --all -- --check` | 0 | clean, no output |
| 3 | `rtk cargo clippy --workspace --all-targets -- -D warnings` | 0 | "No issues found" |
| 4 | `rtk cargo test --workspace --all-targets` | 0 | **753 passed** (25 suites, 50.64 s) — matches baseline 753 |
| 5 | `rtk cargo test -p cerberus-packs --test production_pack_pr` | 0 | **19 passed** (1 suite) |
| 6 | `rtk git diff --check` | 0 | no whitespace errors |
| 7 | `shasum -a 256 tests/smoke-test.sh evidence/f4/r9-smoke-test-hygiene.md` | 0 | see §5 hash check |
| 8 | `rtk cargo build --release --workspace` | 0 | 219 crates, 33.29 s |
| 9 | `bash tests/smoke-test.sh --port 18787 > /tmp/f43-verify/positive-run1-console.log 2>&1; echo exit=$?` | 0 | positive run, §3.1 |
| 10 | `bash tests/smoke-test-negative.sh --port 18791 > /tmp/f43-verify/negative-fixed-console.log 2>&1; echo exit=$?` | **1** | fixed test catches injected leak, §3.2 |
| 11 | `rm -f /tmp/cerberus-mock.log && bash tests/smoke-test-negative-old.sh --port 18792 > /tmp/f43-verify/negative-old-console.log 2>&1; echo exit=$?` | **0** | old test vacuous PASS, §3.3 |
| 12 | `grep -c 'sk-abc123def456ghi789jkl012mno345' /tmp/cerberus-mock.log` | 0 | **count = 1** — leak demonstrably present after the old test's "clean" |
| 13 | `ls /tmp/cerberus-smock-18792.log` | 1 | "No such file or directory" — typo'd path never existed |
| 14 | Defeat A: `printf 'STALE LEAK sk-abc…\n' > /tmp/cerberus-smoke-18787.log && bash tests/smoke-test.sh --port 18787 …; echo exit=$?` | 0 | stale pre-created log neutralized, §4 |
| 15 | Defeat B: `bash tests/smoke-test-defeat-403.sh --port 18793 …; echo exit=$?` | **1** | 403 block now FAILs the forwarded-claim, §4 |
| 16 | Defeat C: stub binary exiting 3 → `bash tests/smoke-test.sh --port 18794 …; echo exit=$?` | **1** | init failure aborts with FATAL, §4 |
| 17 | Cleanup: `rm -f <4 fixtures> /tmp/cerberus-mock.log /tmp/cerberus-smoke-*.log` + `git status --porcelain` (empty) + stray-kill | 0 | worktree pristine, no daemons left |

Notes: an initial invocation of #9 failed with shell exit 1 — `zsh: no such file or directory: /tmp/f43-verify/…` (missing console dir created with `mkdir -p`); not a test failure. All smoke-test exit codes above were measured by direct redirection, no pipes. Negative-case fixtures were recreated strictly per Appendix A inside the worktree (temp, untracked, removed after; never committed). Only Defeat B/C required temp fixture/stub variants — the committed `tests/smoke-test.sh` was never modified.

## 2. Per-criterion verdicts

| Criterion | Verdict | Evidence |
|---|---|---|
| M1 `fmt --check` | ✅ PASS | exit 0, no output |
| M2 `clippy -D warnings` | ✅ PASS | exit 0 |
| M3 workspace tests (debug) = 753 | ✅ PASS | 753 passed / 0 failed, exactly baseline |
| M4 `production_pack_pr` 19/19 | ✅ PASS | 19 passed |
| M5 `git diff --check` | ✅ PASS | exit 0 |
| R9-17a — HTTP_CODE from real status, explicit comparison | ✅ PASS | diff replaces exit-status-derived `"200"` with `curl -w '%{http_code}'` + `[ "$HTTP_CODE" = "200" ]`; Defeat B (§4): 403 block → `FAIL … HTTP response code 403` (old code printed "200" here) |
| R9-17a — body asserted with status | ✅ PASS | `grep -q 'hello'` on returned echo body; passes on real forward, fails on block (Defeat B) |
| R9-17b — `smock` typo gone | ✅ PASS | grep: `smock` survives only in 3 fix-documentation comments; no functional path/variable uses it |
| R9-17b — real per-run proxy log | ✅ PASS | `DAEMON_LOG=/tmp/cerberus-smoke-${PORT}.log`, `rm -f` before start, daemon redirected there; leak-check names it |
| R9-17b — real per-run mock log | ✅ PASS | `CERBERUS_MOCK_LOG=/tmp/cerberus-smoke-mock-${MOCK_PORT}.log` (mock-server.py honors it; verified in source), `rm -f` before start |
| R9-17b — 3-surface enumeration + missing = FAIL | ✅ PASS | `LEAK_SURFACES=("$TEST_HOME" "$DAEMON_LOG" "$MOCK_LOG")`; existence pre-pass; **empirically** proven fail-closed in Defeat B (mock never got a request → surface missing → `Leak-check surface(s) missing — evidence would be vacuous`) |
| R9-17b — grep rc≥2 = FAIL | ✅ PASS (code-verified) | `HITS=$(grep -r …) \|\| GREP_RC=$?; [ "$GREP_RC" -ge 2 ] → fail_check`; rc=1 correctly treated as no-match |
| R9-17c — init failure not swallowed | ✅ PASS | `INIT_RC` capture via pipefail-aware `\|\| INIT_RC=$?` → `fail_check` + `FATAL` + `exit 1`; Defeat C (§4): exit-3 init aborts run |
| Negative test: fixed test FAILs on real injected leak | ✅ PASS | exit 1, `RAW SECRET FOUND`, mock-log hit named (§3.2) |
| Vacuity control: old test PASSes same leak | ✅ REPRODUCED | exit 0 while secret provably in the run's mock log (§3.3) |
| Scope: only `tests/smoke-test.sh` + evidence pack | ✅ PASS | `git show 389c95a --name-only` = 2 files; no product code moved |
| R9-5 recorded as finding-not-fixed | ✅ PASS | pack §"Real product bugs exposed" states bypass is already-tracked R9-5, "not fixed here (out of scope, F6.2's unit)"; R9-5 confirmed CRÍTICO/VERIFIED in gauntlet-findings.md:35 |
| Hash check (§5) | ✅ PASS (with P2) | committed files match frozen values exactly; 2/3 temp-fixture hashes not byte-reproducible (P2-1) |

## 3. The three decisive transcripts (condensed; exit codes verbatim)

### 3.1 Positive run — FIXED test, real release build, isolated HOME, port 18787 → exit **0**

```
  ✅ PASS: Binary exists at ./target/release/cerberus
  ✅ PASS: Clean HOME created
  ✅ PASS: Config directory ~/.cerberus created
  ✅ PASS: Health endpoint returns OK on port 18787
  ✅ PASS: Mock upstream server running on port 63810
  Response: {"error":"blocked","flag":"secret.openai_api_key"}
  ✅ PASS: P0-1: SECRET DETECTED (block or redact)
  HTTP response code: 200
  ✅ PASS: P0-4/P0-5: CLEAN REQUEST forwarded successfully (HTTP 200)
  ✅ PASS: P0-4/P0-5: clean content echoed back by upstream (body passthrough intact)
  Mock /__cerberus__/last: {"method": "POST", "path": "/v1/chat/completions", … "body": "{\"messages\":[{\"role\":\"user\",\"content\":\"hello\"}]}", "body_bytes": 48}
  ✅ PASS: P0-6: /api/events returned events (non-empty)
  ✅ PASS: P0-6: /api/stats returned non-trivial data
  ✅ PASS: SQLite database file exists
  ✅ PASS: No raw secret leaked in HOME tree, proxy log (/tmp/cerberus-smoke-18787.log), or mock log (/tmp/cerberus-smoke-mock-63810.log) — 3/3 surfaces present and inspected
  ✅ ALL: Smoke test PASSED
```
exit=0 · 12/12 checks · post-run `ls /tmp/cerberus-smoke-mock-*.log` → no matches (exit-trap cleanup works). NOTE line appears after P0-4 — the documented pre-existing echo-key quirk (pack note 2); the body-passthrough check is what genuinely proves mock receipt.

### 3.2 Negative run — FIXED test + Appendix A leak injection, port 18791 → exit **1**

Injection vector: unauthenticated dev-mode `X-Cerberus-Bypass` (R9-5 behavior at this SHA) pushes the raw secret through the real proxy into a leaky-mock fixture that logs request bodies.

```
  ✅ PASS: Mock upstream server running on port 63974
  ✅ PASS: P0-1: SECRET DETECTED (block or redact)
  [leak-injection] bypass response (truncated): {"mock": true, "echo": {"method": "POST", "path": "/v1/chat/completions", "body": "{\"messages\":[{\
  ✅ PASS: P0-4/P0-5: CLEAN REQUEST forwarded successfully (HTTP 200)
  ✅ PASS: P0-4/P0-5: clean content echoed back by upstream (body passthrough intact)
  ✅ PASS: P0-6: /api/events returned events (non-empty)
  ✅ PASS: P0-6: /api/stats returned non-trivial data
  ✅ PASS: SQLite database file exists
  ❌ FAIL: RAW SECRET FOUND in logs or data files!
--- /tmp/cerberus-smoke-mock-63974.log ---
/tmp/cerberus-smoke-mock-63974.log:{"seq": 1, "logged_body": "{\"messages\":[{\"role\":\"user\",\"content\":\"OPENAI_API_KEY=sk-abc123def456ghi789jkl012mno345\"}]}"}
  Pass: 11
  Fail: 1
  ❌ FAIL: Smoke test has 1 failed checks
```
exit=1. Exactly one surface hit — the mock log, the surface the old test faked; HOME tree and proxy log stayed clean (block/bypass events store hashes only). Matches the builder's negative transcript shape line-for-line (different ephemeral mock port, as expected).

### 3.3 Vacuity control — OLD test (67c3150) + same leaky mock + same injection, port 18792 → exit **0**

```
  ✅ PASS: Mock upstream server running on port 64010
  ✅ PASS: P0-1: SECRET DETECTED (block or redact)
  [leak-injection] bypass response (truncated): {"mock": true, "echo": {"method": "POST", …
  ✅ PASS: P0-4/P0-5: CLEAN REQUEST forwarded successfully (HTTP 200)
  ✅ PASS: P0-6: /api/events returned events (non-empty)
  ✅ PASS: P0-6: /api/stats returned non-trivial data
  ✅ PASS: SQLite database file exists
  ✅ PASS: No raw secret leaked in HOME, proxy logs, or mock logs
  Pass: 11
  Fail: 0
  ✅ ALL: Smoke test PASSED
```
exit=0 — while, measured immediately after the run:

```
$ grep -c 'sk-abc123def456ghi789jkl012mno345' /tmp/cerberus-mock.log
1
{"seq": 1, "logged_body": "{\"messages\":[{\"role\":\"user\",\"content\":\"OPENAI_API_KEY=sk-abc123def456ghi789jkl012mno345\"}]}"}
$ ls /tmp/cerberus-smock-18792.log
ls: /tmp/cerberus-smock-18792.log: No such file or directory
```
The old test's third surface (`cerberus-smock-*`, typo) never existed; the old test never sets `CERBERUS_MOCK_LOG`, so the leaky mock wrote to its uninspected default `/tmp/cerberus-mock.log`. Same leak: **old = vacuous PASS (exit 0) / fixed = real FAIL (exit 1)** — R9-17's "clean" siempre, independently reproduced.

## 4. Defeat attempts on the repaired checks

| Attempt | Method (no committed-file edits) | Outcome | Repair held? |
|---|---|---|---|
| A — stale log feeds leak-check | Pre-created `/tmp/cerberus-smoke-18787.log` containing the raw secret, then ran the fixed test | exit 0; leak-check passed 3/3 on a **fresh** artifact; file absent post-run. `rm -f` before daemon start (L187) neutralizes pre-creation — stale content can neither false-pass nor false-fail | ✅ |
| B — curl succeeds but proxy blocks (the exact R9-17a false-200 scenario) | Temp fixture variant of the fixed test sending `SECRET_PAYLOAD` in the clean step → proxy 403 | `HTTP response code: 403` → `❌ FAIL: CLEAN REQUEST NOT forwarded — HTTP response code 403`; body check also FAILs; run exit 1. Old code would have printed `HTTP_CODE="200"` here. **Bonus:** the blocked clean request meant the mock never got a non-status request → its log file never existed → `❌ FAIL: Leak-check surface(s) missing — evidence would be vacuous` — the AC5 fail-closed path demonstrated under realistic conditions | ✅ |
| C — init failure swallowed (the exact R9-17c defect) | Moved real binary aside, stub `#!/bin/sh … exit 3` in its place, ran fixed test, restored binary (verified `cerberus 0.1.2` after) | `❌ FAIL: cerberus init exited with code 3 (was previously swallowed by '\|\| true')` + `FATAL: init failed — aborting smoke test.` → exit 1 | ✅ |
| (static) vacuous-pass audit of (a) | Could a stale `/tmp/cerberus-smoke-upstream-body.txt` (not rm'd per-run) fake the body check? | No: the status assertion is independent — any non-200 (including 000 on transport failure) fails the run regardless of body; a completed transfer always overwrites the body file | ✅ |
| (static) vacuous-pass audit of (c) | Could a failed init still yield rc 0 through the `tee` pipe? | No: `set -o pipefail` makes the pipeline rc = rightmost non-zero; `\|\| INIT_RC=$?` captures it; `\|\|` form is safe under `set -e` | ✅ |

## 5. Hash check

| File | Pack / commit frozen value | Measured (shasum -a 256) | Match |
|---|---|---|---|
| `tests/smoke-test.sh` | `4be41c0c4eac759a7fea4efb3de43a7b19af1b78810dbf3011e410f09b07691c` (pack + commit body) | `4be41c0c4eac759a7fea4efb3de43a7b19af1b78810dbf3011e410f09b07691c` | ✅ |
| `evidence/f4/r9-smoke-test-hygiene.md` | recorded in commit body (self-reference impossible in-pack) `8f0d18d0ed2e659e1b9deb0c23216186bbe78cdc61a26cbab0213395673db4e4` | `8f0d18d0ed2e659e1b9deb0c23216186bbe78cdc61a26cbab0213395673db4e4` | ✅ |
| `tools/mock-server-leaky.py` (temp, removed) | `163da1209d584f4f20d5ffd041d750967516f43b049355e420309b7f7db1a1da` | `163da1209d584f4f20d5ffd041d750967516f43b049355e420309b7f7db1a1da` | ✅ exact byte reproduction from Appendix A |
| `tests/smoke-test-negative.sh` (temp, removed) | `9a41f1382822e672879b4e24720ba5b6ffd42330f3e0295c9fd3e3639849def0` | `f84d8e0285cbdc83e42e1e0f3dec6719bb19a21bcc5766805efacd94c3deb39f` (and 3 placement/whitespace variants tried) | ❌ → P2-1 |
| `tests/smoke-test-negative-old.sh` (temp, removed) | `b6f4637b3758db35850366f5fa26016e15725c6cad857b2bc8b559464079ae13` | `3776bb5345aeda7dd28afab7b8d2f60d567933288af36dd9c922870d8f45d2d5` (and variants) | ❌ → P2-1 |

## 6. Findings

**P0: none. P1: none.**

- **P2-1 (reproducibility hint)** — Appendix A's recipe does not byte-reproduce two of the three frozen temp-fixture hashes (`smoke-test-negative.sh` `9a41f138…`, `smoke-test-negative-old.sh` `b6f4637b…`); four insertion variants tried (leading-newline placements). The decisive fixture `mock-server-leaky.py` (`163da120…`) reproduces **exactly**, and the behavioral claims were fully reproduced with independently-built fixtures, so no verdict impact — but the frozen shell-fixture hashes are not derivable from the recipe as written. Suggest the pack either publish the exact fixture diffs verbatim or drop the unreproducible hashes.
- **P2-2 (citation imprecision)** — AC1-neg cites `evidence/r0/smoke-test/smoke-run-20260817-173559.log` as the historical artifact of a 403-blocked request misread as "200". That file does not exist. The `NOTE: Proxy returned 200 but mock didn't record` line does exist — in `smoke-run-20260817-165317/173423/173440.log` — but in every instance it follows a **genuine 200 forward with an echo body** (the documented echo-key quirk), not a 403 block. The R9-17a defect itself remains fully proven (old code snippet verified verbatim against 67c3150; Defeat B demonstrates old-vs-new behavior), so this weakens a corroborating citation only.
- **Observation (host hygiene, not this unit's code)** — the builder's worktree `…/opencode/f4-attempt1-builder` left a stray `mock-server.py` process (PID 58924, listening on 19731) running on the host since 19:15:20; killed during this verification's cleanup. It did not interact with any run performed here.
- **Note** — `smock` survives in 3 comment lines of the committed test (fix documentation); no functional occurrence. AC3's "no hits" claim is accurate for code paths.

## 7. Final verdict

**PASS.** All three R9-17 repairs are genuinely repaired and provably non-vacuous:

1. **Matrix green**: fmt PASS · clippy `-D warnings` PASS · 753/753 workspace tests · 19/19 `production_pack_pr` · `git diff --check` PASS.
2. **Decisive negative test reproduced end-to-end**: fixed test + real injected leak (unauthenticated dev-mode bypass → leaky mock) → `RAW SECRET FOUND` naming the per-run mock log, exit 1; old test with the identical leak → vacuous PASS, exit 0, while the raw secret sat demonstrably in that run's actual mock log (`grep -c` = 1) and the typo'd surface it greps never existed.
3. **All three defeat attempts failed to defeat the repairs** (stale-log pre-creation neutralized; 403 block now correctly FAILs the forwarded-claim with a bonus fail-closed missing-surface demonstration; init failure aborts with FATAL).
4. **Scope and hashes clean**: only `tests/smoke-test.sh` + the evidence pack moved; R9-5 recorded as finding-not-fixed (F6.2's unit); committed-file hashes match frozen values exactly.

The two P2s are evidence-quality nits (unreproducible temp-fixture hashes; a mis-cited historical log filename) and do not block closure. Recommend F4.3 CLOSED pending owner sign-off at the phase gate.
