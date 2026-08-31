# Review 9 — G0 independent review, Attempt 2

**Verdict: PASS**

- Reviewer: fresh adversarial reviewer `g0_reviewer2`
- Date: 2026-08-26
- Checkout: `fccd9e4823e17f3598b0aa27a7ae6bd632dfeec7`
- Branch: `docs/fix-install-commands`
- Mode: read-only; no GitHub state or local files modified
- `actionlint`: unavailable; Ruby YAML parsing plus exact structural assertions used

## 1. Workflows inert and fail-closed

```text
release.yml: PASS yaml=true triggers=[] permissions=contents:read job=review9_release_freeze static_if=false guard=exit-1 bypass_cases=35
notify-tap.yml: PASS yaml=true triggers=[] permissions=contents:read job=review9_tap_freeze static_if=false guard=exit-1 bypass_cases=35
workflow_inventory=PASS count=3 ci_events=pull_request,push alternate_publish_routes=none
actionlint=UNAVAILABLE
```

The assertions verified for both frozen workflows:

- exact `"on": []`;
- no dispatch, `workflow_call`, release, push, PR, schedule or tag event;
- exact `permissions: {contents: read}`;
- exactly one job with static `if: ${{ false }}`;
- exactly one bash step containing only `exit 1`;
- no `uses`, secrets, write permissions, ref expressions or publishing primitives;
- 35 ref/event combinations per file, including branches, tags, PR refs and adversarial branch names, could not alter trigger emptiness or job reachability.

All three workflow files were inspected. `ci.yml` exposes only `push` and
`pull_request`, does not call either frozen workflow, and contains no
release/dispatch/push publication route. Repository-wide route searching found
only documentation and historical evidence references, not another executable
workflow path.

No live dispatch was attempted because that would violate the read-only review
contract.

## 2. Exact remote containment

```text
origin  https://github.com/alexeirojas87/cerberus.git
{"nameWithOwner":"alexeirojas87/cerberus","defaultBranchRef":{"name":"main"}}
{"id":340188823,"name":"release","path":".github/workflows/release.yml","state":"disabled_manually"}
{"id":340355133,"name":"notify-tap","path":".github/workflows/notify-tap.yml","state":"disabled_manually"}
```

Remote workflow inventory:

```text
340188822 CI         .github/workflows/ci.yml         active
340355133 notify-tap .github/workflows/notify-tap.yml disabled_manually
340188823 release    .github/workflows/release.yml    disabled_manually
```

Both required workflow IDs are manually disabled in the exact repository.

## 3. Existing releases intact

The read-only GitHub API returned all four existing releases and their original
assets:

```text
375104963 v0.1.2             draft=false prerelease=false assets=5
375100198 v0.1.1             draft=false prerelease=false assets=5
375098412 v0.1.0-ci.161387a  draft=false prerelease=true  assets=5
375013370 v0.1.0             draft=false prerelease=false assets=2
```

Release and asset update timestamps remain from 2026-08-22/23, predating G0
containment. No release, tag or asset was changed during this review.

## 4. Evidence-index invalidation

```text
gauntlet_index=PASS current_gate_fail=1 invalidated_phases=1,2,3,4,5,6,7,8,9 historical_body_preserved_exactly=true current_pass_authority=none
```

`evidence/gauntlet/index.md`:

- contains exactly one current `FAIL` gate;
- invalidates exactly F1–F9 once each;
- explicitly denies publication, release and GA authority to prior PASS claims;
- places every subsequent record under an explicit historical-only umbrella;
- preserves the prior historical body except for the explicit historical labels.

There is no ambiguous current PASS authority.

## 5. Scope and hygiene

```text
scope_hygiene=PASS tracked=3 untracked=3 trailing_whitespace=0 nul=0 bom=0
tracked=.github/workflows/notify-tap.yml,.github/workflows/release.yml,evidence/gauntlet/index.md
untracked=evidence/review9/fix-plan.md,evidence/review9/g0-containment.md,evidence/review9/gauntlet-findings.md
```

`rtk git diff --check` produced no output. The diff is limited to containment
workflows and Review 9 evidence; no product source, release asset or unrelated
file changed.

## Verdict

**PASS.** G0 Attempt 2 meets the reviewed containment criteria. This verdict
closes only the independent G0 technical review; owner approval remains the
gate decision before F1 opens.
