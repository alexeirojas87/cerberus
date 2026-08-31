# Review 9 — G0 integrator cross-check

- Date: 2026-08-26 (America/New_York)
- Integrator: root coordinator
- HEAD: `fccd9e4823e17f3598b0aa27a7ae6bd632dfeec7`
- Repository: `alexeirojas87/cerberus`
- Verdict: **PASS — G0 CLOSED**
- Owner sign-off: **APPROVED 2026-08-26** in the Review 9 implementation thread

## Acceptance criteria

| Criterion | Command | Output | Result |
|---|---|---|---|
| Local workflows inert | Ruby YAML exact assertion over release + notify-tap | `LOCAL_CONTAINMENT=PASS` | PASS |
| Remote release disabled | GitHub Actions workflows API | `release ... disabled_manually` | PASS |
| Remote tap notifier disabled | GitHub Actions workflows API | `notify-tap ... disabled_manually` | PASS |
| Existing releases preserved | GitHub Releases API | v0.1.2/v0.1.1/v0.1.0-ci/v0.1.0 present with 5/5/5/2 assets | PASS |
| F1–F9 invalidated | Exact phase-row assertion | `INDEX_INVALIDATION=PASS phases=1,2,3,4,5,6,7,8,9` | PASS |
| Patch hygiene | `rtk git diff --check` | no output | PASS |

## Exact workflow read-back

```text
340188822  CI          .github/workflows/ci.yml          active
340355133  notify-tap  .github/workflows/notify-tap.yml  disabled_manually
340188823  release     .github/workflows/release.yml     disabled_manually
```

The two remote disable operations are reversible. They must remain disabled
until the inert workflow files are merged into protected `main`; F8 may
re-enable their replacements only after its own PASS and owner sign-off.

## Existing release read-back

```text
375104963  v0.1.2             draft=false prerelease=false assets=5 updated=2026-08-23T03:30:15Z
375100198  v0.1.1             draft=false prerelease=false assets=5 updated=2026-08-23T03:01:54Z
375098412  v0.1.0-ci.161387a  draft=false prerelease=true  assets=5 updated=2026-08-23T02:51:23Z
375013370  v0.1.0             draft=false prerelease=false assets=2 updated=2026-08-22T19:02:07Z
```

No release, tag or asset was deleted or modified by G0.

## Artifact hashes

```text
b4792e64b104365ef374c7021d53874640beaf79c6bf6c9ef3d53a5e61883c76  .github/workflows/release.yml
e4da1875850197329b0f211ba9b69367ca88e1c8a1017cd4e7bb97d2e8887705  .github/workflows/notify-tap.yml
ca3d0ba682b0a3b9c540fc20afd68a1be1208b4bb6aee1c453b2e5e10b1a7e87  evidence/gauntlet/index.md
4b91e5c77823564c3ffae3adbe5114f2e3c2cd78fca87460b5b88272086bc40b  evidence/review9/g0-containment.md
ae900a65c1677301200858bb674f8b195d6220bc99144e25c7444885a519c59f  evidence/review9/g0-independent-review-attempt2.md
```

## Gate

Builder Attempt 1 failed independent review because `workflow_dispatch`
allowed historical-ref selection. Attempt 2 removed all events from both
distribution workflows, and the fresh reviewer plus integrator reproduced the
remote disablement. The owner approved the G0 gate on 2026-08-26; F1 is open.
