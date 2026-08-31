# Review 9 G0 containment — builder reproduction record (Attempt 2)

- **Date:** 2026-08-26 (America/New_York)
- **Base checkout:** `fccd9e4823e17f3598b0aa27a7ae6bd632dfeec7`
- **Scope:** containment only; no F1 remediation was opened
- **Attempt 1 review:** **FAIL** — a manual dispatch could select a historical
  ref whose copy of the workflow still contained publishing jobs
- **Builder status:** Attempt 2 local containment checks completed successfully
- **Independent review:** **PENDING** — this record is not an independent verdict or phase sign-off

## Attempt 2 containment

1. `.github/workflows/release.yml` and `.github/workflows/notify-tap.yml` both
   declare an empty event list (`"on": []`). They expose no event or reusable-
   workflow entry point and cannot be dispatched against current or historical
   refs through these workflow definitions.
2. Both files grant repository contents read permission only. They contain no
   checkout, version bump, push, artifact build/upload, credential use, release
   publication, or tap repository dispatch.
3. Each structural job is additionally unreachable (`if: ${{ false }}`) and
   contains only `exit 1`; neither can mutate release state even if evaluated.
4. Existing releases are untouched. F8 must replace the inert workflows only
   after an independently reviewed PASS Evidence Pack and owner sign-off.
5. `evidence/gauntlet/index.md` retains all historical transcripts but marks
   every prior F1–F9 PASS/closure status as `SUPERSEDED / INVALIDATED BY REVIEW
   9` for current release and GA decisions.

## Builder reproduction transcript

All commands were run in the isolated worktree
`/tmp/cerberus-g0-builder-fccd9e4`.

### Exact base and initial isolation

```text
$ rtk git rev-parse HEAD
fccd9e4823e17f3598b0aa27a7ae6bd632dfeec7

$ rtk git status --short
<no output before the G0 edits>
```

### Both workflows parse and are semantically inert

```text
$ rtk proxy ruby -e 'require "yaml"; expected={"release.yml"=>"review9_release_freeze","notify-tap.yml"=>"review9_tap_freeze"}; expected.each{|file,job| d=YAML.safe_load(File.read(".github/workflows/#{file}")); abort "#{file}: triggers" unless d["on"]==[]; abort "#{file}: permissions" unless d["permissions"]=={"contents"=>"read"}; abort "#{file}: jobs" unless d["jobs"].keys==[job]; j=d.dig("jobs",job); abort "#{file}: reachable" unless j["if"]=="${{ false }}"; abort "#{file}: guard" unless j.dig("steps",0,"run")&.strip=="exit 1"}; puts "workflow_semantics=PASS files=2 triggers=none jobs=unreachable permissions=contents:read guards=exit-1"'
workflow_semantics=PASS files=2 triggers=none jobs=unreachable permissions=contents:read guards=exit-1
```

### No event entry point or publishing primitive remains

```text
$ rtk grep -n "workflow_dispatch|workflow_call|push:|pull_request:|schedule:|release:|tags:|contents: write|git push|gh release|gh api|upload-artifact|GITHUB_TOKEN|secrets\." .github/workflows/release.yml .github/workflows/notify-tap.yml
0 matches for 'workflow_dispatch|workflow_call|push:|pull_request:|schedule:|release:|tags:|contents: write|git push|gh release|gh api|upload-artifact|GITHUB_TOKEN|secrets\.'
```

```text
$ rtk grep -n '"on": \[\]|contents: read|if:.*false|exit 1' .github/workflows/release.yml .github/workflows/notify-tap.yml
8 matches in 2 files:

.github/workflows/notify-tap.yml:7:"on": []
.github/workflows/notify-tap.yml:10:contents: read
.github/workflows/notify-tap.yml:15:if: ${{ false }}
.github/workflows/notify-tap.yml:21:exit 1
.github/workflows/release.yml:14:"on": []
.github/workflows/release.yml:17:contents: read
.github/workflows/release.yml:22:if: ${{ false }}
.github/workflows/release.yml:28:exit 1
```

### Every F1–F9 gate is visibly invalidated

```text
$ rtk grep -n "SUPERSEDED / INVALIDATED BY REVIEW 9|CURRENT RELEASE GATE: FAIL" evidence/gauntlet/index.md
13 matches in 1 files: one current FAIL marker, one row each for F1–F9, and
three invalidated historical aggregate headings/statuses.
```

### Diff and changed-file hygiene

```text
$ rtk git diff --check
<no output>

$ rtk proxy ruby -e 'files=[".github/workflows/release.yml",".github/workflows/notify-tap.yml","evidence/gauntlet/index.md","evidence/review9/g0-containment.md"]; bad=[]; files.each{|f| File.readlines(f,chomp:true).each_with_index{|line,i| bad << "#{f}:#{i+1}" if line.match?(/[ \t]+$/)}}; abort "trailing whitespace: #{bad.join(",")}" unless bad.empty?; puts "changed_files_whitespace=PASS files=#{files.length}"'
changed_files_whitespace=PASS files=4
```

`actionlint` was not installed in the builder environment
(`actionlint=UNAVAILABLE`). The Ruby YAML and exact semantic assertions above
are the local fallback; the independent reviewer or CI should additionally run
`actionlint` before accepting G0.

## Remote containment required until merge

These file changes cannot neutralize the workflows already present on the
remote default branch before they are merged. A repository administrator must
disable both remote workflows through the GitHub Actions API/UI and keep them
disabled until the inert replacements are merged into the protected default
branch. This is an operational gate, not something this builder can validate
solely from a local worktree.

The coordinator reports that remote workflow id `340188823` (`release`) has
been disabled. This builder did not execute or independently read back that
state, so it remains pending reviewer evidence. Remote `notify-tap` disablement
is also pending at the time of this Attempt 2 record.

Suggested administrator command, after resolving the repository explicitly:

```text
rtk gh api --method PUT repos/OWNER/REPO/actions/workflows/WORKFLOW_ID/disable
```

The independent reviewer must capture the repository identity, command output,
and read-backs showing both workflow states are `disabled_manually`. Until that
remote evidence exists, G0 containment is incomplete and Review 9 remains FAIL.

## Remaining gate

An independent reviewer must reproduce the checks, inspect the diff, verify the
remote disablement, and issue the G0 verdict. No claim in this builder record
reopens F1 or closes any phase.
