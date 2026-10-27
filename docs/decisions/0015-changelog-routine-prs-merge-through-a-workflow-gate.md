# 0015. The changelog routine's PRs merge through a workflow running its gate

- **Status:** Accepted
- **Date:** 2026-10-27
- **Deciders:** Adam Daniel (2026-10-26 14:14 UTC card "Yes to both": accepted
  loop changes merge with no human once every required check passes;
  2026-10-27 01:18 UTC, after merging
  [_agent-guidance#346](https://github.com/Adam-S-Daniel/_agent-guidance/pull/346)
  by hand: "why couldn't that have been automatic?")
- **Supersedes:** the "the owner merges" half of
  [ADR 0006](0006-changelog-routine-accumulates-on-a-persistent-branch-owner-merges.md);
  its persistent branch and PR-only-on-substance rules stand.

## Context

ADR 0006 stopped the vendor changelog routine from merging its own PR
because the claude.ai session's permission classifier denied the merge call.
The routine still runs `scripts/routine-merge-gate.js` in _agent-guidance, a
mechanical check (title, no "Declined" heading, a fixed path allowlist, every
check run on the head green), and writes the result into the PR body. Then
the PR waits for the owner, who merges a PR the gate already passed.

## Decision

A workflow in _agent-guidance, `vendor-changelog-merge.yml`, merges the PR:

- It runs on `workflow_run` when CI or agent-checks completes on
  `persistent/vendor-changelog`, so it is always the default branch's copy of
  the workflow and of the gate. Nothing from the PR branch runs.
- It fetches the PR, its files, the head's check runs and statuses, runs the
  gate, and merges with a merge commit pinned to the gated head
  (`--match-head-commit`) only when the gate exits 0.
- It uses the job's `GITHUB_TOKEN` (contents, pull-requests and actions
  write). No App, no bypass actor, no new secret.
- The routine itself still never merges.

The gate's path allowlist (the changelogs, the discrepancy files, the run log
and the issue map) is the scope control, as ADR 0012 requires of every loop
exception. The routine's own instructions are not on it, so a run can never
merge a change to the text it obeys.

## Consequences

- No more hand merges of gate-passed changelog PRs. A refused gate leaves
  the PR open for the owner, as before.
- A merge made with `GITHUB_TOKEN` fires no `push` workflows. The workflow
  dispatches `vendor-discrepancy-alert.yml` itself when the merged PR touched
  its paths; `sync.yml` filters on files the allowlist cannot touch.
- Like every exception under ADR 0012, it holds only while required checks
  gate the merge and no bot approves.
