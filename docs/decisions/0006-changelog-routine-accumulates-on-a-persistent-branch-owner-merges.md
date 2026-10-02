# 0006. Accumulate the changelog routine's work on a persistent branch; the owner merges

- **Status:** Accepted
- **Date:** 2026-10-02
- **Deciders:** Adam Daniel (decided 2026-10-02)

## Context

ADR 0005 let the daily "agent changelog watcher" Routine in `_agent-guidance`
merge its own PR once a mechanical gate
(`scripts/routine-merge-gate.js` in `_agent-guidance`) passed. On 2026-10-01
and 2026-10-02 the gate passed, but the claude.ai session's permission
classifier denied the merge call (`PUT /repos/.../pulls/<n>/merge`). The PR
stayed open, the owner got an "awaiting your merge" push every day, even on
runs that filed no issues, and merged
[`_agent-guidance` PR 222](https://github.com/Adam-S-Daniel/_agent-guidance/pull/222)
by hand.

The classifier is outside this repo's control, so the self-merge path cannot be
relied on, and a daily PR whose only content is bookkeeping is noise whether
the routine or the owner merges it.

## Decision

Every run pushes to one dedicated branch, `persistent/vendor-changelog`, in
`_agent-guidance`. A PR to `main` opens only on a substantive change: a
changelog issue filed in a fleet repo, a discrepancy entry added, changed or
closed, or instruction-shaped text declined. Quiet runs push and stay silent.
The run never merges; the owner does. The gate stays as a pre-review check, and
its result goes in the PR body. Notifications fire only when there is something
to act on, plus a weekly reminder while a PR is open. The Routine's own
platform push setting was turned off on 2026-10-02.

The spec lives in
[`docs/reference/agent-changelog-routine.md`](https://github.com/Adam-S-Daniel/_agent-guidance/blob/main/docs/reference/agent-changelog-routine.md)
and was changed by
[`_agent-guidance` PR 224](https://github.com/Adam-S-Daniel/_agent-guidance/pull/224).
This supersedes ADR 0005.

## Consequences

- No daily no-op PR and no daily "awaiting your merge" push.
- Unmerged changelog bookkeeping lives on the branch; consumers of `main` see
  it only after a merge.
- The Declined-heading and path-allowlist concerns from ADR 0005 are now
  reviewed by a human before anything reaches `main`, so the unattended-merge
  residual risk goes away.
- The branch outlives its PRs, so its name and protection follow ADR 0007.

## Alternatives considered

**Keep self-merge and add a permission allow rule for the merge call.**
Rejected: the classifier is outside this repo's control, and widening an
unattended agent's merge path is what ADR 0005's gate tried to contain.

**Keep a PR per run but notify less.** Rejected: it still leaves the owner
merging no-op PRs.

## References

- ADR 0005: [Let the vendor changelog routine merge its own PR through a mechanical gate](0005-changelog-routine-merges-its-own-pr-through-a-gate.md)
- ADR 0007: [Name persistent branches `persistent/<purpose>`](0007-persistent-branches-use-the-persistent-prefix-and-a-deletion-ruleset.md)
- Routine spec: <https://github.com/Adam-S-Daniel/_agent-guidance/blob/main/docs/reference/agent-changelog-routine.md>
- Spec change: <https://github.com/Adam-S-Daniel/_agent-guidance/pull/224>
- Hand-merged PR after the denied merge: <https://github.com/Adam-S-Daniel/_agent-guidance/pull/222>
