# 0007. Name persistent branches `persistent/<purpose>` and protect them from deletion with a ruleset

- **Status:** Accepted
- **Date:** 2026-10-02
- **Deciders:** Adam Daniel

## Context

Some branches are meant to outlive any PR: ADR 0001's results branches
(skills-evals' `eval-results`) and now the changelog routine's accumulation
branch (ADR 0006). Nothing in their names tells a human, or an agent cleaning
up stale branches, to leave them alone. Separately, `delete_branch_on_merge:
true` (fleet default) deletes a head branch the moment its PR merges.

## Decision

1. A branch meant to persist across PRs is named `persistent/<purpose>`, with a
   lowercase kebab-case purpose. Feature, fix and PR-proposal branches never
   use the prefix.
2. Every repo that has one declares, in `fleet.yml` under its `overrides:`, an
   `extra_rulesets` entry named `persistent branches` with
   `target_branches: ["persistent/**"]`, `rules: [deletion]` and no bypass
   actors. Only deletion is blocked, so bots and humans still push (ADR 0001's
   "unprotected results branch" stays unprotected for writes), and GitHub's
   delete-on-merge silently skips the branch.
3. Deleting one deliberately means removing the entry and the live ruleset by
   hand (per `schema.md`, removing an entry does not delete the live ruleset).
   The friction is the point.
4. Agents never delete a `persistent/` branch, and stale-branch cleanups skip
   the prefix.

`roster/proposal` in skills-evals is a proposal branch with its own ruleset
(ADR 0004) and is out of scope.

## Consequences

- A persistent branch survives its PR's merge, so a writer must handle "branch
  is an ancestor of `main`" by fast-forwarding, never force-pushing.
- Renaming an existing persistent branch (for example `eval-results`) means
  updating every consumer (workflows, badge URLs) in the same change.
- `extra_rulesets` is per-repo only (`schema.md`), so the entry is repeated in
  each repo that has such a branch.
- Private repos without Pro skip rulesets as usual; there the prefix is the
  only guard.

## Alternatives considered

**Name-only convention, no enforcement.** Rejected as the weaker guard.

**A `defaults:`-level ruleset.** Not supported for `extra_rulesets`; `schema.md`
explains why (list values are replaced, not merged).

**`keep/` or `long-lived/` prefixes.** `persistent/` is the plainest statement
of intent.

## References

- ADR 0001: [Route bot writes to results branches; declare rare ruleset bypasses in fleet.yml](0001-bot-writes-results-branch-or-declared-bypass.md)
- ADR 0004: [Confine skills-evals' roster/proposal branch to the roster App with an extra ruleset](0004-confine-roster-proposal-branch-to-the-roster-app.md)
- ADR 0006: [Accumulate the changelog routine's work on a persistent branch; the owner merges](0006-changelog-routine-accumulates-on-a-persistent-branch-owner-merges.md)
