# 0013. Lesson-check PRs in _agent-guidance auto-merge under ADR 0012

- **Status:** Accepted
- **Date:** 2026-10-26
- **Deciders:** Adam Daniel (2026-10-26 14:00 UTC, build the closed
  self-improvement loop with no human in it; 14:14 UTC card "Yes to both",
  accepted loop changes auto-merge once every required check passes; 14:21 UTC,
  git hooks are the first choice for any lesson, ahead of a skill or guidance
  text)
- **Amends:** [ADR 0012](0012-eval-loop-prs-auto-merge-as-a-declared-exception.md)

## Context

ADR 0012 lets eval-loop PRs in three repos auto-merge, each limited to an exact
path allowlist, and says a path outside its table needs a new ADR. This is that
ADR.

Adam's 14:21 UTC rule makes a check in the fleet's commit-time runner,
`.githooks/agent-checks` (_agent-guidance ADR 0021), the first home for a
lesson an agent learns. The fleet worker routine in _agent-guidance now has a
lesson-check pass
([_agent-guidance ADR 0027](https://github.com/Adam-S-Daniel/_agent-guidance/blob/main/docs/decisions/0027-lessons-become-agent-checks-through-the-fleet-worker.md)):
it drafts the check, proves its test cases fail before the change and pass
after, and runs it against every fleet repo's default branch. A PR follows
only when that scan finds zero new refusals.

## Decision

Add one row to ADR 0012's table:

| Repo | PRs | Paths the PR may touch | Opened by |
|---|---|---|---|
| _agent-guidance | lesson checks for the agent-checks runner | `templates/agent-checks/agent-checks`, `.githooks/agent-checks` (byte-identical to the template), `test/fixtures/agent-checks-cases.jsonl`, `docs/agent-checks-lessons.md` | the fleet worker routine's cloud session (ADR 0025 there) |

The PR opens ready for review and arms native auto-merge with a merge commit.
Every condition of ADR 0012 still holds: required checks gate the merge, no
bot approves, merge commits only. The scope control is the routine's `scope`
step (`scripts/agent_check_lane.py scope`), which refuses any other path, a
deletion, a rename, or runner copies that differ, before auto-merge is armed.

The guard, `.claude/hooks/agent-checks-guard.sh` and its template, and
`scripts/sync.sh` stay outside the allowlist. They change what Claude Code
runs or what the sync writes, so they wait for the owner.

## Consequences

- A merged check reaches every fleet repo on the next sync. A check that
  refuses good work blocks commits fleet-wide, which is why the zero-refusal
  scan on every default branch is a precondition for the PR, not a review
  item.
- Unlike ADR 0012's rows, the opener is not a narrow GitHub App: the fleet
  worker runs as the owner's account through the session's GitHub connector.
  The path allowlist in the routine is the only scope control, as ADR 0012
  already accepts for its gates. Moving this to a dedicated App is the
  stronger form and needs no new ADR.
- `_agent-guidance`'s required context is `test`, which runs the runner's case
  table and the lane's own tests.

## References

- ADR 0012: [Eval-loop PRs auto-merge as a declared exception](0012-eval-loop-prs-auto-merge-as-a-declared-exception.md)
- _agent-guidance ADR 0021: <https://github.com/Adam-S-Daniel/_agent-guidance/blob/main/docs/decisions/0021-the-sync-delivers-agent-checks-to-every-fleet-repo.md>
- _agent-guidance ADR 0025 (the fleet worker): <https://github.com/Adam-S-Daniel/_agent-guidance/blob/main/docs/decisions/0025-a-cloud-fleet-worker-merges-narrow-instruction-fixes.md>
