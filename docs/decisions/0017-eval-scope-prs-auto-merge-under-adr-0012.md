# 0017. Eval-scope PRs in skills-evals auto-merge under ADR 0012

- **Status:** Accepted
- **Date:** 2026-11-03
- **Deciders:** Adam Daniel (2026-11-03 13:18 UTC, make the call on which
  fixtures are worth evaluating autonomous and frequent; 14:02 UTC card
  "Yes, auto-merge them")
- **Amends:** [ADR 0012](0012-eval-loop-prs-auto-merge-as-a-declared-exception.md)

## Context

ADR 0012's skills-evals row allows auto-merge only for paths under
`evals/real-work/<id>/**`. skills-evals now runs an eval scope pass,
`scripts/eval_scope.py` in `.github/workflows/eval-scope.yml`. It runs after
every results ingest, daily, and on dispatch. It pauses a scheduled fixture
that can no longer show a gain: its without arm is at the ceiling, both arms
are at the floor, or the skill had no recorded use. It resumes a paused
fixture when that fixture's content changes or the skill is used again. Each
change edits the fixture schedule, not a fixture, so it falls outside that
row.

## Decision

Add one row to ADR 0012's table:

| Repo | PRs | Paths the PR may touch | Opened by |
|---|---|---|---|
| skills-evals | eval scope changes (pause or resume scheduled fixtures) | `evals/scheduled.yml`, `evals/unscheduled.yml`, `evals/scope-auto.yml` | the roster App, `adam-s-daniel-skills-evals-roster` (App id 5116415, skills-evals only) |

The PR opens ready for review and arms native auto-merge with a merge commit
(`--match-head-commit`). Every condition of ADR 0012 still holds: required
checks (`test`) gate the merge, no bot approves, and only merge commits are
used. The workflow's scope control runs before it mints the App token. It
applies the plan and refuses any change outside the three paths. It also
opens nothing while another `eval-scope/` PR is open.

The pass never removes a skill, a guidance section, or a fixture directory.
Removals stay on their own lane (skills-evals ADR 0014 and its
`retirement_mode`).

## Consequences

- A paused fixture stops costing eval runs with no human step. If a pause is
  wrong, the cost is a fixture that sits unrun until the pass resumes it,
  which happens when the fixture's content changes, or until a person
  reverts the PR. Nothing is lost.
- The roster App's key now opens a third kind of PR. All three are in
  skills-evals, so the App's reach does not grow.

## References

- ADR 0012: [Eval-loop PRs auto-merge as a declared exception](0012-eval-loop-prs-auto-merge-as-a-declared-exception.md)
- skills-evals PR adding the pass: <https://github.com/Adam-S-Daniel/skills-evals/pull/650>
