# 0003. Scope skills-evals' roster auto-merge as a declared exception to ADR 0001

- **Status:** Superseded in part (2026-09-29): the GITHUB_TOKEN path was replaced by a dedicated GitHub App; see Amendment
- **Date:** 2026-09-28
- **Deciders:** Adam Daniel (path chosen 2026-09-28)

## Context

ADR 0001 says PR + auto-merge is not a sanctioned bot-write path in this
fleet. Its reasons were generated data (badges, run summaries) that belongs on
a results branch, required contexts left unreported by data-only commits, and
auto-merge chains that fired early or deadlocked on an approval rule.

skills-evals' weekly Real eval run produces a roster proposal: a change to
files that live on `main` and that later runs read from there. That output is
not generated data, so a results branch does not fit it. The two remaining
paths were:

- a bypass-actor GitHub App that pushes the roster straight to `main`; or
- the run opens a PR with `GITHUB_TOKEN`, dispatches `ci.yml` so the required
  `test` check reports on the PR head (events made by `GITHUB_TOKEN` do not
  start `pull_request` workflows), and enables auto-merge.

The second path needs "Allow GitHub Actions to create and approve pull
requests" (`can_approve_pull_request_reviews`) on the repo. Adam turned it on
by hand on 2026-09-28. Until issue #51 the engine did not read or write that
setting, so it was neither declared nor audited.

## Decision

skills-evals' roster PR is the one declared exception to ADR 0001's "PR +
auto-merge is not a sanctioned bot-write path". It is recorded in
`repo-settings/fleet.yml` as a skills-evals override of
`actions.can_approve_pull_request_reviews: true`. Every other managed repo
keeps the fleet default `false`. The rest of ADR 0001 stands: generated data
still goes to a results branch, and a bot that must push to a default branch
still gets a declared bypass actor.

The exception holds only while all of these hold on skills-evals:

- the ruleset still requires the `test` check, so the PR merges only after
  CI concludes green on its head;
- merge commits only, so the roster commit keeps its parents;
- the roster change is a PR a human can read, revert, or close before it
  merges.

## Consequences

- No new identity can push to `main`: there is no bypass actor and no
  standing hole in the ruleset. The bot's change goes through the same
  ruleset as a human's.
- The setting also lets `GITHUB_TOKEN` submit approving reviews. With
  `required_approving_review_count: 0` on skills-evals that grants nothing
  new today. **If that count is ever raised above 0, a workflow could approve
  its own PR and satisfy the rule.** Revisit this setting in the same change
  that raises the count.
- A second repo wanting the same path is a policy change, not a config tweak:
  `tests/test_repo_settings.py`'s `WorkflowPermissionsFleetConfigTests` fails
  until its allowlist names the repo, and this ADR (or a successor) should say
  why.
- ADR 0001's scars still apply here. A required check that a path filter or a
  cancelled run leaves unreported blocks the roster PR. skills-evals has to
  keep `test` always-run and free of a `concurrency` group that can cancel it.

## Alternatives considered

**Bypass-actor App pushing to `main`.** The path ADR 0001 sanctions. Rejected
for this bot: it needs a new App, a private key to guard, and a standing
ruleset bypass for one weekly write, and the roster change would land without
passing `test` first.

**Leave the setting undeclared.** Rejected: the next `apply` would either
ignore it forever or, once the engine learned the field, reset it to the
fleet default and break the roster run.

## References

- Issue: [Adam-S-Daniel/repo-settings#51](https://github.com/Adam-S-Daniel/repo-settings/issues/51)
- ADR 0001: [Route bot writes to results branches; declare rare ruleset bypasses in fleet.yml](0001-bot-writes-results-branch-or-declared-bypass.md)
- Schema: [`repo-settings/schema.md`](../../repo-settings/schema.md) (`actions.can_approve_pull_request_reviews`)

## Amendment (2026-09-29)

The `GITHUB_TOKEN` path above did not work in practice. A PR opened by
`github-actions[bot]` had its `pull_request` CI run held `action_required`, and
a dispatched `ci.yml` run did not satisfy the required `test` check
([run 36509251840](https://github.com/Adam-S-Daniel/skills-evals/actions/runs/36509251840),
PR [#214](https://github.com/Adam-S-Daniel/skills-evals/pull/214)).

skills-evals [PR #216](https://github.com/Adam-S-Daniel/skills-evals/pull/216)
(merged) moved the roster PR to a dedicated GitHub App,
`adam-s-daniel-skills-evals-roster` (App id 5116415): installed on skills-evals
only, Contents R/W and Pull requests R/W, and not a ruleset bypass actor. It
opens, reopens and arms auto-merge on the roster PR. Proven live 2026-09-29:
[run 36516990079](https://github.com/Adam-S-Daniel/skills-evals/actions/runs/36516990079)
had the App close, reopen and arm #214, `test` ran without approval, and #214
auto-merged at 03:36:23Z as merge commit 7548298 by
`app/adam-s-daniel-skills-evals-roster`.

What changes:

- The exception to ADR 0001's "PR + auto-merge is not a sanctioned bot-write
  path" still stands for the roster PR; its identity is now the App, not
  `GITHUB_TOKEN`.
- `actions.can_approve_pull_request_reviews` returns to the fleet default
  `false` for every managed repo. `GITHUB_TOKEN` no longer creates or approves
  PRs there, and leaving it `true` would keep the risk named in Consequences
  (a workflow approving its own PR if required approvals ever rise above 0).
  The test allowlist in `WorkflowPermissionsFleetConfigTests` is now empty.
- The App is not a bypass actor, so the ruleset (required `test`, merge commits
  only) still gates the merge.

Existing Apps were rejected: agents-md-sync is an always-bypass actor
fleet-wide; the repo-settings App administers all repos; the CMS automation
App's key would reach the CMS site repos.
