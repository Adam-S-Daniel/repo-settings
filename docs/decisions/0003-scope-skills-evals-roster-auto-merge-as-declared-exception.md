# 0003. Scope skills-evals' roster auto-merge as a declared exception to ADR 0001

- **Status:** Accepted
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
