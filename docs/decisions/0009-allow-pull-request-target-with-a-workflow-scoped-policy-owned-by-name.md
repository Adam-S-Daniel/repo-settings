# 0009. Allow pull_request_target with a workflow-scoped Actions event policy the engine owns by name

- **Status:** Accepted
- **Date:** 2026-10-09
- **Deciders:** Adam Daniel

## Context

On 2026-11-02 GitHub will block `pull_request_target` on public repos that have
no applicable Actions event policy. The warning is already shown on
[a current run](https://github.com/Adam-S-Daniel/adam-agentskills/actions/runs/37841935690/job/113533312463):
"On November 2, 2026, GitHub will restrict pull_request_target on public
repositories by default. To continue allowing the event trigger, configure an
Actions policy."

adam-agentskills' `.github/workflows/plugin-runtime-review.yml` triggers only on
`pull_request_target`, by design (its header explains why that event is the
security property), and publishes `plugin-runtime-approval`, a required check
declared in `fleet.yml`. A blocked event means the check never reports and every
PR there is unmergeable.

A scan on 2026-10-09 parsed every default-branch workflow of every public,
non-fork, non-archived repo of both owners (12 repos with workflows): that
workflow is the only one in the fleet that triggers on `pull_request_target`.

An Actions policy's `allowed_events` is an allowlist. GitHub's docs describe the
policy as controlling which events are permitted, and a blocked run fails with
"Event 'workflow_dispatch' is not allowed to trigger Actions workflows". For the
workflows a policy covers, every unlisted event is blocked, so a repo-wide
policy would have to list every event every workflow uses.

## Decision

Manage repository Actions event policies as a per-repo `actions_policies` list
(`schema.md`). adam-agentskills declares one policy, scoped to
`.github/workflows/plugin-runtime-review.yml`, allowing only
`pull_request_target`.

The engine owns only the policy names a repo declares, matched by name: it POSTs
when absent, PUTs the full body when present, and never edits or deletes
anything else. Removing an entry from `fleet.yml` leaves the live policy; to
retire one, set `enforcement: disabled`, apply, delete it by hand, then drop the
entry.

## Consequences

- A new trigger on `plugin-runtime-review.yml` must be added to the policy's
  `allowed_events`, or its runs are blocked. `fleet.yml` carries a comment
  saying so.
- GitHub does not define what makes a policy "applicable". The claim that a
  workflow-scoped policy lifts the default rests on the
  [GA changelog](https://github.blog/changelog/2026-09-17-workflow-execution-protections-in-github-actions-generally-available/)
  line "Specific workflows can be allow-listed using the new workflow file
  targeting." Verify it after the first apply: (a) `plugin-runtime-approval`
  reports on a real PR head, and (b) the "On November 2, 2026" annotation no
  longer appears on the next `pull_request_target` run.
- Fallback if (b) still shows the warning: widen the scope to `~ALL` with
  `allowed_events` listing every event adam-agentskills' workflows use
  (`pull_request`, `pull_request_target`, `push`, `schedule`,
  `workflow_dispatch`, plus any Dependabot-driven event). That trades the
  warning against the risk of blocking a trigger someone adds later.
- A stray hand-made policy is invisible to the drift report, as stray rulesets
  are: the engine lists them but never compares or writes a policy it does
  not own.
- The new endpoints need the repository Administration: write permission, GET
  included. The fan-out App already holds it, so no App change is needed; a
  credential without it gets a `skipped` record, not drift.
- repo-settings is private without GitHub Pro, so its own drift check is not
  required: the newly declared policy shows as DRIFT on the PR until the
  push-to-main apply converges it.

## Alternatives considered

**`~ALL` scope.** Rejected: the allowlist would block every unlisted event on
every workflow in the repo, so one forgotten `schedule` or `workflow_dispatch`
silently breaks a job. It stays the documented fallback.

**Move the workflow off `pull_request_target`.** Rejected: its header explains
why that event is the security property.

**Set the policy by hand in the UI.** Rejected: undeclared and unaudited, the
same reasoning as ADR 0001's ban on hand-granted bypass.

**Engine owns and deletes every repo policy.** Rejected, consistent with
"never touches rulesets it does not own": a policy someone added for a reason
would vanish on the next apply.

**Support `restrict_actions_actors` and org or enterprise levels now.**
Rejected: no current need. `generate` skips a policy in those shapes rather than
misstate it.

## References

- [Warning on a current adam-agentskills run](https://github.com/Adam-S-Daniel/adam-agentskills/actions/runs/37841935690/job/113533312463)
- [GitHub changelog: workflow execution protections GA (2026-09-17)](https://github.blog/changelog/2026-09-17-workflow-execution-protections-in-github-actions-generally-available/)
- [Securely using pull_request_target](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target)
- [REST: Actions policies](https://docs.github.com/en/rest/actions/policies)
- [Permissions required for GitHub Apps: Administration](https://docs.github.com/en/rest/authentication/permissions-required-for-github-apps#repository-permissions-for-administration)
- ADR 0001: [Route bot writes to results branches; declare rare ruleset bypasses in fleet.yml](0001-bot-writes-results-branch-or-declared-bypass.md)
- [`repo-settings/schema.md`](../../repo-settings/schema.md), `actions_policies:`
