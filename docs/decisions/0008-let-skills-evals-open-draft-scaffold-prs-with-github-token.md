# 0008. Let skills-evals' scaffold gate open draft PRs with GITHUB_TOKEN

- **Status:** Accepted
- **Date:** 2026-10-06
- **Deciders:** Adam Daniel (chose "Yes, via repo-settings (Recommended)", 2026-10-06)

## Context

skills-evals' scaffold gate (fixtures PR 5, branch `feat/real-work-scaffolder`,
not yet on the remote when this was written, so no link) opens a draft PR for
each real-work fixture it scaffolds. It opens them with the workflow
`GITHUB_TOKEN`, which GitHub allows only while the repo setting "Allow GitHub
Actions to create and approve pull requests"
(`actions.can_approve_pull_request_reviews`) is on. ADR 0003's amendment
(2026-09-29) had put that setting back to `false` fleet-wide after the roster
PR moved to a dedicated App, and `tests/test_repo_settings.py` pinned the
allowlist at empty, so the next apply would turn it off again.

The same switch also lets `GITHUB_TOKEN` submit approving reviews. Read live on
2026-10-06 (GET only), skills-evals' `default branch protection` ruleset
(18877855) requires 0 approving reviews, no code-owner review, no extra
approval for unattributed changes, merge commits only, and the `test` status
check. Its bypass actors are the Admin role and the agents-md-sync App
(4268639); `github-actions` is not one.

## Decision

Declare, as a skills-evals override in `repo-settings/fleet.yml`,
`actions.can_approve_pull_request_reviews: true` (leaving
`default_workflow_permissions: read`) and a label `eval-scaffold` (color
`C5DEF5`, description "Draft real-work fixture opened by the scaffold gate").
Every other managed repo keeps the fleet default `false` and no labels. The
engine gains a per-repo `labels:` block (by name, never deleting) to declare the
label.

## Consequences

- **A workflow-approved self-merge is not newly possible.** With
  `required_approving_review_count: 0` an approval satisfies nothing the ruleset
  asks for, so the setting adds no merge power. What still gates a merge: a PR
  is required (no bypass for `github-actions`), a draft PR cannot merge, and the
  required `test` check must pass; a PR opened by `GITHUB_TOKEN` gets no passing
  `test` on its own (ADR 0003, amendment: its `pull_request` run was held and a
  dispatched run did not satisfy the check).
- **The guard is the count, and it is now tested.**
  `WorkflowPermissionsFleetConfigTests` fails if a repo with the setting on
  requires approving reviews or approval for unattributed changes. Raising
  either on skills-evals means revisiting this ADR first, because a workflow
  could then approve its own PR.
- A second repo wanting the setting is still a policy change: the test
  allowlist names skills-evals only.
- Writing a label needs Issues (or Pull requests) write on the credential. The
  fan-out App is documented as Administration + Actions + Metadata, so the label
  create may come back as an `error` record on the first apply until the App
  grant is verified or widened, or the apply is run once from ambient `gh auth`.
  The Actions setting itself is already written by the existing engine path.
- The PR check's drift report shows both settings as drift until the push-to-main
  apply converges them.

## Alternatives considered

**Leave the setting off and create the label by hand.** Rejected: the next apply
would reset the setting and break the scaffold gate, and a hand-made label is
undeclared state the audit never sees.

**A dedicated GitHub App for the scaffold gate (the ADR 0003 amendment path).**
Not chosen: the gate opens drafts only and never merges, so an App's key and
install are more standing capability than the job needs.

## References

- ADR 0001: [Route bot writes to results branches; declare rare ruleset bypasses in fleet.yml](0001-bot-writes-results-branch-or-declared-bypass.md)
- ADR 0003: [Scope skills-evals' roster auto-merge as a declared exception to ADR 0001](0003-scope-skills-evals-roster-auto-merge-as-declared-exception.md)
- Issue: [Adam-S-Daniel/repo-settings#51](https://github.com/Adam-S-Daniel/repo-settings/issues/51) (the workflow-permissions engine support)
- Schema: [`repo-settings/schema.md`](../../repo-settings/schema.md) (`labels:`, workflow permissions)
