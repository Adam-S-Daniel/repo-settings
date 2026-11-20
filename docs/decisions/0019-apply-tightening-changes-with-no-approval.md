# 0019. Apply changes that cannot reduce protection with no approval; review the rest

- **Status:** Accepted
- **Date:** 2026-11-17
- **Deciders:** Adam Daniel (2026-11-17: asked that deployment reviews which
  could reasonably be automatic be made automatic)

## Context

Every apply waited for the owner's approval in the `fleet-apply` environment
([#90](https://github.com/Adam-S-Daniel/repo-settings/issues/90),
[#13](https://github.com/Adam-S-Daniel/repo-settings/issues/13)). Issue
[#116](https://github.com/Adam-S-Daniel/repo-settings/issues/116) already
stopped asking when the plan found nothing. What was left still asked for
every plan that changed anything.

From the first gated run to 2026-11-17, 16 runs entered `fleet-apply` and the
owner decided 12 of them (11 approved, 1 rejected). Every plan that can still
be read only added protection or was neutral: SHA pinning on, stricter fork-PR
approval, Dependabot alerts, secret scanning and CodeQL on, rulesets created,
a required check added, a label's color or description. The run waiting on
2026-11-17
([44204576489](https://github.com/Adam-S-Daniel/repo-settings/actions/runs/44204576489))
asked for approval to add one required check to one ruleset. Median wait for
an approval was 84 minutes, during which a merged tightening was not in
force.

An approval asked for on every plan is not read as closely as one asked for
rarely. cms-platform reached the same conclusion for its own settings and
narrowed its gate to writes that could weaken a repo
(`scripts/repo-settings-write-risk.js` there); nothing has asked for review
there since 2026-10-05.

## Decision

Split the apply by what a write can do, not by who merged the change.

- **The engine classifies every planned write** (`write_risk` in
  `scripts/repo_settings.py`). A write is `safe` only when the engine can
  show it cannot leave a repo with fewer constraints than it has now.
  Everything else is `gated`. It is an allowlist: a writer, rule type,
  parameter or value it does not name is gated, including one GitHub adds
  later.
- **`apply --refuse-weakening` makes only the safe writes** and reports the
  rest as left for review (exit 3 when any were left). The check runs at the
  write, so the workflow's routing cannot cause an unreviewed weakening
  write; a wrong `if:` can only cause a red job or an extra approval.
- **A new job, `apply-auto`, runs it with no reviewer**, in a new
  environment, `fleet-apply-auto`, that only `main` may deploy to. It
  re-plans under the admin token, because the plan job's read-only token
  cannot see bypass actors, Actions policies or merge flags.
- **The reviewed `repo-settings` job runs only when `apply-auto` left
  something**, or did not answer `false` for every owner. It applies
  everything, as before.
- **Neither job applies from a commit `main` has moved past.** An apply
  makes the fleet match the commit it runs from, and an approval can arrive
  hours after the run started. Without this, approving an older run would
  put its config over what a newer commit's `apply-auto` had already
  tightened, and the plan the owner approved would not show the removal.
  Each job's first step compares its commit with `main` and refuses when
  `main` has since changed a file an apply reads (the workflow's own push
  path filter). The newer commit started its own run; that is the one to
  approve.

What is safe, in short. The code and `tests/test_write_risk.py` are the full
list.

| Surface | Safe | Gated |
|---|---|---|
| Rulesets | A new ruleset. Added rules and required checks, removed bypass actors, enforcement to `active`, stricter pull-request parameters, fewer merge methods | A removed rule or check, an added bypass actor or a changed bypass mode, any change to which refs are covered, a live setting the write would switch off, a check pinned to an app, any field or parameter the engine does not know |
| Actions | SHA pinning on, stricter fork-PR approval, read-only workflow token, workflows may not approve pull requests | The reverse of each; every Actions event policy write |
| Security | Alerts, security updates, secret scanning and push protection on; the larger CodeQL suite where default setup is already on; CodeQL default setup on | Anything turned off; the smaller suite |
| Repo | A merge method off, delete branch on merge on, auto-merge on or off, the merge commit text | A merge method on, delete branch on merge off |
| Labels | Create, set color and description, or fix the name's case | A label read without its name |

On a repo being set up, the Gated column does not apply to settings that
come from `defaults:` alone (see the 2026-11-20 amendment below).

A writer that sends a whole group in one call (merge methods, workflow
permissions, secret scanning, CodeQL) is safe only when every key it sends is
either the stricter value or was read as already set.

**Amended 2026-11-20 (owner's rules).** The owner approved a reviewed apply
that only turned on CodeQL default setup and auto-merge for a newly onboarded
repo (run 44744406728) and set the rule: a run needs no approval when its
changes set a repo up to fleet standards, or when none of them loosens a rule,
adds a rule that loosens a restriction, enables a feature that decreases
security, or disables a security feature. So:

- **Judged on that test alone**, four writes that used to wait are safe:
  CodeQL default setup on (it enables a security feature), auto-merge on (it
  merges only what every rule and required check already allow), the merge
  commit's default text, and a case-only label rename (neither is a rule or a
  security feature). Everything that loosens still waits, and so does any
  write the classifier cannot read.
- **Setting a repo up to the fleet standard.** When the plan creates the
  repo's managed ruleset from scratch (the repo is being onboarded), a write
  that would otherwise wait is safe if its setting comes from `defaults:`
  alone, with no repo override touching it (`fleet_standard` and
  `classify_records`). The ruleset itself is already safe as a new ruleset.
  Repo overrides, extra rulesets and Actions policies never qualify.
- **Why only while setting up.** Any agent can merge a `fleet.yml` change, so
  the apply gate is the one place a person sees a loosening. If "matches the
  defaults" were enough on every repo, a loosening edit to `defaults:` would
  reach the whole fleet unreviewed. Limited to set-up, it reaches only repos
  that have nothing to protect yet.
- **Cost.** A repo that runs CodeQL from its own workflow reads as "not
  configured", and GitHub stops accepting that workflow's results once
  default setup is on. Check for one before declaring such a repo.

The ruleset comparison reads the live ruleset as GitHub returned it, not the
engine's normalized view. A ruleset write replaces the whole body, so a live
setting the engine does not manage (the up-to-date-branch policy, code owner
review) would be switched off by a write made for another reason. That was
true before this change and nothing reported it; such a write is now gated
and the reason names the setting.

## Consequences

- A merged change that only tightens is in force minutes after the merge,
  with no approval. The owner is asked only when a write could weaken a repo
  or the engine cannot tell.
- **The admin key now also sits in an environment with no reviewer.** Before,
  no run could use the key without the owner's approval. Now a workflow on
  `main` can. What stands between a change on `main` and an unreviewed admin
  write is the classifier and the workflow file, so a pull request that
  changes `write_risk`, `cmd_apply`, or `repo-settings.yml` widens authority
  and is the owner's to merge (_agent-guidance ADR 0041). cms-platform
  accepted the same trade for its own settings.
- **Nothing changes until the owner sets the environment up**: create
  `fleet-apply-auto` with no reviewer, restrict it to the branch `main`, and
  add `REPO_SETTINGS_APP_PRIVATE_KEY` to it. Until then `apply-auto` applies
  nothing and asks for the review, as before. Removing the secret turns the
  unreviewed apply off again. The job refuses, red, if the key is there but
  the environment is not main-only.
- A plan with safe and gated writes is applied in two parts: the safe ones
  at once, the gated ones after approval. The job summary of `apply-auto`
  lists both, with the reason each gated write waits.
- A failed write in `apply-auto` turns the run red and does not by itself
  ask for review, since approving would only repeat it. A setting the plan
  could not read does ask for it: the failed read can hide a change that
  would have waited.
- An approval given to a run `main` has moved past fails that run, with a
  message naming the reason, in place of applying it. The owner approves
  the newer run.
- Onboarding a repo still asks once, for CodeQL default setup, when the repo
  does not have it on yet.
- The weekly blind spot from
  [#113](https://github.com/Adam-S-Daniel/repo-settings/pull/113) stays as
  it is: `apply-auto` runs on the same conditions the apply ran on.

## Alternatives considered

- **Refuse the whole plan when any write is gated** (cms-platform's choice).
  Simpler, but one gated write the owner has not approved would hold back
  every tightening behind it.
- **Classify in the plan job and route there.** The read-only token cannot
  see bypass actors, so every change to an existing ruleset would route to
  review. Adding a required check is the most common change.
- **Auto-approve the deployment from a workflow.** It would keep one
  environment, but an approval made by automation is not a review, and it
  would need a credential that can approve deployments.

## How to verify

- `tests/test_write_risk.py`: the directions, and that unknown shapes gate.
  One test reads `apply_record`'s writers from its syntax tree and fails
  when a new writer has not been given a verdict.
- `tests/test_repo_settings_workflow_token.py`: `apply-auto` never runs on
  pull requests, passes `--refuse-weakening` on every apply, uses the key
  only after its setup check, and the reviewed job is asked for unless every
  owner answered `false`. Both jobs refuse a commit `main` has moved past.
  The jobs' scripts run there against fake API responses and the real
  engine.

## References

- cms-platform: `scripts/repo-settings-write-risk.js` and
  `.github/workflows/repo-settings-apply.yml`
- Engine: `write_risk`, `classify_records`, `cmd_apply` in
  [`scripts/repo_settings.py`](../../scripts/repo_settings.py)
- Workflow: [`.github/workflows/repo-settings.yml`](../../.github/workflows/repo-settings.yml)
