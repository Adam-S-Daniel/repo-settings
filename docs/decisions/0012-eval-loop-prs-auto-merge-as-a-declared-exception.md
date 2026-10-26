# 0012. Eval-loop PRs auto-merge as a declared exception

- **Status:** Accepted
- **Date:** 2026-10-26
- **Deciders:** Adam Daniel (decision cards 2026-10-25 23:14 UTC, removal PRs
  auto-merge with no human; 2026-10-26 14:14 UTC, "Yes to both": accepted loop
  changes open ready PRs and auto-merge once every required check passes)

## Context

ADR 0001 says PR + auto-merge is not a sanctioned bot-write path. ADR 0003 made
one exception, skills-evals' weekly roster PR, opened and armed by a dedicated
GitHub App behind the required `test` check (as amended 2026-09-29).

skills-evals now runs a closed improvement loop over skills and fleet guidance
sections. Its gates validate a candidate without running it, then open a pull
request in the repo the candidate changes:

- **skills-evals:** the scaffold gate (`scripts/scaffold_real_work.py gate`)
  opens new real-work fixtures under `evals/real-work/<id>/`, and a later PR
  promotes a draft fixture to ready. Today these open as drafts with
  `GITHUB_TOKEN` (ADR 0008).
- **adam-agentskills:** the improve gate (`scripts/improve_gate.py`) opens one
  SKILL.md edit; the retirement path (`scripts/retire_skill.py`, skills-evals
  ADR 0014) opens a skill removal. The improve gate opens drafts.
- **_agent-guidance:** guidance-section edits and removals, which pass that
  repo's `check-guidance-coverage.js` and `check-guidance-touch.js`.

Adam decided that once a gate accepts a change, a human merge adds only
latency. The one exception he kept: a change to how a plugin runs code still
waits for him, through adam-agentskills' `plugin-runtime-review` environment.

Every managed repo already has what native auto-merge needs:
`repo.allow_auto_merge: true` and `required_approving_review_count: 0` are
fleet defaults, and each of the three repos requires its CI checks in its
ruleset (`fleet.yml`). `fleet.yml` has no per-repo knob for "this repo may
auto-merge bot PRs": the exception lives in the gates and in this ADR, not in a
setting.

## Decision

Eval-loop PRs in these three repos are a declared exception to ADR 0001's "PR +
auto-merge is not a sanctioned bot-write path", generalizing ADR 0003. They
open ready for review and arm native auto-merge (merge commit). No human
review or approval is required.

| Repo | PRs | Paths the PR may touch | Opened by |
|---|---|---|---|
| skills-evals | scaffolded fixtures, fixture promotions | `evals/real-work/<id>/**` | the roster App, `adam-s-daniel-skills-evals-roster` (App id 5116415, skills-evals only) |
| adam-agentskills | skill improvements, skill removals | `plugins/<plugin>/skills/<skill>/**`, `docs/skill-impact.md`; a removal also the `version` in that plugin's `plugin.json` and `.claude-plugin/plugin.json` (skills-evals ADR 0014) | the eval-improve App (skills-evals secrets `EVAL_IMPROVE_APP_CLIENT_ID`, `EVAL_IMPROVE_APP_PEM`), installed on adam-agentskills only |
| _agent-guidance | guidance-section edits and removals | `agents-md/**`, `AGENTS.md`, `docs/guidance-impact.md` | a dedicated eval-guidance App, installed on _agent-guidance only |

Each App has Contents and Pull requests write and nothing else, and none is a
ruleset bypass actor. Its token is minted in the gate job that uses it.

The exception holds only while all of these hold:

- **Required checks gate every merge.** Auto-merge fires only when every
  required context on the head has passed. In adam-agentskills that includes
  `plugin-runtime-approval`, so a PR that touches plugin hooks, `bin/`,
  `package.json` or settings waits for Adam's approval of the
  `plugin-runtime-review` environment. No loop job approves that environment.
- **Approvals stay at 0, and the loop never approves.** No review is needed
  today. If a ruleset ever requires approving reviews, these PRs stop merging,
  which is the safe failure. Do not answer that by having a bot approve.
- **The gates enforce the scope.** Each gate in skills-evals checks the
  candidate's changed paths against an exact allowlist (the table above)
  before it mints a token. The ruleset cannot express "only these paths," and
  the App's permissions cover the whole repo, so the allowlist is the control.
  Trusting the loop is not.
- **Merge commits only, and every change is a PR** a human can read, revert,
  or close before it merges.

## Consequences

- No new bypass actor, ruleset change or `fleet.yml` setting. The bot's change
  goes through the same ruleset as a human's.
- Content reaches `main` with no human reading it. A gate that accepts a wrong
  path or a bad edit merges it. The mitigations are the allowlists, each
  repo's required checks, and the gates' own tests in skills-evals.
- A PR opened by `GITHUB_TOKEN` gets no passing required check (ADR 0003,
  amendment), so the scaffold gate has to move from `GITHUB_TOKEN` to the
  roster App before its PRs can auto-merge. Once it has, nothing in
  skills-evals opens PRs with `GITHUB_TOKEN`, and its
  `actions.can_approve_pull_request_reviews: true` override (ADR 0008) should
  return to the fleet default `false` in the same or a following change.
- The roster App's key now also opens fixture PRs. Both live in skills-evals
  and reach skills-evals only, so its reach does not grow. ADR 0004's ruleset
  still lets only that App and admins push `roster/proposal`.
- The guidance App's key reaches _agent-guidance, whose `AGENTS.md` and
  `agents-md/` feed every session in the fleet. Keep its secrets in
  skills-evals alone, never on a workflow a pull request can run.
- A skill removal re-pins nothing in consumers. Their `skills.lock` goes stale
  until each is re-pinned, as skills-evals ADR 0014 says.
- ADR 0001's scars still apply. A required check that a path filter or a
  cancelled run leaves unreported blocks the PR, so each repo keeps its
  required checks always-run and free of a cancelling `concurrency` group.
- A fourth repo, or a path outside the table, is a policy change. It needs a
  new ADR, not a widened allowlist.

## Alternatives considered

**Adam merges every accepted change (ADR 0001 as written).** His decision of
2026-10-26 rejected it: the gates already decide, and the merge was latency.

**A bypass-actor App pushing to `main`.** Rejected, as in ADR 0003: a standing
ruleset hole, and the change would skip the required checks.

**One App for all three repos.** Fewer keys, but one leaked key would reach the
skill registry and the fleet guidance together. The ADR 0003 amendment
rejected shared Apps for the same reason.

**A `fleet.yml` knob listing auto-merge repos.** Nothing for the engine to
apply: auto-merge is already on fleet-wide, and what matters (paths, identity)
is not a repo setting. It would be inert config.

## References

- ADR 0001: [Route bot writes to results branches; declare rare ruleset bypasses in fleet.yml](0001-bot-writes-results-branch-or-declared-bypass.md)
- ADR 0003: [Scope skills-evals' roster auto-merge as a declared exception to ADR 0001](0003-scope-skills-evals-roster-auto-merge-as-declared-exception.md)
- ADR 0004: [Confine skills-evals' roster/proposal branch to the roster App with an extra ruleset](0004-confine-roster-proposal-branch-to-the-roster-app.md)
- ADR 0008: [Let skills-evals' scaffold gate open draft PRs with GITHUB_TOKEN](0008-let-skills-evals-open-draft-scaffold-prs-with-github-token.md)
- skills-evals ADR 0014: <https://github.com/Adam-S-Daniel/skills-evals/blob/main/docs/decisions/0014-removal-pull-requests-merge-without-review.md>
- The improve gate's App credential: <https://github.com/Adam-S-Daniel/skills-evals/blob/main/.github/workflows/routine-improve-gate.yml>
- adam-agentskills' plugin runtime gate (its ADR 0016): <https://github.com/Adam-S-Daniel/adam-agentskills/blob/main/.github/workflows/plugin-runtime-review.yml>
