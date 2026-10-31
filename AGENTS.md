<!-- BEGIN MANAGED SECTION — DO NOT EDIT ABOVE "## Repo-specific additions" -->
<!-- Source: _agent-guidance -->
<!-- Sections: none -->
<!-- Mode: stub -->

# AGENTS.md

> **Managed by [`_agent-guidance`].**
> Edit only below the `## Repo-specific additions` header.
> Everything above it will be overwritten on the next sync.

guidance-marker: fleet-stub (transcript counts use this line; keep it)

## Fleet guidance is delivered once per session — not by this file

The account's full guidance — incidents, fleet policy, machine layout, the
traps that cost real outages — is installed into **user memory**
(`~/.claude/CLAUDE.md`) by the `fleet-memory` SessionStart hook, so it is
loaded **once per session** no matter how many repos are attached
([inlined per repo, it took 332.3k tokens](https://github.com/Adam-S-Daniel/_agent-guidance/blob/main/docs/evidence/2026-08-29-guidance-inlined-in-every-repo.md)).

**Check the session-start verdict before you rely on it.** The hook prints one
line:

- `fleet-guidance: installed (v<id>, <n> bytes)` or `fleet-guidance: current` —
  the full guidance is in context. Use it.
- `fleet-guidance: DEGRADED — <reason>` — it is **not** in context. You have
  only what is below. Read `agents-md/base.md` in the `_agent-guidance`
  checkout (or on GitHub) before non-trivial work, and say in your reply that
  you were running degraded.
- `fleet-guidance: skipped (FLEET_GUIDANCE_SKIP set)` — also not in context,
  but by the machine owner's deliberate choice, not a fault. User memory is
  GLOBAL on a durable machine, so the guidance would otherwise load in every
  unrelated project on that box; `FLEET_GUIDANCE_SKIP` opts out and removes any
  block an earlier session installed. Read `agents-md/base.md` the same way you
  would when degraded — just don't report it as a problem or try to "fix" it.

No verdict at all means the hook never ran — treat that as DEGRADED.

## Codex reads the same block, from `~/.codex/AGENTS.md`

The hook writes the same block there whenever `~/.codex` exists. Setup for
local Codex and Codex Cloud, and how to verify delivery:
[`docs/codex-cloud.md`](https://github.com/Adam-S-Daniel/_agent-guidance/blob/main/docs/codex-cloud.md).

## The floor: rules that hold even when the guidance did not load

These are the ones with teeth. They are restated here, deliberately, because a
session that lost the guidance must not also lose these.

- **Branch protection is real.** Fleet repos are PR-only on their default
  branch; a direct push is rejected (GH013), even from the repo's own
  workflows. Never design a bot that pushes to a protected default branch.
- **Every `uses:` is pinned through `.github/workflows/actions.lock`: an
  exact tag, locked, checked by a required `gh actions-lock --verify`
  failing on any pin finding.** A repo not yet migrated keeps the legacy
  form, a full 40-character commit SHA with no trailing version comment,
  until its migration PR; never mix the two in one repo. Cross-repo
  reusable workflows take a full SHA either way. The one carve-out is a ref
  into this account's own `cms-platform`, which stays on its release tag.
- **Never commit secrets or `.env` files, and never print personal data to a
  CI log** — logs, artifacts and git history on a public repo are public.
- **A successful `git push` does not mean your commit exists.** A refused
  pre-commit hook still lets the push report success. Verify with
  `git merge-base --is-ancestor <sha> origin/<branch>` — it is the only check
  that names both the commit and the ref.
- **"The watch finished" is not "CI passed."** Read the parsed conclusions;
  never infer pass/fail from a watch command's exit code.
- **A GitHub 404 means "not authorized", not "not there."** Never report a
  repo, PR or branch as gone on a 404 alone.
- **The fleet spans TWO owners** — `Adam-S-Daniel` and `jodidaniel`. A query
  scoped to one returns a plausible, complete-shaped, wrong answer.
- **Anything you name gets its link** — what you hand over, what you are
  waiting on, and what you cite as already done.
- **Merge with a merge commit** (`gh pr merge --merge`), except in the three
  cms-platform-managed repos (`cms-platform`, `adamdaniel.ai`,
  `jodidaniel.com`), which squash; do not amend published commits or
  force-push shared branches.
- **Keep this file under 32 KiB.** Codex truncates project instructions at
  that byte silently; the sync warns and the drift report flags
  `codex-truncated`.

<!-- END MANAGED SECTION -->
## Repo-specific additions

<!-- Add your repo-specific agent guidance below this line -->

### Architecture Decision Records

Non-obvious policy decisions are recorded in
[docs/decisions/](docs/decisions/README.md). Read the relevant ADR before
proposing to revert a policy — start with ADR 0001 (how bots write to
protected branches).

### Merge-setting fields go missing on a low-scope token

- `GET /repos/{owner}/{repo}` returns the **merge-setting** fields —
  `allow_merge_commit`, `allow_squash_merge`, `allow_rebase_merge`,
  `allow_auto_merge`, `delete_branch_on_merge` — only to a token with
  write-level access to the repo's contents. Below that the keys are **absent**,
  not `false`. Non-merge fields (`has_wiki`, `default_branch`), rulesets and
  `actions/permissions` stay visible, so the token looks perfectly alive.
- The engine therefore treats an absent key as an informational **skip**, never
  as drift and never as a `KeyError`. Keep it that way: a `KeyError` there
  escapes both `plan_repo`'s `GhError` guard and `plan_repo_records`, taking the
  whole fleet run down over one repo's payload. Never "fix" it by promoting an
  absent key to drift.
- Consequence for CI: while the fan-out App is scoped Administration + Actions +
  Issues + Metadata, with no Contents (README, "CI fan-out" step 1), the
  scheduled run cannot audit or reconcile the merge-method policy — those
  records come back as skips, and
  merge-method drift is caught only by an operator `apply` under ambient
  `gh auth`. Accept that gap knowingly, or widen the App and **verify** the keys
  actually appear before trusting the audit again.
- Never probe a read-scoped token by asking for `.delete_branch_on_merge` — an
  absent key reads exactly like a dead token. Probe with
  `gh api repos/<owner>/<repo>/actions/permissions --jq .enabled`.

### Pull before you apply

- `repo_settings.py apply` is a **converging** writer: it makes the fleet match
  the checkout it runs from. `write_ruleset` PUTs the whole desired body, so a
  stale checkout silently reverts everything merged since — a `bypass_actors`
  grant added on `main` is stripped the moment someone applies from a branch
  that predates it, with no error and no drift to show for it.
- So: `git pull` immediately before any local `apply`, and after a failed or
  partial run re-run from current `main` rather than assuming the legs that
  already passed are still good.
- Same hazard from the workflow: `workflow_dispatch` executes the engine and
  `fleet.yml` **of the ref you dispatch**, not of `main`. Dispatch from `main`
  unless you are deliberately testing a branch — a dispatch on a stale branch
  produces a convincing, wrong audit.

### A stray ruleset defeats a declared bypass

- GitHub enforces the **union** of every ruleset on a repo, and a bypass actor
  exempts only the ruleset that grants it. A leftover hand-made ruleset with an
  empty `bypass_actors` therefore blocks the declared bypass App **and** admins,
  even while `fleet.yml`'s managed ruleset grants both.
- The engine is idempotent **by name** and never touches rulesets it does not
  own (`repo-settings/schema.md`), so a stray never surfaces as drift. The symptom is a bot
  still taking GH013 after its grant applied cleanly and `diff` reports
  converged — that is the signature of a second ruleset, not a bug in the grant.
- Before declaring a repo onboarded — especially one that already carried
  protection by hand — enumerate its rulesets and delete the strays:
  `gh api repos/<owner>/<repo>/rulesets --jq '.[] | "\(.id) \(.name)"'`.
  Deletion stays manual and deliberate; the engine will not do it for you.

### Workflows and required checks

The fleet rule makes every CI job that runs on pull requests a required check
unless this file says why not
([issue #86](https://github.com/Adam-S-Daniel/repo-settings/issues/86)).
`tests/test_required_checks.py` enforces that against `fleet.yml` and the
workflows: every job that runs on pull requests needs exactly one row in the
table below, and its **Required** column must say `yes` when `fleet.yml`
requires the job and `no` when it does not. Every row must also name a workflow
file and job that exist.

Python packages are split: `requirements.txt` holds what `repo-settings.yml`
needs, and `requirements-dev.txt` adds the test-only ones (`markdown-it-py`,
which parses this table) for `tests.yml` alone, so test-only packages never run
beside the App private key. `tests/test_workflow_dependency_pins.py` enforces
the split.

**Nothing is enforced while this repo is private:** rulesets answer 403
("Upgrade to GitHub Pro or make this repository public") and the engine records
a skip. The required checks are declared anyway, per
[ADR 0002](docs/decisions/0002-declare-dependabot-security-settings-including-the-unenforceable-one.md),
so enforcement needs no further change if the repo goes public or the account
moves to Pro.

| Workflow | Job | Triggers | Salient paths | Required | Why |
|---|---|---|---|---|---|
| agent-checks.yml | `agent-checks` | pull_request, push (main, master), workflow_dispatch | none (always runs) | yes | The fleet default check (_agent-guidance ADR 0021). |
| tests.yml | `unit` | pull_request, push (main) | pull_request: none, always runs; push: scripts, tests, repo-settings, workflows, dependabot.yml, requirements.txt, requirements-dev.txt, AGENTS.md | yes | Always runs on PRs: a required check cannot use `on.paths`, since a skipped workflow never reports and blocks the merge. No gate step: the whole job takes about 10 s, and a gate would add a way to fail open plus a second path list. |
| repo-settings.yml | `plan` | push (main), schedule, workflow_dispatch; never pull_request (its `if:` excludes it, so it shows as skipped on PRs) | repo-settings/fleet.yml, scripts/repo_settings.py, its own workflow, requirements.txt | no | The ungated plan (issue #116): no environment, so no approval. It mints a read-only token per owner from the read App (every `permission-*` input `read`), runs `diff` for each, and sets `needs_apply` when either owner has drift; a `diff` exit 2 (could not ask, or a config error) fails it. It writes the planned changes to the job summary and as up to 10 notices, the 10th an all-caps heads-up when there are more, since the approval dialog cannot show them. It also runs the coverage audit and the undeclared-repo nudge, all three `continue-on-error`. Not a matrix, because matrix legs overwrite each other's job outputs. |
| repo-settings.yml | `repo-settings` (checks `repo-settings (<owner>)`) | push (main), schedule, workflow_dispatch; never pull_request (its `if:` excludes it, so it shows as skipped on PRs) | repo-settings/fleet.yml, scripts/repo_settings.py, its own workflow, requirements.txt | no | The apply job, and the only job that holds the admin App key. It `needs: plan` and runs only when the plan succeeded and found drift (push, or a dispatch that is not a dry run), when a non-dry-run dispatch sets `force_apply`, or on the weekly schedule when the plan found drift or failed. The read token cannot see ruleset `bypass_actors`, Actions policies or merge flags, so drift confined to those waits for an apply triggered by other drift or a `force_apply` dispatch (owner's choice, PR #113: no weekly approval for runs that change nothing). A dry-run dispatch is the plan alone. It runs in the `fleet-apply` environment, which needs the owner's approval and deploys from `main` only, so it cannot run on a PR at all. Its first step refuses to apply unless that environment still has a required reviewer and a `main`-only branch policy (issue #13, property 4). The admin apply runs with `--cms-label-only skip`; the cms-platform repos' labels are applied by later steps under a second token minted with only `permission-issues: write` and `repositories:` from `repo_settings.py cms-label-repos`, which run even if the admin apply failed but never if the environment check failed ([ADR 0016](docs/decisions/0016-cms-platform-repos-take-allowlisted-labels-only.md)). Applies are serialized per owner by the job-level group `repo-settings-${{ matrix.owner }}` (`cancel-in-progress: false`). A leg waiting for approval holds its owner's group, and only one job can be pending behind it, so a newer queued apply for that owner cancels an older pending one. |
| repo-settings.yml | `drift` (checks `drift (<owner>)`) | pull_request | repo-settings/fleet.yml, scripts/repo_settings.py, its own workflow, requirements.txt | no | Skipped while the repo variable `REPO_SETTINGS_READ_APP_CLIENT_ID` is unset (issue #90), and a skipped job counts as success. When the variable is set, it is an advisory preview: red by design on every PR that changes settings, because a change not yet applied is drift. Skipped on Dependabot and fork PRs, which get no secrets, so it could never mint a token there (PR #78). It writes the same summary and notices as `plan`. It has no concurrency group, so it never waits on an apply. |
| dependabot-auto-merge.yml | `auto-merge` | pull_request (opened, synchronize, reopened), schedule, workflow_dispatch | none | no | A check that only Dependabot PRs trigger. It verifies that every changed path is on the manifest allowlist and merges nothing. It is skipped for every other author, and a skipped job counts as success, so requiring it would add nothing for human PRs. The sweep checks the same allowlist again before any merge. |
| dependabot-auto-merge.yml | `sweep` | schedule, workflow_dispatch (the file also triggers on pull_request) | none | no | Schedule and dispatch only. It shows as skipped on PRs only because the workflow file also triggers on pull_request. |
| scheduled-run-health.yml | audit | schedule, workflow_dispatch | none | no | Does not run on pull requests. |
