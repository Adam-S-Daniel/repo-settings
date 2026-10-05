<!-- BEGIN MANAGED SECTION — DO NOT EDIT ABOVE "## Repo-specific additions" -->
<!-- Source: _agent-guidance -->
<!-- Sections: none -->
<!-- Mode: stub -->

# AGENTS.md

> **Managed by [`_agent-guidance`].**
> Edit only below the `## Repo-specific additions` header.
> Everything above it will be overwritten on the next sync.

## Fleet guidance is delivered once per session — not by this file

The account's full guidance — incidents, fleet policy, machine layout, the
traps that cost real outages — is installed into **user memory**
(`~/.claude/CLAUDE.md`) by the `fleet-memory` SessionStart hook, so it is
loaded **once per session** no matter how many repos are attached
([2026-08-29: inlined per repo, it took 332.3k tokens](https://github.com/Adam-S-Daniel/_agent-guidance/blob/main/docs/evidence/2026-08-29-guidance-inlined-in-every-repo.md)).

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

The hook writes the same block to `~/.codex/AGENTS.md` whenever `~/.codex`
exists — Codex's global **user** instructions, outside its 32 KiB
`project_doc_max_bytes` project-doc budget. Register it once per machine with
`scripts/register-codex-hook.sh` from an `_agent-guidance` checkout, then
trust it in `/hooks`. `codex debug prompt-input` shows exactly what a session
loaded; no `fleet-guidance:` line there means DEGRADED.

For Codex Cloud, use **Manual** environment setup with persistent
`CODEX_HOME=/opt/codex`. Preserve the repository's dependency setup and run
`bash .claude/hooks/fleet-memory.sh --codex-cloud` in both setup and
maintenance; reset the cache for the first verification. Fresh setup and
cached maintenance were verified in the `_agent-guidance` environment. See
[`docs/codex-cloud.md`](https://github.com/Adam-S-Daniel/_agent-guidance/blob/main/docs/codex-cloud.md).
If the Cloud shell has no `codex debug prompt-input`, the saved task response's
raw initial instruction envelope is the echo-free proof of model-visible
delivery.

## The floor: rules that hold even when the guidance did not load

These are the ones with teeth. They are restated here, deliberately, because a
session that lost the guidance must not also lose these.

- **Branch protection is real.** Fleet repos are PR-only on their default
  branch; a direct push is rejected (GH013), even from the repo's own
  workflows. Never design a bot that pushes to a protected default branch.
- **Every `uses:` is pinned to a full 40-character commit SHA, with no
  trailing version comment.** The one carve-out is a ref into this account's
  own `cms-platform`, which stays on its release tag.
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
- **Merge with a merge commit** (`gh pr merge --merge`); do not amend
  published commits or force-push shared branches.
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
  Metadata (README, "CI fan-out" step 1), the scheduled run cannot audit or
  reconcile the merge-method policy — those records come back as skips, and
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
  own (`schema.md`), so a stray never surfaces as drift. The symptom is a bot
  still taking GH013 after its grant applied cleanly and `diff` reports
  converged — that is the signature of a second ruleset, not a bug in the grant.
- Before declaring a repo onboarded — especially one that already carried
  protection by hand — enumerate its rulesets and delete the strays:
  `gh api repos/<owner>/<repo>/rulesets --jq '.[] | "\(.id) \(.name)"'`.
  Deletion stays manual and deliberate; the engine will not do it for you.
