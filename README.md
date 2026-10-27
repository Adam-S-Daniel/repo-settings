# repo-settings

Repository security settings as code for the `Adam-S-Daniel` (user) and
`jodidaniel` (org) fleets. This is the central controller: it holds the desired
state (`repo-settings/fleet.yml`), the engine (`scripts/repo_settings.py`), and a
scheduled fan-out workflow that reconciles drift.

This repo is the **canonical home** of the engine, its schema and the fan-out
workflow. The `github-actions-repo-settings` skill in
[Adam-S-Daniel/adam-agentskills](https://github.com/Adam-S-Daniel/adam-agentskills)
used to ship a copy; it now points here instead
([adam-agentskills#62](https://github.com/Adam-S-Daniel/adam-agentskills/issues/62)),
so change the engine here and nowhere else. Schema reference:
[`repo-settings/schema.md`](repo-settings/schema.md).

## What it enforces

Per repo, according to `fleet.yml`:

- **SHA pinning** required for Actions (`sha_pinning_required`).
- **Fork-PR approval** = `all_external_contributors` (public repos only).
- **Default-branch protection** as a repository **ruleset** (public repos only).
- **Allow auto-merge** (`repo.allow_auto_merge`) — a plain repo setting, so it
  applies to private repos too. It's the prerequisite for GitHub's native
  auto-merge to be armable at all (e.g. for Dependabot's unattended-merge
  path); with it off, arming auto-merge fails outright regardless of
  branch-protection/ruleset state.
- **Dependabot alerts** (`security.vulnerability_alerts`) and **Dependabot
  security updates** (`security.automated_security_fixes`) — both read/written
  via `PUT`/`DELETE repos/{repo}/vulnerability-alerts` and
  `.../automated-security-fixes`, with **no request body**: the HTTP method
  itself carries the value. These land through the fan-out App's existing
  **Administration: Read & write** grant — no new credential, no workflow
  change. Security updates require alerts to be on first, so the engine
  applies the two in a dependency-aware order (see
  [`repo-settings/schema.md`](repo-settings/schema.md), "`security:`"). A
  third leaf, **grouped security updates**
  (`security.grouped_security_updates`), is declared in `fleet.yml` for the
  record but is **reported-only** — GitHub exposes no API for it at any scope,
  so the engine always reports it `skipped` and names the manual UI path
  instead of pretending it converged.
- **Actions event policies** (`actions_policies`, per-repo only) — repository
  Actions policies that restrict which events may trigger a workflow. The one
  use is adam-agentskills' `plugin-runtime-review.yml`, which triggers only on
  `pull_request_target` and publishes a required check; GitHub blocks that event
  on public repos by default from 2026-11-02 unless a policy allows it
  ([ADR 0009](docs/decisions/0009-allow-pull-request-target-with-a-workflow-scoped-policy-owned-by-name.md)).
  Policies are matched by name and the engine owns only the names `fleet.yml`
  declares. They need the repository Administration permission, which the
  fan-out App already holds.

Private repos get SHA pinning + `repo.allow_auto_merge` — the API rejects
fork-PR approval (422) and rulesets (403, needs GitHub Pro); the engine logs an
explicit skip for those two only. `cms-platform` + its consumer sites are
excluded (`manage: []`) — they own their settings via the platform's own
manifest, and two ruleset controllers on one repo would fight (GitHub enforces
the union).

## Policy: bot writes vs the PR-only ruleset

The ruleset requires PRs into every managed default branch — bots included.
The sanctioned patterns
([ADR 0001](docs/decisions/0001-bot-writes-results-branch-or-declared-bypass.md)):

- **Generated data** (badges, run summaries, dashboards): publish to a
  dedicated unprotected results branch (model: skills-evals' `persistent/eval-results`);
  consumers read from that branch. No ruleset changes.
- **The rare bot that must write to the default branch**: declare its service
  identity as a ruleset bypass actor in `fleet.yml` (per-repo `bypass_actors:`
  override; `defaults:`-level only for a fleet-standard bot like
  agents-md-sync) so the grant is auditable and drift-checked. Never
  hand-grant bypass in the UI — the drift report flags it.
- **PR + auto-merge is not a sanctioned bot-write path** in this fleet,
  except where an ADR declares it: skills-evals' roster PR
  ([ADR 0003](docs/decisions/0003-scope-skills-evals-roster-auto-merge-as-declared-exception.md))
  and the eval loop's gated PRs in skills-evals, adam-agentskills and
  _agent-guidance ([ADR 0012](docs/decisions/0012-eval-loop-prs-auto-merge-as-a-declared-exception.md)).

## Local use

```bash
pip install pyyaml
python scripts/repo_settings.py diff  --config repo-settings/fleet.yml            # audit
python scripts/repo_settings.py apply --config repo-settings/fleet.yml            # enforce
python scripts/repo_settings.py apply --config repo-settings/fleet.yml --owner jodidaniel --dry-run
```

Local runs use your `gh auth` (which must have admin on the targets).

## CI fan-out — one-time setup (required before the workflow does anything)

The workflow (`.github/workflows/repo-settings.yml`) authenticates with a
**GitHub App** so it can reach both accounts with short-lived, least-privilege
tokens (a fine-grained PAT can only ever cover one owner). Until the App is
configured, the workflow **skips itself** (guarded on
`vars.REPO_SETTINGS_APP_CLIENT_ID`).

1. **Create a GitHub App** (github.com → Settings → Developer settings → GitHub
   Apps → New). Repository permissions: **Administration: Read & write**,
   **Actions: Read & write**, **Issues: Read & write** (the `labels` surface
   creates and edits labels), **Metadata: Read-only**. No webhook. The
   jodidaniel installation's permissions were read directly; the
   Adam-S-Daniel one is inferred from the
   [2026-10-23 apply run](https://github.com/Adam-S-Daniel/repo-settings/actions/runs/39945750183)'s
   label writes.
2. **Generate a private key** (downloads a `.pem`).
3. **Install the App** on both `Adam-S-Daniel` and the `jodidaniel` org. You can
   grant access to just the repos in `fleet.yml` or choose "All repositories" --
   but know which, because the two differ in blast radius. **Both installations
   are currently on "All repositories"** (owner, 2026-08-29), so the App's
   Administration, Actions and Issues **write** reach is every repo in both
   accounts. `fleet.yml` declares repos, and each element's required `manage`
   array says which surfaces the engine manages there (`["all"]`, a list, or
   `[]` for none; see [`repo-settings/schema.md`](repo-settings/schema.md),
   "`manage`"). Declared-vs-in-account was equal when last verified
   (2026-08-29). So the exposure is prospective -- the next repo created in
   either account would be the first to sit inside the App's reach while
   appearing in no registry.
   **That is now audited.** `repo_settings.py coverage` asks
   `/installation/repositories` what the credential can actually administer and
   reports anything `fleet.yml` does not DECLARE; the weekly workflow runs it
   per owner and files a `ci`-labelled issue naming the repos, closing it when
   the file catches up. It runs in the ungated `plan` job, under the read-only
   App's token (step 6), so it needs no approval. Declared is the test, not managed: a repo carrying
   `manage: []` has been decided about and is not reported -- which is what
   the two forks carry. Absence is the finding, because absence and a
   deliberate omission looked identical from outside the file.
   Three things it deliberately does NOT do: fail the plan or the apply (a repo
   nobody has declared is no reason to abandon the settings the declared ones
   are owed), run on pull requests, or conclude anything from an enumeration
   that failed -- an empty listing exits 2 and leaves any open issue alone,
   because a clean line over zero repos reads exactly like a clean line over
   all of them.
4. In **this repo** → Settings → Secrets and variables → Actions:
   - Variable `REPO_SETTINGS_APP_CLIENT_ID` = the App's **Client ID** (on the
     App's settings page). Not the numeric App ID -- the action's `app-id`
     input is deprecated in favour of `client-id`.
   - Secret `REPO_SETTINGS_APP_PRIVATE_KEY` = the full contents of the `.pem`,
     stored as a secret of the **`fleet-apply` environment** (Settings →
     Environments), never as a repo-level secret. See step 5.
5. **The `fleet-apply` environment gates the admin key**
   ([#90](https://github.com/Adam-S-Daniel/repo-settings/issues/90),
   [#13](https://github.com/Adam-S-Daniel/repo-settings/issues/13)). It needs a
   required reviewer (the owner) and a deployment-branch policy that allows only
   `main`. The `repo-settings` apply job declares it, so every apply waits for
   approval (the `plan` job does not, so a plan alone asks for none), and its
   first step refuses to apply unless both rules are still
   there: naming an environment that does not exist silently creates one with
   no protection. GitHub serves environment secrets only to jobs that declare
   the environment, and only after approval. An environment secret also
   [takes precedence](https://docs.github.com/en/actions/reference/security/secrets)
   over a repo secret of the same name.
6. **A read-only App for the plan and the pull-request drift preview**
   (`repo-settings-drift-read`). The `plan` job and the pull-request `drift`
   job never get the admin key; they mint from a second App with only
   Administration: Read, Actions: Read, Issues: Read and Metadata: Read,
   installed on all repos in **both** accounts (each owner's mint fails until
   it is installed there). In this repo, set variable
   `REPO_SETTINGS_READ_APP_CLIENT_ID` and secret
   `REPO_SETTINGS_READ_APP_PRIVATE_KEY` (repo level). Until the variable
   exists, `drift` is skipped, and `plan` fails, which withholds the apply
   except on the weekly schedule, where a failed plan still asks for it. Reads that need write come back as skips,
   never drift.

After that, every push to `main` (config/script changes), weekly schedule and
manual dispatch first runs the `plan` job, with no approval: `diff` per owner
under the read-only token
([#116](https://github.com/Adam-S-Daniel/repo-settings/issues/116)). The gated
apply, and so the owner's approval of the `fleet-apply` deployment, follows
only when:

- the plan found drift, on a push or on a dispatch that is not a dry run;
- a dispatch that is not a dry run sets `force_apply`, for an apply the plan
  saw no reason for;
- the run is the weekly schedule and the plan found drift, or the plan
  failed (a run that cannot rule drift out still asks).

The read token cannot see ruleset `bypass_actors`, Actions policies or the
repo merge flags (all are skips), so drift confined to those never shows in
the plan, on schedule included. That is a deliberate trade
([#113](https://github.com/Adam-S-Daniel/repo-settings/pull/113)): no weekly
approval for a run that changes nothing, in exchange for no weekly backstop on
those three. A push or dispatch that applies for other drift still converges
them, and so does a dispatch with `force_apply`.

A dry-run dispatch is the plan alone and asks for no approval. On pull
requests, the workflow reports drift only and fails the `drift` check if there
is any.

> Reuse note: `_agent-guidance` already runs a GitHub App (`agents-md-sync`) with
> the same per-owner token-minting pattern, but only Contents/PR permissions. A
> **separate** App is used here on purpose, to keep the far more powerful
> Administration/Actions-write capability isolated from the content-sync App.
