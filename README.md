# repo-settings

Repository security settings as code for the `Adam-S-Daniel` (user) and
`jodidaniel` (org) fleets. This is the central controller: it holds the desired
state (`repo-settings/fleet.yml`), the engine (`scripts/repo_settings.py`), and a
scheduled fan-out workflow that reconciles drift.

The engine and schema come from the `github-actions-repo-settings` skill in
[Adam-S-Daniel/agentskills](https://github.com/Adam-S-Daniel/agentskills). Schema
reference: [`repo-settings/schema.md`](repo-settings/schema.md).

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

Private repos get SHA pinning + `repo.allow_auto_merge` — the API rejects
fork-PR approval (422) and rulesets (403, needs GitHub Pro); the engine logs an
explicit skip for those two only. `cms-platform` + its consumer sites are
excluded (`manage: false`) — they own their settings via the platform's own
manifest, and two ruleset controllers on one repo would fight (GitHub enforces
the union).

## Policy: bot writes vs the PR-only ruleset

The ruleset requires PRs into every managed default branch — bots included.
The sanctioned patterns
([ADR 0001](docs/decisions/0001-bot-writes-results-branch-or-declared-bypass.md)):

- **Generated data** (badges, run summaries, dashboards): publish to a
  dedicated unprotected results branch (model: skills-evals' `eval-results`);
  consumers read from that branch. No ruleset changes.
- **The rare bot that must write to the default branch**: declare its service
  identity as a ruleset bypass actor in `fleet.yml` (per-repo `bypass_actors:`
  override; `defaults:`-level only for a fleet-standard bot like
  agents-md-sync) so the grant is auditable and drift-checked. Never
  hand-grant bypass in the UI — the drift report flags it.
- **PR + auto-merge is not a sanctioned bot-write path** in this fleet.

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
`vars.REPO_SETTINGS_APP_CLIENT_ID` / `vars.REPO_SETTINGS_APP_ID`).

1. **Create a GitHub App** (github.com → Settings → Developer settings → GitHub
   Apps → New). Repository permissions: **Administration: Read & write**,
   **Actions: Read & write**, **Metadata: Read-only**. No webhook.
2. **Generate a private key** (downloads a `.pem`).
3. **Install the App** on both `Adam-S-Daniel` and the `jodidaniel` org, granting
   access to the repos in `fleet.yml` (or "All repositories").
4. In **this repo** → Settings → Secrets and variables → Actions:
   - Variable `REPO_SETTINGS_APP_CLIENT_ID` = the App's **Client ID** (on the
     App's settings page, format `Iv23li...`). The older
     `REPO_SETTINGS_APP_ID` (numeric App ID) still works as a fallback, but
     the action deprecated `app-id` -- prefer the Client ID, and delete the
     old variable once it is set.
   - Secret `REPO_SETTINGS_APP_PRIVATE_KEY` = the full contents of the `.pem`.

After that the workflow runs on push to `main` (config/script changes), a weekly
schedule, and manual dispatch (apply); on pull requests it reports drift only and
fails the check if there is any.

> Reuse note: `_agent-guidance` already runs a GitHub App (`agents-md-sync`) with
> the same per-owner token-minting pattern, but only Contents/PR permissions. A
> **separate** App is used here on purpose, to keep the far more powerful
> Administration/Actions-write capability isolated from the content-sync App.
