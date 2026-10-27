# 0016. The cms-platform repos take allowlisted labels only, under a narrowed token

- **Status:** Accepted
- **Date:** 2026-10-27
- **Deciders:** Adam Daniel (2026-10-27: asked for
  [#88](https://github.com/Adam-S-Daniel/repo-settings/issues/88) to be
  implemented, which is the owner sign-off its "Order" step 2 asks for on the
  cms-platform side)

## Context

`Adam-S-Daniel/cms-platform`, `Adam-S-Daniel/adamdaniel.ai` and
`jodidaniel/jodidaniel.com` were `manage: []`: cms-platform owns their
settings through its own manifest (`repo-settings.yml`), applied behind its
own `repo-settings` environment, so every admin write there is
human-approved. The engine made no API calls to them at all.

The fleet-wide `agent-authored` label (ADR 0010, _agent-guidance ADR 0023)
must exist in every repo agents open PRs in, these three included. ADR 0011
made `manage: ["labels"]` possible, but an adversarial review of #83 found
three problems with simply using it here:

1. **Ownership is by label name, not only by surface.** cms-platform's
   manifest declares no labels, yet its workflows create labels with fixed
   colors (`ci`, `cms/draft`, `cms/ready`, `cms/preview-only`,
   `not-decap-created`, `content-guard/override`) and Decap owns
   `decap-cms/*`. `merge_labels` sends every `defaults.labels` entry to a
   repo that manages labels, so a later fleet default named `ci` would
   silently overwrite cms's label.
2. **It adds an unattended writer.** The apply job is approved in
   repo-settings' `fleet-apply` environment, not cms-platform's, and it runs
   on every settings push and weekly. Its token carries Administration write,
   so the only thing keeping it to labels would be the `manage` filter.
3. **`labeled` events reach cms workflows** once agents can apply the label.

## Decision

- **Ownership splits by surface and by label name.** cms-platform owns every
  surface of these repos except `labels`, and within `labels` it owns every
  name except those on `CMS_LABEL_ALLOWLIST` (today only `agent-authored`).
  The three repos are `manage: ["labels"]` in `fleet.yml`.
- **A guard in the engine, at validation.** For a repo in
  `CMS_LABEL_ONLY_REPOS`, `resolve_targets` refuses (config error, exit 2,
  before any API call):
  - any `manage` other than `[]` or `["labels"]`;
  - when it manages labels, every label name reaching it that is not on
    `CMS_LABEL_ALLOWLIST` or that matches a `CMS_OWNED_LABELS` pattern
    (`ci`, `cms/*`, `cms/draft`, `cms/preview-only`, `cms/ready`,
    `content-guard/override`, `decap-cms/*`, `not-decap-created`),
    compared case-insensitively as GitHub does. Every label is checked and
    the error names all of them, not the first match.

  The three sets are constants in `scripts/repo_settings.py`, defined once;
  the error messages and the workflow's repository list are built from them.
  A new fleet default label therefore fails the whole config until someone
  either adds it to the allowlist (a cms-platform decision) or the cms repos
  stop managing labels.
- **The unattended-writer exception.** Label definitions on the allowlist are
  written to these repos by repo-settings' App without cms-platform's
  approval. That is acceptable because a label definition is not a security
  setting, the engine only creates or edits it (never deletes), and the
  allowlist is the whole scope. cms-platform's `repo-settings.yml`,
  `docs/SYNC.md` and `consumer-repo-provisioning` skill say so (the
  cms-platform PR for #88, merged first).
- **The token decision: a narrowed token for the label-only leg.** In each
  owner's apply leg, the admin apply runs with `--cms-label-only skip`, so it
  never plans these repos. Three further steps then ask the engine for that
  owner's cms label-only repos (`repo_settings.py cms-label-repos`), mint a
  second installation token with `actions/create-github-app-token`'s
  `permission-issues: write` and `repositories:` limited to those repos, and
  run `apply --cms-label-only only` under it. The per-owner fan-out was no
  obstacle: each matrix leg already has one owner, and the engine prints the
  names for that owner, so the list lives in one place.

  The narrowing protects against the engine, not against the job. The job
  still holds the App's private key, which can mint any permission the App
  has, so a compromised job is no weaker than before. What changes is that a
  planning bug, a wrong filter or a future surface cannot make an
  Administration write to a cms repo: the token in that process cannot. A
  separate job would not move the key out either (it would need the same
  environment secret) and would add a second approval, so the leg stays in
  the existing job.
- The label-only steps run when the admin apply failed (an error on another
  repo must not withhold the label), but never when the `fleet-apply`
  environment self-check failed.

## Consequences

- `agent-authored` already existed on all three repos on 2026-10-27, as
  GitHub creates a label on first use: color `ededed`, no description. The
  next apply edits it to the fleet's `D4C5F9` and description; `diff` shows
  one label record per repo and nothing else.
- A future fleet-wide label does not reach the cms repos silently: the config
  is refused until the allowlist is changed on purpose.
- Agents applying `agent-authored` fire `pull_request: labeled` into
  cms-platform workflows; what that triggers is recorded in the cms-platform
  PR for #88.
- `plan` and `drift` read these repos under the read-only App, as for every
  other repo.

## References

- Issue: [#88](https://github.com/Adam-S-Daniel/repo-settings/issues/88)
- Depends on: [ADR 0010](0010-labels-may-be-declared-fleet-wide-and-merge-by-name.md),
  [ADR 0011](0011-make-manage-a-required-array-of-surfaces.md)
- Engine: `CMS_LABEL_ONLY_REPOS`, `CMS_LABEL_ALLOWLIST`, `CMS_OWNED_LABELS`
  in [`scripts/repo_settings.py`](../../scripts/repo_settings.py)
