# repo-settings config schema

`repo_settings.py` reads a YAML document describing the **desired** state of a
repo's Actions-security settings and default-branch protection. Branch
protection is expressed as a **GitHub repository ruleset** (the modern
replacement for classic branch protection, and the same primitive the
cms-platform-managed repos use). Two document shapes are accepted.

## Single-repo shape

Lives in a repo as `.github/repo-settings.yml`, or anywhere when passing
`--repo`.

```yaml
# Optional. If omitted, pass --repo owner/name on the command line.
repo: Adam-S-Daniel/agentskills

actions:
  # Require every `uses:` to be pinned to a full-length commit SHA.
  sha_pinning_required: true

  # Fork pull-request approval policy. Accepted values:
  #   first_time_contributors        (approval only for first-time contributors)
  #   all_external_contributors      (approval for ALL outside collaborators)
  # Omit the key, or set it to null, to leave the policy unmanaged.
  # NOTE: not applicable to PRIVATE repos -- the API returns 422; the engine
  # detects private repos and skips this automatically.
  fork_pr_approval: all_external_contributors

  # Settings -> Actions -> General -> Workflow permissions (issue #51). Both
  # keys live on one endpoint, .../actions/permissions/workflow; the engine
  # PUTs whichever of the two are declared together, in one call. No
  # private-repo gate -- this endpoint works on every plan. Omit either key,
  # or set it to null, to leave it unmanaged. See "Workflow permissions"
  # below for the 403 handling and the approval-review risk.
  default_workflow_permissions: read      # "read" or "write" -- GITHUB_TOKEN's default scope
  can_approve_pull_request_reviews: false # workflows may submit approving PR reviews

# Dependabot alerts + security-update automation. See "security:" below for
# the endpoints, the read/write semantics, and why grouped_security_updates
# can be declared but never applied.
security:
  # Prerequisite for automated_security_fixes below -- Dependabot cannot open
  # a security-update PR without an alert to resolve. Omit the key, or set it
  # to null, to leave it unmanaged.
  vulnerability_alerts: true

  # Whether Dependabot opens PRs for known vulnerabilities in dependencies.
  # Requires vulnerability_alerts above; the engine applies these two in a
  # dependency-aware order (see "security:" below) so a run never lands a
  # repo with security updates on and alerts off, even partway through.
  # Omit the key, or set it to null, to leave it unmanaged.
  automated_security_fixes: true

  # Declared for the record, not because the engine can act on it -- GitHub
  # exposes grouped security updates through the UI only (no REST endpoint at
  # repo or org level). Always reported `skipped`, never applied. Omit the
  # key to leave it entirely undeclared (distinct from declaring it and never
  # converging it -- see "security:" below for why this repo does the latter).
  grouped_security_updates: true

ruleset:
  # Omit the whole block, or set enabled: false, to leave protection unmanaged.
  # PUBLIC repos only -- private repos need GitHub Pro (API 403); the engine
  # detects private repos and skips this automatically.
  enabled: true

  # The managed ruleset is idempotent BY NAME: apply creates it if absent,
  # updates it in place if present, and never touches other rulesets.
  name: "default branch protection"

  # active = enforced; evaluate = dry-run/reporting; disabled = off.
  enforcement: active

  # Which branches the ruleset targets. Default: the repo's default branch
  # (via the ~DEFAULT_BRANCH special ref, so it follows a renamed default).
  # To target explicit branches instead:
  #   target_branches: [main, release]

  # null / omit -> the "require a pull request before merging" rule is left off.
  # a mapping   -> the rule is enabled.
  require_pull_request:
    required_approving_review_count: 0   # 0 = PR required, self-merge allowed
    dismiss_stale_reviews: false

    # "Require an approval for changes not attributed to a user."
    # INDEPENDENT of required_approving_review_count above: with this true a
    # PR whose commits are unattributed (Dependabot's are, by definition)
    # needs an approving review even when the count is 0, and the merge API
    # answers `mergeStateStatus=BLOCKED` / "the base branch policy prohibits
    # the merge". Omit the key to get GitHub's own default, which is TRUE --
    # so a ruleset this engine created has always carried it, silently, until
    # the field became managed here. See "The unattributed-changes parameter"
    # below.
    require_extra_approval_for_unattributed_changes: false

  block_force_pushes: true               # adds the non_fast_forward rule
  block_deletions: true                  # adds the deletion rule

  # Check contexts that must pass before merge. Empty/omit = rule not added
  # (recommended unless you have stable, always-present check names).
  required_status_checks: []

  # true  = the repo Admin role bypasses the ruleset ("always") -- the human
  #         owner can still push directly; only non-admins (incl. the Actions
  #         bot) are forced through PRs.
  # false = nobody bypasses (stricter; matches the cms-platform `main` ruleset).
  admin_bypass: true

  # Extra bypass actors beyond the Admin-role toggle above. This is the
  # sanctioned path for the RARE bot that genuinely must write to the protected
  # default branch (docs/decisions/0001): declare its service identity here so
  # the grant is auditable and drift-checked -- never hand-grant bypass in the
  # GitHub UI (the drift report will flag it). Each entry:
  #   actor_type:  Integration | Team | RepositoryRole | OrganizationAdmin | DeployKey
  #   actor_id:    numeric id (for Integration, the GitHub App's id)
  #   bypass_mode: always | pull_request   (default: always)
  # Omit or leave empty for no extra actors -- the default AND the policy
  # default: generated data belongs on an unprotected results branch instead.
  # In fleet configs, a defaults-level entry is reserved for fleet-standard bots.
  bypass_actors: []
```

### `extra_rulesets:` -- additional named rulesets (per-repo only)

A sibling of `ruleset:` (a top-level key in single-repo configs; under a repo's
`overrides:` in fleet configs) holding a LIST of extra branch rulesets. The
first use is skills-evals' `roster/proposal` ruleset (docs/decisions/0004).
The `persistent/**` deletion-only ruleset (docs/decisions/0007) is the other use.

```yaml
extra_rulesets:
  - name: roster proposal branch        # required; unique; != the default ruleset's name
    target_branches: [roster/proposal]  # required; each -> refs/heads/<b>; patterns allowed
    rules: [creation, update, deletion, non_fast_forward]   # required; only these four
    enforcement: active                 # optional; active | evaluate | disabled
    bypass_actors:                      # same entry shape/validation as `ruleset.bypass_actors`
      - {actor_type: Integration, actor_id: 5116415, bypass_mode: always}
      - {actor_type: RepositoryRole, actor_id: 5, bypass_mode: always}
```

- **Rules.** Only `creation`, `update`, `deletion`, `non_fast_forward`; anything
  else is rejected. `update` renders with
  `update_allows_fetch_and_merge: false`, so only bypass actors can update the
  ref. Rules compare as a set (type + parameters), so order never drifts.
- **Bypass.** There is no implicit admin bypass here: list every actor,
  including the Admin role (`RepositoryRole`, id 5), if it should bypass.
- **By name, like `ruleset:`.** apply POSTs when the name is absent, PUTs when
  present; `diff` reports `MISSING`/`DRIFT`. Private repos without Pro are
  skipped as for `ruleset:`.
- **Removal does not delete.** Dropping an entry leaves the live ruleset alone,
  consistent with "never touches other rulesets"; delete it by hand.
- **Per-repo only.** `extra_rulesets` under `defaults:` is rejected: list
  values are replaced (not merged) by an override, so a fleet default would be
  silently dropped by any repo that declares its own, and a bypass grant is a
  repo-specific decision (ADR 0001).
- `generate` does not emit `extra_rulesets`; it identifies the default ruleset
  by its name.

### `labels:` -- repo labels (fleet-wide defaults plus per-repo)

A sibling of `extra_rulesets:` (a top-level key in single-repo configs; under a
repo's `overrides:` in fleet configs) holding a LIST of labels the repo must
carry. The first use is skills-evals' `eval-scaffold` label (docs/decisions/0008).

```yaml
labels:
  - name: eval-scaffold                  # required; the label's identity
    color: C5DEF5                        # required; six hex digits, no leading '#'
    description: Draft real-work fixture opened by the scaffold gate   # optional, <= 100 chars
```

- **By name, like `ruleset:`.** The plan reads `GET repos/{repo}/labels/{name}`:
  a match is `ok`; a 404 is `DRIFT` (apply POSTs `repos/{repo}/labels`); a
  different color, description or name casing is `DRIFT` (apply PATCHes the
  label in place). Names compare case-insensitively on GitHub, so two entries
  differing only in case are refused; color compares case-insensitively.
- **A bare 404 is probed, not trusted.** A 404 reads the same whether the label
  is missing or the repo is invisible to the credential, so the plan then reads
  the repo itself: if that fails, the record is an `error`, never a create.
- **Removal does not delete.** Dropping an entry leaves the live label alone,
  consistent with "never touches other rulesets"; delete it by hand.
- **Defaults merge with per-repo labels.** `labels` under `defaults:` is
  created in every managed repo (docs/decisions/0010). Because `deep_merge`
  replaces lists, the engine merges this one key by name: a repo's own
  `overrides.labels` entry replaces a default of the same name
  (case-insensitive), and the rest of both lists apply. A repo that declares
  no labels simply gets the defaults.
- **Not visibility-gated.** Labels exist on every plan.
- **Needs a permission the fan-out App may not hold.** Creating or editing a
  label needs the credential's **Issues** (or Pull requests) **write**
  permission, which is not part of the documented Administration + Actions +
  Metadata grant. A write the credential cannot make comes back as an `error`
  record naming the HTTP failure, never a silent skip. Verify the App's grant
  (or apply from ambient `gh auth`) before relying on the scheduled run to
  create a label.
- `generate` does not emit `labels`.

### `actions_policies:` -- repository Actions event policies (per-repo only)

A sibling of `labels:` (a top-level key in single-repo configs; under a repo's
`overrides:` in fleet configs) holding a LIST of repository Actions event
policies (Settings -> Actions -> Policies). The first use is adam-agentskills'
`pull_request_target` allowance (docs/decisions/0009).

```yaml
actions_policies:
  - name: "plugin-runtime-review: allow pull_request_target"   # required; the policy's identity
    enforcement: active                  # optional; active (default) | disabled
    workflow_paths:                      # required
      include: [.github/workflows/plugin-runtime-review.yml]   # required, non-empty; or [~ALL] alone
      exclude: []                        # optional, default []
    allowed_events: [pull_request_target]   # required, non-empty, no duplicates
```

- **What it is.** On 2026-11-02 GitHub restricts `pull_request_target` on public
  repos by default unless an Actions policy applies
  ([docs](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target)).
  A policy's rule `restrict_action_events` carries `allowed_events`.
- **`allowed_events` is an allowlist** for every workflow the policy covers:
  an unlisted event is blocked ("Event 'workflow_dispatch' is not allowed to
  trigger Actions workflows"). So scope the policy to workflow paths and prefer
  one policy per workflow over `~ALL`; a `~ALL` policy must list every event
  every workflow uses, `schedule` and `workflow_dispatch` included. If a covered
  workflow gains a trigger, add it to `allowed_events` or its runs are blocked.
- **By name, like `ruleset:`.** The plan lists `GET repos/{repo}/actions/policies`
  and matches by `name`: absent is `DRIFT` (apply POSTs); present and different
  is `DRIFT` (apply PUTs the full body); equal is `ok`. `diff` reports DRIFT.
- **Ownership.** The engine owns only the names a repo declares. It never edits
  or deletes an undeclared policy, and it ignores inherited org or enterprise
  policies (`source_type` other than `Repository`) even when the name matches.
  Two live policies with a declared name is an `error`: the engine will not
  guess which one to converge; delete the extras by hand.
- **Removal does not delete.** Dropping an entry leaves the live policy alone.
  To retire one, set `enforcement: disabled`, let it apply, delete the policy by
  hand, then drop the entry. For adam-agentskills' policy, dropping it
  re-exposes `plugin-runtime-review.yml` to the default block.
- **Compared fields:** enforcement, `include` and `exclude` (as sets) and the
  rules (as a set of type and parameters, `allowed_events` as a set). Server
  fields (`id`, `node_id`, `_links`, timestamps, `source`, `source_type`,
  `target`) are ignored.
- **Refused at plan time.** `enforcement: evaluate` (GitHub Enterprise Cloud
  only), any unknown key (a typo like `enforcment` must not become `active`),
  and `~ALL` together with another include path. Only `restrict_action_events`
  rules are supported (not `restrict_actions_actors`), and only at repository
  level.
- **Per-repo only.** `actions_policies` under `defaults:` is rejected, for the
  same list-replacement reason as `extra_rulesets`, and because a policy names
  one repo's workflow files.
- **Permission.** Every repository endpoint, GET included, needs the repository
  **Administration: write** permission
  ([docs](https://docs.github.com/en/rest/authentication/permissions-required-for-github-apps#repository-permissions-for-administration)),
  which the fan-out App already holds. A 403, 404 or 422 on a read is a
  `skipped` record, and a list payload without `policies` is also `skipped`,
  never a `KeyError`; any other failure is an `error`.
- **API version.** Requests carry `X-GitHub-Api-Version: 2026-03-10`.
- **Not visibility-gated.** Policies are planned on every repo.
- `generate` emits only the policies expressible in this shape (one or more
  `restrict_action_events` rules, `active` or `disabled`, a non-empty include)
  and notes the rest on stderr.

### `repo:` -- plain repo settings

A separate, optional top-level `repo:` block manages ordinary repository
settings that are neither Actions-specific nor the ruleset -- read/written via
`GET`/`PATCH repos/{owner}/{repo}` directly. Unlike `actions.fork_pr_approval`
and `ruleset` above, these are NOT downgraded/skipped on private repos (there
is no 422/403 to handle): a plain repo setting applies the same way regardless
of visibility.

```yaml
repo:
  # "Allow auto-merge" (repo Settings -> General -> Pull Requests). This is a
  # PREREQUISITE for GitHub's native auto-merge to be armable at all -- if
  # it's off, `gh pr merge --auto` (or a workflow/Dependabot calling the same
  # API) fails outright, independent of branch-protection/ruleset state.
  # Omit the key, or set it to null, to leave it unmanaged.
  allow_auto_merge: true

  # "Automatically delete head branches" (repo Settings -> General -> Pull
  # Requests). Unlike allow_auto_merge above this is NOT plan-gated -- it is
  # honoured on private repos too, so it needs no downgrade handling.
  #
  # It matters more than tidiness. A bot that proposes from a fixed branch
  # name cannot re-propose while a branch of that name still exists carrying
  # content it did not write, and refusing to force-push over it is correct.
  # So a merged PR whose branch outlives it silently disables that bot for the
  # repo, with nothing going red. Omit the key, or set it to null, to leave it
  # unmanaged.
  delete_branch_on_merge: true

  # Merge-commit message (repo Settings -> General -> Pull Requests -> "Allow
  # merge commits"). Declare both keys together. The engine accepts only the
  # three pairs that page offers -- MERGE_MESSAGE/PR_TITLE ("Default
  # message"), PR_TITLE/BLANK ("Default to pull request title") and
  # PR_TITLE/PR_BODY ("Default to pull request title and description") -- and
  # reports anything else, or one key alone, as a skip at plan time rather than
  # applying it. Omit both, or set them to null, to leave them unmanaged. Why
  # the fleet pins "Default message": see fleet.yml.
  merge_commit_title: MERGE_MESSAGE
  merge_commit_message: PR_TITLE
```

**Collision with the single-repo shape's identifier field:** the single-repo
shape already uses the top-level key `repo:` for the identifier string shown
above (`repo: Adam-S-Daniel/agentskills`) -- the same key can't be both a
string and a mapping in one document. If you want to manage
`repo.allow_auto_merge` from a single-repo config file, pass the identifier as
`--repo owner/name` on the command line instead of embedding it in the file,
and put the mapping form (above) in the file's `repo:` key. This collision
does not exist in the fleet/fan-out shape below, where the identifier always
comes from each entry's `name:` and `repo:` is free to be a settings mapping.

### `security:` -- Dependabot alerts and security updates

Three leaves, two of them applyable. Like `repo:` above these are ordinary
per-repo toggles, not Actions-specific and not the ruleset -- but unlike
`repo:`, two of the three DO need downgrade handling, because the read (not
the write) can fail on a scope the fan-out App's grant does not cover on every
installation.

```yaml
security:
  # Dependabot ALERTS -- the prerequisite for everything below. Omit the key,
  # or set it to null, to leave it unmanaged.
  vulnerability_alerts: true

  # Dependabot SECURITY UPDATES -- automated PRs that resolve an open alert.
  # Requires vulnerability_alerts above (see "Apply order" below). Omit the
  # key, or set it to null, to leave it unmanaged.
  automated_security_fixes: true

  # Dependabot GROUPED security updates. Declared for the record; the engine
  # can never apply it (see "grouped_security_updates has no API" below).
  # Omit the key to leave it undeclared instead of declared-and-skipped.
  grouped_security_updates: true
```

**Endpoints, and the PUT/DELETE-carries-the-value shape.** Both applyable
leaves are read and written through a pair of GitHub endpoints that take
`PUT` to enable and `DELETE` to disable, with **no request body either way** --
unlike every other writer in this file, which PATCHes or PUTs a JSON value,
here the HTTP **method itself** is the value:

| Leaf | Endpoint | Read shape |
|---|---|---|
| `vulnerability_alerts` | `repos/{repo}/vulnerability-alerts` | HTTP status only -- 204 = enabled, 404 = disabled, no JSON body ever |
| `automated_security_fixes` | `repos/{repo}/automated-security-fixes` | `200 {"enabled": bool, "paused": bool}` on current GitHub; tolerate the legacy 204-empty/404 shape too, since which vintage a given installation answers with is not something to assume |

`paused` (on `automated_security_fixes`) is deliberately **not managed** -- it
is GitHub's own operational signal that Dependabot has paused security-update
PRs for the repo (e.g. after a run of unmergeable ones), not a policy toggle a
human flips, and there is no write surface for it at all.

**Why a 404 here reads as "disabled", not "not authorized".** The
account-wide guidance is right that a bare GitHub 404 is ambiguous by design
and should not be read as absence -- but that rule exists because most 404s
come from a credential that cannot see the resource at all, indistinguishable
from a real absence. This endpoint is different: the fan-out App's
**installation** is what grants visibility into a repo in the first place,
not a narrower per-endpoint scope sitting on top of an otherwise-working
credential. A token that cannot see the repo fails `get_repo` and the ruleset
reads too, and `plan_repo_records`' fault isolation turns THAT failure into a
repo-level `error` record -- so a lone 404 on this one endpoint, with every
other record for the same repo reading cleanly, is the documented feature-off
signal and nothing else. There is no scope tier that sits between "can
administer this repo at all" and "can read this one flag".

**Why a 403 maps to a skip, not a raised error.** This surface is bolted onto
an already-working weekly fleet run whose App grant (Administration: Read &
write) predates this setting existing at all -- proven to cover every other
writer in this file, not yet proven to cover these two specific endpoints on
every installation. A hard failure here would take the ENTIRE apply down over
one repo's scope gap, turning a working enforcement lane into a broken one.
So a 403 on either read produces a visible `skipped` record naming the 403 --
the same contract `actions.fork_pr_approval`'s 403/404/422 handling already
uses -- which keeps the gap honest (a reader sees "cannot read") rather than
silent. **The false-green risk this accepts, explicitly:** a fleet-wide 403 on
every repo would make the whole `security` group report clean `skipped`
records forever, with no drift and no error to prompt a second look --
identical in shape to a scoped search that returns a plausible, complete-shaped
wrong answer. Watch the rendered report for a `skip` naming HTTP 403 on a
repo where every other record reads normally; that is the signature.

**Apply order is a real dependency, not cosmetics.** Dependabot security
updates cannot open a PR without an alert to resolve, so
`automated_security_fixes` being on with `vulnerability_alerts` off is a state
that should never be produced, even transiently by a partial apply.
`cmd_apply` walks `drift` records in list order, so `plan_repo` builds the
order to match: when `automated_security_fixes` is desired `true`, the
`vulnerability_alerts` record is emitted first (prerequisite before
dependent); when it is desired `false`, `automated_security_fixes` is emitted
first (dependent disabled before the prerequisite is pulled out from under
it).

**`grouped_security_updates` has no API, at any scope.** Verified against
GitHub's REST reference for both surfaces, not inferred from a failed call:
absent from a repo's `security_and_analysis` object (whose keys are
`advanced_security`, `code_security`, `dependabot_security_updates`,
`secret_scanning`, `secret_scanning_push_protection`,
`secret_scanning_non_provider_patterns`, `secret_scanning_ai_detection`,
`secret_scanning_delegated_alert_dismissal`,
`secret_scanning_delegated_bypass`, `secret_scanning_delegated_bypass_options`),
and absent from org/enterprise code-security configurations too -- which are
**org-scoped**, so useless here regardless: 18 of the fleet's repos sit under
a user account, not an org.
[`integrations/terraform-provider-github` issue 3334](https://github.com/integrations/terraform-provider-github/issues/3334)
is the open community request asking for exactly this endpoint. It is UI-only
(repo Settings -> Code security & analysis) or expressible per-repo in a
site's own `.github/dependabot.yml` via `groups:` with `applies-to:
security-updates`.

The engine reports this leaf as a permanent `skip` naming both the manual UI
path and the `dependabot.yml` alternative, and it never carries a `_writer` --
there is nothing `apply_record` could dispatch to. Declaring it (rather than
omitting the key, which would leave it undeclared like any other unmanaged
setting) is deliberate: an omitted third toggle beside two applied ones reads
as "forgotten"; a declared one that always reports `skipped` reads as "known,
blocked, and here is why" -- which is the true state. See
[docs/decisions/0002](../docs/decisions/0002-declare-dependabot-security-settings-including-the-unenforceable-one.md)
for the full reasoning.

## Fleet / fan-out shape

One document describing many repos. `defaults:` is the baseline every repo
inherits; each entry may add `overrides:` (deep-merged over the defaults) or set
`manage: false` to exclude the repo (reported as excluded, not touched).

```yaml
defaults:
  repo:
    # Plain repo setting (applies to private repos too -- see "repo:" above).
    allow_auto_merge: true
  actions:
    sha_pinning_required: true
    fork_pr_approval: all_external_contributors
  security:
    # See "security:" above -- vulnerability_alerts must apply before
    # automated_security_fixes; the engine orders the two records itself.
    vulnerability_alerts: true
    automated_security_fixes: true
    # Declared but not applyable -- see "grouped_security_updates has no API".
    grouped_security_updates: true
  ruleset:
    enabled: true
    name: "default branch protection"
    enforcement: active
    require_pull_request:
      required_approving_review_count: 0
      require_extra_approval_for_unattributed_changes: false
    block_force_pushes: true
    block_deletions: true
    admin_bypass: true

repos:
  # Inherits everything from defaults, incl. repo.allow_auto_merge.
  - name: Adam-S-Daniel/agentskills

  # Private repo: the engine auto-skips fork_pr_approval and the ruleset, but
  # repo.allow_auto_merge still applies (it's not visibility-gated) unless
  # overridden here.
  - name: Adam-S-Daniel/rss-inator
    overrides:
      ruleset: { enabled: false }

  # Scratch/experimental repo: keep the harmless Actions hardening, skip the
  # workflow-changing ruleset.
  - name: Adam-S-Daniel/scratch-jules-001
    overrides:
      ruleset: { enabled: false }

  # Excluded entirely (e.g. a fork, or a repo owned by another settings system).
  - name: Adam-S-Daniel/OctopusDeploy-Api
    manage: false
```

## Downgrade behavior (why one baseline works everywhere)

The engine introspects each repo and skips settings the repo cannot accept,
logging a `skip` with the reason:

| Condition | Skipped setting | API signal |
|-----------|-----------------|------------|
| Private repo | `actions.fork_pr_approval` | 422 "not allowed for private repositories" |
| Private repo without GitHub Pro | `ruleset` | 403 "Upgrade to GitHub Pro" |
| Private repo without GitHub Pro | `repo.allow_auto_merge` | **none -- 200, then silently ignored** |

That third row is the dangerous one, because it is the only downgrade with **no
error to catch**. GitHub offers auto-merge on private repos only on
Pro/Team/Enterprise; below that the `PATCH repos/{owner}/{repo}` succeeds and
the value simply never changes.

This was originally documented here the other way round -- as "a plain repo
setting, not Pro-gated, applied uniformly" -- on the strength of GitHub's docs
for the *public* case. The 2026-08-11 runs disproved it, and the shape of that
mistake is worth keeping: an apply reporting `CHANGED` is **not** evidence the
setting took. Only a later read is.

| Repo | apply 03:16 | diff 03:23 |
|---|---|---|
| `scratch-jules-001` (public) | `CHANGED -> True` | `[ok]` |
| `4A`, `rss-inator`, `jc`, `agentskills-private` (private) | `CHANGED -> True` | `[DRIFT] from: False` |

Same run, same token, same code -- only visibility differs. Left unskipped this
yields a false `CHANGED` on every apply and permanent `DRIFT` on every PR: a red
drift check that merging can never clear, because the write never lands.

If this account moves to Pro/Team/Enterprise, remove the `is_private()` branch
in the `allow_auto_merge` block -- the write path already works; it is the plan
that refuses it.

## The unattributed-changes parameter (why it is declared, not defaulted)

`require_extra_approval_for_unattributed_changes` sits inside the ruleset's
`pull_request` rule and means "require an approving review for changes not
attributed to a user". It is **independent of
`required_approving_review_count`**: the count can be `0` and this can still
demand an approval. Dependabot's commits are unattributed, so the two together
produce a PR that is mergeable, has green checks, and that GitHub refuses:

    mergeStateStatus=BLOCKED
    Pull request ...#40 is not mergeable: the base branch policy prohibits the merge.

Human-authored PRs are attributed and merge normally, so a fleet in this state
looks entirely healthy — only the unattended dependency-merge path dies.
Measured on the nightly sweep: skills-evals run
[32342667620](https://github.com/Adam-S-Daniel/skills-evals/actions/runs/32342667620)
(2026-08-20, scheduled, conclusion `failure`) ended `merged=0 updated=0
skipped=0 failed=3`.

**The discriminator is attributed-vs-unattributed authorship, not the presence
of a required status check.** An early reading of the same failure blamed
`required_status_checks: []`; it is wrong. `agentskills` carries a required
check (`pytest-windows`) and measured this parameter `true` alongside every
other visible fleet ruleset (agentskills, skills-evals, claude-memory-map,
wsl-automation, fastmail-actions, GHA-bench, `_agent-guidance`; 2026-08-20).
`repo-settings`' own ruleset could not be read for that measurement — it is
private and rulesets need GitHub Pro (`GET .../rulesets` → 403 "Upgrade to
GitHub Pro"), which is the same reason the engine skips its ruleset entirely.

Three notes on how the engine treats it:

- **Always written.** `build_ruleset_body` emits the key unconditionally, so
  the converging `PUT` in `write_ruleset` always states it. A key omitted from
  that body is a key GitHub re-defaults to `true` on the next apply.
- **Compared, not merely written.** `normalize_ruleset` carries it, so an
  undeclared value is drift the daily report shows — the same lesson
  `allowed_merge_methods` taught. A payload that omits the key (an API version
  predating the parameter) normalizes to GitHub's default `true`, not `false`:
  guessing `false` would report a clean audit for a rule that is being
  enforced.
- **Round-tripped.** `ruleset_doc` emits it, so `generate` against a repo where
  it is off cannot produce a config that silently re-arms it.

Effective value on a live branch, in one read (works with plain repository read
access, unlike `GET .../rulesets/{id}`):

```bash
gh api "repos/<owner>/<repo>/rules/branches/<branch>" \
  --jq '.[] | select(.type=="pull_request") | .parameters'
```

## Fork-PR approval values (verified against the live API)

The correct enum values are the short forms returned by
`GET repos/{repo}/actions/permissions/fork-pr-contributor-approval`:

| GitHub UI label | API value |
|-----------------|-----------|
| Require approval for first-time contributors | `first_time_contributors` |
| **Require approval for all outside collaborators** | `all_external_contributors` |

## Workflow permissions (`actions.default_workflow_permissions` / `actions.can_approve_pull_request_reviews`)

Settings -> Actions -> General -> Workflow permissions (issue #51). Both
fields live on one endpoint: `GET`/`PUT repos/{repo}/actions/permissions/workflow`
returns/accepts `{"default_workflow_permissions": "read"|"write",
"can_approve_pull_request_reviews": bool}`, either or both keys at once.

- **No private-repo gate.** Unlike `fork_pr_approval` and `ruleset`, this
  endpoint answers on every plan, so the planner never calls `is_private()`
  for it.
- **One PUT carries the whole declared group**, same reasoning as
  `write_merge_methods`: whichever declared key drifted, the apply sends
  every declared key together, so re-applying is idempotent regardless of
  which record triggered the write.
- **`default_workflow_permissions` accepts only `"read"` or `"write"`.** Any
  other value is refused at plan time (a `skipped` record naming the allowed
  values), before any API call -- the same "refuse where a human is reading,
  not as a failed fleet-wide PUT" pattern as the merge-commit-message pairs.
- **A 403 on the read is a `skipped` record per declared key**, not an
  aborted run -- same contract as `security.vulnerability_alerts`' 403
  handling: the App grant this surface is bolted onto predates the setting,
  so a scope gap must not take the whole apply down.
- **A key absent from the payload is a `skipped` record naming that key**,
  not a `KeyError` -- the same defensive-read pattern as every other
  repo/actions field in this file.

**Risk: `can_approve_pull_request_reviews: true` lets `GITHUB_TOKEN` submit
approving reviews.** On a repo whose ruleset requires approvals
(`require_pull_request.required_approving_review_count` > 0), a workflow that
approves its own PR makes that PR count as approved -- the review comes from
a token the repo's own Action controls, not an independent reviewer.
Revisit this setting before raising `required_approving_review_count` on any
repo that has it `true`. skills-evals is the one repo that has it `true`
(docs/decisions/0008); `WorkflowPermissionsFleetConfigTests` fails if it, or
any repo with the setting on, requires approving reviews.
