#!/usr/bin/env python3
"""
repo_settings.py -- repo-settings-as-code for GitHub Actions security settings
and default-branch protection (via GitHub repository rulesets).

Subcommands:

  generate   Introspect a repo's CURRENT settings and emit a repo-settings YAML
             document to stdout (so you can commit it and edit it).

  diff       Compare DESIRED settings (from a config file) against the CURRENT
             live settings and print a drift report. Makes no changes. Exits 1
             if there is drift, 0 if everything already matches, 2 on error.

  apply      Apply DESIRED settings from a config file to the live repo(s).
             Prints per-setting CHANGED / ok / skipped. Use --dry-run to preview.
             Exits non-zero if any apply errored.

  coverage   Report repos the credential can administer that a fleet config
             does not declare. Exits 0 complete, 1 undeclared, 2 on error.

  changes-report
             Render the files `diff --changes-json` wrote as a job-summary
             table or as `::notice` lines, for the reviewer of an apply.

Every subcommand that reads a config exits 2 when the config is refused (see
ConfigError), the same code as "could not ask": 1 already means drift for
`diff` and undeclared repos for `coverage`.

Managed settings:
  * actions.sha_pinning_required           -> repos/{repo}/actions/permissions
  * actions.fork_pr_approval               -> .../actions/permissions/fork-pr-contributor-approval
  * actions.default_workflow_permissions   -> .../actions/permissions/workflow  (PUT, one call
    actions.can_approve_pull_request_reviews  for the declared group -- see
                                               write_workflow_permissions; no private-repo gate)
  * ruleset (default-branch protection)    -> repos/{repo}/rulesets  (idempotent BY NAME)
  * repo.allow_auto_merge                  -> repos/{repo}  (PATCH; skipped on
                                               private repos -- see the downgrade
                                               note below, it is plan-gated there)
  * repo.delete_branch_on_merge            -> repos/{repo}  (PATCH; absent key
                                                            on a low-scope token
                                                            is a skip)
  * repo.allow_merge_commit                -> repos/{repo}  (PATCH, one call for
    repo.allow_squash_merge                   the whole group -- see
    repo.allow_rebase_merge                   write_merge_methods)
  * repo.merge_commit_title                -> repos/{repo}  (PATCH, one call for
    repo.merge_commit_message                  the pair -- see write_merge_commit_message)
  * security.vulnerability_alerts          -> repos/{repo}/vulnerability-alerts
                                               (PUT/DELETE, no body -- the
                                               METHOD carries the value)
  * security.automated_security_fixes      -> repos/{repo}/automated-security-fixes
                                               (PUT/DELETE, no body; requires
                                               vulnerability_alerts -- apply
                                               order is dependency-aware, see
                                               plan_repo)
  * security.codeql_default_setup          -> repos/{repo}/code-scanning/default-setup
    security.codeql_query_suite               (PATCH, one call for the pair --
                                               see write_codeql_default_setup;
                                               skipped on private repos)
  * labels (defaults + per-repo)           -> repos/{repo}/labels/{name}  (GET, then
                                               POST when absent or PATCH on
                                               drift; idempotent BY NAME, never
                                               deletes a label)
  * actions_policies (per-repo only)       -> repos/{repo}/actions/policies  (idempotent
                                               BY NAME; never edits or deletes an
                                               undeclared policy)
  * security.secret_scanning               -> repos/{repo}  (PATCH
    security.secret_scanning_push_protection  `security_and_analysis`, one call
                                               for the pair -- see
                                               write_secret_scanning; skipped
                                               on private and archived repos)
  * security.grouped_security_updates      -> NOT APPLYABLE. No REST endpoint
                                               exists at any scope; declared
                                               and always reported `skipped`
                                               naming the manual UI path.

We use repository RULESETS rather than classic branch protection so the fleet
speaks the same primitive as the cms-platform-managed repos. A managed ruleset
is identified by its `name`: apply creates it if absent, updates it in place if
present, and never touches other rulesets. A repo may declare additional
named rulesets (`extra_rulesets`, per-repo only) handled the same way.

All GitHub access goes through the `gh` CLI, so authentication is whatever `gh`
is configured with: locally your `gh auth` keyring, or in CI the `GH_TOKEN`
environment variable. Writing these settings requires repo-admin (a fine-grained
PAT with "Administration: read and write", a classic PAT with `repo` scope, or a
GitHub App token). The default Actions `GITHUB_TOKEN` cannot change repo settings.

Config schema: see ../repo-settings/schema.md. A SURFACE is one top-level key
of a repo's resolved settings, which plan_repo plans independently: the seven
names in SURFACES. Two shapes are accepted:

  * Single-repo -- top-level surface blocks (`actions:`, `ruleset:`, ...), plus
    an optional top-level `repo:` key that is EITHER the identifier string
    `owner/name` (the existing convention; pass --repo to override it) OR a
    settings map like `{allow_auto_merge: true}` -- the same top-level key
    can't be both at once, so when `repo:` is a map the identifier must come
    from --repo. The surfaces managed are exactly the blocks present.

  * Fleet / fan-out -- a top-level `repos:` array, with an optional `defaults:`
    map that every repo inherits and per-repo `overrides:`. Each element of
    `repos` must carry `manage`, an array of surfaces: `["all"]`, `[]`, or
    surface names in canonical order (validate_manage). A `[]` element is
    skipped (recorded as excluded). Here `repo:` is always a settings map (the
    identifier comes from each element's `name:`), so there is no collision.

Unknown keys are refused at every level -- the file's top level, a `repos`
element, `defaults:` / `overrides:`, and inside each surface -- with an error
naming the accepted keys, so a misspelling cannot silently drop a setting.

The engine auto-detects repo visibility and downgrades gracefully: fork-PR
approval (API 422), rulesets (API 403 "upgrade to Pro") and allow_auto_merge are
skipped on private repos with a logged reason, so one baseline can target public
and private repos.

allow_auto_merge is the awkward one: GitHub offers auto-merge on private repos
only on Pro/Team/Enterprise, and on a plan without it the PATCH returns 200 and
is then silently ignored -- there is no error to catch. Measured 2026-08-11:
a public repo went CHANGED -> True and read back [ok], while four private repos
in the same run went CHANGED -> True and read back False. Left unskipped it
produces a false CHANGED on every apply and permanent DRIFT on every PR.
"""
from __future__ import annotations

import argparse
import copy
import fnmatch
import json
import re
import subprocess
import sys
import urllib.parse
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.stderr.write("error: PyYAML is required. Install with `pip install pyyaml`.\n")
    sys.exit(2)

DEFAULT_RULESET_NAME = "default branch protection"
ADMIN_ROLE_ID = 5  # RepositoryRole id for "Admin" (used for bypass actors)
BYPASS_ACTOR_TYPES = {
    "Integration",
    "OrganizationAdmin",
    "RepositoryRole",
    "Team",
    "DeployKey",
}


# --------------------------------------------------------------------------- #
# gh plumbing
# --------------------------------------------------------------------------- #
class GhError(Exception):
    def __init__(self, status: int | None, message: str):
        self.status = status
        self.message = message
        super().__init__(f"HTTP {status}: {message}" if status else message)


class ConfigError(SystemExit):
    """A config the engine refuses. main() prints the message and exits 2.

    A SystemExit subclass so it unwinds like the engine's older
    `SystemExit("error: ...")` refusals, which main() also maps to exit 2:
    every message-carrying SystemExit in this file is a config error."""


def gh_api(path: str, method: str = "GET", body: dict | None = None,
           api_version: str | None = None) -> Any:
    """Call `gh api`. Return parsed JSON (or None for empty). Raise GhError on
    HTTP failure, parsing the HTTP status out of gh's output when possible.
    `api_version` pins the X-GitHub-Api-Version header for endpoints that need
    a newer one than gh's default."""
    cmd = ["gh", "api", "-X", method, path]
    if api_version:
        cmd += ["-H", f"X-GitHub-Api-Version: {api_version}"]
    stdin = None
    if body is not None:
        cmd += ["--input", "-"]
        stdin = json.dumps(body)
    proc = subprocess.run(cmd, input=stdin, capture_output=True, text=True)
    out = proc.stdout.strip()
    err = proc.stderr.strip()
    if proc.returncode != 0:
        status = None
        for token in ("400", "401", "402", "403", "404", "409", "422", "500"):
            if token in err or token in out:
                status = int(token)
                break
        message = err or out
        try:
            payload = json.loads(out)
            if isinstance(payload, dict) and payload.get("message"):
                message = payload["message"]
                if payload.get("errors"):
                    message += f" ({payload['errors']})"
        except (ValueError, TypeError):
            pass
        raise GhError(status, message)
    if not out:
        return None
    try:
        return json.loads(out)
    except ValueError:
        return out


def get_repo(repo: str) -> dict:
    return gh_api(f"repos/{repo}")


def default_branch(repo: str) -> str:
    return get_repo(repo)["default_branch"]


def write_allow_auto_merge(repo: str, desired: bool) -> None:
    gh_api(f"repos/{repo}", method="PATCH", body={"allow_auto_merge": desired})


def write_delete_branch_on_merge(repo: str, desired: bool) -> None:
    gh_api(f"repos/{repo}", method="PATCH", body={"delete_branch_on_merge": desired})


# The merge-method toggles, in the order GitHub's own UI lists them.
MERGE_METHOD_KEYS = ("allow_merge_commit", "allow_squash_merge", "allow_rebase_merge")


def write_merge_methods(repo: str, desired: dict) -> None:
    """PATCH every managed merge-method toggle in ONE call.

    Not one call per toggle, because GitHub rejects a repository with zero
    merge methods enabled (422) and a per-toggle apply passes through exactly
    that state whenever the run both enables one method and disables another:
    disable-first leaves the repo momentarily with none, and which order the
    records happen to be in is not something the caller controls. Sending the
    whole desired group at once means the repo never occupies the invalid
    state, and re-sending it is idempotent — so it does not matter which of the
    group's records triggered the write.
    """
    gh_api(f"repos/{repo}", method="PATCH", body=dict(desired))


# The two merge-commit-message fields, always written together.
MERGE_COMMIT_MESSAGE_KEYS = ("merge_commit_title", "merge_commit_message")

# The three (title, message) pairs GitHub's own "Allow merge commits" section
# offers, in the order its UI lists them: "Default message", "Default to pull
# request title", and "Default to pull request title and description".
MERGE_COMMIT_MESSAGE_PAIRS = (
    ("MERGE_MESSAGE", "PR_TITLE"),
    ("PR_TITLE", "BLANK"),
    ("PR_TITLE", "PR_BODY"),
)


def write_merge_commit_message(repo: str, desired: dict) -> None:
    """PATCH both merge-commit-message fields in ONE call.

    Same reasoning as write_merge_methods just above: sending the pair
    together means the repo never holds a half-applied combination the config
    did not choose -- whichever of the two records triggered the write, the
    PATCH carries both keys.
    """
    gh_api(f"repos/{repo}", method="PATCH", body=dict(desired))


# The two secret-scanning toggles under `security_and_analysis`, always
# written together.
SECRET_SCANNING_KEYS = ("secret_scanning", "secret_scanning_push_protection")


def write_secret_scanning(repo: str, desired: dict) -> None:
    """PATCH every declared secret-scanning toggle in ONE call.

    Push protection depends on secret scanning, so a per-toggle apply that
    enables both would ask for push protection on a repo whose scanning is
    still off whenever the records happen to come in that order. One PATCH
    carrying the whole declared group never passes through that state.
    """
    gh_api(
        f"repos/{repo}",
        method="PATCH",
        body={
            "security_and_analysis": {
                key: {"status": "enabled" if on else "disabled"}
                for key, on in desired.items()
            }
        },
    )


# --------------------------------------------------------------------------- #
# Actions settings readers/writers
# --------------------------------------------------------------------------- #
def read_actions(repo: str) -> dict:
    return gh_api(f"repos/{repo}/actions/permissions")


# Settings -> Actions -> General -> Workflow permissions (issue #51): the
# GITHUB_TOKEN default scope and "Allow GitHub Actions to create and approve
# pull requests". One endpoint, repos/{repo}/actions/permissions/workflow,
# carries both -- GET/PUT accept either or both keys.
WORKFLOW_PERMISSIONS_KEYS = ("default_workflow_permissions", "can_approve_pull_request_reviews")

# Settings -> Actions -> Policies: repository Actions event policies (REST
# actions/policies, ADR 0009). The endpoints need a newer API version than gh's
# default; `evaluate` enforcement is GitHub Enterprise Cloud only, so it is not
# offered here.
ACTIONS_POLICIES_API_VERSION = "2026-03-10"
ACTIONS_POLICY_ENFORCEMENTS = ("active", "disabled")
ACTIONS_POLICY_KEYS = ("name", "enforcement", "workflow_paths", "allowed_events")


def read_workflow_permissions(repo: str) -> dict:
    # `or {}`: gh_api returns None for an empty body, and callers test key
    # membership -- a None here would TypeError past every GhError guard.
    return gh_api(f"repos/{repo}/actions/permissions/workflow") or {}


def write_workflow_permissions(repo: str, desired: dict) -> None:
    """PUT the whole declared workflow-permissions group in ONE call.

    Same reasoning as write_merge_methods above: the two fields live on one
    endpoint, so sending the declared group together is idempotent regardless
    of which record in the group triggered the write.
    """
    gh_api(f"repos/{repo}/actions/permissions/workflow", method="PUT", body=dict(desired))


def read_fork_approval(repo: str) -> str | None:
    try:
        data = gh_api(f"repos/{repo}/actions/permissions/fork-pr-contributor-approval")
        return data.get("approval_policy")
    except GhError as e:
        if e.status in (403, 404, 422):
            return None
        raise


def read_vulnerability_alerts(repo: str) -> bool | None:
    """Read whether Dependabot ALERTS are on, or None when the read itself
    could not be answered (a scope gap on the credential, not a live value).

    `GET repos/{repo}/vulnerability-alerts` is one of the handful of GitHub
    endpoints that carries its whole answer in the HTTP STATUS and never in a
    body: 204 (No Content) means enabled, 404 means disabled, and there is no
    JSON payload to inspect either way -- `gh_api` already returns None for an
    empty 204, so success here just means "the call did not raise".

    WHY A 404 HERE MEANS "DISABLED" RATHER THAN THE HOUSE RULE'S "NOT
    AUTHORIZED". The account-wide guidance is emphatic that a GitHub 404 is
    ambiguous by design and must not be read as "not there" -- and that rule
    holds precisely because most 404s come from a credential that cannot see
    the resource at all, with no way to tell that apart from a real absence.
    This endpoint is different in one load-bearing way: the fan-out App's
    INSTALLATION is what grants this token visibility into a repo in the
    first place, not some narrower per-endpoint scope layered on top of a
    working credential. A token that cannot see this repo fails `get_repo`
    and the ruleset reads too -- and `plan_repo_records`' fault isolation
    turns THAT failure into a repo-level `error` record, so a session looking
    at the report sees the whole repo flagged, not a lone clean-looking
    "disabled" hiding a blind credential. A 404 on THIS ONE endpoint, with
    every other record for the same repo reading normally, is therefore the
    documented feature-off signal and nothing else -- there is no scope that
    sits between "can administer this repo" and "can read this one flag".

    WHY A 403 MAPS TO None (a skip) RATHER THAN RAISING. This surface is
    being bolted onto an already-working weekly fleet run whose App grant
    predates it -- Administration: Read & write, the same scope every other
    writer in this file relies on, but not proven to cover this specific
    endpoint on every installation until it is actually exercised. A hard
    failure here would take the ENTIRE apply down over one repo's scope gap,
    turning a working enforcement lane into a broken one over a setting that
    used to not exist at all. So `plan_repo` reports it as a visible
    `skipped` record naming the 403 -- the same contract
    `read_fork_approval`'s 403/404/422 handling already uses below -- which
    keeps the gap honest (a reader sees "cannot read") instead of silent (a
    reader sees nothing, or worse, a false "disabled").

    Any OTHER GhError (500, a timeout gh surfaces as a bare non-2xx, etc.) is
    re-raised rather than swallowed into either bucket: plan_repo's caller,
    plan_repo_records, turns an uncaught GhError into a proper `error` record,
    which is the right outcome for a failure that is not one of the two
    documented, well-understood shapes above.
    """
    try:
        gh_api(f"repos/{repo}/vulnerability-alerts")
        return True
    except GhError as e:
        if e.status == 404:
            return False
        if e.status == 403:
            return None
        raise


def read_automated_security_fixes(repo: str) -> bool | None:
    """Read whether Dependabot SECURITY UPDATES are on. Same None-on-403 /
    False-on-404 contract as read_vulnerability_alerts above, and the same
    justification for both (see that function's docstring) -- this is the
    dependent half of the same pair, so the read semantics have to match or a
    plan_repo caller could not compare the two consistently.

    Unlike vulnerability-alerts, this endpoint DOES carry a JSON body on
    current GitHub: `GET repos/{repo}/automated-security-fixes` returns
    `{"enabled": bool, "paused": bool}` with a 200. Older GitHub behaviour --
    still worth tolerating, since we cannot pin which vintage a given
    installation answers with -- was the same 204-empty/404 shape as
    vulnerability-alerts, so a `None` payload (gh_api's return for an empty
    body) is read as the legacy enabled-with-no-body case, exactly like the
    other endpoint.

    `paused` is DELIBERATELY NOT MANAGED. GitHub sets it when Dependabot has
    paused security-update PRs for the repo (e.g. after a run of unmergeable
    updates) as an operational signal, not a policy toggle a human is
    expected to flip back and forth -- there is no PUT/DELETE surface for it
    at all, only the read. Folding it into the desired/current comparison
    here would invent drift the engine has no way to correct.

    A dict WITHOUT an `enabled` key is an unexpected response shape, not a
    value to guess at: an empty dict is treated the same as a legacy
    204-empty success (True), but any other dict missing the key means the
    payload does not match either documented vintage, and this raises rather
    than silently defaulting -- an unexpected shape must never quietly become
    a value the audit reports with confidence it does not have.
    """
    try:
        payload = gh_api(f"repos/{repo}/automated-security-fixes")
    except GhError as e:
        if e.status == 404:
            return False
        if e.status == 403:
            return None
        raise
    if payload is None:
        return True
    if isinstance(payload, dict):
        if "enabled" in payload:
            return bool(payload["enabled"])
        if not payload:
            return True
        raise GhError(
            None,
            f"unexpected automated-security-fixes payload shape for {repo}: "
            f"{payload!r} (missing 'enabled')",
        )
    raise GhError(
        None,
        f"unexpected automated-security-fixes payload type for {repo}: {payload!r}",
    )


def write_sha_pinning(repo: str, current: dict, desired: bool) -> None:
    gh_api(
        f"repos/{repo}/actions/permissions",
        method="PUT",
        body={
            # enabled + allowed_actions are required in the PUT; preserve them.
            "enabled": current.get("enabled", True),
            "allowed_actions": current.get("allowed_actions", "all"),
            "sha_pinning_required": desired,
        },
    )


def write_fork_approval(repo: str, desired: str) -> None:
    gh_api(
        f"repos/{repo}/actions/permissions/fork-pr-contributor-approval",
        method="PUT",
        body={"approval_policy": desired},
    )


def write_vulnerability_alerts(repo: str, desired: bool) -> None:
    """Enable/disable Dependabot alerts. Unlike every other writer in this
    file, the VALUE lives in the HTTP METHOD, not in a request body: PUT
    turns the feature on, DELETE turns it off, and both are called with no
    body at all (`gh_api`'s `body` stays unset -- it already omits `--input`
    for a None body, and this endpoint has nothing to accept anyway)."""
    gh_api(f"repos/{repo}/vulnerability-alerts", method="PUT" if desired else "DELETE")


def write_automated_security_fixes(repo: str, desired: bool) -> None:
    """Enable/disable Dependabot security updates. Same method-carries-the-
    value shape as write_vulnerability_alerts above, and for the same reason:
    this endpoint too takes PUT-to-enable / DELETE-to-disable with no body."""
    gh_api(f"repos/{repo}/automated-security-fixes", method="PUT" if desired else "DELETE")


CODEQL_QUERY_SUITES = ("default", "extended")


def read_codeql_default_setup(repo: str) -> dict | None:
    """Return {"configured": bool, "query_suite": str | None}, or None when
    the read could not be answered (403/404: a scope gap, or code scanning not
    available to the repo) -- a skip, never drift."""
    try:
        data = gh_api(f"repos/{repo}/code-scanning/default-setup") or {}
    except GhError as e:
        if e.status in (403, 404):
            return None
        raise
    # An answer with no `state` is an unknown shape, not "off": reading it as
    # off would PATCH a repo nobody has looked at. cms-platform's
    # audit-repo-settings.js refuses the same shape.
    if not isinstance(data, dict) or not isinstance(data.get("state"), str):
        raise GhError(None, f"repos/{repo}/code-scanning/default-setup returned no 'state'")
    return {
        "configured": data["state"] == "configured",
        "query_suite": data.get("query_suite"),
    }


def write_codeql_default_setup(repo: str, desired: dict) -> None:
    """PATCH CodeQL default setup in ONE call: state plus, when declared, the
    query suite. GitHub detects the languages itself; leaving `languages` out
    keeps that, and a repo that later gains a language picks it up."""
    body: dict = {"state": "configured" if desired.get("codeql_default_setup", True) else "not-configured"}
    if body["state"] == "configured" and desired.get("codeql_query_suite"):
        body["query_suite"] = desired["codeql_query_suite"]
    gh_api(f"repos/{repo}/code-scanning/default-setup", method="PATCH", body=body)


# --------------------------------------------------------------------------- #
# Ruleset handling
# --------------------------------------------------------------------------- #
def list_rulesets(repo: str) -> list[dict]:
    """Return branch rulesets, or raise GhError (403 on private-no-Pro)."""
    data = gh_api(f"repos/{repo}/rulesets")
    return data or []


def get_ruleset(repo: str, ruleset_id: int) -> dict:
    return gh_api(f"repos/{repo}/rulesets/{ruleset_id}")


def find_ruleset(repo: str, name: str) -> dict | None:
    """Return the full ruleset with the given name, or None."""
    summary = next((r for r in list_rulesets(repo) if r.get("name") == name), None)
    if summary is None:
        return None
    return get_ruleset(repo, summary["id"])


# GitHub's enum for bypass_actors[].bypass_mode
# (https://docs.github.com/en/rest/repos/rules#create-a-repository-ruleset).
# Every `bypass_actors` config entry must name one. Kept apart from
# ADMIN_BYPASS_MODES below: that key also accepts `none` and refuses `exempt`.
BYPASS_MODES = ("always", "pull_request", "exempt")


def _bypass_entries(actors: list | None) -> list[dict]:
    """Validate and render `bypass_actors` config entries (shared by the
    default ruleset and every `extra_rulesets` entry)."""
    out: list[dict] = []
    for actor in actors or []:
        if not isinstance(actor, dict) or "actor_id" not in actor:
            raise SystemExit(
                f"error: bypass_actors entries must be mappings with an "
                f"actor_id (got {actor!r})"
            )
        actor_type = actor.get("actor_type")
        if actor_type not in BYPASS_ACTOR_TYPES:
            raise SystemExit(
                f"error: bypass_actors entry has invalid actor_type "
                f"{actor_type!r} (expected one of "
                f"{', '.join(sorted(BYPASS_ACTOR_TYPES))})"
            )
        # Required, with no default: a defaulted mode would grant `always`
        # bypass to an entry that never asked for it (settings-schema-design
        # rule 2). isinstance first: a YAML boolean, or an unhashable value,
        # is never one of the string modes.
        mode = actor.get("bypass_mode")
        if not isinstance(mode, str) or mode not in BYPASS_MODES:
            raise SystemExit(
                f"error: bypass_actors entry {actor!r} needs a bypass_mode, one "
                f"of {' | '.join(BYPASS_MODES)} (got {mode!r})"
            )
        entry = {
            "actor_id": int(actor["actor_id"]),
            "actor_type": actor_type,
            "bypass_mode": mode,
        }
        if entry not in out:
            out.append(entry)
    return out


# `ruleset.admin_bypass`: each accepted value and the `bypass_mode` it gives
# the repository Admin role (None = no admin bypass entry). GitHub's enum for
# bypass_actors[].bypass_mode is always | pull_request | exempt, default always
# (https://docs.github.com/en/rest/repos/rules#create-a-repository-ruleset).
# `pull_request` lets an admin merge a pull request past the rules but not push
# directly. The key grants access, so it is required wherever a ruleset is
# enabled and has no default here: omitting it must not widen access
# (_agent-guidance docs/reference/settings-schema-design.md, rule 2).
ADMIN_BYPASS_MODES: dict[str, str | None] = {
    "always": "always",
    "pull_request": "pull_request",
    "none": None,
}


def admin_bypass_mode(cfg: dict) -> str | None:
    """Validate `admin_bypass` in an enabled ruleset's effective config and
    return the admin role's bypass_mode, or None for no admin entry."""
    accepted = " | ".join(ADMIN_BYPASS_MODES)
    if "admin_bypass" not in cfg:
        raise SystemExit(
            f"error: ruleset.admin_bypass is required when the ruleset is "
            f"enabled (accepted values: {accepted})"
        )
    value = cfg["admin_bypass"]
    # isinstance first: a YAML boolean, or an unhashable value, is never one
    # of the string keys.
    if not isinstance(value, str) or value not in ADMIN_BYPASS_MODES:
        raise SystemExit(
            f"error: ruleset.admin_bypass must be one of {accepted} (got {value!r})"
        )
    return ADMIN_BYPASS_MODES[value]


def build_ruleset_body(cfg: dict) -> dict:
    """Build the POST/PUT body for a desired ruleset from config."""
    name = cfg.get("name", DEFAULT_RULESET_NAME)
    if cfg.get("target_branches"):
        include = [f"refs/heads/{b}" for b in cfg["target_branches"]]
    else:
        include = ["~DEFAULT_BRANCH"]
    rules: list[dict] = []
    if cfg.get("block_deletions", True):
        rules.append({"type": "deletion"})
    if cfg.get("block_force_pushes", True):
        rules.append({"type": "non_fast_forward"})
    pr = cfg.get("require_pull_request")
    if pr is not None:
        rules.append(
            {
                "type": "pull_request",
                "parameters": {
                    "required_approving_review_count": pr.get(
                        "required_approving_review_count", 0
                    ),
                    "dismiss_stale_reviews_on_push": pr.get(
                        "dismiss_stale_reviews", False
                    ),
                    "require_code_owner_review": False,
                    "require_last_push_approval": False,
                    "required_review_thread_resolution": False,
                    # "Require an approval for changes not attributed to a
                    # user." Dependabot's commits are exactly that, so a
                    # Dependabot PR needs an extra approving review even where
                    # `required_approving_review_count` is 0 -- the two
                    # parameters are INDEPENDENT. A human-authored PR is
                    # attributed and merges normally, which is why a fleet with
                    # this on looks entirely healthy right up until the
                    # unattended dependency path is the thing being watched.
                    #
                    # The discriminator is attributed-vs-unattributed
                    # AUTHORSHIP, not the presence of a required status check:
                    # agentskills carries a required check (`pytest-windows`)
                    # and was measured with this parameter true along with
                    # every other visible fleet ruleset (2026-08-20).
                    #
                    # Defaulted True because that is GitHub's own default and
                    # what every fleet ruleset has silently carried since the
                    # engine created it -- so a config that never mentions the
                    # key renders exactly the ruleset it rendered before.
                    # Always emitted, never conditional: `write_ruleset` PUTs
                    # this whole body, so a key omitted here is a key GitHub
                    # re-defaults to true on the next apply.
                    "require_extra_approval_for_unattributed_changes": pr.get(
                        "require_extra_approval_for_unattributed_changes", True
                    ),
                    # Configurable, defaulting to all three so an existing
                    # config's rendered ruleset is unchanged. The fleet sets it
                    # explicitly: without that this rule RE-ASSERTS squash and
                    # rebase on every apply, contradicting the repo-level
                    # toggles it sits beside. Repo-level wins where they
                    # disagree, so this is defence in depth rather than the
                    # enforcement -- but a ruleset that says the opposite of
                    # the policy is one a reader has to reconcile.
                    "allowed_merge_methods": pr.get(
                        "allowed_merge_methods", ["merge", "squash", "rebase"]
                    ),
                },
            }
        )
    checks = cfg.get("required_status_checks") or []
    if checks:
        rules.append(
            {
                "type": "required_status_checks",
                "parameters": {
                    "strict_required_status_checks_policy": False,
                    "required_status_checks": [
                        {"context": c} for c in checks
                    ],
                },
            }
        )
    bypass: list[dict] = []
    admin_mode = admin_bypass_mode(cfg)
    if admin_mode is not None:
        bypass.append(
            {
                "actor_id": ADMIN_ROLE_ID,
                "actor_type": "RepositoryRole",
                "bypass_mode": admin_mode,
            }
        )
    for entry in _bypass_entries(cfg.get("bypass_actors")):
        if entry not in bypass:
            bypass.append(entry)
    return {
        "name": name,
        "target": "branch",
        "enforcement": cfg.get("enforcement", "active"),
        "conditions": {"ref_name": {"include": include, "exclude": []}},
        "rules": rules,
        "bypass_actors": bypass,
    }


# Simple (parameterless, bar `update`) rule types an `extra_rulesets` entry may
# use. `update` restricts who may update the ref; with
# update_allows_fetch_and_merge false only bypass actors may push it.
EXTRA_RULE_TYPES = ("creation", "update", "deletion", "non_fast_forward")


def build_extra_ruleset_body(cfg: dict) -> dict:
    """Build the POST/PUT body for one `extra_rulesets` entry (a ref-protection
    ruleset on non-default branches). Unlike the default ruleset there is no
    implicit admin bypass: every bypass actor is declared."""
    if not isinstance(cfg, dict):
        raise SystemExit(f"error: extra_rulesets entries must be mappings (got {cfg!r})")
    name = cfg.get("name")
    if not isinstance(name, str) or not name.strip():
        raise SystemExit("error: extra_rulesets entry needs a non-empty `name`")
    branches = cfg.get("target_branches")
    if (
        not isinstance(branches, list)
        or not branches
        or not all(isinstance(b, str) and b for b in branches)
    ):
        raise SystemExit(
            f"error: extra_rulesets[{name}] needs a non-empty `target_branches` "
            f"list of branch names/patterns"
        )
    rule_names = cfg.get("rules")
    if not isinstance(rule_names, list) or not rule_names:
        raise SystemExit(f"error: extra_rulesets[{name}] needs a non-empty `rules` list")
    rules: list[dict] = []
    for rt in rule_names:
        if rt not in EXTRA_RULE_TYPES:
            raise SystemExit(
                f"error: extra_rulesets[{name}] has unsupported rule type {rt!r} "
                f"(allowed: {', '.join(EXTRA_RULE_TYPES)})"
            )
        if any(r["type"] == rt for r in rules):
            raise SystemExit(f"error: extra_rulesets[{name}] lists rule {rt!r} twice")
        rule: dict = {"type": rt}
        if rt == "update":
            rule["parameters"] = {"update_allows_fetch_and_merge": False}
        rules.append(rule)
    return {
        "name": name,
        "target": "branch",
        "enforcement": cfg.get("enforcement", "active"),
        "conditions": {
            "ref_name": {"include": [f"refs/heads/{b}" for b in branches], "exclude": []}
        },
        "rules": rules,
        "bypass_actors": _bypass_entries(cfg.get("bypass_actors")),
    }


def build_extra_ruleset_bodies(settings: dict) -> list[dict]:
    """Validate and build every `extra_rulesets` entry of one repo's settings.
    Names must be unique and must not collide with the default-branch ruleset
    (the engine matches live rulesets BY NAME)."""
    entries = settings.get("extra_rulesets") or []
    if not isinstance(entries, list):
        raise SystemExit("error: extra_rulesets must be a list")
    default_name = (settings.get("ruleset") or {}).get("name", DEFAULT_RULESET_NAME)
    seen = {default_name}
    bodies = []
    for cfg in entries:
        body = build_extra_ruleset_body(cfg)
        if body["name"] in seen:
            raise SystemExit(
                f"error: extra_rulesets name {body['name']!r} is duplicated or "
                f"collides with the default-branch ruleset name"
            )
        seen.add(body["name"])
        bodies.append(body)
    return bodies


def _extra_rule_params(rule: dict) -> dict:
    """A rule's parameters minus GitHub-omitted defaults: GitHub stores an
    `update` rule with update_allows_fetch_and_merge false as a bare
    {"type": "update"}, so a live/desired compare must treat them alike."""
    params = dict(rule.get("parameters") or {})
    if rule.get("type") == "update" and params.get("update_allows_fetch_and_merge") is False:
        del params["update_allows_fetch_and_merge"]
    return params


# GitHub returns `bypass_actors` only to a caller that can edit the ruleset.
# The "Get a repository ruleset" REST docs say: "To prevent leaking sensitive
# information, the bypass_actors property is only returned if the user making
# the API request has write access to the ruleset."
# (https://docs.github.com/en/rest/repos/rules#get-a-repository-ruleset).
# PR #95 measured it: a read-only token got no field, and 9 rulesets read as
# `'bypass': []` drift. So an ABSENT field normalizes to BYPASS_UNKNOWN, never
# to [], and plan_ruleset compares everything else; a present [] still compares.
BYPASS_UNKNOWN = None


def _normalize_bypass(rs_: dict) -> list | None:
    if "bypass_actors" not in rs_:
        return BYPASS_UNKNOWN
    return sorted(
        (b.get("actor_type"), b.get("actor_id"), b.get("bypass_mode"))
        for b in rs_["bypass_actors"] or []
    )


def normalize_extra_ruleset(rs_: dict | None) -> dict | None:
    """Reduce an extra ruleset (live or desired) to comparable fields. Rules are
    compared as a set of (type, parameters); includes and bypass sorted."""
    if rs_ is None:
        return None
    cond = rs_.get("conditions", {}).get("ref_name", {})
    rules = sorted(
        (r["type"], json.dumps(_extra_rule_params(r), sort_keys=True))
        for r in rs_.get("rules", [])
    )
    return {
        "enforcement": rs_.get("enforcement"),
        "include": sorted(cond.get("include", [])),
        "exclude": sorted(cond.get("exclude", [])),
        "rules": rules,
        "bypass": _normalize_bypass(rs_),
    }


def normalize_ruleset(rs: dict | None) -> dict | None:
    """Reduce a ruleset (live or a desired body) to the fields we manage, so
    current vs desired can be compared field-for-field."""
    if rs is None:
        return None
    rules_by_type: dict[str, dict] = {}
    for r in rs.get("rules", []):
        rules_by_type[r["type"]] = r.get("parameters", {}) or {}
    pr = rules_by_type.get("pull_request", {})
    checks = sorted(
        c["context"]
        for c in rules_by_type.get("required_status_checks", {}).get(
            "required_status_checks", []
        )
    )
    include = sorted(
        rs.get("conditions", {}).get("ref_name", {}).get("include", [])
    )
    bypass = _normalize_bypass(rs)
    return {
        "enforcement": rs.get("enforcement"),
        "include": include,
        "rule_types": sorted(rules_by_type.keys()),
        "pr_approvals": pr.get("required_approving_review_count"),
        "pr_dismiss_stale": bool(pr.get("dismiss_stale_reviews_on_push", False)),
        # Compared, not merely written -- the same lesson as merge_methods
        # below. Until this line existed the engine had no concept of the
        # parameter at all: `apply` could never set it and `diff` could never
        # report it, so the repo whose whole job is settings-as-code carried a
        # live, load-bearing ruleset parameter that was neither declared nor
        # audited. Absent from a payload (an API version predating the
        # parameter) we read GitHub's own default, True, rather than False --
        # guessing False there would report a CLEAN audit for a rule that is in
        # fact being enforced.
        "pr_extra_approval_unattributed": bool(
            pr.get("require_extra_approval_for_unattributed_changes", True)
        ),
        # Compared, not merely written: this was absent, so a hand-edit in the
        # UI adding squash back to the ruleset produced no drift and nothing
        # ever said so. Sorted because GitHub does not promise an order and an
        # unordered compare would report drift on a reshuffle.
        "merge_methods": sorted(pr.get("allowed_merge_methods") or []),
        "checks": checks,
        "bypass": bypass,
    }


def ruleset_doc(branch_rs: dict) -> dict:
    """Reduce a live branch ruleset to the config-schema `ruleset:` block
    (the inverse of build_ruleset_body, for `generate`)."""
    norm = normalize_ruleset(branch_rs)
    if norm["bypass"] is BYPASS_UNKNOWN:
        # Emitting "none" here would write a config that strips every bypass
        # actor on the next apply.
        raise SystemExit(
            f"error: ruleset {branch_rs.get('name')!r} was read without "
            f"bypass_actors (this token cannot edit it); generate needs a token "
            f"that can"
        )
    doc = {
        "enabled": True,
        "name": branch_rs.get("name"),
        "enforcement": branch_rs.get("enforcement"),
        "require_pull_request": {
            "required_approving_review_count": norm["pr_approvals"] or 0,
            # Carried through, or `generate` would emit a config that rebuilds
            # into a DIFFERENT ruleset than the one it read -- silently widening
            # a merge-only repo back to all three methods.
            "allowed_merge_methods": norm["merge_methods"],
            # Carried through for the same reason as allowed_merge_methods
            # above: without it, `generate` against a repo that has this
            # switched off emits a config that rebuilds with the True default
            # -- silently re-arming the rule on the next apply.
            "require_extra_approval_for_unattributed_changes": norm[
                "pr_extra_approval_unattributed"
            ],
        }
        if "pull_request" in norm["rule_types"]
        else None,
        "block_force_pushes": "non_fast_forward" in norm["rule_types"],
        "block_deletions": "deletion" in norm["rule_types"],
        "required_status_checks": norm["checks"],
        # The admin role's live bypass_mode, or "none". A mode outside
        # ADMIN_BYPASS_MODES (GitHub's `exempt`) is emitted as read, so the
        # generated config fails validation rather than silently changing it.
        "admin_bypass": next(
            (
                m
                for (t, i, m) in norm["bypass"]
                if t == "RepositoryRole" and i == ADMIN_ROLE_ID
            ),
            "none",
        ),
    }
    extra = [
        {"actor_type": t, "actor_id": i, "bypass_mode": m}
        for (t, i, m) in norm["bypass"]
        if not (t == "RepositoryRole" and i == ADMIN_ROLE_ID)
    ]
    if extra:
        doc["bypass_actors"] = extra
    return doc


BYPASS_UNKNOWN_NOTE = (
    "bypass actors not returned to this token (it cannot edit the ruleset) "
    "-- bypass not compared"
)
BYPASS_UNKNOWN_REFUSAL = (
    "refusing to write ruleset: the live read has no bypass_actors (this "
    "token cannot edit the ruleset), so a PUT would overwrite bypass actors "
    "it cannot see"
)


def write_ruleset(repo: str, body: dict, existing_id: int | None,
                  bypass_unknown: bool = False) -> None:
    if bypass_unknown:
        # Never write blind: a PUT replaces bypass_actors wholesale, and this
        # read could not see what it would overwrite.
        raise GhError(None, BYPASS_UNKNOWN_REFUSAL)
    if existing_id is not None:
        gh_api(f"repos/{repo}/rulesets/{existing_id}", method="PUT", body=body)
    else:
        gh_api(f"repos/{repo}/rulesets", method="POST", body=body)


# --------------------------------------------------------------------------- #
# Labels (per-repo only)
# --------------------------------------------------------------------------- #
LABEL_COLOR_RE = re.compile(r"[0-9a-fA-F]{6}")
LABEL_DESCRIPTION_MAX = 100  # GitHub rejects longer descriptions (422)


def build_label_specs(settings: dict) -> list[dict]:
    """Validate and normalize every `labels` entry of one repo's settings.

    A label is identified BY NAME, and GitHub compares names case-insensitively,
    so two entries differing only in case are the same label and are refused.
    Color is six hex digits with no leading `#` (the REST shape), lowercased so
    the compare against the live value is exact. Description is optional and
    defaults to empty, which is also what GitHub returns for none."""
    entries = settings.get("labels") or []
    if not isinstance(entries, list):
        raise SystemExit("error: labels must be a list")
    specs: list[dict] = []
    seen: set[str] = set()
    for cfg in entries:
        if not isinstance(cfg, dict):
            raise SystemExit(f"error: labels entries must be mappings (got {cfg!r})")
        name = cfg.get("name")
        if not isinstance(name, str) or not name.strip():
            raise SystemExit("error: labels entry needs a non-empty `name`")
        color = cfg.get("color")
        if not isinstance(color, str) or not LABEL_COLOR_RE.fullmatch(color):
            raise SystemExit(
                f"error: labels[{name}] needs a `color` of six hex digits with "
                f"no leading '#' (got {color!r})"
            )
        description = cfg.get("description", "")
        if description is None:
            description = ""
        if not isinstance(description, str) or len(description) > LABEL_DESCRIPTION_MAX:
            raise SystemExit(
                f"error: labels[{name}] `description` must be a string of at most "
                f"{LABEL_DESCRIPTION_MAX} characters"
            )
        if name.lower() in seen:
            raise SystemExit(f"error: labels name {name!r} is duplicated (names are case-insensitive)")
        seen.add(name.lower())
        specs.append({"name": name, "color": color.lower(), "description": description})
    return specs


def normalize_label(label: dict | None) -> dict | None:
    """Reduce a label (live or desired) to the fields we manage."""
    if label is None:
        return None
    return {
        "name": label.get("name"),
        "color": str(label.get("color") or "").lower(),
        "description": label.get("description") or "",
    }


def _label_path(repo: str, name: str) -> str:
    return f"repos/{repo}/labels/{urllib.parse.quote(name, safe='')}"


def read_label(repo: str, name: str) -> dict | None:
    """The live label, or None on a 404. A bare 404 is ambiguous (label gone, or
    repo invisible to this credential): the caller probes the repo to tell."""
    try:
        return gh_api(_label_path(repo, name))
    except GhError as e:
        if e.status == 404:
            return None
        raise


def write_label(repo: str, spec: dict, exists: bool) -> None:
    """Create the label (POST), or converge an existing one in place (PATCH,
    which also repairs a name that differs only in case). Never deletes."""
    body = {"color": spec["color"], "description": spec["description"]}
    if exists:
        gh_api(_label_path(repo, spec["name"]), method="PATCH",
               body=dict(body, new_name=spec["name"]))
    else:
        gh_api(f"repos/{repo}/labels", method="POST", body=dict(body, name=spec["name"]))


# --------------------------------------------------------------------------- #
# Actions policies (per-repo only)
# --------------------------------------------------------------------------- #
def _str_list(value: Any, allow_empty: bool) -> bool:
    return (
        isinstance(value, list)
        and (allow_empty or bool(value))
        and all(isinstance(v, str) and v for v in value)
    )


def build_actions_policy_body(cfg: dict) -> dict:
    """Build the POST/PUT body for one `actions_policies` entry: a repository
    Actions event policy that allows only the listed events for the workflow
    files it covers. `allowed_events` is an ALLOWLIST -- every unlisted event is
    blocked for those workflows -- so the scope is declared, never defaulted."""
    if not isinstance(cfg, dict):
        raise SystemExit(f"error: actions_policies entries must be mappings (got {cfg!r})")
    unknown = [k for k in cfg if k not in ACTIONS_POLICY_KEYS]
    if unknown:
        raise SystemExit(
            f"error: actions_policies entry has unknown key(s) {', '.join(map(repr, unknown))} "
            f"(allowed: {', '.join(ACTIONS_POLICY_KEYS)})"
        )
    name = cfg.get("name")
    if not isinstance(name, str) or not name.strip():
        raise SystemExit("error: actions_policies entry needs a non-empty `name`")
    enforcement = cfg.get("enforcement", "active")
    if enforcement == "evaluate":
        raise SystemExit(
            f"error: actions_policies[{name}] enforcement 'evaluate' is GitHub "
            f"Enterprise Cloud only (allowed: {', '.join(ACTIONS_POLICY_ENFORCEMENTS)})"
        )
    if enforcement not in ACTIONS_POLICY_ENFORCEMENTS:
        raise SystemExit(
            f"error: actions_policies[{name}] enforcement must be one of "
            f"{', '.join(ACTIONS_POLICY_ENFORCEMENTS)} (got {enforcement!r})"
        )
    paths = cfg.get("workflow_paths")
    if not isinstance(paths, dict):
        raise SystemExit(
            f"error: actions_policies[{name}] needs a `workflow_paths` mapping "
            f"with an `include` list"
        )
    bad = [k for k in paths if k not in ("include", "exclude")]
    if bad:
        raise SystemExit(
            f"error: actions_policies[{name}] workflow_paths has unknown key(s) "
            f"{', '.join(map(repr, bad))} (allowed: include, exclude)"
        )
    include = paths.get("include")
    if not _str_list(include, allow_empty=False):
        raise SystemExit(
            f"error: actions_policies[{name}] workflow_paths.include needs a "
            f"non-empty list of workflow file paths (or '~ALL')"
        )
    if "~ALL" in include and len(include) > 1:
        raise SystemExit(
            f"error: actions_policies[{name}] workflow_paths.include '~ALL' must "
            f"stand alone"
        )
    exclude = paths.get("exclude", [])
    if not _str_list(exclude, allow_empty=True):
        raise SystemExit(
            f"error: actions_policies[{name}] workflow_paths.exclude must be a "
            f"list of workflow file paths"
        )
    events = cfg.get("allowed_events")
    if not _str_list(events, allow_empty=False):
        raise SystemExit(
            f"error: actions_policies[{name}] needs a non-empty `allowed_events` "
            f"list of event names"
        )
    if len(set(events)) != len(events):
        raise SystemExit(f"error: actions_policies[{name}] allowed_events lists an event twice")
    return {
        "name": name,
        "enforcement": enforcement,
        "conditions": {"workflow_path": {"include": include, "exclude": exclude}},
        "rules": [
            {"type": "restrict_action_events", "parameters": {"allowed_events": events}}
        ],
    }


def build_actions_policy_bodies(settings: dict) -> list[dict]:
    """Validate and build every `actions_policies` entry of one repo's settings.
    Names must be unique (the engine matches live policies BY NAME)."""
    entries = settings.get("actions_policies") or []
    if not isinstance(entries, list):
        raise SystemExit("error: actions_policies must be a list")
    seen: set[str] = set()
    bodies = []
    for cfg in entries:
        body = build_actions_policy_body(cfg)
        if body["name"] in seen:
            raise SystemExit(f"error: actions_policies name {body['name']!r} is duplicated")
        seen.add(body["name"])
        bodies.append(body)
    return bodies


def normalize_actions_policy(p: dict | None) -> dict | None:
    """Reduce an Actions policy (live or desired) to the managed fields, so the
    server-added ones (id, node_id, _links, timestamps, source, source_type,
    target) never register as drift. Rules compare as a set of (type,
    parameters); the name is the match key, not a compared field."""
    if p is None:
        return None
    cond = (p.get("conditions") or {}).get("workflow_path") or {}
    rules = []
    for r in p.get("rules") or []:
        params = dict(r.get("parameters") or {})
        if isinstance(params.get("allowed_events"), list):
            params["allowed_events"] = sorted(params["allowed_events"])
        rules.append((r.get("type"), json.dumps(params, sort_keys=True)))
    return {
        "enforcement": p.get("enforcement"),
        "include": sorted(cond.get("include") or []),
        "exclude": sorted(cond.get("exclude") or []),
        "rules": sorted(rules),
    }


def list_actions_policies(repo: str) -> list[dict] | None:
    """Return the repository's own Actions policies (every page), or None when a
    page is not a payload carrying a `policies` list. Inherited org/enterprise
    policies are dropped: they are not ours even when the name matches. Raises
    GhError (403/404/422 without Administration: write)."""
    out: list[dict] = []
    page = 1
    while True:
        data = gh_api(
            f"repos/{repo}/actions/policies?per_page=100&page={page}",
            api_version=ACTIONS_POLICIES_API_VERSION,
        )
        if not isinstance(data, dict) or not isinstance(data.get("policies"), list):
            return None
        batch = data["policies"]
        out += [
            p for p in batch
            if isinstance(p, dict) and p.get("source_type", "Repository") == "Repository"
        ]
        if len(batch) < 100:
            return out
        page += 1


def get_actions_policy(repo: str, policy_id: int) -> dict:
    return gh_api(
        f"repos/{repo}/actions/policies/{policy_id}",
        api_version=ACTIONS_POLICIES_API_VERSION,
    ) or {}


def write_actions_policy(repo: str, body: dict, existing_id: int | None) -> None:
    """Converging writer, like write_ruleset: PUT the whole body over an existing
    policy, else POST it. Never DELETEs -- retiring a policy is a manual step."""
    if existing_id is not None:
        gh_api(f"repos/{repo}/actions/policies/{existing_id}", method="PUT",
               body=body, api_version=ACTIONS_POLICIES_API_VERSION)
    else:
        gh_api(f"repos/{repo}/actions/policies", method="POST",
               body=body, api_version=ACTIONS_POLICIES_API_VERSION)


def actions_policy_doc(p: dict) -> dict | None:
    """Render a live policy as an `actions_policies` config entry (for
    `generate`), or None when it is not expressible in that shape: no rules, a
    rule other than `restrict_action_events`, an enforcement we do not manage,
    or an empty include."""
    rules = p.get("rules") or []
    if not rules or any(r.get("type") != "restrict_action_events" for r in rules):
        return None
    if p.get("enforcement") not in ACTIONS_POLICY_ENFORCEMENTS:
        return None
    cond = (p.get("conditions") or {}).get("workflow_path") or {}
    include = list(cond.get("include") or [])
    if not include:
        return None
    events: list[str] = []
    for r in rules:
        for ev in (r.get("parameters") or {}).get("allowed_events") or []:
            if ev not in events:
                events.append(ev)
    return {
        "name": p.get("name"),
        "enforcement": p["enforcement"],
        "workflow_paths": {"include": include, "exclude": list(cond.get("exclude") or [])},
        "allowed_events": events,
    }


# --------------------------------------------------------------------------- #
# Config handling
# --------------------------------------------------------------------------- #
def deep_merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def merge_labels(default_labels, repo_labels) -> list:
    """Fleet-wide `defaults.labels` plus a repo's own `labels`; the repo's
    entry replaces a default of the same name. Shape errors are left for
    build_label_specs to refuse, so a non-list passes through untouched."""
    if repo_labels is None:
        return copy.deepcopy(default_labels)
    if not isinstance(default_labels, list) or not isinstance(repo_labels, list):
        return copy.deepcopy(repo_labels)
    own = {
        str(c.get("name")).lower() for c in repo_labels if isinstance(c, dict)
    }
    kept = [
        c for c in default_labels
        if not (isinstance(c, dict) and str(c.get("name")).lower() in own)
    ]
    return copy.deepcopy(kept + repo_labels)


# The surfaces: the top-level keys of one repo's resolved settings, each of
# which plan_repo plans independently. Surfaces are top-level only -- there is
# no way to manage part of `actions`. Defined ONCE: `manage` validation, the
# unknown-key checks, the single-repo shape and every error message are built
# from this tuple. Its order is the canonical order a `manage` array must use,
# and it is alphabetical so a human can write it without looking it up.
SURFACES = (
    "actions",
    "actions_policies",
    "extra_rulesets",
    "labels",
    "repo",
    "ruleset",
    "security",
)
# `manage: ["all"]` -- every surface, INCLUDING any added to SURFACES later
# (docs/decisions/0011).
MANAGE_ALL = "all"

# Surfaces whose value is a map; the rest are arrays of maps.
MAP_SURFACES = ("actions", "repo", "ruleset", "security")

# The keys each surface's planner reads: for a map surface the keys of the map,
# for an array surface the keys of each element. Derived from plan_repo and the
# build_* helpers; a key not listed here is one the engine would silently
# ignore, so it is refused instead.
SURFACE_KEYS = {
    "actions": (
        "sha_pinning_required",
        "fork_pr_approval",
        *WORKFLOW_PERMISSIONS_KEYS,
    ),
    "actions_policies": ACTIONS_POLICY_KEYS,
    "extra_rulesets": ("name", "enforcement", "target_branches", "rules", "bypass_actors"),
    "labels": ("name", "color", "description"),
    "repo": (
        "allow_auto_merge",
        "delete_branch_on_merge",
        *MERGE_METHOD_KEYS,
        *MERGE_COMMIT_MESSAGE_KEYS,
    ),
    "ruleset": (
        "enabled",
        "name",
        "enforcement",
        "target_branches",
        "require_pull_request",
        "block_force_pushes",
        "block_deletions",
        "required_status_checks",
        "admin_bypass",
        "bypass_actors",
    ),
    "security": (
        "vulnerability_alerts",
        "automated_security_fixes",
        "grouped_security_updates",
        *SECRET_SCANNING_KEYS,
        "codeql_default_setup",
        "codeql_query_suite",
    ),
}

# Accepted keys of the fleet shape's top level and of each `repos` element.
FLEET_KEYS = ("defaults", "repos")
REPO_ELEMENT_KEYS = ("name", "manage", "overrides")

MANAGE_ACCEPTED = (
    f'expected an array: ["{MANAGE_ALL}"] for every surface (including any '
    f"added later), [] for none, or one or more of {', '.join(SURFACES)}, in "
    f"that order"
)

# The three cms-platform-managed repos (docs/decisions/0016). cms-platform owns
# every surface but one through its own manifest, so here they may manage
# `labels` and nothing else, and only the names on CMS_LABEL_ALLOWLIST: the
# fleet-wide default label the engine must create there. CMS_OWNED_LABELS are
# fnmatch patterns of the label names cms-platform's workflows (and Decap, for
# `decap-cms/*`) create and own; the engine must never write them. Names and
# patterns compare case-insensitively, as on GitHub.
CMS_LABEL_ONLY_REPOS = (
    "Adam-S-Daniel/adamdaniel.ai",
    "Adam-S-Daniel/cms-platform",
    "jodidaniel/jodidaniel.com",
)
CMS_LABEL_ALLOWLIST = ("agent-authored",)
CMS_OWNED_LABELS = (
    "ci",
    "cms/*",
    "cms/draft",
    "cms/preview-only",
    "cms/ready",
    "content-guard/override",
    "decap-cms/*",
    "not-decap-created",
)
CMS_LABEL_ONLY_MANAGE = ("labels",)


def _json(value: Any) -> str:
    """Render a config value the way the docs write it: `["labels"]`, not
    Python's `['labels']`."""
    try:
        return json.dumps(value)
    except (TypeError, ValueError):
        return repr(value)


class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader that refuses a map with the same key twice. PyYAML's own
    loaders silently keep the LAST one, so a second `manage:` or `ruleset:` in
    one element would quietly win over the first."""


def _construct_unique_mapping(loader: yaml.SafeLoader, node: yaml.MappingNode,
                              deep: bool = False) -> dict:
    seen: dict = {}
    for key_node, _value in node.value:
        if key_node.tag == "tag:yaml.org,2002:merge":
            continue  # `<<:` merges are flattened by construct_mapping
        key = loader.construct_object(key_node, deep=True)
        try:
            first = seen.get(key)
        except TypeError:
            continue  # unhashable key: construct_mapping reports it
        if first is not None:
            raise ConfigError(
                f"error: duplicate key {key!r} at line {key_node.start_mark.line + 1} "
                f"(first at line {first.start_mark.line + 1}); a map may name a "
                f"key once"
            )
        seen[key] = key_node
    return loader.construct_mapping(node, deep=deep)


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def load_config(path: str) -> dict:
    """Read a config file with the duplicate-key-refusing loader. A file that
    does not parse, or whose top level is not a map, is a ConfigError."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            cfg = yaml.load(fh, Loader=_UniqueKeyLoader)  # a SafeLoader subclass
    except ConfigError as e:
        raise ConfigError(f"{e.code} in {path}") from e
    except yaml.YAMLError as e:
        raise ConfigError(f"error: {path} is not valid YAML: {e}") from e
    if cfg is None:
        return {}
    if not isinstance(cfg, dict):
        raise ConfigError(f"error: {path}: the top level must be a map (got {_json(cfg)})")
    return cfg


def _check_keys(where: str, value: dict, accepted) -> None:
    unknown = [k for k in value if k not in accepted]
    if unknown:
        raise ConfigError(
            f"error: {where}: unknown key(s) {', '.join(map(repr, unknown))} "
            f"(accepted: {', '.join(accepted)})"
        )


def validate_surfaces(where: str, block: dict) -> None:
    """Check a map of surfaces (`defaults:`, an element's `overrides:`, or the
    single-repo top level): only surface names, each of the right shape, each
    carrying only the keys its planner reads. Values are left to plan_repo and
    the build_* helpers, which own them."""
    _check_keys(where, block, SURFACES)
    for surface, value in block.items():
        at = f"{where}.{surface}"
        if surface in MAP_SURFACES:
            if not isinstance(value, dict):
                raise ConfigError(f"error: {at} must be a map (got {_json(value)})")
            _check_keys(at, value, SURFACE_KEYS[surface])
        else:
            if not isinstance(value, list):
                raise ConfigError(f"error: {at} must be an array (got {_json(value)})")
            for i, element in enumerate(value):
                # A non-map element is left to the surface's build_* helper,
                # which refuses it with its own message.
                if isinstance(element, dict):
                    _check_keys(f"{at}[{i}]", element, SURFACE_KEYS[surface])


def validate_manage(where: str, value: Any) -> list[str]:
    """Return a `manage` value if it is one of the documented ones, else raise
    ConfigError. One meaning, one value: `["all"]`, `[]`, or surface names
    from SURFACES, each once, in SURFACES' order, short of naming all seven."""

    def bad(problem: str) -> ConfigError:
        return ConfigError(f"error: {where}: `manage` {problem}; {MANAGE_ACCEPTED}")

    if not isinstance(value, list):
        raise bad(f"must be an array, not {_json(value)}")
    for element in value:
        if not isinstance(element, str):
            raise bad(
                f"element {_json(element)} is not a string (PyYAML loads an "
                f"unquoted no, yes, on or off as a boolean)"
            )
    if MANAGE_ALL in value:
        if value != [MANAGE_ALL]:
            raise bad(f'"{MANAGE_ALL}" must stand alone, not in {_json(value)}')
        return list(value)
    unknown = [e for e in value if e not in SURFACES]
    if unknown:
        raise bad(f"names unknown surface(s) {_json(unknown)}")
    if len(set(value)) != len(value):
        raise bad(f"names a surface twice in {_json(value)}")
    canonical = [s for s in SURFACES if s in value]
    if value != canonical:
        raise bad(f"must list surfaces in canonical order: write {_json(canonical)}")
    if len(value) == len(SURFACES):
        raise bad(f'names every surface; write ["{MANAGE_ALL}"]')
    return list(value)


def _validate_builders(where: str, settings: dict) -> None:
    """Run the surfaces' own value checks (the build_* helpers) over one repo's
    DECLARED settings, so a bad value is refused before anything is planned --
    including on a surface the repo's `manage` leaves out."""
    try:
        build_label_specs(settings)
        build_extra_ruleset_bodies(settings)
        build_actions_policy_bodies(settings)
        ruleset_cfg = settings.get("ruleset") or {}
        if ruleset_cfg.get("enabled"):
            build_ruleset_body(ruleset_cfg)
    except SystemExit as e:
        if isinstance(e.code, str):
            raise ConfigError(f"{e.code} (in {where})") from e
        raise


def manages(target: dict, surface: str) -> bool:
    """Whether `target` manages `surface`. The only way to ask: never test
    target["manage"] for truthiness."""
    if surface not in SURFACES:
        raise ValueError(f"unknown surface {surface!r}")
    manage = target["manage"]
    return MANAGE_ALL in manage or surface in manage


def manage_label(target: dict) -> str:
    """What `diff`, `apply` and `coverage` print about a target's scope."""
    manage = target["manage"]
    if not any(manages(target, s) for s in SURFACES):
        return "excluded (manage: [])"
    if MANAGE_ALL in manage:
        return f"managed: {MANAGE_ALL}"
    return "managed: " + ", ".join(s for s in SURFACES if manages(target, s))


def effective_settings(declared: dict, manage: list[str]) -> dict:
    """Keep only the surfaces `manage` lists. Applied after the defaults and
    merge_labels, so a surface reaches plan_repo only when named: it fails
    closed."""
    if MANAGE_ALL in manage:
        return copy.deepcopy(declared)
    return {k: copy.deepcopy(v) for k, v in declared.items() if k in manage}


def is_cms_label_only(repo: str) -> bool:
    return repo.casefold() in {r.casefold() for r in CMS_LABEL_ONLY_REPOS}


def _cms_owned(name: str) -> bool:
    return any(
        fnmatch.fnmatchcase(name.casefold(), pat.casefold())
        for pat in CMS_OWNED_LABELS
    )


def check_cms_label_only(target: dict) -> None:
    """Refuse a config that would let the engine touch more than the fleet-wide
    label in a cms-platform-managed repo (docs/decisions/0016). Runs for every
    target in CMS_LABEL_ONLY_REPOS, in both config shapes."""
    if not is_cms_label_only(target["repo"]):
        return
    where = f"repos[{target['repo']}]"
    manage = target["manage"]
    if manage not in ([], list(CMS_LABEL_ONLY_MANAGE)):
        raise ConfigError(
            f"error: {where}: `manage` is {_json(manage)}; a cms-platform-managed "
            f"repo accepts only [] or {_json(list(CMS_LABEL_ONLY_MANAGE))}, because "
            f"cms-platform owns every other surface"
        )
    if not manages(target, "labels"):
        return  # labels never reach the repo, so none are checked
    allowed = {n.casefold() for n in CMS_LABEL_ALLOWLIST}
    refused = []
    # EVERY entry, not the first bad one: the message names them all.
    for entry in target["effective"].get("labels") or []:
        if not isinstance(entry, dict):
            continue  # build_label_specs refuses a non-map entry
        name = str(entry.get("name"))
        if name.casefold() not in allowed or _cms_owned(name):
            refused.append(name)
    if refused:
        raise ConfigError(
            f"error: {where}: label(s) {', '.join(repr(n) for n in refused)} are not "
            f"allowed; this repo may carry only {', '.join(CMS_LABEL_ALLOWLIST)} "
            f"(cms-platform owns labels matching {', '.join(CMS_OWNED_LABELS)})"
        )


def resolve_targets(cfg: dict, repo_arg: str | None) -> list[dict]:
    """Validate a config and resolve it into one target per repo:
    `{"repo", "manage", "declared", "effective"}`. `declared` is the repo's
    settings after defaults and overrides, before filtering; `effective` keeps
    only the surfaces `manage` names, and is what plan_repo is given. The
    whole config is validated before anything is filtered, so a `[]` element
    and an unmanaged surface are checked too."""
    if "repos" in cfg:  # fleet mode
        _check_keys("top level", cfg, FLEET_KEYS)
        defaults = cfg.get("defaults", {})
        if not isinstance(defaults, dict):
            raise ConfigError(f"error: defaults must be a map (got {_json(defaults)})")
        validate_surfaces("defaults", defaults)
        # Per-repo only: deep_merge REPLACES lists, so a defaults-level list
        # would be silently dropped by any repo that declares its own, and a
        # ruleset with bypass actors is a repo-specific grant (ADR 0004).
        if "extra_rulesets" in defaults:
            raise ConfigError(
                "error: extra_rulesets is per-repo only -- declare it under a "
                "repo's `overrides:`, not `defaults:`"
            )
        # Same list-replacement hazard, and a policy names one repo's workflow
        # files: a defaults-level policy would point at files other repos lack.
        if "actions_policies" in defaults:
            raise ConfigError(
                "error: actions_policies is per-repo only -- declare it under a "
                "repo's `overrides:`, not `defaults:`"
            )
        repos = cfg["repos"]
        if not isinstance(repos, list):
            raise ConfigError(f"error: repos must be an array (got {_json(repos)})")
        targets = []
        seen: dict[str, str] = {}
        for i, entry in enumerate(repos):
            if not isinstance(entry, dict):
                # A bare `- owner/repo` string cannot carry `manage`.
                raise ConfigError(
                    f"error: repos[{i}] must be a map with `name` and `manage` "
                    f"(got {_json(entry)}); write `- name: ...` with `manage:`"
                )
            name = entry.get("name")
            if (
                not isinstance(name, str)
                or name.count("/") != 1
                or not all(name.split("/"))
            ):
                raise ConfigError(
                    f"error: repos[{i}] needs `name: owner/repo` (got {_json(name)})"
                )
            where = f"repos[{name}]"
            _check_keys(where, entry, REPO_ELEMENT_KEYS)
            if name.lower() in seen:
                raise ConfigError(
                    f"error: {where} is declared twice (as {seen[name.lower()]!r} "
                    f"and {name!r}); repo names compare case-insensitively"
                )
            seen[name.lower()] = name
            if "manage" not in entry:
                raise ConfigError(f"error: {where}: `manage` is required; {MANAGE_ACCEPTED}")
            manage = validate_manage(where, entry["manage"])
            overrides = entry.get("overrides", {})
            if not isinstance(overrides, dict):
                raise ConfigError(
                    f"error: {where}.overrides must be a map (got {_json(overrides)})"
                )
            validate_surfaces(f"{where}.overrides", overrides)
            declared = deep_merge(defaults, overrides)
            if "labels" in defaults:
                # deep_merge REPLACES lists, so merge labels here instead: the
                # fleet-wide labels plus the repo's own, a repo entry winning a
                # name clash (names compare case-insensitively, as on GitHub).
                declared["labels"] = merge_labels(defaults["labels"], overrides.get("labels"))
            _validate_builders(where, declared)
            target = {
                "repo": name,
                "manage": manage,
                "declared": declared,
                "effective": effective_settings(declared, manage),
            }
            check_cms_label_only(target)
            targets.append(target)
        return targets
    repo_field = cfg.get("repo")
    # `repo:` is overloaded in this shape: the pre-existing convention is the
    # identifier string `owner/name`; the new settings map (e.g.
    # {allow_auto_merge: true}) is a different, mutually-exclusive use of the
    # same key. Only fall back to it as the identifier when it's a string, so
    # an existing config's `repo: owner/name` keeps working unchanged.
    repo = repo_arg or (repo_field if isinstance(repo_field, str) else None)
    if not repo:
        raise ConfigError(
            "error: single-repo config needs a top-level `repo: owner/name` "
            "or a --repo argument."
        )
    # The surfaces are the blocks present, through the same constant -- an
    # omitted block is not managed. A string `repo:` is the identifier, not a
    # surface.
    declared = {
        k: v for k, v in cfg.items() if not (k == "repo" and isinstance(v, str))
    }
    validate_surfaces("top level", declared)
    _validate_builders(repo, declared)
    manage = [s for s in SURFACES if s in declared]
    target = {
        "repo": repo,
        "manage": manage,
        "declared": declared,
        "effective": effective_settings(declared, manage),
    }
    check_cms_label_only(target)
    return [target]


# --------------------------------------------------------------------------- #
# Planning: desired vs current -> list of change records
# --------------------------------------------------------------------------- #
def plan_repo(repo: str, settings: dict) -> list[dict]:
    records: list[dict] = []
    meta: dict = {}  # cache for private lookup
    actions_cfg = settings.get("actions") or {}
    ruleset_cfg = settings.get("ruleset") or {}
    repo_cfg = settings.get("repo") or {}

    def is_private() -> bool:
        if "private" not in meta:
            meta["private"] = bool(get_repo(repo)["private"])
        return meta["private"]

    # -- sha pinning -------------------------------------------------------- #
    if "sha_pinning_required" in actions_cfg:
        desired = bool(actions_cfg["sha_pinning_required"])
        try:
            cur = read_actions(repo)
            current = bool(cur.get("sha_pinning_required"))
            records.append(
                {
                    "setting": "actions.sha_pinning_required",
                    "status": "match" if current == desired else "drift",
                    "current": current,
                    "desired": desired,
                    "_writer": ("sha", cur, desired),
                }
            )
        except GhError as e:
            records.append(_err("actions.sha_pinning_required", desired, e))

    # -- fork PR approval --------------------------------------------------- #
    fork = actions_cfg.get("fork_pr_approval", "unset")
    if fork != "unset" and fork is not None:
        if is_private():
            records.append(_skip("actions.fork_pr_approval", fork,
                                 "private repo -- fork-PR approval not applicable (API 422)"))
        else:
            try:
                current = read_fork_approval(repo)
                records.append(
                    {
                        "setting": "actions.fork_pr_approval",
                        "status": "match" if current == fork else "drift",
                        "current": current,
                        "desired": fork,
                        "_writer": ("fork", None, fork),
                    }
                )
            except GhError as e:
                records.append(_err("actions.fork_pr_approval", fork, e))

    # -- workflow permissions (GITHUB_TOKEN scope + PR-approval) ------------- #
    # No plan gate, unlike fork_pr_approval above: this endpoint works on
    # every plan, public and private alike -- the planner must not even ask
    # whether the repo is private.
    wp_wanted = {
        key: actions_cfg[key]
        for key in WORKFLOW_PERMISSIONS_KEYS
        if actions_cfg.get(key, "unset") not in ("unset", None)
    }
    if wp_wanted:
        perm = wp_wanted.get("default_workflow_permissions")
        if "default_workflow_permissions" in wp_wanted and perm not in ("read", "write"):
            # Refused here, where a human is reading, rather than as a failed
            # PUT against the fleet -- GitHub only accepts these two values.
            for key, desired in wp_wanted.items():
                records.append(
                    _skip(f"actions.{key}", desired,
                          "default_workflow_permissions must be 'read' or 'write'")
                )
        else:
            try:
                payload = read_workflow_permissions(repo)
            except GhError as e:
                if e.status == 403:
                    for key, desired in wp_wanted.items():
                        records.append(
                            _skip(f"actions.{key}", desired,
                                  "cannot read -- HTTP 403 (token lacks Administration "
                                  "on this repo)")
                        )
                else:
                    for key, desired in wp_wanted.items():
                        records.append(_err(f"actions.{key}", desired, e))
            else:
                for key in WORKFLOW_PERMISSIONS_KEYS:
                    if key not in wp_wanted:
                        continue
                    desired = wp_wanted[key]
                    if key not in payload:
                        # Same defensive read as the repo-field blocks below:
                        # an unexpected payload shape must never KeyError past
                        # plan_repo_records' GhError-only guard.
                        records.append(
                            _skip(f"actions.{key}", desired,
                                  f"GitHub did not return {key} for this repo "
                                  "(token scope or payload shape) -- leaving it "
                                  "unmanaged")
                        )
                        continue
                    if key == "can_approve_pull_request_reviews":
                        current = bool(payload[key])
                        desired_v: Any = bool(desired)
                    else:
                        current = payload[key]
                        desired_v = str(desired)
                    records.append(
                        {
                            "setting": f"actions.{key}",
                            "status": "match" if current == desired_v else "drift",
                            "current": current,
                            "desired": desired_v,
                            # Every record in the group carries the WHOLE
                            # declared group: see write_workflow_permissions
                            # for why it is one PUT.
                            "_writer": ("workflow_permissions", None, wp_wanted),
                        }
                    )

    # -- security (Dependabot alerts + security updates) --------------------- #
    # Three possible leaves, at most three records, in an order that is a real
    # dependency and not cosmetics -- see below.
    security_cfg = settings.get("security") or {}

    vuln_rec: dict | None = None
    if "vulnerability_alerts" in security_cfg:
        vuln_desired = bool(security_cfg["vulnerability_alerts"])
        try:
            current = read_vulnerability_alerts(repo)
        except GhError as e:
            vuln_rec = _err("security.vulnerability_alerts", vuln_desired, e)
        else:
            if current is None:
                # 403: the read itself could not be answered (a scope gap on
                # a grant that predates this setting), not a live value -- see
                # read_vulnerability_alerts' docstring for why this is a skip
                # and not a raised error.
                vuln_rec = _skip(
                    "security.vulnerability_alerts", vuln_desired,
                    "cannot read -- HTTP 403 (token lacks Administration on this repo)",
                )
            else:
                vuln_rec = {
                    "setting": "security.vulnerability_alerts",
                    "status": "match" if current == vuln_desired else "drift",
                    "current": current,
                    "desired": vuln_desired,
                    "_writer": ("vuln_alerts", None, vuln_desired),
                }

    autofix_rec: dict | None = None
    autofix_desired = False
    if "automated_security_fixes" in security_cfg:
        autofix_desired = bool(security_cfg["automated_security_fixes"])
        try:
            current = read_automated_security_fixes(repo)
        except GhError as e:
            autofix_rec = _err("security.automated_security_fixes", autofix_desired, e)
        else:
            if current is None:
                autofix_rec = _skip(
                    "security.automated_security_fixes", autofix_desired,
                    "cannot read -- HTTP 403 (token lacks Administration on this repo)",
                )
            else:
                autofix_rec = {
                    "setting": "security.automated_security_fixes",
                    "status": "match" if current == autofix_desired else "drift",
                    "current": current,
                    "desired": autofix_desired,
                    "_writer": ("auto_sec_fixes", None, autofix_desired),
                }

    # ORDERING IS A REAL DEPENDENCY, NOT COSMETICS. Dependabot security
    # updates require Dependabot alerts to be on -- an alert is what a
    # security-update PR resolves, so switching on the dependent before the
    # prerequisite exists asks GitHub for a PR against nothing. `cmd_apply`
    # walks `drift` records in LIST ORDER, so the order these two are
    # appended in is the write order the apply actually performs:
    #   desired True  -> alerts first, security updates second (enable the
    #                     prerequisite, then the thing that depends on it)
    #   desired False -> security updates first, alerts second (disable the
    #                     dependent before pulling the floor out from under
    #                     it, so a run that dies partway through never leaves
    #                     the repo with updates on and alerts off)
    # This mirrors write_merge_methods' reasoning a few sections up: the
    # invalid intermediate state is real, GitHub's ordinary per-record apply
    # would produce it depending on which record happens to come first, and
    # the fix is to make the record order state the dependency explicitly
    # rather than leave it to whichever order a dict happened to iterate in.
    if autofix_desired:
        records.extend(r for r in (vuln_rec, autofix_rec) if r is not None)
    else:
        records.extend(r for r in (autofix_rec, vuln_rec) if r is not None)

    if "grouped_security_updates" in security_cfg:
        # ALWAYS a skip, never a drift record and never a _writer -- GitHub
        # exposes no REST endpoint for grouped security updates at repo OR
        # org level (absent from `security_and_analysis`, absent from
        # org/enterprise code-security configurations -- which are org-only
        # anyway and so unreachable for the fleet repos that sit under a
        # user account). It is UI-only, or expressible per-repo in
        # `.github/dependabot.yml` via `groups:` with `applies-to:
        # security-updates`. Declaring the key at all (rather than omitting
        # it) records the fleet's INTENT even though no automation here can
        # ever converge it -- see fleet.yml's comment on this leaf for why
        # that is deliberate rather than an oversight.
        records.append(
            _skip(
                "security.grouped_security_updates",
                bool(security_cfg["grouped_security_updates"]),
                "no REST endpoint exists at repo or org level -- enable by hand in "
                "Settings -> Code security & analysis, or express per-repo grouping "
                "in .github/dependabot.yml via groups: with applies-to: "
                "security-updates",
            )
        )

    # -- secret scanning + push protection ----------------------------------- #
    # Free on public repos. On a private repo without GitHub Secret Protection
    # (Advanced Security) the API refuses them, and an archived repo is
    # read-only, so both plan a skip rather than a write that can only fail.
    ss_wanted = {
        key: bool(security_cfg[key])
        for key in SECRET_SCANNING_KEYS
        if security_cfg.get(key) is not None
    }
    if ss_wanted:
        if is_private():
            for key, desired in ss_wanted.items():
                records.append(
                    _skip(f"security.{key}", desired,
                          "private repo -- secret scanning needs GitHub Secret "
                          "Protection (Advanced Security), which the API refuses "
                          "without")
                )
        else:
            try:
                repo_obj = get_repo(repo)
            except GhError as e:
                for key, desired in ss_wanted.items():
                    records.append(_err(f"security.{key}", desired, e))
            else:
                if repo_obj.get("archived"):
                    # An archived repo is read-only: the PATCH would fail, and
                    # nothing new can be pushed to it to leak a secret.
                    for key, desired in ss_wanted.items():
                        records.append(
                            _skip(f"security.{key}", desired,
                                  "archived repo -- read-only, nothing to protect")
                        )
                else:
                    # Read defensively, like the repo-field blocks below:
                    # `security_and_analysis` is returned only to a token that
                    # may administer the repo, and a KeyError here would
                    # escape plan_repo_records' GhError-only guard.
                    saa = repo_obj.get("security_and_analysis")
                    for key, desired in ss_wanted.items():
                        entry = saa.get(key) if isinstance(saa, dict) else None
                        status = entry.get("status") if isinstance(entry, dict) else None
                        if status not in ("enabled", "disabled"):
                            records.append(
                                _skip(f"security.{key}", desired,
                                      f"GitHub did not return "
                                      f"security_and_analysis.{key} for this repo "
                                      "(token scope or payload shape) -- leaving "
                                      "it unmanaged")
                            )
                            continue
                        current = status == "enabled"
                        records.append(
                            {
                                "setting": f"security.{key}",
                                "status": "match" if current == desired else "drift",
                                "current": current,
                                "desired": desired,
                                # The WHOLE declared pair: see write_secret_scanning.
                                "_writer": ("secret_scanning", None, ss_wanted),
                            }
                        )

    # CodeQL default setup. Free on public repos; on a private repo it needs
    # GitHub Code Security, which a personal account cannot buy, so private
    # repos get an explicit skip.
    cq_wanted = {k: security_cfg[k] for k in ("codeql_default_setup", "codeql_query_suite")
                 if security_cfg.get(k) is not None}
    if cq_wanted:
        if "codeql_default_setup" in cq_wanted:
            cq_wanted["codeql_default_setup"] = bool(cq_wanted["codeql_default_setup"])
        if cq_wanted.get("codeql_query_suite", "default") not in CODEQL_QUERY_SUITES:
            raise ConfigError(
                f"error: security.codeql_query_suite must be one of {', '.join(CODEQL_QUERY_SUITES)} "
                f"(got {_json(cq_wanted['codeql_query_suite'])})")
        try:
            private = is_private()
            live = None if private else read_codeql_default_setup(repo)
        except GhError as e:
            records.extend(_err(f"security.{k}", v, e) for k, v in cq_wanted.items())
        else:
            if private or live is None:
                note = ("private repo -- CodeQL needs GitHub Code Security (not offered to "
                        "personal accounts)") if private else \
                       "cannot read code-scanning/default-setup -- HTTP 403/404"
                records.extend(_skip(f"security.{k}", v, note) for k, v in cq_wanted.items())
            else:
                current = {"codeql_default_setup": live["configured"],
                           "codeql_query_suite": live["query_suite"] if live["configured"] else None}
                for key, desired_v in cq_wanted.items():
                    if key == "codeql_query_suite" and cq_wanted.get("codeql_default_setup") is False:
                        continue  # a suite means nothing with default setup off
                    records.append({
                        "setting": f"security.{key}",
                        "status": "match" if current[key] == desired_v else "drift",
                        "current": current[key],
                        "desired": desired_v,
                        # Every record carries the WHOLE declared group: see
                        # write_codeql_default_setup for why it is one PATCH.
                        "_writer": ("codeql", None, cq_wanted),
                    })

    # -- ruleset ------------------------------------------------------------ #
    def plan_ruleset(name: str, body: dict, normalize) -> None:
        try:
            existing = find_ruleset(repo, name)
            existing_id = existing["id"] if existing else None
            current, desired = normalize(existing), normalize(body)
            unknown = current is not None and current["bypass"] is BYPASS_UNKNOWN
            if unknown:
                # Compare all but the bypass list: the rest decides between
                # an informational skip and drift on what does differ. Never
                # `match` (the bypass is unverified), never drift BY the bypass.
                current = dict(current, bypass="unknown")
                rest_same = all(
                    current[k] == desired[k] for k in desired if k != "bypass"
                )
                if rest_same:
                    records.append(
                        _skip(f"ruleset[{name}]", desired, BYPASS_UNKNOWN_NOTE)
                    )
                    return
            same = current == desired
            rec = {
                "setting": f"ruleset[{name}]",
                "status": "match" if same else "drift",
                "current": current,
                "desired": desired,
                "_writer": ("ruleset", body, existing_id),
                # The live body as GitHub returned it, for write_risk: the PUT
                # replaces the whole ruleset, fields `normalize` drops included.
                "_live": existing,
            }
            if unknown:
                rec["note"] = BYPASS_UNKNOWN_NOTE
                rec["bypass_unknown"] = True
            records.append(rec)
        except GhError as e:
            if e.status in (402, 403) and is_private():
                records.append(_skip(f"ruleset[{name}]", "enabled",
                                     "private repo without GitHub Pro -- rulesets "
                                     "not available (API 403)"))
            else:
                records.append(_err(f"ruleset[{name}]", "enabled", e))

    if ruleset_cfg.get("enabled"):
        name = ruleset_cfg.get("name", DEFAULT_RULESET_NAME)
        plan_ruleset(name, build_ruleset_body(ruleset_cfg), normalize_ruleset)
    elif "admin_bypass" in ruleset_cfg:
        # Not required while disabled, but a value that is given is checked.
        admin_bypass_mode(ruleset_cfg)

    # Extra named rulesets: same by-name idempotence. Removing an entry from
    # config leaves its live ruleset alone (never touches undeclared rulesets).
    for extra_body in build_extra_ruleset_bodies(settings):
        plan_ruleset(extra_body["name"], extra_body, normalize_extra_ruleset)

    # -- allow auto-merge ---------------------------------------------------- #
    auto_merge = repo_cfg.get("allow_auto_merge", "unset")
    if auto_merge != "unset" and auto_merge is not None:
        desired = bool(auto_merge)
        if is_private():
            # GitHub offers auto-merge on PRIVATE repos only on Pro/Team/
            # Enterprise. On a plan without it the PATCH is ACCEPTED and
            # returns 200 -- it is simply never honoured, so there is no error
            # to catch, unlike the 422/403 the two settings above give us.
            #
            # Measured 2026-08-11, one apply run and the diff seven minutes
            # later, same token, same code:
            #   scratch-jules-001 (public):  CHANGED -> True, then [ok]
            #   4A / rss-inator / jc / agentskills-private (private):
            #                                CHANGED -> True, then still False
            # Without this skip every private repo reports a false CHANGED on
            # every apply and permanent DRIFT on every PR -- a red drift check
            # that no merge can ever clear.
            #
            # If this account moves to Pro/Team/Enterprise, drop this branch:
            # the write path already works, it is the plan that refuses it.
            records.append(
                _skip(
                    "repo.allow_auto_merge",
                    desired,
                    "private repo without GitHub Pro -- auto-merge not available "
                    "(PATCH returns 200 but is silently ignored)",
                )
            )
        else:
            try:
                repo_obj = get_repo(repo)
            except GhError as e:
                records.append(_err("repo.allow_auto_merge", desired, e))
            else:
                # Read defensively rather than subscripting: a KeyError here would
                # escape the `except GhError` above AND plan_repo_records' own
                # GhError-only guard, aborting the entire fleet run over one repo's
                # unexpected payload. GitHub returns `allow_auto_merge` on the full
                # repository object, but a token without the scope to see it (or a
                # future payload change) would otherwise be a fleet-wide outage.
                if "allow_auto_merge" not in repo_obj:
                    records.append(
                        _skip(
                            "repo.allow_auto_merge",
                            desired,
                            "GitHub did not return allow_auto_merge for this repo "
                            "(token scope or payload shape) -- leaving it unmanaged",
                        )
                    )
                else:
                    current = bool(repo_obj["allow_auto_merge"])
                    records.append(
                        {
                            "setting": "repo.allow_auto_merge",
                            "status": "match" if current == desired else "drift",
                            "current": current,
                            "desired": desired,
                            "_writer": ("auto_merge", None, desired),
                        }
                    )

    # -- delete branch on merge ---------------------------------------------- #
    # "Automatically delete head branches". A plain repo field like the merge
    # toggles below — honoured on every plan, public and private alike — so it
    # gets no private gate of the kind allow_auto_merge needs above.
    #
    # WHY IT IS MANAGED AT ALL, since a leftover branch sounds cosmetic. A bot
    # that opens a pull request from a fixed branch name cannot re-propose
    # while a branch of that name still exists carrying content it did not
    # write, and refusing to force-push over it is the correct behaviour —
    # that rule is what stops it clobbering a reviewer's commit. So a merged
    # PR whose branch outlives it silently disables the bot for that repo, and
    # nothing goes red: the bot exits 0 and the repo just stops receiving
    # updates. Measured 2026-08-25: five of ten lock-carrying repos had been
    # stuck that way since 2026-08-21, serving a stale skills bundle while
    # their own session-start verdict read OK.
    #
    # _agent-guidance's bumper now deletes its own branch after merging, which
    # is the fix for the bot that has one. This setting is the fleet-wide
    # backstop for every OTHER automation, present and future, that does not.
    delete_on_merge = repo_cfg.get("delete_branch_on_merge", "unset")
    if delete_on_merge != "unset" and delete_on_merge is not None:
        desired = bool(delete_on_merge)
        try:
            repo_obj = get_repo(repo)
        except GhError as e:
            records.append(_err("repo.delete_branch_on_merge", desired, e))
        else:
            # The same defensive read as the two blocks around it, and for the
            # same reason: this is one of the MERGE-SETTING fields GitHub
            # returns only to a token with write-level contents access. Below
            # that the key is ABSENT, not false — so a subscript here would
            # KeyError past plan_repo_records' GhError-only guard and take the
            # whole fleet run down over one repo's payload. See AGENTS.md,
            # "Merge-setting fields go missing on a low-scope token".
            if "delete_branch_on_merge" not in repo_obj:
                records.append(
                    _skip("repo.delete_branch_on_merge", desired,
                          "GitHub did not return delete_branch_on_merge for this "
                          "repo (token scope or payload shape) — leaving it "
                          "unmanaged")
                )
            else:
                current = bool(repo_obj["delete_branch_on_merge"])
                records.append(
                    {
                        "setting": "repo.delete_branch_on_merge",
                        "status": "match" if current == desired else "drift",
                        "current": current,
                        "desired": desired,
                        "_writer": ("delete_branch_on_merge", None, desired),
                    }
                )

    # -- merge methods ------------------------------------------------------- #
    # No plan gate, unlike allow_auto_merge above: these are ordinary
    # repository fields honoured on every plan, public and private alike, so
    # they are read and written the same way everywhere.
    wanted = {
        key: bool(repo_cfg[key])
        for key in MERGE_METHOD_KEYS
        if repo_cfg.get(key, "unset") not in ("unset", None)
    }
    if wanted:
        if not any(wanted.values()) and len(wanted) == len(MERGE_METHOD_KEYS):
            # GitHub 422s a repo with no merge method at all, so a config
            # saying that is refused HERE, where a human is reading, rather
            # than as a failed apply against every repo in the fleet.
            for key in wanted:
                records.append(
                    _skip(f"repo.{key}", wanted[key],
                          "config disables every merge method; GitHub requires at "
                          "least one — leaving all three unmanaged")
                )
        else:
            try:
                repo_obj = get_repo(repo)
            except GhError as e:
                for key, desired in wanted.items():
                    records.append(_err(f"repo.{key}", desired, e))
            else:
                for key, desired in wanted.items():
                    if key not in repo_obj:
                        # Same defensive read as allow_auto_merge above: a
                        # KeyError here would abort the whole fleet run.
                        records.append(
                            _skip(f"repo.{key}", desired,
                                  f"GitHub did not return {key} for this repo "
                                  "(token scope or payload shape) — leaving it "
                                  "unmanaged")
                        )
                        continue
                    current = bool(repo_obj[key])
                    records.append(
                        {
                            "setting": f"repo.{key}",
                            "status": "match" if current == desired else "drift",
                            "current": current,
                            "desired": desired,
                            # Every record in the group carries the WHOLE group:
                            # see write_merge_methods for why it is one call.
                            "_writer": ("merge_methods", None, wanted),
                        }
                    )

    # -- merge commit message ------------------------------------------------ #
    # merge_commit_title / merge_commit_message -- the pair behind GitHub's
    # "Allow merge commits" message choice. Why this is managed at all, and
    # why only the three pairs the UI offers are accepted:
    #
    # A PR description carried into the merge commit (PR_BODY) becomes commit
    # text, and a closing keyword next to an issue number closes that issue
    # from commit text even inside backticks -- commit text is not markdown,
    # so quoting the keyword does nothing. Measured 2026-09-15 on
    # scratch-claude-001: the same description with the keyword in a code span
    # left its issue open under MERGE_MESSAGE/PR_TITLE, and closed it through
    # the merge commit under PR_TITLE/PR_BODY
    # (https://github.com/Adam-S-Daniel/_agent-guidance/issues/132#issuecomment-5687434470).
    # Refusing any pair GitHub's own settings page does not offer means a
    # human reading the config finds out at plan time, rather than an apply
    # writing a combination nobody picked from that page.
    wanted = {
        key: repo_cfg[key]
        for key in MERGE_COMMIT_MESSAGE_KEYS
        if repo_cfg.get(key, "unset") not in ("unset", None)
    }
    if wanted:
        if len(wanted) != len(MERGE_COMMIT_MESSAGE_KEYS):
            for key in wanted:
                records.append(
                    _skip(f"repo.{key}", wanted[key],
                          "declare merge_commit_title and merge_commit_message "
                          "together — they are one setting on GitHub's side; "
                          "leaving it unmanaged")
                )
        else:
            title = wanted["merge_commit_title"]
            message = wanted["merge_commit_message"]
            if (str(title), str(message)) not in MERGE_COMMIT_MESSAGE_PAIRS:
                for key in wanted:
                    records.append(
                        _skip(f"repo.{key}", wanted[key],
                              "not one of the pairs GitHub's 'Allow merge "
                              "commits' section offers -- MERGE_MESSAGE/"
                              "PR_TITLE, PR_TITLE/BLANK or PR_TITLE/PR_BODY -- "
                              "leaving it unmanaged")
                    )
            else:
                try:
                    repo_obj = get_repo(repo)
                except GhError as e:
                    for key, desired in wanted.items():
                        records.append(_err(f"repo.{key}", desired, e))
                else:
                    for key, desired in wanted.items():
                        if key not in repo_obj:
                            # Same defensive read as allow_auto_merge and the
                            # merge-method block above, and for the same
                            # reason: a KeyError here would escape
                            # plan_repo_records' GhError-only guard and abort
                            # the whole fleet run over one repo's payload.
                            records.append(
                                _skip(f"repo.{key}", desired,
                                      f"GitHub did not return {key} for this "
                                      "repo (token scope or payload shape) — "
                                      "leaving it unmanaged")
                            )
                            continue
                        current = repo_obj[key]
                        records.append(
                            {
                                "setting": f"repo.{key}",
                                "status": "match" if current == desired else "drift",
                                "current": current,
                                "desired": desired,
                                # Every record carries the WHOLE pair: see
                                # write_merge_commit_message for why it is one
                                # call.
                                "_writer": ("merge_commit_message", None, wanted),
                            }
                        )

    # -- Actions policies ---------------------------------------------------- #
    # Per-repo, by name (like `ruleset:`): the engine owns only the names a repo
    # declares, never edits or deletes an undeclared or inherited policy, and an
    # entry removed from config leaves its live policy alone. Not
    # visibility-gated. Every endpoint, GET included, needs the repository
    # Administration: write permission, so a read the credential cannot make is
    # an informational skip, not drift (see schema.md).
    policy_bodies = build_actions_policy_bodies(settings)
    if policy_bodies:

        def policy_skip(status: int | None) -> str:
            return (
                f"cannot read Actions policies -- HTTP {status} (needs the repository "
                "Administration: write permission; see schema.md)"
            )

        try:
            live_policies = list_actions_policies(repo)
        except GhError as e:
            for body in policy_bodies:
                setting = f"actions_policy[{body['name']}]"
                desired = normalize_actions_policy(body)
                if e.status in (403, 404, 422):
                    records.append(_skip(setting, desired, policy_skip(e.status)))
                else:
                    records.append(_err(setting, desired, e))
        else:
            for body in policy_bodies:
                name = body["name"]
                setting = f"actions_policy[{name}]"
                desired = normalize_actions_policy(body)
                if live_policies is None:
                    records.append(
                        _skip(setting, desired,
                              "GitHub did not return a `policies` list for this repo "
                              "(token scope or payload shape) -- leaving Actions "
                              "policies unmanaged")
                    )
                    continue
                matches = [p for p in live_policies if p.get("name") == name]
                if len(matches) > 1:
                    records.append(
                        {
                            "setting": setting,
                            "status": "error",
                            "current": None,
                            "desired": desired,
                            "note": f"{len(matches)} repository Actions policies are "
                                    f"named {name!r} -- the engine matches by name and "
                                    "will not guess; delete the extras by hand",
                        }
                    )
                    continue
                existing = None
                existing_id = None
                if matches:
                    existing_id = matches[0].get("id")
                    if existing_id is None:
                        records.append(
                            _skip(setting, desired,
                                  f"the live Actions policy named {name!r} carries no "
                                  "id -- leaving it unmanaged")
                        )
                        continue
                    try:
                        existing = get_actions_policy(repo, existing_id)
                    except GhError as e:
                        if e.status in (403, 404, 422):
                            records.append(_skip(setting, desired, policy_skip(e.status)))
                        else:
                            records.append(_err(setting, desired, e))
                        continue
                current = normalize_actions_policy(existing)
                records.append(
                    {
                        "setting": setting,
                        "status": "match" if current == desired else "drift",
                        "current": current,
                        "desired": desired,
                        "_writer": ("actions_policy", body, existing_id),
                    }
                )

    # -- labels --------------------------------------------------------------- #
    # Per-repo only, by name, never deleting: an entry removed from config
    # leaves its live label alone. No private-repo gate: labels exist on every
    # plan. Writing one needs the credential's Issues (or Pull requests) write
    # permission. The fan-out App holds Issues: write (README, "CI fan-out");
    # any credential that does not gets an `error` record for the write, never
    # a silent skip.
    for spec in build_label_specs(settings):
        setting = f"label[{spec['name']}]"
        desired = normalize_label(spec)
        try:
            live = read_label(repo, spec["name"])
            if live is None:
                # A bare 404 reads the same whether the label is missing or the
                # repo is invisible to this credential. Probe the repo: it
                # raises GhError for the second case, which then surfaces as an
                # error record instead of a bogus "missing -> create".
                get_repo(repo)
        except GhError as e:
            records.append(_err(setting, desired, e))
            continue
        current = normalize_label(live)
        records.append(
            {
                "setting": setting,
                "status": "match" if current == desired else "drift",
                "current": current,
                "desired": desired,
                "_writer": ("label", spec, live is not None),
            }
        )

    return records


def plan_repo_records(repo: str, settings: dict) -> list[dict]:
    """plan_repo with per-repo fault isolation: a repo-level API failure
    (deleted or renamed repo, no access) becomes one error record instead of
    aborting the whole fleet run."""
    try:
        return plan_repo(repo, settings)
    except GhError as e:
        return [
            {
                "setting": "repo",
                "status": "error",
                "current": None,
                "desired": None,
                "note": e.message,
            }
        ]


def _err(setting: str, desired: Any, e: GhError) -> dict:
    return {"setting": setting, "status": "error", "current": None,
            "desired": desired, "note": e.message}


def _skip(setting: str, desired: Any, note: str) -> dict:
    return {"setting": setting, "status": "skipped", "current": None,
            "desired": desired, "note": note}


def apply_record(repo: str, rec: dict) -> None:
    kind, a, b = rec["_writer"]
    if kind == "sha":
        write_sha_pinning(repo, a, b)
    elif kind == "fork":
        write_fork_approval(repo, b)
    elif kind == "workflow_permissions":
        write_workflow_permissions(repo, b)
    elif kind == "ruleset":
        write_ruleset(repo, a, b, rec.get("bypass_unknown", False))
    elif kind == "label":
        write_label(repo, a, b)
    elif kind == "actions_policy":
        write_actions_policy(repo, a, b)
    elif kind == "auto_merge":
        write_allow_auto_merge(repo, b)
    elif kind == "merge_methods":
        write_merge_methods(repo, b)
    elif kind == "merge_commit_message":
        write_merge_commit_message(repo, b)
    elif kind == "delete_branch_on_merge":
        write_delete_branch_on_merge(repo, b)
    elif kind == "vuln_alerts":
        write_vulnerability_alerts(repo, b)
    elif kind == "auto_sec_fixes":
        write_automated_security_fixes(repo, b)
    elif kind == "secret_scanning":
        write_secret_scanning(repo, b)
    elif kind == "codeql":
        write_codeql_default_setup(repo, b)


# --------------------------------------------------------------------------- #
# Write risk: which planned writes may be applied with no reviewer
# --------------------------------------------------------------------------- #
# The apply used to wait for the owner's approval every time. Almost every plan
# he approved only added protection (docs/decisions/0019), and a gate that is
# clicked for every plan stops being read. So `apply --refuse-weakening`
# applies a write only when this section can show it cannot leave a repo with
# FEWER constraints than it has now, and leaves the rest for the reviewed apply.
#
# Two properties hold it up, the same two as cms-platform's
# scripts/repo-settings-write-risk.js, which this follows:
#
#   1. It is an allowlist. A writer, setting, rule type, parameter or value
#      that is not named below is GATED, including one GitHub adds later. A
#      false GATED costs one approval; a false SAFE is an unreviewed admin
#      write that weakened a repo.
#   2. It is enforced where the write happens. The workflow routes on the
#      verdict, but the unreviewed job also passes --refuse-weakening, so a
#      wrong `if:` in the workflow can produce a red job and never a
#      weakening write.
#
# It says nothing about whether a setting is good, only about direction.
# Removing a required check can reduce protection; adding one cannot.
SAFE, GATED = "safe", "gated"

# Fork-PR approval, least to most restrictive.
FORK_APPROVAL_RANK = (
    "first_time_contributors_new_to_github",
    "first_time_contributors",
    "all_external_contributors",
)

# For the writers that send a whole declared group in one call: the value of
# each key that cannot reduce protection. A key set to anything else is safe
# only when the same plan read it as already matching, so the call leaves it
# as it is.
SAFE_GROUP_VALUES: dict[str, dict[str, Any]] = {
    "workflow_permissions": {
        "default_workflow_permissions": "read",
        "can_approve_pull_request_reviews": False,
    },
    "merge_methods": {key: False for key in MERGE_METHOD_KEYS},
    "secret_scanning": {key: True for key in SECRET_SCANNING_KEYS},
}
GROUP_SETTING_PREFIX = {
    "workflow_permissions": "actions.",
    "merge_methods": "repo.",
    "secret_scanning": "security.",
}

# Top-level keys of a live ruleset that a PUT neither sends nor changes.
RULESET_READ_ONLY_KEYS = frozenset({
    "id", "node_id", "source", "source_type", "created_at", "updated_at",
    "_links", "current_user_can_bypass",
})
# Rule types with no parameters to compare.
PARAMETERLESS_RULES = frozenset({"creation", "deletion", "non_fast_forward"})
# `pull_request` parameters where True is the stricter value.
PR_STRICTER_WHEN_TRUE = frozenset({
    "dismiss_stale_reviews_on_push",
    "require_code_owner_review",
    "require_last_push_approval",
    "required_review_thread_resolution",
    "require_extra_approval_for_unattributed_changes",
})
# Parameters GitHub returns that the engine's body never sends, with the only
# live values a PUT without them is known not to relax.
OMITTED_PARAM_OK: dict[str, dict[str, tuple]] = {
    "pull_request": {
        "required_reviewers": ([],),
        # Organization-owned repos return this. Disabled with no actors is
        # its least strict value, so a PUT without it cannot relax it.
        "dismissal_restriction": ({"enabled": False, "allowed_actors": []},),
    },
    # Off is the stricter value, so whichever of the two is live, a PUT that
    # omits it cannot relax it.
    "required_status_checks": {"do_not_enforce_on_create": (False, True)},
}


def _gated(reason: str) -> tuple[str, str]:
    return GATED, reason


def _safe(reason: str) -> tuple[str, str]:
    return SAFE, reason


def _group_risk(kind: str, wanted: Any, statuses: dict[str, str]) -> tuple[str, str]:
    safe_values = SAFE_GROUP_VALUES[kind]
    if not isinstance(wanted, dict) or not wanted:
        return _gated(f"{kind}: the write carries no readable group of keys")
    for key, value in wanted.items():
        if key not in safe_values:
            return _gated(f"{key} is not on the non-weakening list")
        if type(value) is type(safe_values[key]) and value == safe_values[key]:
            continue
        if statuses.get(GROUP_SETTING_PREFIX[kind] + key) == "match":
            continue  # already this value: the call does not change it
        return _gated(f"{key} -> {_json(value)} can relax the repo")
    return _safe(f"{kind}: every key written is unchanged or stricter")


def _codeql_risk(wanted: Any, statuses: dict[str, str],
                 records: list[dict]) -> tuple[str, str]:
    if not isinstance(wanted, dict):
        return _gated("codeql: the write carries no readable group of keys")
    if set(wanted) - {"codeql_default_setup", "codeql_query_suite"}:
        return _gated("codeql: the write carries a key this classifier does not know")
    if wanted.get("codeql_default_setup", True) is not True:
        return _gated("CodeQL default setup -> off")
    # Turning default setup ON is not on the list. A repo that runs CodeQL
    # from its own workflow reads as "not configured" here, and GitHub stops
    # accepting that workflow's results once default setup is on, so the
    # write can swap a broader analysis for a narrower one unseen.
    suite_rec = next(
        (r for r in records if r.get("setting") == "security.codeql_query_suite"), None)
    live_on = (statuses.get("security.codeql_default_setup") == "match"
               or (suite_rec is not None and suite_rec.get("status") in ("match", "drift")
                   and isinstance(suite_rec.get("current"), str)))
    if not live_on:
        return _gated("CodeQL default setup -> on would replace the results of a "
                      "CodeQL workflow the repo may run itself; this plan cannot see one")
    suite = wanted.get("codeql_query_suite")
    if suite is not None and suite != "extended" \
            and statuses.get("security.codeql_query_suite") != "match":
        return _gated(f"CodeQL query suite -> {_json(suite)} runs fewer queries")
    return _safe("CodeQL default setup stays on; the query suite is unchanged or larger")


def _rule_params(rule: dict) -> dict:
    params = rule.get("parameters")
    return dict(params) if isinstance(params, dict) else {}


def _pull_request_param_risk(key: str, live: Any, desired: Any) -> str | None:
    """None when desired cannot relax live for this parameter, else why not."""
    if key == "required_approving_review_count":
        ok = (type(live) is int and type(desired) is int and desired >= live)
        return None if ok else f"{key} {_json(live)} -> {_json(desired)}"
    if key in PR_STRICTER_WHEN_TRUE:
        return None if desired is True else f"{key} -> {_json(desired)}"
    if key == "allowed_merge_methods":
        ok = (isinstance(live, list) and isinstance(desired, list) and desired
              and all(isinstance(m, str) for m in live + desired)
              and set(desired) <= set(live))
        return None if ok else f"{key} {_json(live)} -> {_json(desired)} allows another method"
    return f"`{key}` is not on the non-weakening list"


def _status_checks_param_risk(key: str, live: Any, desired: Any) -> str | None:
    if key == "strict_required_status_checks_policy":
        return None if desired is True else f"{key} -> {_json(desired)}"
    if key == "required_status_checks":
        if not isinstance(live, list) or not isinstance(desired, list):
            return f"{key} is not a list on both sides"
        desired_contexts = set()
        for entry in desired:
            if not isinstance(entry, dict) or set(entry) != {"context"}:
                return f"a desired check is not a bare context: {_json(entry)}"
            desired_contexts.add(entry["context"])
        for entry in live:
            if not isinstance(entry, dict) or not set(entry) <= {"context", "integration_id"}:
                return f"a live check has a shape this classifier does not know: {_json(entry)}"
            if entry.get("integration_id") is not None:
                return (f"live check {_json(entry.get('context'))} is pinned to an app, "
                        "and the write would drop the pin")
            if entry.get("context") not in desired_contexts:
                return f"required check {_json(entry.get('context'))} removed"
        return None
    return f"`{key}` is not on the non-weakening list"


def _rule_risk(rule_type: str, live_rule: dict, desired_rule: dict) -> str | None:
    """None when replacing live_rule with desired_rule cannot relax it."""
    if rule_type == "update":
        same = _extra_rule_params(live_rule) == _extra_rule_params(desired_rule)
        return None if same else "rule `update` parameters differ"
    live, desired = _rule_params(live_rule), _rule_params(desired_rule)
    if rule_type in PARAMETERLESS_RULES:
        return None if not live and not desired else f"rule `{rule_type}` carries parameters"
    if rule_type == "pull_request":
        param_risk = _pull_request_param_risk
    elif rule_type == "required_status_checks":
        param_risk = _status_checks_param_risk
    else:
        return None if live == desired else (
            f"rule `{rule_type}` differs, and this classifier does not know its direction")
    omitted_ok = OMITTED_PARAM_OK.get(rule_type, {})
    for key in sorted(set(live) | set(desired)):
        if key not in desired:
            if key in omitted_ok and any(
                    type(live[key]) is type(v) and live[key] == v for v in omitted_ok[key]):
                continue
            return (f"live `{rule_type}.{key}` is {_json(live[key])} and the write "
                    "does not send it")
        if key not in live:
            return f"`{rule_type}.{key}` is not in the live rule, so its direction is unknown"
        if type(live[key]) is type(desired[key]) and live[key] == desired[key]:
            continue
        if (key == "allowed_merge_methods" and isinstance(live[key], list)
                and isinstance(desired[key], list)
                and sorted(map(str, live[key])) == sorted(map(str, desired[key]))):
            continue  # the same methods in another order
        why = param_risk(key, live[key], desired[key])
        if why is not None:
            return why
    return None


def _ruleset_put_risk(name: str, live: Any, desired: Any) -> tuple[str, str]:
    """Risk of replacing the live ruleset body with `desired` (a PUT)."""
    label = f"ruleset[{name}]"
    if not isinstance(live, dict) or not isinstance(desired, dict):
        return _gated(f"{label}: no live body to compare the write against")
    unknown = set(live) - RULESET_READ_ONLY_KEYS - set(desired)
    if unknown:
        return _gated(f"{label}: the live ruleset has field(s) the write does not "
                      f"send: {', '.join(sorted(unknown))}")
    extra = set(desired) - {"name", "target", "enforcement", "conditions", "rules",
                            "bypass_actors"}
    if extra:
        return _gated(f"{label}: the write sends field(s) this classifier does not "
                      f"know: {', '.join(sorted(extra))}")
    for key in ("name", "target"):
        if live.get(key) != desired.get(key):
            return _gated(f"{label}: `{key}` differs")
    if live.get("enforcement") != desired.get("enforcement") and desired.get("enforcement") != "active":
        return _gated(f"{label}: enforcement -> {_json(desired.get('enforcement'))}")

    # Which refs the ruleset covers. Any change here can uncover a branch.
    def refs(body: dict) -> tuple | None:
        cond = body.get("conditions")
        if not isinstance(cond, dict) or set(cond) != {"ref_name"}:
            return None
        ref = cond["ref_name"]
        if not isinstance(ref, dict) or set(ref) != {"include", "exclude"}:
            return None
        if not all(isinstance(ref[k], list) and all(isinstance(x, str) for x in ref[k])
                   for k in ("include", "exclude")):
            return None
        return sorted(ref["include"]), sorted(ref["exclude"])

    live_refs, desired_refs = refs(live), refs(desired)
    if live_refs is None or desired_refs is None or live_refs != desired_refs:
        return _gated(f"{label}: `conditions` differ or have a shape this classifier "
                      "does not know")

    # Bypass actors. GitHub hides the list from a token that cannot edit the
    # ruleset; an unseen list cannot be compared, so it gates.
    def actors(body: dict) -> set | None:
        listed = body.get("bypass_actors")
        if not isinstance(listed, list):
            return None
        out = set()
        for actor in listed:
            if not isinstance(actor, dict) or set(actor) != {"actor_id", "actor_type", "bypass_mode"}:
                return None
            out.add((actor["actor_type"], actor["actor_id"], actor["bypass_mode"]))
        return out

    live_actors, desired_actors = actors(live), actors(desired)
    if live_actors is None:
        return _gated(f"{label}: live bypass actors are not visible or not readable, "
                      "so the write cannot be compared")
    if desired_actors is None:
        return _gated(f"{label}: the write's bypass actors are not readable")
    added = desired_actors - live_actors
    if added:
        shown = ", ".join(f"{t} {i} ({m})" for t, i, m in sorted(added, key=repr))
        return _gated(f"{label}: bypass actor(s) added: {shown}")

    # Rules, by type.
    def by_type(body: dict) -> dict | None:
        listed = body.get("rules")
        if not isinstance(listed, list):
            return None
        out: dict[str, dict] = {}
        for rule in listed:
            if (not isinstance(rule, dict) or not isinstance(rule.get("type"), str)
                    or rule["type"] in out or set(rule) - {"type", "parameters"}):
                return None
            out[rule["type"]] = rule
        return out

    live_rules, desired_rules = by_type(live), by_type(desired)
    if live_rules is None or desired_rules is None:
        return _gated(f"{label}: `rules` have a shape this classifier does not know")
    removed = sorted(set(live_rules) - set(desired_rules))
    if removed:
        return _gated(f"{label}: rule(s) removed: {', '.join(removed)}")
    for rule_type in sorted(set(live_rules) & set(desired_rules)):
        why = _rule_risk(rule_type, live_rules[rule_type], desired_rules[rule_type])
        if why is not None:
            return _gated(f"{label}: {why}")
    return _safe(f"{label}: no rule, check, ref or bypass actor is removed or relaxed")


def _onboarding(records: list[dict]) -> bool:
    """True when the same plan creates a managed ruleset that does not exist
    yet: the repo is being onboarded, so nothing on it predates the fleet's
    settings. The owner's rule (2026-11-20): on a newly onboarded repo,
    turning on CodeQL default setup and auto-merge needs no review."""
    for r in records:
        writer = r.get("_writer")
        if (r.get("status") == "drift" and isinstance(writer, tuple) and len(writer) == 3
                and writer[0] == "ruleset" and writer[2] is None
                and r.get("_live") is None and r.get("current") is None):
            return True
    return False


def write_risk(rec: dict, records: list[dict]) -> tuple[str, str]:
    """(SAFE | GATED, reason) for one drift record of a repo's plan.

    `records` is the whole plan for the same repo, as planned and before any
    write: a group writer sends every declared key, so whether one of them is
    safe can depend on what the plan read for its siblings."""
    writer = rec.get("_writer")
    if rec.get("status") != "drift" or not isinstance(writer, tuple) or len(writer) != 3:
        return _gated("not a planned write this classifier can read")
    if rec.get("bypass_unknown"):
        return _gated("this token cannot see the ruleset's bypass actors; the "
                      "apply decides with a token that can")
    kind, a, b = writer
    statuses = {r["setting"]: r["status"] for r in records if "setting" in r}
    current, desired = rec.get("current"), rec.get("desired")

    if kind == "sha":
        # write_sha_pinning sends back `enabled` and `allowed_actions`; with
        # either missing from the read it would send a default instead.
        if b is not True:
            return _gated("actions.sha_pinning_required -> false")
        if not isinstance(a, dict) or "enabled" not in a or "allowed_actions" not in a:
            return _gated("actions permissions were read without `enabled` or "
                          "`allowed_actions`, which the write must send back")
        return _safe("actions.sha_pinning_required -> true")
    if kind == "fork":
        if current not in FORK_APPROVAL_RANK or b not in FORK_APPROVAL_RANK:
            return _gated(f"fork-PR approval {_json(current)} -> {_json(b)}: a value "
                          "this classifier cannot rank")
        if FORK_APPROVAL_RANK.index(b) < FORK_APPROVAL_RANK.index(current):
            return _gated(f"fork-PR approval -> {b} asks for fewer approvals")
        return _safe(f"fork-PR approval -> {b} (stricter)")
    if kind in SAFE_GROUP_VALUES:
        return _group_risk(kind, b, statuses)
    if kind == "codeql":
        verdict = _codeql_risk(b, statuses, records)
        if (verdict[0] == GATED and _onboarding(records) and isinstance(b, dict)
                and b.get("codeql_default_setup") is True
                and not set(b) - {"codeql_default_setup", "codeql_query_suite"}):
            return _safe("CodeQL default setup -> on while the repo is onboarded "
                         "(its managed ruleset is created in the same plan)")
        return verdict
    if kind == "auto_merge":
        if b is False:
            return _safe("repo.allow_auto_merge -> false")
        if b is True and _onboarding(records):
            return _safe("repo.allow_auto_merge -> true while the repo is onboarded "
                         "(its managed ruleset is created in the same plan)")
        return _gated("repo.allow_auto_merge -> true adds a way to merge")
    if kind == "delete_branch_on_merge":
        return _safe("repo.delete_branch_on_merge -> true") if b is True else \
            _gated("repo.delete_branch_on_merge -> false")
    if kind in ("vuln_alerts", "auto_sec_fixes"):
        return _safe(f"{rec.get('setting')} -> on") if b is True else \
            _gated(f"{rec.get('setting')} -> off")
    if kind == "label":
        # A label write creates the label or sets its color and description.
        # It never deletes one or removes it from an issue or pull request.
        # On an existing label it also sends the declared name, which renames
        # one that differs only in case; a workflow that matches the old
        # spelling exactly would stop matching, so that write waits.
        if b is not False:
            live_name = current.get("name") if isinstance(current, dict) else None
            spec_name = a.get("name") if isinstance(a, dict) else None
            if not isinstance(spec_name, str) or live_name != spec_name:
                return _gated(f"{rec.get('setting')}: the write renames the live "
                              f"label {_json(live_name)}")
        return _safe(f"{rec.get('setting')}: create, or set color and description")
    if kind == "ruleset":
        name = a.get("name") if isinstance(a, dict) else None
        if b is None and rec.get("_live") is None and current is None:
            # GitHub enforces the union of a repo's rulesets, and a bypass
            # actor bypasses only the ruleset that names it, so a ruleset
            # that does not exist yet cannot relax anything by existing.
            return _safe(f"ruleset[{name}]: new ruleset (rulesets add up)")
        return _ruleset_put_risk(str(name), rec.get("_live"), a)
    # actions_policy (it allows events GitHub would block), merge_commit_message
    # (no protective direction) and anything added later.
    return _gated(f"writer `{kind}` is not on the non-weakening list")


def classify_records(records: list[dict]) -> None:
    """Set `risk` and `risk_reason` on every drift record of one repo's plan.
    Call it before any write: it reads the statuses as planned."""
    verdicts = [(r, write_risk(r, records)) for r in records if r.get("status") == "drift"]
    for rec, (verdict, reason) in verdicts:
        rec["risk"], rec["risk_reason"] = verdict, reason


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
GREEN, YELLOW, RED, DIM, RESET = (
    "\033[32m", "\033[33m", "\033[31m", "\033[2m", "\033[0m"
)


def _sym(status: str) -> str:
    return {
        "match": f"{GREEN}ok{RESET}",
        "drift": f"{YELLOW}DRIFT{RESET}",
        "changed": f"{YELLOW}CHANGED{RESET}",
        "skipped": f"{DIM}skip{RESET}",
        "error": f"{RED}ERROR{RESET}",
        "would-change": f"{YELLOW}would change{RESET}",
        "gated": f"{YELLOW}LEFT FOR REVIEW{RESET}",
    }.get(status, status)


def render_records(repo: str, records: list[dict], scope: str | None = None) -> None:
    print(f"\n{repo}")
    if scope is not None:
        print(f"  {DIM}{scope}{RESET}")
    if not records:
        print("  (no managed settings)")
        return
    for r in records:
        line = f"  [{_sym(r['status'])}] {r['setting']}"
        if r["status"] in ("drift", "would-change"):
            line += f"\n      from: {r['current']!r}\n      to:   {r['desired']!r}"
            if r.get("note"):
                line += f"\n      note: {r['note']}"
        elif r["status"] == "gated":
            line += (f"\n      from: {r['current']!r}\n      to:   {r['desired']!r}"
                     f"\n      why:  {r.get('note', '')}")
        elif r["status"] == "changed":
            line += f"  -> {r['desired']!r}"
        elif r["status"] in ("skipped", "error"):
            line += f"  ({r.get('note', '')})"
        print(line)


# --------------------------------------------------------------------------- #
# generate
# --------------------------------------------------------------------------- #
def cmd_generate(args) -> int:
    repo = args.repo
    info = get_repo(repo)
    private = bool(info["private"])
    actions = read_actions(repo)
    doc: dict = {
        "repo": repo,
        "actions": {"sha_pinning_required": bool(actions.get("sha_pinning_required"))},
    }
    if not private:
        fork = read_fork_approval(repo)
        if fork is not None:
            doc["actions"]["fork_pr_approval"] = fork
    try:
        wp = read_workflow_permissions(repo)
    except GhError:
        pass  # workflow-permissions unavailable (e.g. scope gap) -- see plan_repo
    else:
        for key in WORKFLOW_PERMISSIONS_KEYS:
            if key in wp:
                doc["actions"][key] = wp[key]
    # Emit a ruleset block from the branch ruleset targeting the default branch,
    # if any is present; otherwise a disabled stub for public repos.
    try:
        rulesets = list_rulesets(repo)
        branch_rs = None
        # Match the default ruleset BY NAME first: a repo may also carry
        # `extra_rulesets`-style rulesets on other branches, and "first branch
        # ruleset" would misattribute one as the default. The fallback keeps
        # generate working for repos whose ruleset has another name.
        # `generate` does not emit `extra_rulesets`.
        branch_summaries = [x for x in rulesets if x.get("target") == "branch"]
        chosen = next(
            (x for x in branch_summaries if x.get("name") == DEFAULT_RULESET_NAME),
            branch_summaries[0] if branch_summaries else None,
        )
        if chosen is not None:
            branch_rs = get_ruleset(repo, chosen["id"])
        if branch_rs:
            doc["ruleset"] = ruleset_doc(branch_rs)
        elif not private:
            doc["ruleset"] = {"enabled": False, "name": DEFAULT_RULESET_NAME}
    except GhError:
        pass  # rulesets unavailable (e.g. private-no-Pro)
    # Emit only the policies expressible as an `actions_policies` entry.
    try:
        live_policies = list_actions_policies(repo)
    except GhError:
        live_policies = None  # policies unavailable (e.g. scope gap) -- see plan_repo
    policy_docs = []
    for summary in live_policies or []:
        pname = summary.get("name")
        try:
            full = get_actions_policy(repo, summary.get("id"))
        except GhError as e:
            sys.stderr.write(f"generate: skipping Actions policy {pname!r} -- {e}\n")
            continue
        policy_doc = actions_policy_doc(full)
        if policy_doc is None:
            sys.stderr.write(
                f"generate: skipping Actions policy {pname!r} -- "
                "not expressible in actions_policies\n"
            )
            continue
        policy_docs.append(policy_doc)
    if policy_docs:
        doc["actions_policies"] = policy_docs
    header = (
        "# Generated by repo_settings.py generate. Edit to describe DESIRED state,\n"
        "# then `repo_settings.py apply --config <this file>`.\n"
    )
    sys.stdout.write(header)
    yaml.safe_dump(doc, sys.stdout, sort_keys=False, default_flow_style=False)
    return 0


# --------------------------------------------------------------------------- #
# diff / apply
# --------------------------------------------------------------------------- #
def _filter_owner(targets: list[dict], owner: str | None) -> list[dict]:
    """Keep only targets under `owner` (the part before '/'). Used by the
    fan-out workflow to run one pass per account with that account's
    short-lived GitHub App installation token."""
    if not owner:
        return targets
    o = owner.lower()
    return [t for t in targets if t["repo"].split("/", 1)[0].lower() == o]


def installation_repos(owner: str | None) -> list[str]:
    """Every repository this credential can administer, as `owner/name`."""
    return sorted(installation_repo_visibility(owner))


def installation_repo_visibility(owner: str | None) -> dict[str, bool]:
    """Every repository this credential can administer, as `owner/name` mapped
    to whether it is private. A response missing `private` counts as private:
    withholding a name wrongly costs a local re-run, publishing one cannot be
    undone.

    `/installation/repositories` rather than `/users/{o}/repos` or
    `/orgs/{o}/repos`, for three reasons and the third is the one that matters:
    it does not require knowing whether an account is a user or an org; it is
    paginated identically either way; and it returns EXACTLY the set the App
    can act on, which is the set this coverage question is actually about. A
    user listing would happily return repos the App was never installed on,
    and reporting those as "undeclared" would be reporting a gap nothing in
    this repo could close.
    """
    repos: dict[str, bool] = {}
    page = 1
    while True:
        # `gh api` follows no pagination of its own here because the response
        # is an OBJECT, not an array, so --paginate would concatenate objects.
        payload = gh_api(f"/installation/repositories?per_page=100&page={page}")
        chunk = (payload or {}).get("repositories") or []
        if not chunk:
            break
        for r in chunk:
            repos[r["full_name"]] = bool(r.get("private", True))
        if len(chunk) < 100:
            break
        page += 1
    if owner:
        o = owner.lower()
        repos = {n: v for n, v in repos.items() if n.split("/", 1)[0].lower() == o}
    return repos


def cmd_coverage(args) -> int:
    """Report repositories the credential can administer that `fleet.yml` does
    not DECLARE.

    Declared, not managed. A repo carrying `manage: []` is a decision
    somebody wrote down and is not reported; a repo absent from the file
    entirely is a decision nobody has made, and until this command existed the
    two were indistinguishable from the outside. Same shape as the
    `skills_bootstrap` partition in `_agent-guidance` (its ADR 0011), for the
    same reason: an allowlist that says nothing about what it omits cannot be
    audited for completeness.

    Exit 0 when every reachable repo is declared, 1 when some are not, and 2
    when the question could not be asked -- never 0 on an enumeration that
    failed, because a clean line over zero repos reads exactly like a clean
    line over all of them. A refused config is also 2 (ConfigError, raised
    before any API call).

    The output goes to a public CI log and into an auto-filed issue, so the
    name of an undeclared PRIVATE repo is withheld (a count is printed) unless
    `--show-private` is passed, which is for local use only. Declared private
    repos are still named: `fleet.yml` is in this repo and already names them,
    so printing them adds no exposure. Only undeclared private names are new
    information.
    """
    cfg = load_config(args.config)
    if "repos" not in cfg:
        sys.stderr.write(
            "coverage: this config is single-repo shaped; there is no fleet to "
            "be complete about.\n"
        )
        return 2

    declared = {t["repo"].lower(): t for t in resolve_targets(cfg, None)}
    visibility = installation_repo_visibility(getattr(args, "owner", None))
    reachable = sorted(visibility)
    show_private = getattr(args, "show_private", False)
    if not reachable:
        sys.stderr.write(
            "coverage: the installation reported no repositories -- refusing to "
            "certify a fleet as complete against an empty enumeration.\n"
        )
        return 2

    undeclared = [r for r in reachable if r.lower() not in declared]
    withheld = 0
    for repo in reachable:
        t = declared.get(repo.lower())
        if t is None and visibility[repo] and not show_private:
            withheld += 1
        elif t is None:
            print(f"UNDECLARED  {repo}: reachable by this credential, absent from the config")
        else:
            print(f"OK          {repo}: declared, {manage_label(t)}")

    if withheld:
        print(
            f"UNDECLARED (private)  {withheld} undeclared private repo(s); "
            "names withheld because this log is public"
        )

    print(
        f"\n{len(reachable)} reachable, {len(reachable) - len(undeclared)} declared, "
        f"{len(undeclared)} undeclared"
    )
    return 1 if undeclared else 0


def cmd_diff(args) -> int:
    cfg = load_config(args.config)
    targets = _filter_owner(resolve_targets(cfg, args.repo), getattr(args, "owner", None))
    any_drift = any_error = False
    changes: list[dict] = []
    for t in targets:
        if not any(manages(t, s) for s in SURFACES):
            print(f"\n{t['repo']}\n  {DIM}{manage_label(t)}{RESET}")
            continue
        records = plan_repo_records(t["repo"], t["effective"])
        classify_records(records)
        render_records(t["repo"], records, manage_label(t))
        any_drift |= any(r["status"] == "drift" for r in records)
        any_error |= any(r["status"] == "error" for r in records)
        changes.extend(
            {"repo": t["repo"], "setting": r["setting"], "status": r["status"],
             "current": r["current"], "desired": r["desired"],
             "note": r.get("note"), "risk": r.get("risk"),
             "risk_reason": r.get("risk_reason")}
            for r in records if r["status"] in ("drift", "error")
        )
    if getattr(args, "changes_json", None):
        with open(args.changes_json, "w", encoding="utf-8") as fh:
            json.dump(changes, fh, indent=2, default=repr)
    if any_error:
        return 2
    return 1 if any_drift else 0


def cmd_apply(args) -> int:
    cfg = load_config(args.config)
    targets = _filter_owner(resolve_targets(cfg, args.repo), getattr(args, "owner", None))
    # The workflow applies the cms-platform repos in their own step, under a
    # token that can write issues and nothing else (docs/decisions/0016).
    mode = getattr(args, "cms_label_only", None)
    # With --refuse-weakening only the writes write_risk calls SAFE are made;
    # the rest are left, reported as `gated`, for an apply without the flag.
    refuse = bool(getattr(args, "refuse_weakening", False))
    any_error = any_gated = False
    results: list[dict] = []
    for t in targets:
        if mode and is_cms_label_only(t["repo"]) != (mode == "only"):
            if mode == "skip":
                print(
                    f"\n{t['repo']}\n  {DIM}applied by the label-only step "
                    f"(--cms-label-only only){RESET}"
                )
            continue
        if not any(manages(t, s) for s in SURFACES):
            print(f"\n{t['repo']}\n  {DIM}{manage_label(t)}{RESET}")
            continue
        records = plan_repo_records(t["repo"], t["effective"])
        # Before the first write: the verdicts read the statuses as planned.
        classify_records(records)
        planned = [r for r in records if r["status"] in ("drift", "error")]
        for r in records:
            if r["status"] == "drift":
                if r.get("bypass_unknown"):
                    # Refused in a dry run too, so it never promises a write
                    # that apply would refuse.
                    r["status"] = "error"
                    r["note"] = BYPASS_UNKNOWN_REFUSAL
                elif refuse and r.get("risk") != SAFE:
                    # Checked here, at the write, and not only where the
                    # workflow routes: this is what keeps the unreviewed
                    # lane from making a write nobody classified as safe.
                    r["status"] = "gated"
                    r["note"] = r.get("risk_reason") or "not classified"
                elif args.dry_run:
                    r["status"] = "would-change"
                else:
                    try:
                        apply_record(t["repo"], r)
                        r["status"] = "changed"
                    except GhError as e:
                        r["status"] = "error"
                        r["note"] = e.message
        render_records(t["repo"], records, manage_label(t))
        any_error |= any(r["status"] == "error" for r in records)
        any_gated |= any(r["status"] == "gated" for r in records)
        results.extend(
            {"repo": t["repo"], "setting": r["setting"], "status": r["status"],
             "current": r["current"], "desired": r["desired"],
             "note": r.get("note"), "risk": r.get("risk"),
             "risk_reason": r.get("risk_reason")}
            for r in planned
        )
    if getattr(args, "result_json", None):
        with open(args.result_json, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2, default=repr)
    if any_error:
        return 2
    # 3, not 0: "every safe write was made" must not read as "nothing is left".
    return 3 if any_gated else 0


# --------------------------------------------------------------------------- #
# changes-report: what a reviewer reads before approving an apply
# --------------------------------------------------------------------------- #
# GitHub keeps at most 10 annotations of each level per step and drops the
# rest without saying so. Past this many changes the last notice slot carries
# the heads-up instead, so a truncated list never reads as the whole plan.
MAX_NOTICES = 10
# A ruleset's current and desired values are whole normalized bodies; a table
# cell or a notice line shows this much and the log keeps the rest.
MAX_VALUE_CHARS = 120


def _short(value: Any) -> str:
    text = _json(value)
    if len(text) > MAX_VALUE_CHARS:
        text = text[: MAX_VALUE_CHARS - 1] + "\u2026"
    return text


def _change_line(c: dict) -> str:
    if c["status"] == "error":
        return f"{c['repo']}: {c['setting']} could not be read ({c.get('note') or 'error'})"
    return f"{c['repo']}: {c['setting']} {_short(c['current'])} -> {_short(c['desired'])}"


def _annotation_escape(text: str) -> str:
    # GitHub's workflow-command encoding for a message.
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _md_text(value: Any) -> str:
    """Prose for a Markdown table cell: one line, pipes escaped."""
    return str(value).replace("|", "\\|").replace("\n", " ")


def _review_cell(c: dict) -> str:
    """Which apply makes this change: the one that runs with no reviewer, or
    the one that waits for the owner."""
    if c.get("risk") == SAFE:
        return "not needed"
    return "needed: " + _md_text(c.get("risk_reason") or "not classified")


def changes_markdown(changes: list[dict]) -> str:
    """The job summary: one row per planned change, errors included. Rows sort
    by setting, then repo, so one setting's changes across the fleet read as a
    block."""
    drift = sorted((c for c in changes if c["status"] == "drift"),
                   key=lambda c: (c["setting"], c["repo"].lower()))
    errors = [c for c in changes if c["status"] == "error"]
    lines = ["## Planned changes", ""]
    if not changes:
        lines.append("No changes planned. An apply would change nothing.")
        return "\n".join(lines) + "\n"

    def cell(text: str) -> str:
        return "`" + text.replace("|", "\\|").replace("`", "'") + "`"

    if drift:
        lines += [
            f"{len(drift)} setting(s) would change. Settings this token cannot "
            "read are skipped, not listed; the plan log names them.",
            "",
            "| Repo | Setting | From | To | Review |",
            "|---|---|---|---|---|",
        ]
        lines += [
            f"| {c['repo']} | {c['setting']} | {cell(_short(c['current']))} "
            f"| {cell(_short(c['desired']))} | {_review_cell(c)} |"
            for c in drift
        ]
    if errors:
        lines += ["", f"**{len(errors)} setting(s) could not be read**, so the "
                  "plan is incomplete:", ""]
        lines += [f"- {c['repo']}: {c['setting']} ({c.get('note') or 'error'})"
                  for c in errors]
    return "\n".join(lines) + "\n"


def changes_annotations(changes: list[dict], summary_url: str | None) -> list[str]:
    """`::notice` lines, at most MAX_NOTICES. When there are more changes than
    that, the last line says so instead of showing one more."""
    where = f" at {summary_url}" if summary_url else ""
    lines = [_change_line(c) for c in changes]
    if len(lines) > MAX_NOTICES:
        shown = lines[: MAX_NOTICES - 1]
        hidden = len(lines) - len(shown)
        shown.append(
            f"NOT THE WHOLE PLAN: {hidden} MORE CHANGE(S) NOT SHOWN HERE. "
            f"SEE THE JOB SUMMARY (PLANNED CHANGES){where}."
        )
        lines = shown
    return [f"::notice title=repo-settings plan::{_annotation_escape(l)}" for l in lines]


def cmd_changes_report(args) -> int:
    """Merge the `diff --changes-json` files given and print the job-summary
    Markdown (--markdown) or the notice lines (--annotations)."""
    changes: list[dict] = []
    for path in args.inputs:
        with open(path, "r", encoding="utf-8") as fh:
            changes.extend(json.load(fh))
    if args.format == "markdown":
        sys.stdout.write(changes_markdown(changes))
    else:
        for line in changes_annotations(changes, args.summary_url):
            print(line)
    return 0


def apply_markdown(results: list[dict]) -> str:
    """The job summary of an `apply --refuse-weakening`: what it changed, and
    what it left for the reviewed apply and why."""
    def rows(status: str) -> list[dict]:
        return sorted((r for r in results if r["status"] == status),
                      key=lambda r: (r["setting"], r["repo"].lower()))

    def cell(text: str) -> str:
        return "`" + text.replace("|", "\\|").replace("`", "'") + "`"

    changed, gated, errors = rows("changed"), rows("gated"), rows("error")
    lines = ["## Applied without review", ""]
    if changed:
        lines += ["| Repo | Setting | From | To |", "|---|---|---|---|"]
        lines += [
            f"| {r['repo']} | {r['setting']} | {cell(_short(r['current']))} "
            f"| {cell(_short(r['desired']))} |"
            for r in changed
        ]
    else:
        lines.append("Nothing.")
    lines += ["", "## Left for the reviewed apply", ""]
    if gated:
        lines += [
            f"{len(gated)} change(s) could reduce protection, or could not be "
            "shown not to. Approving the reviewed apply makes them.",
            "",
            "| Repo | Setting | From | To | Why |",
            "|---|---|---|---|---|",
        ]
        lines += [
            f"| {r['repo']} | {r['setting']} | {cell(_short(r['current']))} "
            f"| {cell(_short(r['desired']))} "
            f"| {_md_text(r.get('note') or '')} |"
            for r in gated
        ]
    elif results_need_review(results):
        lines.append(
            "No change was held back, but a setting could not be read or "
            "classified (below), so the reviewed apply is still asked for.")
    else:
        lines.append("Nothing. No approval is needed for this plan.")
    if errors:
        lines += ["", f"**{len(errors)} setting(s) failed:**", ""]
        lines += [f"- {r['repo']}: {r['setting']} ({r.get('note') or 'error'})"
                  for r in errors]
    return "\n".join(lines) + "\n"


def results_need_review(results: list[dict]) -> bool:
    """True when an `apply --refuse-weakening` left something for the reviewed
    apply: a change it would not make, or a setting it could not read or
    classify. A failed read can hide a change that would have waited, so only
    a write already classified safe may fail without asking for the review."""
    return any(
        r["status"] == "gated" or (r["status"] == "error" and r.get("risk") != SAFE)
        for r in results
    )


def cmd_apply_report(args) -> int:
    """Merge the `apply --result-json` files given and print the job summary
    (--format markdown), or `true`/`false` for whether a change was left for
    the reviewed apply (--format needs-review)."""
    results: list[dict] = []
    for path in args.inputs:
        with open(path, "r", encoding="utf-8") as fh:
            loaded = json.load(fh)
        # Refused, not guessed at: "nothing was left for review" must never be
        # read out of a file that is not a result list.
        if not isinstance(loaded, list) or not all(
                isinstance(r, dict) and isinstance(r.get("status"), str)
                and isinstance(r.get("setting"), str) and isinstance(r.get("repo"), str)
                for r in loaded):
            raise SystemExit(f"error: {path} is not a list of apply results")
        results.extend(loaded)
    if args.format == "markdown":
        sys.stdout.write(apply_markdown(results))
    else:
        print("true" if results_need_review(results) else "false")
    return 0


# --------------------------------------------------------------------------- #
def cmd_cms_label_repos(args) -> int:
    """One line: the names (after the `/`) of this owner's label-managing
    cms-platform repos, comma-separated, for the workflow's token mint."""
    cfg = load_config(args.config)
    targets = _filter_owner(resolve_targets(cfg, None), args.owner)
    names = sorted(
        t["repo"].split("/", 1)[1]
        for t in targets
        if is_cms_label_only(t["repo"]) and manages(t, "labels")
    )
    print(",".join(names))
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="repo-settings-as-code for GitHub")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="emit current settings as YAML")
    g.add_argument("--repo", required=True, help="owner/name")
    g.set_defaults(func=cmd_generate)

    d = sub.add_parser("diff", help="drift report; exit 1 if drift")
    d.add_argument("--config", required=True)
    d.add_argument("--repo", help="override/set target for single-repo config")
    d.add_argument("--owner", help="only process repos under this owner (account)")
    d.add_argument(
        "--changes-json",
        help="also write the drift and error records to this file, for changes-report",
    )
    d.set_defaults(func=cmd_diff)

    cr = sub.add_parser(
        "changes-report",
        help="render diff --changes-json files as a job summary or notice lines",
    )
    cr.add_argument("inputs", nargs="+", help="files written by diff --changes-json")
    cr.add_argument("--format", choices=("markdown", "annotations"), required=True)
    cr.add_argument(
        "--summary-url",
        help="where the job summary is, named in the notice that flags a cut-off list",
    )
    cr.set_defaults(func=cmd_changes_report)

    a = sub.add_parser("apply", help="apply desired settings")
    a.add_argument("--config", required=True)
    a.add_argument("--repo", help="override/set target for single-repo config")
    a.add_argument("--owner", help="only process repos under this owner (account)")
    a.add_argument("--dry-run", action="store_true", help="preview only")
    a.add_argument(
        "--cms-label-only",
        choices=("skip", "only"),
        help="skip the cms-platform label-only repos, or apply only them "
        "(default: every target)",
    )
    a.add_argument(
        "--refuse-weakening",
        action="store_true",
        help="make only the writes that cannot reduce protection; leave the "
        "rest (reported as left for review) and exit 3 if any were left",
    )
    a.add_argument(
        "--result-json",
        help="also write what happened to each planned change to this file, "
        "for apply-report",
    )
    a.set_defaults(func=cmd_apply)

    ar = sub.add_parser(
        "apply-report",
        help="render apply --result-json files as a job summary, or say "
        "whether anything was left for review",
    )
    ar.add_argument("inputs", nargs="+", help="files written by apply --result-json")
    ar.add_argument("--format", choices=("markdown", "needs-review"), required=True)
    ar.set_defaults(func=cmd_apply_report)

    cl = sub.add_parser(
        "cms-label-repos",
        help="print the owner's label-managing cms-platform repos, comma-separated",
    )
    cl.add_argument("--config", required=True)
    cl.add_argument("--owner", required=True)
    cl.set_defaults(func=cmd_cms_label_repos)

    c = sub.add_parser(
        "coverage",
        help="report repos this credential can administer that the config does not declare",
    )
    c.add_argument("--config", required=True)
    c.add_argument("--owner", help="only consider repos under this owner (account)")
    c.add_argument(
        "--show-private",
        action="store_true",
        help="name undeclared PRIVATE repos too; local use only, never in CI "
        "(the log and the nudge issue are public)",
    )
    c.set_defaults(func=cmd_coverage)

    args = p.parse_args()
    try:
        return args.func(args)
    except GhError as e:
        sys.stderr.write(f"gh error: {e}\n")
        return 2
    except SystemExit as e:
        # A message-carrying SystemExit is a refused config (ConfigError, or
        # a build_* helper's older `SystemExit("error: ...")`). Exit 2, not
        # Python's default 1: 1 means drift for `diff` and undeclared repos
        # for `coverage`, and a config the engine could not read is neither.
        if isinstance(e.code, str):
            sys.stderr.write(f"{e.code}\n")
            return 2
        raise


if __name__ == "__main__":
    sys.exit(main())
