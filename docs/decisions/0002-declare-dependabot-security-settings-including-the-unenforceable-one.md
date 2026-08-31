# 0002. Manage Dependabot security settings as fleet code, including one the engine can never apply

- **Status:** Accepted
- **Date:** 2026-08-31
- **Deciders:** Adam Daniel

## Context

`fleet.yml` declared three groups under `defaults:` — `repo`, `actions`,
`ruleset` — and Dependabot's own security posture (alerts, automated security
updates, grouped security updates) was managed nowhere: not read, not
written, not reported on by any drift check. It was also demonstrably not
uniform across the fleet. On 2026-08-31, `GET repos/{repo}/dependabot/alerts`
against `agentskills`, `repo-settings`, `skills-evals` and
`agentskills-private` all answered HTTP 403 "Dependabot alerts are disabled
for this repository" — an explicit feature-off message, not the ambiguous 404
the account-wide guidance warns about elsewhere, so this was measured rather
than inferred. `_agent-guidance` alone answered with a permissions error
instead of that feature-off message, meaning it likely already had alerts on.
Nobody had decided the fleet should be split this way; it simply drifted
there, unaudited, because nothing in this repo looked.

Two of the three Dependabot security toggles have a normal GitHub REST
surface and can be read and written like everything else this engine already
manages. The third — grouped security updates, the checkbox that lets
Dependabot bundle related version bumps into one PR instead of one-per-package
— does not. It was verified against GitHub's own REST reference for both
surfaces a value like this could plausibly live on: a repository's
`security_and_analysis` object (whose documented keys are
`advanced_security`, `code_security`, `dependabot_security_updates`,
`secret_scanning`, `secret_scanning_push_protection`,
`secret_scanning_non_provider_patterns`, `secret_scanning_ai_detection`,
`secret_scanning_delegated_alert_dismissal`,
`secret_scanning_delegated_bypass`, `secret_scanning_delegated_bypass_options`
— no grouping field among them), and org/enterprise code-security
configurations (which do carry a grouping-adjacent field, but are
**org-scoped**, and 18 of this fleet's repos sit under a user account, not an
org — so even where the field exists, this engine's credential model cannot
reach it). `integrations/terraform-provider-github` issue 3334 is the open
community request for exactly this endpoint, unresolved as of this writing.
It is a UI-only setting, or expressible per-repo inside a site's own
`.github/dependabot.yml` via `groups:` with `applies-to: security-updates`.

That left a real design question distinct from "does the API exist": does a
settings-as-code manifest declare a value it can never converge, or does it
stay silent about the gap the way it stayed silent about the whole group
before this ADR?

## Decision

Add a fourth managed group, `security`, alongside `repo` / `actions` /
`ruleset`, with three leaves:

- `vulnerability_alerts` — Dependabot alerts. Read via the HTTP **status** of
  `GET repos/{repo}/vulnerability-alerts` (204 = enabled, 404 = disabled, no
  JSON body either way); written via `PUT`/`DELETE` on the same path, with
  **no request body** — the method itself carries the value, unlike every
  other writer in this engine.
- `automated_security_fixes` — Dependabot security updates. Read via
  `GET repos/{repo}/automated-security-fixes`, which returns `200
  {"enabled": bool, "paused": bool}` on current GitHub (the legacy
  204-empty/404 shape is tolerated too, since which vintage a given
  installation answers with is not something to assume); written the same
  `PUT`/`DELETE`-no-body way. `paused` is deliberately not managed — it is
  GitHub's own operational signal, not a policy toggle. This leaf depends on
  `vulnerability_alerts` (Dependabot cannot open a security-update PR without
  an alert to resolve), so `plan_repo` orders the two records so `cmd_apply`
  — which walks drift records in list order — enables the prerequisite before
  the dependent, and disables the dependent before the prerequisite.
- `grouped_security_updates` — **declared, but never applied.** The engine
  always reports this leaf `skipped`, carrying no `_writer`, with a note
  naming both the manual UI path (repo Settings → Code security & analysis)
  and the `.github/dependabot.yml` `groups:` alternative. `fleet.yml` sets it
  `true` anyway, as a statement of the fleet's intent rather than an
  assertion the engine can back up.

Both applyable leaves read and write through the fan-out App's existing
**Administration: Read & write** grant — the same scope the engine already
requires for the ruleset and Actions settings. No new credential, no App
permission change, no workflow edit.

## Consequences

- **A previously-invisible gap becomes both visible and (mostly) fixable.**
  The four repos measured with alerts off get fixed by the next apply, and
  every repo's alert/security-update posture now shows up in `diff` output
  going forward instead of living wherever an operator happened to leave it.
- **A declared-but-unenforceable leaf is a deliberate readability trade.**
  `grouped_security_updates: true` in `fleet.yml` can never produce a
  `changed` record — only `skipped`, forever. That is the point: an omitted
  third toggle beside two applied ones reads as "forgotten", inviting someone
  to eventually "fix" the gap by adding write support that does not exist to
  add. A declared-and-permanently-skipped leaf reads instead as "known,
  blocked, and here is why" — the true state — and the note on the skip
  record names the manual path for whoever actually wants it turned on.
- **The false-green risk this accepts, and named so it can be watched for.**
  A 403 on the two applyable leaves' reads is treated as a skip, not a raised
  error — deliberately, so a scope gap on a grant that predates this setting
  cannot take the whole weekly apply down. The honest cost: if the fan-out
  App's installation lacked this scope everywhere, the entire `security`
  group would report clean `skipped` records fleet-wide, forever, with
  nothing red to prompt a second look — the same shape as a code search
  scoped to one owner reporting a plausible, complete-shaped wrong answer
  (see the account-wide guidance, "The fleet spans TWO owners"). The
  mitigation is the same one that guidance recommends elsewhere: the signature
  to watch for in the rendered report is a `skip` naming HTTP 403 on a repo
  where every other record — sha pinning, the ruleset, delete-branch-on-merge
  — reads normally. A single repo doing that is a genuine gap on one
  installation; every repo doing that at once is the credential, not the
  repos.
- **A 404-means-disabled reading that departs from this account's own
  standing rule, and is justified narrowly rather than by exception.** The
  account-wide guidance is emphatic that a bare GitHub 404 means "not
  authorized", not "not there", because most 404s come from a credential that
  cannot see the resource at all. This endpoint's 404 is read as "disabled"
  anyway, and the justification has to hold on its own: the fan-out App's
  **installation** is what grants a token visibility into a repo in the first
  place, not a narrower per-endpoint scope layered on top of an otherwise-
  working credential. A token that cannot see the repo fails `get_repo` and
  the ruleset reads too, and `plan_repo_records`' existing fault isolation
  turns that into a repo-level `error` record — so a lone 404 on
  `vulnerability-alerts`, with every other record for that repo reading
  cleanly, cannot be a hidden authorization failure; there is no scope tier
  between "can administer this repo at all" and "can read this one flag".
  This reasoning is specific to this one endpoint's relationship to the
  fan-out App's grant model — it does not generalize to 404s from other
  GitHub surfaces, and should not be cited as one.
- **Apply order becomes something `plan_repo` has to construct, not just
  report.** Every other managed setting in this engine is independent of
  every other; this is the first pair with a real ordering dependency, and
  `cmd_apply`'s existing "walk drift records in list order" behavior is what
  makes building that order in `plan_repo` sufficient — no change to the
  apply loop itself was needed, only to the order two records are appended
  in.

## Alternatives considered

**Omit `grouped_security_updates` entirely, since nothing can apply it.**
Rejected: an audit of "what does this fleet manage for Dependabot" would then
show two of three toggles with no visible acknowledgment that a third exists
and was left out on purpose versus by oversight — the exact ambiguity this
whole manifest exists to remove for every other setting. Declaring it and
reporting `skipped` costs one line in the fleet config and one line in the
rendered report; omitting it costs a reader having to already know GitHub's
Dependabot UI well enough to notice the gap themselves.

**Treat a 403 on the two applyable leaves as a hard `error` instead of a
skip.** Rejected for the same reason `allow_auto_merge`'s private-repo skip
and `repo.delete_branch_on_merge`'s absent-key skip were built as skips
rather than errors elsewhere in this engine: this is a new capability being
added to an App grant that predates it, and a hard failure on one repo's
scope gap would take the entire weekly apply down over a setting group that,
before this ADR, did not exist for anyone to depend on. The false-green risk
this accepts is named above rather than hidden.

**Wait for GitHub to ship a `grouped_security_updates` API before declaring
the leaf at all.** Rejected: `integrations/terraform-provider-github#3334` has
been open with no resolution, and there is no reason to believe it lands on
any particular timeline. Declaring intent now and revisiting when (if) the
API ships costs nothing the alternative saves.

## How to verify

`tests/test_repo_settings.py` pins the engine behavior: the two readers'
204/403/404/dict-payload branches, the two writers' PUT/DELETE-no-body calls,
`plan_repo`'s match/drift/skip records for all three leaves, the apply-order
regression guard (`vulnerability_alerts` before `automated_security_fixes`
when the latter is desired `true`, reversed when `false`), and that
`grouped_security_updates` never carries a `_writer` and never reports
anything but `skipped`. A `FleetConfigTests`-style assertion confirms the
shipped `fleet.yml` actually declares all three defaults as `true` and that
every managed repo resolves them via `resolve_targets`.

## References

- Issue: none filed — this group was scoped and delivered directly from
  operator instruction on 2026-08-31.
- GitHub REST reference for `security_and_analysis` (repository object) and
  the `vulnerability-alerts` / `automated-security-fixes` endpoints.
- [`integrations/terraform-provider-github` issue 3334](https://github.com/integrations/terraform-provider-github/issues/3334)
  — the open community request for a grouped-security-updates API.
- Schema: [`repo-settings/schema.md`](../../repo-settings/schema.md)
  (`security:`).
- Account-wide guidance: `AGENTS.md`, "A GitHub 404 means 'not authorized', not
  'not there'" and "The fleet spans TWO owners" (the false-green shape this
  ADR's Consequences section borrows).
