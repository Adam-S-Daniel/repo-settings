# 0020. Fan the privacy denylist out as a `secrets` surface

- **Status:** Accepted
- **Date:** 2026-11-24
- **Deciders:** Adam Daniel (issue
  [#231](https://github.com/Adam-S-Daniel/repo-settings/issues/231))

## Context

The fleet's privacy denylist reached CI in two repos, each through a
`PRIVACY_DENYLIST` repository secret set by hand, and the copies had drifted
(12 patterns against the owner's 16). `Adam-S-Daniel` is a personal account
with no organization secrets, so a secret exists only per repo or per
environment. This repo already acts as the fleet's organization layer for both
owners.

## Decision

- **`secrets` is an eighth surface**, an array of `{name}` like `labels`, and
  `["all"]` includes it. `fleet.yml` declares `PRIVACY_DENYLIST` under
  `defaults`. Names must be on `SECRET_SOURCES` in the engine, so a config
  change cannot make the engine copy another variable (the admin App key)
  into a repo.
- **One source, never in the file.** `scripts/set_privacy_denylist.py` stores
  the owner's local denylist (stdin, or a `--file` outside any git work tree)
  as the `PRIVACY_DENYLIST` secret of both apply environments, and records the
  time in the repo variable `PRIVACY_DENYLIST_UPDATED_AT`. The two apply jobs
  get the value from their environment; every job gets the timestamp.
- **Drift is age, not content.** The API returns a secret's name and
  `updated_at`, never its value, so a repo is drifted when its secret is
  missing, or last updated before the source timestamp. The value is never
  hashed, compared or printed, and error text is redacted. With no source
  timestamp, a present secret is left alone.
- **The write is `gh secret set --app actions`**, which seals the value with
  the repo's public key and takes it on stdin. That avoids a new dependency
  (PyNaCl) in the job that holds the admin key.
- **The write is classified safe**, so `apply-auto` makes it with no approval:
  a secret holds no constraint, the name is allowlisted, and the value is the
  owner's own.
- **Tokens.** Both Apps need **Secrets**: the read App Read (plan and drift),
  the admin App Read & write. No Dependabot secrets: Dependabot runs skip the
  scan with a warning.

## Consequences

- The three cms-platform-managed repos (`manage: ["labels"]`, ADR 0016) and
  `manage: []` repos do not receive the secret. Extending the label-only
  token to Secrets would need its own decision.
- Until the Apps hold Secrets permission, every repo's `fanout[...]` record is
  an `error` (HTTP 403), not drift and not a silent skip.
- The source's age is the setter script's own timestamp, so rotating the
  denylist by any other route leaves the copies looking current.
