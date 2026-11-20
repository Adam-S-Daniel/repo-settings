# Code scanning: fleet setup against GitHub's docs

A review of the fleet's CodeQL setup against GitHub's
[Configure code scanning](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/configure-code-scanning)
pages, limited to what the free plan offers. How each setting is declared:
[`schema.md`](../repo-settings/schema.md) ("CodeQL default setup",
`require_code_scanning`). Why onboarding applies it unreviewed:
[ADR 0019](decisions/0019-apply-tightening-changes-with-no-approval.md).

## What the fleet runs (swept 2026-11-20, `gh repo list` for both owners)

- **19 public, non-fork, non-archived repos:** default setup `configured`,
  `query_suite: extended` (see below), `threat_model: remote`,
  `runner_type: standard`, languages chosen by GitHub.
- **No repo has an advanced-setup workflow** (no `github/codeql-action/init`,
  `analyze` or `upload-sarif` in `.github/workflows`).
- **5 private repos:** skipped; CodeQL there needs GitHub Code Security, a paid
  product. **2 forks:** `not-configured`, unmanaged by design. **2 archived:**
  nothing to do.
- **acsi-kit** carries the `code_scanning` ruleset rule as a trial.

## What the engine does about it

- **CodeQL already running another way waits for review.** Turning default
  setup on "will disable the existing workflow file and block any CodeQL
  analysis API uploads"
  ([configure default setup](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/configure-code-scanning/configuring-default-setup-for-code-scanning)),
  and the API gives no warning. The plan looks for non-default CodeQL analyses
  (or, without code scanning read, a `codeql`-named workflow) and gates the
  write, even on a repo being set up.
- **"Require code scanning results"** (`ruleset.require_code_scanning`) blocks
  a merge that adds an alert at or above its thresholds
  ([merge protection](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/manage-your-configuration/set-code-scanning-merge-protection)).
  GitHub accepts it on a user-owned public repo on the free plan. It blocks
  while CodeQL is "not configured" or still running, so the engine drops it on
  private repos. Trial on acsi-kit (`errors`, `high_or_higher`); before the
  fleet gets it, see how it treats a fork pull request (default setup does not
  scan those) and how long it holds auto-merge.
- **Unscanned languages are reported.** A CodeQL language with at least 1% of
  the repo's bytes that default setup does not scan is a report-only
  `security.codeql_languages` advisory. GitHub drops a language whose first
  analysis fails and does not retry. Synced hook scripts (`.githooks/*.js`)
  trigger it until they are marked `linguist-vendored`.

## Extended suite: on fleet-wide

Trial on skills-evals, _agent-guidance and claude-memory-map, compared with
the default suite on the same commits:

- Rules: JavaScript 87 to 103, Python 43 to 50, Ruby 41 to 47, Actions 17 to 23.
- _agent-guidance: one new high alert in first-party code
  (`js/file-system-race`, `scripts/check-cron-coverage.js`).
- claude-memory-map: nothing new.
- skills-evals: 34 new medium and high alerts, all in frozen eval fixtures
  (`evals/real-work/*/seed/`, copies of cms-platform and _agent-guidance
  code), left for triage like the 48 it has already dismissed as "used in
  tests". One Python upload during the
  switch failed with "Unknown Error"; the next scan shows whether it recurs.

More real findings at little noise in first-party code, so `extended` is the
default. The fixture alerts point at the same patterns in cms-platform, which
manages its own settings and still runs `default`.

## Checked, no change

- **`security-and-quality` suite:** not used. Default setup cannot run it,
  and code quality comes from managed linters instead
  ([_agent-guidance ADR 0049](https://github.com/Adam-S-Daniel/_agent-guidance/blob/main/docs/decisions/0049-code-quality-comes-from-managed-linters-not-codeql.md)).
- **Threat model** `remote_and_local`: public preview, Java/Kotlin and C# only.
- **Labeled runners, default setup at scale, advanced setup:** self-hosted or
  org features, or more upkeep for no gain; default setup also picks up new
  languages on its own.
- **Copilot Autofix:** on by default for public repos using CodeQL; nothing
  to set ([Copilot Autofix](https://docs.github.com/en/code-security/concepts/code-scanning/copilot-autofix-for-code-scanning)).

## What a periodic fleet check should cover

| Check | Covered by |
|---|---|
| Default setup on for every managed public repo; declared suite | repo-settings plan (scheduled), enforced |
| Private repos and forks knowingly unscanned | repo-settings `skipped` records; `coverage` names undeclared repos |
| Nothing else runs CodeQL where default setup goes on | repo-settings gate, at turn-on only |
| A CodeQL workflow added later to a default-setup repo (its uploads are refused) | **Nothing.** Add to the plan: non-`dynamic/` CodeQL analyses or workflows while default setup is on |
| Scanned languages match the repo's code | repo-settings `security.codeql_languages` advisory; language detection itself is the drift report's (_agent-guidance) |
| A language whose latest analysis failed, or was dropped | security-alerts `collect` (daily): per-language `errors` and `dropped` in the snapshot |
| Scans going stale (weekly schedule stops after 6 months without a push or pull request; Actions disabled) | security-alerts records `last_run` but flags nothing. **Add:** no default-branch analysis in 8 days |
| Open alerts triaged and fixed | security-alerts `codeql-plan` and `notify-plan` |
| Merge protection rule present where declared | repo-settings ruleset plan |

The two gaps are small: a plan advisory in repo-settings for a late CodeQL
workflow, and a staleness flag in security-alerts. Both are recommendations,
not built.
