# Code scanning: fleet setup against GitHub's docs

A review of the fleet's CodeQL setup against GitHub's
[Configure code scanning](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/configure-code-scanning)
pages, limited to what the free plan offers. How the setting is declared:
[`schema.md`](../repo-settings/schema.md) ("CodeQL default setup"). Why
onboarding applies it unreviewed: [ADR 0019](decisions/0019-apply-tightening-changes-with-no-approval.md).

## What the fleet runs (swept 2026-11-20, `gh repo list` for both owners)

- **19 public, non-fork, non-archived repos:** default setup `configured`,
  `query_suite: default`, `threat_model: remote`, `runner_type: standard`,
  languages chosen by GitHub. 0 open alerts.
- **No repo has an advanced-setup workflow** (no `github/codeql-action/init`,
  `analyze` or `upload-sarif` in `.github/workflows`), so the
  replace-the-workflow risk below has no live case.
- **5 private repos:** skipped; CodeQL there needs GitHub Code Security, a paid
  product. **2 forks:** `not-configured`, unmanaged by design. **2 archived:**
  unreadable, nothing to do.
- No default-branch ruleset carries the `code_scanning` rule.

## Recommended

1. **Gate default setup on an existing CodeQL workflow, in the engine.**
   Turning default setup on "will disable the existing workflow file and block
   any CodeQL analysis API uploads"
   ([configure default setup](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/configure-code-scanning/configuring-default-setup-for-code-scanning)).
   GitHub's API gives no signal for this, and ADR 0019 leaves the check to
   whoever declares the repo. Make it mechanical: when the plan would set
   `codeql_default_setup: true`, read the default branch's
   `.github/workflows/*` and, if any uses `github/codeql-action/init`,
   `analyze` or `upload-sarif`, classify the write as gated with that reason
   (`_codeql_risk`), plus a test.
2. **Trial "Require code scanning results" on one repo.** CodeQL reports on
   every same-repo pull request but blocks nothing, and agents merge on green.
   The ruleset rule (`code_scanning`, tool `CodeQL`, security alerts
   `high_or_higher`, alerts `errors`) blocks a merge that adds such an alert
   ([merge protection](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/manage-your-configuration/set-code-scanning-merge-protection)).
   Before the fleet gets it:
   - The docs do not say whether a user-owned public repo on the free plan can
     use it; add it to one repo and read the ruleset back.
   - It blocks when CodeQL is "not configured for the repository" or still
     running, so declare it only where default setup is on (never private
     repos or forks), and expect it to hold up auto-merge until the scan ends.
   - Default setup skips pull requests from forks; check what the rule does
     with one before relying on it.
   - The engine does not model this rule type, so a ruleset write would gate
     it as unknown; it needs schema and classifier support first.

## Checked, no change

- **Extended suite** (`security-extended`): more queries, more false
  positives. Keep `default`; a repo can opt in with `codeql_query_suite` in its
  overrides ([query suites](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-query-suites)).
- **Threat model** `remote_and_local`: public preview, Java/Kotlin and C# only.
- **Labeled runners, default setup at scale, advanced setup:** self-hosted or
  org features, or more upkeep for no gain; default setup also picks up new
  languages on its own.
- **Copilot Autofix:** on by default for public repos using CodeQL; nothing
  to set ([Copilot Autofix](https://docs.github.com/en/code-security/concepts/code-scanning/copilot-autofix-for-code-scanning)).

## Worth knowing

- **A language that fails is dropped silently.** GitHub falls back to the last
  working configuration
  ([setup types](https://docs.github.com/en/code-security/concepts/code-scanning/setup-types)).
  `claude-plan-usage-estimator`'s first `javascript-typescript` analysis
  failed when default setup was turned on, and its languages read
  `actions,python` since, so its JavaScript is not scanned. Security > Code
  scanning > Tool status shows why.
- **The weekly scan stops after 6 months without a push or pull request**, so
  a dormant repo is not re-scanned when CodeQL adds queries. Its next push
  restarts it.
