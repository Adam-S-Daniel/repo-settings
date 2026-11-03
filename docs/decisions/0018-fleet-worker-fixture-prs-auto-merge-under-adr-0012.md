# 0018. Fleet worker fixture PRs in skills-evals auto-merge under ADR 0012

- **Status:** Accepted (on merge of repo-settings#162)
- **Date:** 2026-11-03
- **Deciders:** Adam Daniel (standing decisions of 2026-10-26: "closed loop
  with no human in the loop", and loop changes that pass evals or checks
  auto-merge); accepted by his merge of repo-settings#162
- **Amends:** [ADR 0012](0012-eval-loop-prs-auto-merge-as-a-declared-exception.md)

## Context

skills-evals' weekly sweep now files one `agent-ready` issue per skill or
guidance section that needs more fixtures, or a harder one, before the
improve lane can work on it
([skills-evals#659](https://github.com/Adam-S-Daniel/skills-evals/issues/659)).
The fleet worker's issue pass answers such an issue with a pull request that
adds fixtures. It never merges, and its PR pass merges only narrow
instruction fixes (_agent-guidance ADRs 0025 and 0028), so every fixture pull
request would wait for Adam. That is the one human step left in the fixture
supply.

Those pull requests are opened by the fleet worker, which writes as
Adam-S-Daniel through the claude.ai GitHub connector, not by an App. So the
exception cannot be keyed on the opener alone, as ADR 0012's rows are.

## Decision

Add one row to ADR 0012's table:

| Repo | PRs | Paths the PR may touch | Opened by |
|---|---|---|---|
| skills-evals | fleet worker fixtures answering a fixture-need issue | new directories `evals/<skill>/<name>/**` or `evals/guidance/<section>/<name>/**` for the issue's subject, plus appended entries for them in `evals/unscheduled.yml` (skill) or `evals/scheduled.yml` (guidance) | the fleet worker (as Adam-S-Daniel, label `agent-authored`); auto-merge armed by the roster App, `adam-s-daniel-skills-evals-roster` (App id 5116415, skills-evals only) |

`.github/workflows/fixture-pr-gate.yml` decides, from the default branch's
copy only (a `workflow_run` of a permission-less `pull_request` signal). It
reads the head with git plumbing as data and runs nothing from it.
`scripts/fixture_pr_gate.py` puts a pull request in the lane only when its
author is Adam-S-Daniel, it carries `agent-authored`, its head branch is in
skills-evals, and its body names exactly one open issue that
github-actions[bot] opened with a fixture-need marker. Such a pull request is
armed (merge commit, `--match-head-commit`) only when every change adds a
regular file under a new fixture directory for that subject, each new
fixture names the subject and is not a draft, and the one list file changes
only by appending entries for the new fixtures, under size caps. A later push
that breaks any of this turns auto-merge off. Pull requests outside the lane
are never touched.

Every condition of ADR 0012 still holds: the required check (`test`) gates
the merge, no bot approves, and only merge commits are used. A merged skill
fixture is an isolation pair on `evals/unscheduled.yml`. It costs no eval
run until skills-evals' `contextualize_fixtures.py` gives it a context and
schedules it, and the eval scope pass (ADR 0017) pauses a fixture that cannot
show a gain.

## Consequences

- The fixture queue drains with no human step. A weak fixture costs a few
  eval runs before the scope pass pauses it; a wrong one is reverted like any
  other pull request.
- Anyone who can write as Adam-S-Daniel could have a fixture-only pull
  request merge itself. That account can already merge anything, so the
  exception adds no reach. Only the roster App's key arms these pull
  requests, so the App's reach does not grow either.
- The gate keys on a label, a body reference and a diff shape, not an App
  identity. That is weaker than ADR 0012's other rows, so the path list
  above is the whole of what may merge this way.

## References

- ADR 0012: [Eval-loop PRs auto-merge as a declared exception](0012-eval-loop-prs-auto-merge-as-a-declared-exception.md)
- ADR 0017: [Eval-scope PRs in skills-evals auto-merge under ADR 0012](0017-eval-scope-prs-auto-merge-under-adr-0012.md)
- skills-evals PR adding the gate: <https://github.com/Adam-S-Daniel/skills-evals/pull/667>
