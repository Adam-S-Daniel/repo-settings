# 0005. Let the vendor changelog routine merge its own PR through a mechanical gate

- **Status:** Accepted
- **Date:** 2026-09-30
- **Deciders:** Adam Daniel (decided 2026-09-30)

## Context

`_agent-guidance` runs a daily claude.ai cloud Routine, "agent changelog
watcher" (spec:
[`docs/reference/agent-changelog-routine.md`](https://github.com/Adam-S-Daniel/_agent-guidance/blob/main/docs/reference/agent-changelog-routine.md)).
Each run appends vendor (Claude Code, Codex) changelog entries, files impact
issues in fleet repos, logs the run, and opens one PR in `_agent-guidance`.
Until now the owner merged that PR by hand (for example
[`_agent-guidance` PR 216](https://github.com/Adam-S-Daniel/_agent-guidance/pull/216),
merged 2026-09-30 by the owner). A PR left open made the next run carry it
forward instead of opening a new one.

The PR's diff is data under `docs/reference/`: two CHANGELOGs, two
DISCREPANCIES files, a run log and an issue map. The actionable output is the
issues, not the diff. Reviewing it daily adds latency without much judgment.

ADR 0001 says PR + auto-merge is not a sanctioned bot-write path, and ADR 0003
made the first declared exception (skills-evals' roster). The routine is a bot
in all but name: it runs with the owner's credentials, not an App identity.

What the human review actually guarded: every run quotes fetched vendor text
verbatim into files that the next run reads back from `main`, so review was the
only gate against instruction-shaped text landing there. The spec also told
runs to add "Known traps" to the routine's own instructions file in the same
PR, so an unreviewed merge could rewrite the routine's own prompt.

`_agent-guidance`'s ruleset has `required_approving_review_count: 0` and
requires only the `test` check (`fleet.yml`). Nothing mechanical stops the
merge, so the constraint has to live in the routine.

## Decision

The routine is the second declared exception to ADR 0001's "PR + auto-merge is
not a sanctioned bot-write path". It merges its own PR only when
`scripts/routine-merge-gate.js` in `_agent-guidance` exits 0. The gate requires
all of:

- the PR is open, not a draft, based on `main`, with a same-repo head;
- the title starts `Vendor changelog routine: ` and has no `DRY_RUN`;
- the body has no "Declined" heading;
- every changed path is on an exact allowlist of those `docs/reference/`
  files. The routine's own spec file is **not** on it: trap notes now go to
  issues;
- every check run on the head completed `success`, `neutral` or `skipped`,
  with `test` `success`, and every legacy status is `success`;
- the issue map parses.

The merge uses the REST merge endpoint with `merge_method: merge`, pinned to
the judged head `sha`, and no typed commit message (the fleet's
`merge_commit_message: PR_TITLE` keeps body keywords out of the commit). The
routine never arms native auto-merge, because auto-merge waits only for
required contexts (the Dependabot sweep's lesson,
[cms-platform issue 437](https://github.com/Adam-S-Daniel/cms-platform/issues/437)),
and never uses a bypass actor.

A refused gate leaves the PR open for the owner, and the carry-forward path
handles it on the next run.

No setting in `fleet.yml` changes. The exception lives in the routine's spec
and the gate script, not in the ruleset. That is a real weakness: nothing here
drift-checks it, and this ADR is the record.

## Consequences

- No daily human merge. Issues reach the laptop issue worker (label
  `agent-ready`) sooner.
- No new identity, no bypass actor and no ruleset change. The merge goes
  through the same `test` check as a human's.
- Vendor text reaches `main` without a human reading it. Mitigations: the path
  allowlist, the Declined-heading refusal, and the rule that the routine may
  not edit its own spec. Residual risk: instruction-shaped text the routine did
  not recognize, sitting in data files that later agents read and are expected
  to treat as data.
- The gate is enforced by the routine running it, with the owner's
  credentials. A routine that skipped the gate could still merge, and the
  ruleset cannot express "only these paths" for a PR merge. If that becomes
  unacceptable, move the merge to a dedicated App identity (the ADR 0003
  amendment pattern) or back to the owner.
- A push to `main` from a merge touching `agent-*.DISCREPANCIES.md` fires
  `_agent-guidance`'s `vendor-discrepancy-alert` workflow, which opens issues.
  That is intended, but it is now unattended.

## Alternatives considered

**Keep merging by hand (status quo).** Rejected by the owner: a daily latency
cost for a data-only PR.

**Native auto-merge armed by the routine.** Rejected. Auto-merge waits only for
required contexts, so it can fire before the other checks on the head finish.
ADR 0001 records the same scar.

**A dedicated GitHub App with a sweep** (like skills-evals' roster App or the
Dependabot sweep). Better identity separation, but it adds a new App and
private key for one daily docs PR. Revisit if the gate's self-enforcement
proves insufficient.

**A results branch (ADR 0001's default).** Rejected: the next run reads these
files from `main` (window start, issue map), so they are not generated data.

## How to verify

`_agent-guidance`'s `test/test-routine-merge-gate.js`, run by
`test/run-tests.sh`, shows that each refusal condition flips the verdict.

## References

- ADR 0001: [Route bot writes to results branches; declare rare ruleset bypasses in fleet.yml](0001-bot-writes-results-branch-or-declared-bypass.md)
- ADR 0003: [Scope skills-evals' roster auto-merge as a declared exception to ADR 0001](0003-scope-skills-evals-roster-auto-merge-as-declared-exception.md)
- Routine spec: <https://github.com/Adam-S-Daniel/_agent-guidance/blob/main/docs/reference/agent-changelog-routine.md>
- A hand-merged routine PR: <https://github.com/Adam-S-Daniel/_agent-guidance/pull/216>
- The Dependabot sweep's auto-merge lesson: <https://github.com/Adam-S-Daniel/cms-platform/issues/437>
