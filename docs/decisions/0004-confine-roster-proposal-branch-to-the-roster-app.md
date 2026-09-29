# 0004. Confine skills-evals' roster/proposal branch to the roster App with an extra ruleset

- **Status:** Accepted
- **Date:** 2026-09-29
- **Deciders:** Adam Daniel

## Context

ADR 0003 (as amended 2026-09-29) has a dedicated GitHub App,
`adam-s-daniel-skills-evals-roster` (App id 5116415), open and arm auto-merge on
skills-evals' weekly roster PR from the branch `roster/proposal`. GitHub checks
`--match-head-commit` only when auto-merge is enabled, so any other
write-access actor that pushes `roster/proposal` afterwards retargets the armed
PR: the merge lands a head nobody reviewed. There is a known instance:
skills-evals' `dependabot-auto-merge.yml` job holds a persisted `GITHUB_TOKEN`
with `contents: write`.

The engine managed exactly one ruleset per repo (the default branch), so
nothing could restrict a non-default ref, and nothing declared a per-repo bypass
actor beyond the fleet's agents-md-sync App.

## Decision

The engine gains a per-repo `extra_rulesets:` list (schema in
`repo-settings/schema.md`). Each entry is a named branch ruleset limited to the
rule types `creation`, `update`, `deletion`, `non_fast_forward`, planned,
diffed and applied by name exactly like the default ruleset. skills-evals
declares one: `roster proposal branch`, targeting `roster/proposal`, whose only
bypass actors are the roster App (Integration 5116415) and the repo Admin role
(RepositoryRole 5, the encoding `admin_bypass` uses).

This is the first non-default-branch ruleset and the first per-repo bypass
actor in the fleet config; ADR 0001 requires such grants to be declared here,
where they are auditable and drift-checked, and this is that declaration.

- `github-actions` is not a bypass actor: it is also the Dependabot job's
  identity, so granting it would reopen the gap.
- `extra_rulesets` is per-repo only. `deep_merge` replaces lists, so a
  `defaults:` entry would vanish in any repo declaring its own, and bypass
  grants are repo-specific. `defaults:` use is rejected.
- Removing an entry from config does not delete the live ruleset (the engine
  never touches rulesets it does not declare); delete by hand.
- A fleet test asserts no extra ruleset lists any Integration other than
  5116415.

## Consequences

- **Ordering.** The skills-evals PR that moves the push of `roster/proposal`
  to the App must merge and be verified before this ruleset is applied;
  otherwise the weekly `GITHUB_TOKEN` push is blocked.
- Any other pusher of `roster/proposal`, including a repo Write collaborator or
  `github-actions`, is rejected; only the App and admins remain, and admins are
  a human path.
- A new ADR rather than a third amendment to 0003: this is an engine feature
  with its own alternatives, not a change to 0003's auto-merge exception.
  0003's exception and its `test`-check gate on the default branch are unchanged.

## Alternatives considered

**Make the Dependabot job's checkout not persist credentials.** Fixes the one
known instance but not the class: any future write-access workflow reopens it.
Worth doing anyway in skills-evals.

**Add `github-actions` as a bypass actor.** Rejected: it is the Dependabot
job's identity.

**Put the ruleset in the repo by hand in the UI.** Rejected by ADR 0001:
undeclared, undrifted bypass grants.

## References

- ADR 0001: [0001-bot-writes-results-branch-or-declared-bypass.md](0001-bot-writes-results-branch-or-declared-bypass.md)
- ADR 0003: [0003-scope-skills-evals-roster-auto-merge-as-declared-exception.md](0003-scope-skills-evals-roster-auto-merge-as-declared-exception.md)
- skills-evals ADR 0003: <https://github.com/Adam-S-Daniel/skills-evals/blob/main/docs/decisions/0003-roster-merges-automatically.md>
