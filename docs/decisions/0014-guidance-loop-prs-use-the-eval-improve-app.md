# 0014. Guidance-loop PRs in _agent-guidance use the eval-improve App

- **Status:** Accepted (Adam, decision card 2026-10-27 01:18 UTC, "Reuse the eval-improve App")
- **Date:** 2026-10-27
- **Deciders:** Adam Daniel (2026-10-10, guidance section removal is
  automatic, skills-evals#124; 2026-10-25, removal PRs auto-merge with no
  human; 2026-10-26, build the closed loop with no human in it, and keep
  setup simple and consolidated)
- **Amends:** [ADR 0012](0012-eval-loop-prs-auto-merge-as-a-declared-exception.md)

## Context

ADR 0012's table lets guidance-section edits and removals in _agent-guidance
auto-merge, opened by "a dedicated eval-guidance App, installed on
_agent-guidance only". That App was never created, so skills-evals'
scheduled retirement job can only file an issue for a guidance section's
`retire` verdict.

Two facts the table missed:

- A removal of a section of `agents-md/base.md` must also rewrite
  `.claude/hooks/fleet-guidance.md`, _agent-guidance's own fleet-memory
  payload, which a check requires to be a byte-identical copy of base.md.
  That path is not in the row's allowlist.
- A second App means a second private key and two more secrets to rotate,
  for the same two permissions the eval-improve App already holds.

## Decision

The eval-improve App (skills-evals secrets `EVAL_IMPROVE_APP_CLIENT_ID`,
`EVAL_IMPROVE_APP_PEM`) is installed on _agent-guidance as well as
adam-agentskills, and opens the guidance-loop PRs. No dedicated
eval-guidance App is created.

ADR 0012's _agent-guidance row becomes:

| Repo | PRs | Paths the PR may touch | Opened by |
|---|---|---|---|
| _agent-guidance | guidance-section edits and removals | `agents-md/**`, `AGENTS.md`, `docs/guidance-impact.md`, `.claude/hooks/fleet-guidance.md` (only as a byte-identical copy of `agents-md/base.md`) | the eval-improve App, installed on adam-agentskills and _agent-guidance |

Every condition of ADR 0012 still holds, and the per-repo scoping moves into
the token: each workflow step mints the App's token for **one** repository
(`repositories:` names a single repo), only in the step that writes, after
the gate has checked the changed paths against that repo's row.

## Consequences

- One App and one key cover both registries the loop writes to. A leaked key
  reaches both repos instead of one. The App still has only Contents and Pull
  requests write, is not a ruleset bypass actor, and every merge still waits
  on the required checks.
- Until Adam adds _agent-guidance to the App's repository access, the mint
  fails under `continue-on-error`, and the job keeps filing an issue. Nothing
  else changes.
- Removing _agent-guidance from the App's repository access turns the
  guidance PRs back into issues, with no code change.
