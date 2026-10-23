# 0010. Labels may be declared fleet-wide and merge with per-repo labels by name

- **Status:** Accepted
- **Date:** 2026-10-20
- **Deciders:** Adam Daniel

## Context

`labels:` was per-repo only (ADR 0008): `deep_merge` replaces lists, so a
`defaults:` list would vanish in any repo that declares its own, and the one
label then in use belonged to a single repo's workflow. The engine refused
`labels` under `defaults:`.

The `agent-authored` label marks PRs and issues an AI agent opens on the
owner's behalf (_agent-guidance ADR 0023, in progress). It must exist in every
managed repo of both owners, which is the opposite case.

## Decision

`labels` is allowed under `defaults:`. The engine merges it with a repo's own
`overrides.labels` by name, case-insensitively as GitHub does; the repo's entry
wins a clash. Other keys keep `deep_merge`, and `extra_rulesets` and
`actions_policies` stay per-repo only. `agent-authored` (`D4C5F9`) is declared
in `defaults:`.

## Consequences

- A new managed repo gets the label on the next apply with no per-repo entry.
- A repo can override a default's color or description by redeclaring the name.
- Removing a default does not delete live labels (unchanged from ADR 0008).
- The label write needs Issues or Pull requests write on the fan-out
  credential (see schema.md); until the App holds it, each repo reports an
  `error` record rather than creating the label.
