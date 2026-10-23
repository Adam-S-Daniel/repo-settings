# 0011. Make `manage` a required array of surfaces

- **Status:** Accepted
- **Date:** 2026-10-23
- **Deciders:** Adam Daniel

## Context

Each element of the `repos` array in `repo-settings/fleet.yml` carried an
optional boolean `manage`, defaulting to `true` when omitted. Omitting it
selected the widest scope, so "managed by decision" could not be told apart
from "never considered", and omitted and `true` were two values with one
meaning. The fleet's settings-schema rules
([_agent-guidance `docs/reference/settings-schema-design.md`](https://github.com/Adam-S-Daniel/_agent-guidance/blob/main/docs/reference/settings-schema-design.md))
say a setting that selects what a tool acts on is required unless its default
selects nothing, and that a setting accepts only its documented values.

A boolean also cannot say "labels only", which the cms-platform-managed repos
need ([#88](https://github.com/Adam-S-Daniel/repo-settings/issues/88)).

PyYAML adds its own synonyms: it loads an unquoted `no` as `False`, and it
keeps the last of two identical keys in a map without a word. Before this
change the engine also ignored any key it did not read, so `overides:` or
`mange:` silently changed nothing, and its config errors exited 1, the code
that already means drift for `diff` and undeclared repos for `coverage`.

## Decision

- `manage` is **required** in every element of `repos`, and its value is an
  **array of strings**: `["all"]`, `[]`, or surface names.
- A **surface** is one top-level key of a repo's resolved settings, which
  `plan_repo` plans independently: `actions`, `actions_policies`,
  `extra_rulesets`, `labels`, `repo`, `ruleset`, `security`. Surfaces are
  **top-level only**; there is no way to manage part of `actions`. They are
  defined once, as `SURFACES` in `scripts/repo_settings.py`, and every check
  and error message is built from that constant.
- `["all"]` means every surface, **including any added to the engine later**.
  A repo that wants a fixed set lists it.
- Surfaces are listed in **canonical order**, which is alphabetical (the order
  of `SURFACES`), so one selection has exactly one spelling. A list naming all
  seven is refused in favor of `["all"]`, and `"all"` must stand alone.
- Every other value is refused: omitted, non-arrays (booleans and null
  included), non-string elements, unknown or miscased names, duplicates.
- **Unknown keys are refused** at every level: the file's top level, a `repos`
  element, `defaults` and `overrides`, and the keys inside each surface, which
  are the keys that surface's planner reads. Maps with a duplicate key and two
  elements naming the same repo (compared case-insensitively) are refused too.
- The whole file is validated **before** anything is filtered, and a refused
  config **exits 2**, before any API call.
- Filtering happens once, in `resolve_targets`, after defaults and the label
  merge: a surface reaches the planner only when `manage` names it.

## Consequences

- Every element states its scope, so a reader never has to know a default. The
  migration was one-for-one: elements that omitted `manage` got `["all"]`,
  `manage: false` became `[]`, and `diff` plans the same calls before and
  after.
- A config written for the old boolean now fails closed with exit 2 and an
  error naming `[]` and `["all"]`, including one taught by a skill that has not
  been updated yet.
- `["all"]` widens on its own when the engine gains a surface. That is the
  point of the value, and it is why a repo owned partly elsewhere must list
  its surfaces instead.
- A new key in a surface needs a matching entry in `SURFACE_KEYS`, or the
  engine refuses configs that use it. That is the intended cost of catching
  misspellings.
- The single-repo shape now selects surfaces through the same constant, which
  fixed a `security:` block it had silently dropped.

## Alternatives considered

**Keep the boolean and add a surface list beside it.** Two keys that both
select scope give two spellings of "everything" and an interaction to define.
Rejected by the one-meaning-one-value rule.

**A string for one surface and an array for several** (`manage: labels`). One
selection would have two spellings, as GitHub's `on: push` and `on: [push]`
do. Rejected.

**Allow any order and sort it.** It accepts `["security", "labels"]` and
`["labels", "security"]` as one value with two spellings. Rejected; the error
names the canonical form instead.

**Order the surfaces as `plan_repo` plans them.** That order is an
implementation detail that a reader cannot apply without opening the engine.
Alphabetical can be written from memory.

**Split surfaces below the top level** (for example, part of `actions`).
Rejected for now: no repo needs it, and it would make `SURFACES` depend on
the shape of each planner.

## References

- Issue: [Adam-S-Daniel/repo-settings#83](https://github.com/Adam-S-Daniel/repo-settings/issues/83)
- Follow-up that needs it: [#88](https://github.com/Adam-S-Daniel/repo-settings/issues/88)
- Schema: [`repo-settings/schema.md`](../../repo-settings/schema.md), "Terms" and "`manage`"
