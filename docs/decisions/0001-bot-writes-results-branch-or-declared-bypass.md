# 0001. Route bot writes to results branches; declare rare ruleset bypasses in fleet.yml

- **Status:** Accepted
- **Date:** 2026-07-20
- **Deciders:** Adam Daniel (decision delegated in issue #5)

## Context

The fleet baseline ruleset requires every change to a managed repo's default
branch to arrive via pull request. That works as intended — including against
our own automation: the skills-evals weekly eval bot's badge/results commit was
rejected with GH013 ("Changes must be made through a pull request"). As a
workaround, skills-evals now publishes generated outputs (run summaries,
shields badge JSON) to an unprotected `eval-results` branch — but that
convention was chosen under pressure, and nothing recorded whether it, or
something else, is the sanctioned pattern for the next bot that needs to write
somewhere a ruleset protects.

## Decision

Generated data (badges, run summaries, reports, dashboard feeds) is published
to a dedicated **unprotected results branch** — skills-evals' `eval-results` is
the model — and consumers (badges, dashboards) read from that branch. The rare
bot that genuinely must write to a protected default branch gets a ruleset
**bypass actor declared in this repo's `fleet.yml`** — a per-repo
`bypass_actors:` override for repo-specific bots, or a `defaults:`-level entry
only for a fleet-standard bot that writes to every managed repo — so the grant
is auditable, fleet-consistent, and drift-checked; hand-granting bypass in the
GitHub UI is not allowed — the engine treats bypass actors as managed state,
so an undeclared grant shows up as drift. PR + auto-merge is **not** a
sanctioned bot-write path in this fleet.

The first declared grant is the `agents-md-sync` GitHub App (App id 4268639),
which pushes the managed `AGENTS.md` (and `CLAUDE.md` bridge) directly to
every fleet repo's default branch. The PR-per-repo alternative it replaces
produced unmergeable bot-PR spam — 18 open sync PRs across the fleet at the
time of this decision.

## Consequences

- Main history stays human, and the common case (generated data) needs no
  ruleset weakening at all.
- When a bypass *is* needed, it is one reviewable line in `fleet.yml` rather
  than an invisible UI toggle, and the weekly drift run flags any grant that
  bypasses the manifest.
- Results branches are unprotected by design: consumers must treat their
  content as untrusted generated data, and nothing blocks a stale or
  force-pushed results branch.
- A declared bypass actor with `bypass_mode: always` is a standing hole in the
  ruleset for that identity. Scope it to the narrowest identity possible — a
  dedicated GitHub App, never a human admin's PAT — and prefer redesigning the
  bot onto a results branch first.
- A `defaults:`-level grant is fleet-wide by construction: whoever holds the
  bot's private key can push to the default branch of every managed repo. Keep
  such keys in a single controller repo's secrets (agents-md-sync's lives only
  in `_agent-guidance`) and audit the list whenever a repo is onboarded.

## Alternatives considered

**PR + auto-merge for bot writes.** Honors the ruleset on paper, but interacts
badly with required checks — a `[skip ci]`-style data commit leaves required
contexts unreported — and this fleet carries two real scars: auto-merge firing
on stub checks before the real end-to-end run finished, and a bot auto-merge
chain deadlocking the moment a ruleset required an approving review. It also
adds latency and PR noise proportional to bot write frequency. Rejected as a
sanctioned *bot-write* path. (It remains the right pattern for humans and for
the cms-platform-managed repos, which are excluded from this fleet and use
PR + auto-merge deliberately for content flows.)

**A bypass actor for every bot.** Rejected: most bot output is generated data
with no reason to live on the default branch, and every bypass actor weakens
the ruleset for its whole identity, not per path.

**Results branches as the only pattern.** Rejected as a universal rule: a bot
whose output must land on the default branch (say, a future version-stamp bot)
would be forced into hand-granted bypasses or auto-merge loops; better to give
that case a declared, auditable path.

## How to verify

`tests/test_repo_settings.py` pins the engine behavior: `bypass_actors` config
entries are built into the ruleset body, `generate` round-trips non-admin
actors, and `normalize_ruleset` treats bypass actors as managed state (which is
what makes an undeclared UI grant surface as drift).

## References

- Issue: [Adam-S-Daniel/repo-settings#5](https://github.com/Adam-S-Daniel/repo-settings/issues/5)
- The rejected bot push: <https://github.com/Adam-S-Daniel/skills-evals/actions/runs/29620223686>
- The live results-branch example: skills-evals' `eval-results` branch
- Schema: [`repo-settings/schema.md`](../../repo-settings/schema.md) (`bypass_actors`)
