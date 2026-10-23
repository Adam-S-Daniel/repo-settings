"""The pull_request leg of repo-settings.yml mints a read-only App token.

That leg runs the PR branch's own `scripts/repo_settings.py diff`, so a token
with the App's full grant there hands fleet-wide Administration, Actions and
Issues write to anyone who can push a branch, before review (issue #91). These
tests parse the workflow with `yaml` and hold that shape in place:

* every App-token mint step that can run on pull_request is restricted to
  pull_request, and sets the four `permission-*` inputs the drift report
  needs, every one of them -- and every other `permission-*` it sets -- to
  `read`;
* no write-capable mint step (one with no `permission-*` inputs, or any input
  other than `read`) can run on pull_request;
* every step that can run on pull_request and uses an App token uses the
  read-only one, and the apply-side steps use the full one.

They fail closed: a mint step whose `if:` they cannot place is treated as able
to run on pull_request.
"""

import re
import unittest

from test_required_checks import WORKFLOWS_DIR, load_workflow, triggers

WORKFLOW = WORKFLOWS_DIR / "repo-settings.yml"
JOB = "repo-settings"
MINT_ACTION = "actions/create-github-app-token@"
REQUIRED_READ = {
    "permission-administration",
    "permission-actions",
    "permission-issues",
    "permission-metadata",
}
APP_GATE = "vars.REPO_SETTINGS_APP_CLIENT_ID != ''"
EVENT_CONJUNCT = re.compile(r"github\.event_name\s*(==|!=)\s*'([a-z_]+)'")
# A step-output reference is a lexical token inside an expression string.
TOKEN_REF = re.compile(r"steps\.([A-Za-z0-9_-]+)\.outputs\.token\b")


def top_level_conjuncts(expr):
    """Split a GitHub expression on its top-level `&&`, leaving any `&&`
    inside parentheses or a quoted string alone."""
    expr = expr.strip()
    if expr.startswith("${{") and expr.endswith("}}"):
        expr = expr[3:-2]
    parts, depth, quoted, start, i = [], 0, False, 0, 0
    while i < len(expr):
        ch = expr[i]
        if ch == "'":
            quoted = not quoted
        elif not quoted and ch == "(":
            depth += 1
        elif not quoted and ch == ")":
            depth -= 1
        elif not quoted and depth == 0 and expr.startswith("&&", i):
            parts.append(expr[start:i].strip())
            start = i + 2
            i += 1
        i += 1
    parts.append(expr[start:].strip())
    return parts


def event_gate(step):
    """'pr-only' if the step's `if:` requires event_name == pull_request,
    'never-pr' if a top-level conjunct rules pull_request out, else 'maybe'
    (no `if:`, or one these tests cannot place -- fail closed)."""
    cond = step.get("if")
    if cond is None:
        return "maybe"
    for part in top_level_conjuncts(str(cond)):
        m = EVENT_CONJUNCT.fullmatch(part)
        if not m:
            continue
        op, event = m.groups()
        if op == "==" and event == "pull_request":
            return "pr-only"
        if (op == "!=" and event == "pull_request") or (op == "==" and event != "pull_request"):
            return "never-pr"
    return "maybe"


def token_refs(step):
    """Step ids whose `outputs.token` the step reads, from any string value."""
    refs = set()

    def walk(value):
        if isinstance(value, str):
            refs.update(TOKEN_REF.findall(value))
        elif isinstance(value, dict):
            for v in value.values():
                walk(v)
        elif isinstance(value, list):
            for v in value:
                walk(v)

    walk(step)
    return refs


def is_write_capable(step):
    """A mint with no `permission-*` input inherits the App's whole grant; any
    `permission-*` other than `read` asks for write."""
    perms = {k: v for k, v in (step.get("with") or {}).items()
             if str(k).startswith("permission-")}
    return not perms or any(str(v) != "read" for v in perms.values())


class ReadOnlyPullRequestTokenTests(unittest.TestCase):
    def setUp(self):
        doc = load_workflow(WORKFLOW)
        self.assertIn("pull_request", triggers(doc, WORKFLOW))
        self.job = (doc.get("jobs") or {}).get(JOB)
        self.assertIsNotNone(self.job, f"{WORKFLOW.name}: no `{JOB}` job")
        self.steps = self.job.get("steps") or []
        self.mints = [s for s in self.steps if str(s.get("uses", "")).startswith(MINT_ACTION)]
        self.assertTrue(self.mints, f"{WORKFLOW.name}: no {MINT_ACTION} step found")

    def pr_mints(self):
        return [s for s in self.mints if event_gate(s) != "never-pr"]

    def test_job_keeps_the_app_configured_gate(self):
        self.assertIn(APP_GATE, str(self.job.get("if", "")))

    def test_exactly_one_mint_runs_on_pull_request_and_only_there(self):
        pr_mints = self.pr_mints()
        self.assertEqual(len(pr_mints), 1, [s.get("name") for s in pr_mints])
        self.assertEqual(event_gate(pr_mints[0]), "pr-only", pr_mints[0].get("if"))

    def test_pull_request_mint_sets_every_needed_permission_to_read(self):
        for step in self.pr_mints():
            inputs = step.get("with") or {}
            perms = {k: v for k, v in inputs.items() if str(k).startswith("permission-")}
            self.assertLessEqual(REQUIRED_READ, set(perms), step.get("name"))
            for key, value in perms.items():
                self.assertEqual(str(value), "read", f"{step.get('name')}: {key}={value!r}")

    def test_no_write_capable_mint_runs_on_pull_request(self):
        for step in self.pr_mints():
            self.assertFalse(is_write_capable(step), step.get("name"))

    def test_every_other_event_still_gets_a_full_token(self):
        # The apply legs need write; this is the mint they read.
        full = [s for s in self.mints if event_gate(s) == "never-pr" and is_write_capable(s)]
        self.assertEqual(len(full), 1, [s.get("name") for s in full])

    def test_each_step_reads_the_token_for_its_event(self):
        ro_ids = {s.get("id") for s in self.pr_mints()}
        full_ids = {s.get("id") for s in self.mints} - ro_ids
        self.assertNotIn(None, ro_ids | full_ids, "every mint step needs an id")
        users = 0
        for step in self.steps:
            refs = token_refs(step)
            if not refs:
                continue
            users += 1
            gate = event_gate(step)
            if gate == "never-pr":
                self.assertLessEqual(refs, full_ids, step.get("name"))
            else:
                # Anything that can run on pull_request reads only the
                # read-only token; a step gated to pull_request must not read
                # the full one, which is never minted there.
                self.assertLessEqual(refs, ro_ids, step.get("name"))
        self.assertGreater(users, 0, "no step reads an App token")


class EventGateTests(unittest.TestCase):
    def test_places_the_workflow_conditions(self):
        self.assertEqual(event_gate({"if": "github.event_name == 'pull_request'"}), "pr-only")
        self.assertEqual(event_gate({"if": "github.event_name != 'pull_request'"}), "never-pr")
        self.assertEqual(
            event_gate({"if": "github.event_name == 'workflow_dispatch' && inputs.dry_run"}),
            "never-pr")
        self.assertEqual(
            event_gate({"if": "github.event_name != 'pull_request' && "
                              "!(github.event_name == 'workflow_dispatch' && inputs.dry_run)"}),
            "never-pr")

    def test_unknown_or_disjunctive_conditions_fail_closed(self):
        self.assertEqual(event_gate({}), "maybe")
        self.assertEqual(event_gate({"if": "always()"}), "maybe")
        self.assertEqual(
            event_gate({"if": "github.event_name != 'pull_request' || always()"}), "maybe")
        self.assertEqual(
            event_gate({"if": "!(github.event_name != 'pull_request' && inputs.x)"}), "maybe")


if __name__ == "__main__":
    unittest.main()
