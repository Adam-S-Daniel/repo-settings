"""The admin App key is reachable only from the approval-gated apply job,
and approval is asked for only when the ungated plan finds something to apply.

A pull request branch controls its own copy of repo-settings.yml, so any job
that can run on pull_request could read whatever secret it names (closed PR
#95). The admin key therefore lives in the `fleet-apply` environment, which
has a required reviewer and deploys from `main` only (issues #90 and #13), and
pull requests get a drift report from a separate read-only App. These tests
parse the workflow with `yaml` and hold that shape in place:

* the apply job (`repo-settings`) declares `environment: fleet-apply` and its
  `if:` rules out pull_request;
* its environment self-check runs before every step that runs
  `repo_settings.py apply`, unconditionally, and fails the job unless the
  environment has a required reviewer and deploys from exactly `main` (the
  script itself runs here against fake API responses);
* no job that can run on pull_request references the admin key anywhere;
* the pull_request job (`drift`) is gated on the read-only App's variable and
  mints with every `permission-*` input set to `read`;
* the `plan` job (issue #116) has no environment, mints read-only per owner,
  fails on `diff` exit 2, and sets `needs_apply`; the apply job needs it and
  runs only on the conditions the issue lists, which `ApplyConditionTests`
  checks by evaluating the parsed `if:` over every combination of inputs.

They fail closed: a job `if:` they cannot place is treated as able to run on
pull_request.
"""

import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_required_checks import WORKFLOWS_DIR, load_workflow, triggers

WORKFLOW = WORKFLOWS_DIR / "repo-settings.yml"
APPLY_JOB = "repo-settings"
DRIFT_JOB = "drift"
PLAN_JOB = "plan"
OWNERS = {"Adam-S-Daniel", "jodidaniel"}
ENVIRONMENT = "fleet-apply"
GATE_STEP_ID = "environment_gate"
MINT_ACTION = "actions/create-github-app-token@"
REQUIRED_READ = {
    "permission-administration",
    "permission-actions",
    "permission-issues",
    "permission-metadata",
}
READ_APP_GATE = "vars.REPO_SETTINGS_READ_APP_CLIENT_ID != ''"
READ_APP_CLIENT_ID = "${{ vars.REPO_SETTINGS_READ_APP_CLIENT_ID }}"
READ_APP_KEY = "${{ secrets.REPO_SETTINGS_READ_APP_PRIVATE_KEY }}"
# Lexical tokens inside expression strings, never a parse of the YAML.
ADMIN_KEY = re.compile(r"\bREPO_SETTINGS_APP_PRIVATE_KEY\b")
EVENT_CONJUNCT = re.compile(r"github\.event_name\s*(==|!=)\s*'([a-z_]+)'")


def top_level_split(expr, op):
    """Split a GitHub expression on its top-level `op` (`&&` or `||`), leaving
    any inside parentheses or a quoted string alone."""
    expr = str(expr).strip()
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
        elif not quoted and depth == 0 and expr.startswith(op, i):
            parts.append(expr[start:i].strip())
            start = i + 2
            i += 1
        i += 1
    parts.append(expr[start:].strip())
    return parts


def top_level_conjuncts(expr):
    return top_level_split(expr, "&&")


def top_level_disjuncts(expr):
    return top_level_split(expr, "||")


EXPR_TOKEN = re.compile(
    r"\s*(?:(\|\||&&|==|!=|!|\(|\))|'((?:[^']|'')*)'|([A-Za-z_][A-Za-z0-9_.-]*))")
STATUS_FUNCTIONS = {"always", "success", "failure", "cancelled"}


def _number(value):
    if value is None:
        return 0.0
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(value.strip() or 0)
    except ValueError:
        return float("nan")


def _equal(a, b):
    """GitHub's `==`: strings compare case-insensitively; mixed types are
    coerced to numbers, so null equals ''."""
    if isinstance(a, str) and isinstance(b, str):
        return a.casefold() == b.casefold()
    if type(a) is type(b) and not isinstance(a, (int, float)):
        return a == b
    return _number(a) == _number(b)


def evaluate(expr, context, functions):
    """Evaluate the subset of GitHub expression syntax the job `if:`s here use:
    `||`, `&&`, `!`, `==`, `!=`, parentheses, string literals, true/false/null,
    dotted context paths and zero-argument calls. A context path or function
    not in the given dicts raises, so a condition that reads something these
    tests do not model fails rather than reading null. Returns
    (value, names of the functions called)."""
    expr = str(expr).strip()
    if expr.startswith("${{") and expr.endswith("}}"):
        expr = expr[3:-2]
    tokens, pos = [], 0
    expr = expr.rstrip()
    while pos < len(expr):
        m = EXPR_TOKEN.match(expr, pos)
        if not m or m.end() == pos:
            raise ValueError(f"cannot tokenize at {expr[pos:]!r}")
        op, string, ident = m.groups()
        tokens.append(("op", op) if op else ("str", string.replace("''", "'"))
                      if string is not None else ("id", ident))
        pos = m.end()
    called, i = set(), 0

    def peek():
        return tokens[i] if i < len(tokens) else (None, None)

    def take(kind=None, value=None):
        nonlocal i
        tok = peek()
        if (kind and tok[0] != kind) or (value and tok[1] != value):
            raise ValueError(f"expected {value or kind}, got {tok}")
        i += 1
        return tok

    def or_expr():
        value = and_expr()
        while peek() == ("op", "||"):
            take()
            right = and_expr()
            value = value if value else right
        return value

    def and_expr():
        value = comparison()
        while peek() == ("op", "&&"):
            take()
            right = comparison()
            value = right if value else value
        return value

    def comparison():
        # `!` binds tighter than `==`/`!=`, as in GitHub's precedence table.
        left = unary()
        if peek() in (("op", "=="), ("op", "!=")):
            op = take()[1]
            right = unary()
            return _equal(left, right) if op == "==" else not _equal(left, right)
        return left

    def unary():
        if peek() == ("op", "!"):
            take()
            return not unary()
        return primary()

    def primary():
        kind, value = take()
        if (kind, value) == ("op", "("):
            inner = or_expr()
            take("op", ")")
            return inner
        if kind == "str":
            return value
        if kind != "id":
            raise ValueError(f"unexpected {value!r}")
        if peek() == ("op", "("):
            take()
            take("op", ")")
            if value not in functions:
                raise KeyError(f"function {value}() is not modeled")
            called.add(value)
            return functions[value]
        if value in ("true", "false", "null"):
            return {"true": True, "false": False, "null": None}[value]
        if value not in context:
            raise KeyError(f"context {value} is not modeled")
        return context[value]

    result = or_expr()
    if i != len(tokens):
        raise ValueError(f"trailing tokens: {tokens[i:]}")
    return result, called


def job_runs(job, context, functions):
    """Whether GitHub would run a job with this `if:`: one that calls no
    status function gets an implicit `success()` in front."""
    value, called = evaluate(job.get("if", "true"), context, functions)
    if not called & STATUS_FUNCTIONS and not functions["success"]:
        return False
    return bool(value)


def event_gate(node):
    """'pr-only' if the node's `if:` requires event_name == pull_request,
    'never-pr' if a top-level conjunct rules pull_request out, else 'maybe'
    (no `if:`, or one these tests cannot place -- fail closed)."""
    cond = node.get("if")
    if cond is None:
        return "maybe"
    for part in top_level_conjuncts(cond):
        m = EVENT_CONJUNCT.fullmatch(part)
        if not m:
            continue
        op, event = m.groups()
        if op == "==" and event == "pull_request":
            return "pr-only"
        if (op == "!=" and event == "pull_request") or (op == "==" and event != "pull_request"):
            return "never-pr"
    return "maybe"


def strings_in(value):
    """Every string (keys included) anywhere in a parsed YAML value."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            if isinstance(k, str):
                yield k
            yield from strings_in(v)
    elif isinstance(value, list):
        for v in value:
            yield from strings_in(v)


def references_admin_key(value):
    return any(ADMIN_KEY.search(s) for s in strings_in(value))


def environment_name(job):
    env = job.get("environment")
    if isinstance(env, dict):
        return env.get("name")
    return env


def runs_subcommand(step, subcommand):
    """True if the step's `run:` invokes `repo_settings.py <subcommand>`."""
    body = step.get("run")
    if not isinstance(body, str):
        return False
    tokens = shlex.split(body, comments=True)
    for i, token in enumerate(tokens[:-1]):
        if token.endswith("repo_settings.py") and tokens[i + 1] == subcommand:
            return True
    return False


def runs_apply(step):
    return runs_subcommand(step, "apply")


def mint_steps(job):
    return [s for s in job.get("steps") or []
            if str(s.get("uses", "")).startswith(MINT_ACTION)]


def plan_diff_steps(doc):
    return [s for s in doc["jobs"][PLAN_JOB].get("steps") or []
            if runs_subcommand(s, "diff")]


def gate_script(doc):
    for step in doc["jobs"][APPLY_JOB].get("steps") or []:
        if step.get("id") == GATE_STEP_ID:
            return step["run"]
    raise AssertionError(f"no step with id: {GATE_STEP_ID}")


class WorkflowShapeTests(unittest.TestCase):
    def setUp(self):
        self.doc = load_workflow(WORKFLOW)
        self.on = triggers(self.doc, WORKFLOW)
        self.jobs = self.doc.get("jobs") or {}
        self.apply = self.jobs.get(APPLY_JOB)
        self.drift = self.jobs.get(DRIFT_JOB)
        self.plan = self.jobs.get(PLAN_JOB)
        self.assertIsNotNone(self.apply, f"{WORKFLOW.name}: no `{APPLY_JOB}` job")
        self.assertIsNotNone(self.drift, f"{WORKFLOW.name}: no `{DRIFT_JOB}` job")
        self.assertIsNotNone(self.plan, f"{WORKFLOW.name}: no `{PLAN_JOB}` job")

    def assertReadOnlyMint(self, step):
        inputs = step.get("with") or {}
        self.assertEqual(inputs.get("client-id"), READ_APP_CLIENT_ID)
        self.assertEqual(inputs.get("private-key"), READ_APP_KEY)
        perms = {k: v for k, v in inputs.items() if str(k).startswith("permission-")}
        self.assertLessEqual(REQUIRED_READ, set(perms))
        for key, value in perms.items():
            self.assertEqual(str(value), "read", f"{key}={value!r}")

    def test_triggers_are_kept(self):
        for event in ("push", "schedule", "workflow_dispatch", "pull_request"):
            self.assertIn(event, self.on)

    def test_apply_job_is_in_the_gated_environment(self):
        self.assertEqual(environment_name(self.apply), ENVIRONMENT)

    def test_apply_job_never_runs_on_pull_request(self):
        self.assertEqual(event_gate(self.apply), "never-pr", self.apply.get("if"))

    def test_apply_job_keeps_the_admin_app_gate(self):
        self.assertIn("vars.REPO_SETTINGS_APP_CLIENT_ID != ''",
                      top_level_conjuncts(self.apply.get("if", "")))

    def test_concurrency_is_per_owner_on_the_apply_job_only(self):
        # A run waiting for fleet-apply approval holds its group. At workflow
        # level that would stall or cancel PR `drift` runs; with one fixed name
        # on this matrix job the two owner legs would share a group, run one
        # at a time, and a newly queued run would cancel the waiting leg.
        self.assertNotIn("concurrency", self.doc, "no workflow-level concurrency")
        self.assertEqual(
            self.apply.get("concurrency"),
            {"group": "repo-settings-${{ matrix.owner }}", "cancel-in-progress": False},
        )
        self.assertNotIn("concurrency", self.drift)

    def test_apply_job_may_read_the_environment(self):
        # Job-level permissions replace the workflow's block; the self-check
        # needs actions: read. The nudge moved to `plan`, so no issues: write.
        self.assertEqual(self.apply.get("permissions"),
                         {"contents": "read", "actions": "read"})

    def test_self_check_runs_unconditionally_before_every_apply(self):
        steps = self.apply.get("steps") or []
        ids = [s.get("id") for s in steps]
        self.assertIn(GATE_STEP_ID, ids)
        gate_index = ids.index(GATE_STEP_ID)
        self.assertEqual(gate_index, 0, "the self-check must be the first step")
        gate = steps[gate_index]
        self.assertNotIn("if", gate, "the self-check must never be skipped")
        self.assertFalse(gate.get("continue-on-error"), "the self-check must fail the job")
        apply_indexes = [i for i, s in enumerate(steps) if runs_apply(s)]
        # One: a dry run is the plan alone now, never a gated step (#116).
        self.assertEqual(len(apply_indexes), 1, "expected exactly one apply step")
        for i in apply_indexes:
            self.assertLess(gate_index, i, steps[i].get("name"))

    def test_self_check_asks_about_this_repo_and_environment(self):
        env = next(s for s in self.apply["steps"] if s.get("id") == GATE_STEP_ID)["env"]
        self.assertEqual(env.get("ENVIRONMENT"), ENVIRONMENT)
        self.assertEqual(env.get("REPO"), "${{ github.repository }}")

    def test_no_job_that_can_run_on_pull_request_references_the_admin_key(self):
        # The workflow-level env and defaults reach every job.
        for key in ("env", "defaults"):
            self.assertFalse(references_admin_key(self.doc.get(key)), key)
        checked = 0
        for job_id, job in self.jobs.items():
            if event_gate(job or {}) == "never-pr":
                continue
            checked += 1
            self.assertFalse(references_admin_key(job), f"{job_id} can run on pull_request")
        self.assertGreater(checked, 0, "no job runs on pull_request; the check is vacuous")

    def test_only_the_gated_job_references_the_admin_key(self):
        holders = [j for j, job in self.jobs.items() if references_admin_key(job)]
        self.assertEqual(holders, [APPLY_JOB])

    def test_drift_job_is_pull_request_only_and_gated_on_the_read_app(self):
        self.assertEqual(event_gate(self.drift), "pr-only", self.drift.get("if"))
        self.assertIn(READ_APP_GATE, top_level_conjuncts(self.drift.get("if", "")))

    def test_drift_job_mints_read_only_from_the_read_app(self):
        mints = mint_steps(self.drift)
        self.assertEqual(len(mints), 1)
        self.assertReadOnlyMint(mints[0])

    def test_drift_job_runs_diff_and_never_apply(self):
        steps = self.drift.get("steps") or []
        self.assertFalse(any(runs_apply(s) for s in steps))
        self.assertTrue(any("repo_settings.py diff" in str(s.get("run", "")) for s in steps))

    # -- the plan job (issue #116) -------------------------------------------

    def test_dispatch_has_a_force_apply_input(self):
        inputs = (self.on.get("workflow_dispatch") or {}).get("inputs") or {}
        force = inputs.get("force_apply") or {}
        self.assertEqual((force.get("type"), force.get("default")), ("boolean", False))
        self.assertEqual((inputs.get("dry_run") or {}).get("type"), "boolean")

    def test_plan_job_is_ungated_and_never_holds_the_admin_key(self):
        self.assertNotIn("environment", self.plan)
        self.assertFalse(references_admin_key(self.plan))
        self.assertEqual(event_gate(self.plan), "never-pr", self.plan.get("if"))
        self.assertNotIn("strategy", self.plan,
                         "a matrix would let one leg's outputs overwrite the other's")
        self.assertEqual(self.plan.get("permissions"),
                         {"contents": "read", "issues": "write"})

    def test_plan_mints_read_only_once_per_owner(self):
        mints = mint_steps(self.plan)
        self.assertEqual(sorted(str((m.get("with") or {}).get("owner")) for m in mints),
                         sorted(OWNERS))
        for mint in mints:
            with self.subTest(mint.get("id")):
                self.assertReadOnlyMint(mint)

    def test_plan_diffs_each_owner_with_that_owners_token(self):
        steps = self.plan.get("steps") or []
        self.assertFalse(any(runs_apply(s) for s in steps))
        token_owner = {m.get("id"): m["with"]["owner"] for m in mint_steps(self.plan)}
        diffs = plan_diff_steps(self.doc)
        seen = set()
        for step in diffs:
            env = step.get("env") or {}
            m = re.fullmatch(r"\$\{\{ steps\.([A-Za-z0-9_-]+)\.outputs\.token \}\}",
                             str(env.get("GH_TOKEN")))
            self.assertIsNotNone(m, step.get("name"))
            self.assertEqual(token_owner.get(m.group(1)), env.get("OWNER"), step.get("name"))
            seen.add(env.get("OWNER"))
        self.assertEqual(len(diffs), len(OWNERS))
        self.assertEqual(seen, OWNERS)

    def test_needs_apply_is_any_owners_drift(self):
        expr = (self.plan.get("outputs") or {}).get("needs_apply")
        ids = {s.get("id") for s in plan_diff_steps(self.doc)}
        self.assertEqual(set(top_level_disjuncts(expr)),
                         {f"steps.{i}.outputs.drift == 'true'" for i in ids})

    def test_coverage_and_nudge_run_in_plan_not_apply(self):
        plan_steps = self.plan.get("steps") or []
        apply_steps = self.apply.get("steps") or []
        self.assertIn("coverage", [s.get("id") for s in plan_steps])
        self.assertNotIn("coverage", [s.get("id") for s in apply_steps])
        nudges = [s for s in plan_steps if "gh issue" in str(s.get("run", ""))]
        self.assertEqual(len(nudges), 1)
        self.assertFalse(any("gh issue" in str(s.get("run", "")) for s in apply_steps))
        self.assertFalse(any("repo_settings.py coverage" in str(s.get("run", ""))
                             for s in apply_steps))
        # Advisory: a broken audit or nudge must not fail the plan, since a
        # failed plan withholds the apply on push.
        coverage = next(s for s in plan_steps if s.get("id") == "coverage")
        self.assertTrue(coverage.get("continue-on-error"))
        self.assertTrue(nudges[0].get("continue-on-error"))

    def test_apply_job_needs_the_plan(self):
        needs = self.apply.get("needs")
        self.assertIn(needs, (PLAN_JOB, [PLAN_JOB]))


class EventGateTests(unittest.TestCase):
    def test_places_the_workflow_conditions(self):
        self.assertEqual(event_gate({"if": "github.event_name == 'pull_request'"}), "pr-only")
        self.assertEqual(event_gate({"if": "github.event_name != 'pull_request'"}), "never-pr")
        self.assertEqual(
            event_gate({"if": "${{ vars.X != '' && github.event_name != 'pull_request' }}"}),
            "never-pr")

    def test_unknown_or_disjunctive_conditions_fail_closed(self):
        self.assertEqual(event_gate({}), "maybe")
        self.assertEqual(event_gate({"if": "always()"}), "maybe")
        self.assertEqual(
            event_gate({"if": "github.event_name != 'pull_request' || always()"}), "maybe")
        self.assertEqual(
            event_gate({"if": "!(github.event_name != 'pull_request' && inputs.x)"}), "maybe")


class EvaluatorTests(unittest.TestCase):
    """The evaluator the apply-condition tests rest on."""

    def ev(self, expr, **context):
        return evaluate(expr, context, {"always": True, "cancelled": False})[0]

    def test_operators_and_precedence(self):
        self.assertTrue(self.ev("a == 'X'", a="x"))
        self.assertTrue(self.ev("a != ''", a="v"))
        self.assertFalse(self.ev("a != ''", a=None))
        self.assertTrue(self.ev("!a == true", a=False))
        self.assertTrue(self.ev("a && b || c", a=False, b=True, c=True))
        self.assertFalse(self.ev("a && (b || c)", a=False, b=True, c=True))
        self.assertTrue(self.ev("${{ !cancelled() && always() }}"))

    def test_unmodeled_names_raise(self):
        with self.assertRaises(KeyError):
            self.ev("unknown.path == 'x'")
        with self.assertRaises(KeyError):
            self.ev("failure()")

    def test_implicit_success_without_a_status_function(self):
        fns = {"always": True, "cancelled": False, "success": False}
        self.assertFalse(job_runs({"if": "true"}, {}, fns))
        self.assertTrue(job_runs({"if": "always()"}, {}, fns))


def apply_scenarios():
    """Every combination of the inputs the apply job's `if:` may read."""
    for event in ("push", "schedule", "workflow_dispatch", "pull_request"):
        dispatch = event == "workflow_dispatch"
        for client_id in ("", "Iv23example"):
            for result in ("success", "failure", "skipped", "cancelled"):
                for needs_apply in ("true", "false", ""):
                    for dry_run in ((True, False) if dispatch else (None,)):
                        for force_apply in ((True, False) if dispatch else (None,)):
                            for run_cancelled in (False, True):
                                yield {
                                    "event": event, "client_id": client_id,
                                    "result": result, "needs_apply": needs_apply,
                                    "dry_run": dry_run, "force_apply": force_apply,
                                    "run_cancelled": run_cancelled,
                                }


def apply_should_run(sc):
    """Issue #116's three conditions, with schedule narrowed by PR #113: it
    applies on planned drift, or when the plan did not succeed (fail closed);
    everything else needs a successful plan."""
    if sc["run_cancelled"] or not sc["client_id"] or sc["event"] == "pull_request":
        return False
    if sc["event"] == "schedule":
        return sc["result"] != "success" or sc["needs_apply"] == "true"
    if sc["result"] != "success":
        return False
    if sc["event"] == "push":
        return sc["needs_apply"] == "true"
    if sc["event"] == "workflow_dispatch":
        return not sc["dry_run"] and (sc["needs_apply"] == "true" or sc["force_apply"])
    return False


def apply_runs(job, sc):
    context = {
        "vars.REPO_SETTINGS_APP_CLIENT_ID": sc["client_id"],
        "github.event_name": sc["event"],
        "needs.plan.result": sc["result"],
        "needs.plan.outputs.needs_apply": sc["needs_apply"],
        "inputs.dry_run": sc["dry_run"],
        "inputs.force_apply": sc["force_apply"],
    }
    functions = {
        "always": True,
        "cancelled": sc["run_cancelled"],
        "success": sc["result"] == "success" and not sc["run_cancelled"],
        "failure": sc["result"] == "failure",
    }
    return job_runs(job, context, functions)


class ApplyConditionTests(unittest.TestCase):
    """Evaluates the apply job's parsed `if:` over every scenario."""

    def setUp(self):
        self.apply = load_workflow(WORKFLOW)["jobs"][APPLY_JOB]

    def test_matches_the_three_conditions_exactly(self):
        count = 0
        for sc in apply_scenarios():
            count += 1
            with self.subTest(**sc):
                self.assertEqual(apply_runs(self.apply, sc), apply_should_run(sc))
        self.assertGreater(count, 100)

    def test_a_dry_run_dispatch_never_reaches_apply(self):
        for sc in apply_scenarios():
            if sc["event"] == "workflow_dispatch" and sc["dry_run"]:
                with self.subTest(**sc):
                    self.assertFalse(apply_runs(self.apply, sc))

    def test_schedule_asks_for_approval_only_on_drift_or_a_failed_plan(self):
        base = {"event": "schedule", "client_id": "x", "dry_run": None,
                "force_apply": None, "run_cancelled": False}
        self.assertFalse(apply_runs(self.apply, dict(base, result="success", needs_apply="false")))
        self.assertTrue(apply_runs(self.apply, dict(base, result="success", needs_apply="true")))
        for result in ("failure", "skipped", "cancelled"):
            with self.subTest(result=result):
                self.assertTrue(apply_runs(self.apply, dict(base, result=result, needs_apply="")))

    def test_push_applies_only_on_planned_drift(self):
        base = {"event": "push", "client_id": "x", "result": "success",
                "dry_run": None, "force_apply": None, "run_cancelled": False}
        self.assertTrue(apply_runs(self.apply, dict(base, needs_apply="true")))
        self.assertFalse(apply_runs(self.apply, dict(base, needs_apply="false")))
        self.assertFalse(apply_runs(self.apply, dict(base, needs_apply="true",
                                                     result="failure")))


def plan_script_run(script, code):
    """Run a plan step's real script under `bash -e` with a stub `python`
    that exits `code`. Returns (process, GITHUB_OUTPUT text)."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        stub = tmp / "python"
        stub.write_text(f'#!/bin/sh\necho "stub diff {code}"\nexit {code}\n')
        stub.chmod(0o755)
        out = tmp / "github_output"
        out.touch()
        env = {"PATH": f"{tmp}:{os.environ['PATH']}", "GITHUB_OUTPUT": str(out),
               "OWNER": "example"}
        proc = subprocess.run(["bash", "-e", "-c", script], cwd=tmp, env=env,
                              capture_output=True, text=True, timeout=30)
        return proc, out.read_text()


class PlanStepScriptTests(unittest.TestCase):
    """Runs each plan step's real script, taken from the parsed workflow."""

    def setUp(self):
        self.steps = plan_diff_steps(load_workflow(WORKFLOW))
        self.assertEqual(len(self.steps), len(OWNERS))

    def test_no_drift_and_drift_set_the_output(self):
        for step in self.steps:
            for code, drift in ((0, "false"), (1, "true")):
                with self.subTest(step=step.get("id"), code=code):
                    proc, output = plan_script_run(step["run"], code)
                    self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                    self.assertEqual(output.splitlines(), [f"drift={drift}"])
                    self.assertIn(f"stub diff {code}", proc.stdout)

    def test_could_not_ask_fails_the_plan(self):
        for step in self.steps:
            for code in (2, 3, 127):
                with self.subTest(step=step.get("id"), code=code):
                    proc, output = plan_script_run(step["run"], code)
                    self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                    self.assertNotIn("drift=", output)


GOOD_ENV = {
    "name": ENVIRONMENT,
    "protection_rules": [
        {"type": "required_reviewers", "prevent_self_review": False,
         "reviewers": [{"type": "User", "reviewer": {"login": "example"}}]},
        {"type": "branch_policy"},
    ],
    "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True},
}
GOOD_POLICIES = {"total_count": 1, "branch_policies": [{"name": "main", "type": "branch"}]}


class SelfCheckScriptTests(unittest.TestCase):
    """Runs the self-check step's real script, taken from the parsed workflow,
    against a stub `gh` that serves fake API responses. Without `jq` these
    fail rather than skip: a skipped check would pass vacuously."""

    def setUp(self):
        self.assertIsNotNone(shutil.which("jq"), "jq is required to run the self-check")

    def run_check(self, env_json, policies_json, policies_rc=0):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "env.json").write_text(env_json)
            (tmp / "policies.json").write_text(policies_json)
            stub = tmp / "gh"
            stub.write_text(
                "#!/bin/sh\n"
                'case "$2" in\n'
                f'  */deployment-branch-policies) cat "{tmp}/policies.json"; exit {policies_rc} ;;\n'
                f'  *) cat "{tmp}/env.json" ;;\n'
                "esac\n"
            )
            stub.chmod(0o755)
            env = {
                "PATH": f"{tmp}:{os.environ['PATH']}",
                "REPO": "example/example",
                "ENVIRONMENT": ENVIRONMENT,
            }
            return subprocess.run(
                ["bash", "-e", "-c", gate_script(load_workflow(WORKFLOW))],
                cwd=tmp, env=env, capture_output=True, text=True, timeout=30,
            )

    def check(self, env=GOOD_ENV, policies=GOOD_POLICIES, **kwargs):
        return self.run_check(json.dumps(env), json.dumps(policies), **kwargs)

    def assertRefused(self, proc):
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_passes_on_the_intended_configuration(self):
        proc = self.check()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_fails_with_a_reviewer_rule_but_no_reviewers(self):
        env = json.loads(json.dumps(GOOD_ENV))
        env["protection_rules"][0]["reviewers"] = []
        self.assertRefused(self.check(env=env))

    def test_fails_with_no_reviewer_rule(self):
        env = json.loads(json.dumps(GOOD_ENV))
        env["protection_rules"] = [{"type": "branch_policy"}]
        self.assertRefused(self.check(env=env))
        env.pop("protection_rules")
        self.assertRefused(self.check(env=env))

    def test_fails_when_any_branch_may_deploy(self):
        env = dict(GOOD_ENV, deployment_branch_policy=None)
        self.assertRefused(self.check(env=env))

    def test_fails_on_branch_policies_other_than_exactly_main(self):
        cases = {
            "empty": {"total_count": 0, "branch_policies": []},
            "other branch": {"total_count": 1,
                             "branch_policies": [{"name": "dev", "type": "branch"}]},
            "main plus another": {"total_count": 2, "branch_policies": [
                {"name": "main", "type": "branch"}, {"name": "dev", "type": "branch"}]},
            "pattern": {"total_count": 1,
                        "branch_policies": [{"name": "*", "type": "branch"}]},
            "a tag named main": {"total_count": 1,
                                 "branch_policies": [{"name": "main", "type": "tag"}]},
            "more beyond the first page": {"total_count": 2,
                                           "branch_policies": [{"name": "main", "type": "branch"}]},
        }
        for label, policies in cases.items():
            with self.subTest(label):
                self.assertRefused(self.check(policies=policies))

    def test_fails_closed_on_an_api_error_or_unreadable_response(self):
        self.assertRefused(self.check(policies_rc=1))
        self.assertRefused(self.run_check("not json", json.dumps(GOOD_POLICIES)))
        self.assertRefused(self.run_check(json.dumps(GOOD_ENV), ""))


if __name__ == "__main__":
    unittest.main()
