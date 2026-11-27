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
  checks by evaluating the parsed `if:` over every combination of inputs;
* the unreviewed job (`apply-auto`, docs/decisions/0019) is the only other
  holder of the admin key: it never runs on pull_request, takes the key from
  `fleet-apply-auto` only after checking that only `main` may deploy there,
  passes `--refuse-weakening` on every apply, and the reviewed job is asked
  for unless it answered `false` for every owner (its two scripts run here
  too, the second against the real engine).

They fail closed: a job `if:` they cannot place is treated as able to run on
pull_request.
"""

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from test_required_checks import WORKFLOWS_DIR, load_workflow, triggers

WORKFLOW = WORKFLOWS_DIR / "repo-settings.yml"
APPLY_JOB = "repo-settings"
AUTO_JOB = "apply-auto"
AUTO_ENVIRONMENT = "fleet-apply-auto"
AUTO_GATE_STEP_ID = "auto_gate"
PROVISIONED = "steps.auto_gate.outputs.provisioned == 'true'"
DRIFT_JOB = "drift"
PLAN_JOB = "plan"
OWNERS = {"Adam-S-Daniel", "jodidaniel"}


def review_output(owner):
    """The apply-auto job output that says whether `owner` still needs the
    reviewed apply: the same key the job's last step derives with `tr`."""
    return "review_" + owner.upper().replace("-", "_")


REVIEW_OUTPUTS = sorted(review_output(o) for o in OWNERS)
REVIEW_CONJUNCT = "(" + " || ".join(
    f"needs.{AUTO_JOB}.outputs.{name} != 'false'" for name in REVIEW_OUTPUTS) + ")"
ENVIRONMENT = "fleet-apply"
GATE_STEP_ID = "environment_gate"
MINT_ACTION = "actions/create-github-app-token@"
REQUIRED_READ = {
    "permission-administration",
    "permission-actions",
    "permission-issues",
    "permission-metadata",
    "permission-secrets",
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
        # Two: the admin Apply and the cms-platform labels-only Apply (#88). A
        # dry run is the plan alone now, never a gated step (#116).
        self.assertEqual(len(apply_indexes), 2, "expected exactly two apply steps")
        for i in apply_indexes:
            self.assertLess(gate_index, i, steps[i].get("name"))

    def _apply_steps(self):
        steps = [s for s in self.apply["steps"] if runs_apply(s)]
        by_mode = {}
        for s in steps:
            argv = shlex.split(s["run"])
            self.assertIn("--cms-label-only", argv, s.get("name"))
            by_mode[argv[argv.index("--cms-label-only") + 1]] = s
        return by_mode

    def test_every_apply_step_says_which_side_of_the_cms_split_it_is(self):
        by_mode = self._apply_steps()
        self.assertEqual(set(by_mode), {"skip", "only"})
        self.assertEqual(by_mode["skip"]["env"]["GH_TOKEN"], "${{ steps.token.outputs.token }}")
        self.assertEqual(by_mode["only"]["env"]["GH_TOKEN"],
                         "${{ steps.token_labels.outputs.token }}")

    def test_labels_token_is_narrowed_to_issues_and_secrets_write_on_the_cms_repos(self):
        step = next(s for s in self.apply["steps"] if s.get("id") == "token_labels")
        self.assertTrue(step["uses"].startswith(MINT_ACTION))
        with_ = step["with"]
        self.assertEqual(set(with_), {"client-id", "private-key", "owner", "repositories",
                                      "permission-issues", "permission-secrets"})
        self.assertEqual(with_["permission-issues"], "write")
        # The secrets fan-out reaches these repos (#241): without it every
        # write there is "Resource not accessible by integration".
        self.assertEqual(with_["permission-secrets"], "write")
        self.assertEqual(with_["repositories"], "${{ steps.cms_label_repos.outputs.repos }}")

    def test_the_cms_apply_step_gets_the_fanned_out_value(self):
        # The engine writes PRIVACY_DENYLIST from its environment; the
        # cms-only step runs separately, so it needs the value too (#241).
        only = self._apply_steps()["only"]
        self.assertEqual(only["env"]["PRIVACY_DENYLIST"], "${{ secrets.PRIVACY_DENYLIST }}")

    def test_admin_token_mint_is_not_narrowed_or_changed(self):
        step = next(s for s in self.apply["steps"] if s.get("id") == "token")
        self.assertEqual(set(step["with"]), {"client-id", "private-key", "owner"})

    def test_label_leg_runs_after_an_admin_failure_but_never_past_the_gate(self):
        steps = {s.get("id"): s for s in self.apply["steps"] if s.get("id")}
        leg = [steps["cms_label_repos"], steps["token_labels"], self._apply_steps()["only"]]
        for step in leg:
            cond = str(step.get("if"))
            with self.subTest(step=step.get("name")):
                self.assertIn("steps.environment_gate.outcome == 'success'",
                              top_level_conjuncts(cond))
                self.assertNotIn("always()", cond)
        for step in leg[1:]:
            self.assertIn("steps.cms_label_repos.outputs.repos != ''",
                          top_level_conjuncts(str(step["if"])))

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

    def test_only_the_two_apply_jobs_reference_the_admin_key(self):
        holders = [j for j, job in self.jobs.items() if references_admin_key(job)]
        self.assertEqual(sorted(holders), sorted([AUTO_JOB, APPLY_JOB]))

    def test_the_reviewed_apply_applies_everything(self):
        # --refuse-weakening here would leave the gated writes unmade after
        # the owner approved them.
        for step in self.apply["steps"]:
            if runs_apply(step):
                self.assertNotIn("--refuse-weakening", shlex.split(step["run"]))

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

    def test_apply_job_needs_the_plan_and_the_unreviewed_apply(self):
        self.assertEqual(sorted(self.apply.get("needs")), sorted([PLAN_JOB, AUTO_JOB]))


class ApplyInputsTests(unittest.TestCase):
    """Both apply jobs refuse a run main has moved past, judged by the files
    an apply reads. That list is the workflow's own push path filter: a file
    whose change starts no run must not strand a waiting one, and a file
    whose change does start a run is one a stale apply must not ignore."""

    def test_both_gates_name_exactly_the_push_paths(self):
        doc = load_workflow(WORKFLOW)
        push_paths = triggers(doc, WORKFLOW)["push"]["paths"]
        self.assertTrue(push_paths)
        for path in push_paths:
            self.assertNotRegex(path, r"[*?\[\s!]", "the gates compare exact file names")
        for job, step_id in ((AUTO_JOB, AUTO_GATE_STEP_ID), (APPLY_JOB, GATE_STEP_ID)):
            with self.subTest(job=job):
                step = next(s for s in doc["jobs"][job]["steps"] if s.get("id") == step_id)
                self.assertEqual(step["env"]["APPLY_INPUTS"].split(" "), push_paths)
                self.assertIn("compare/$GITHUB_SHA...main", step["run"])


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


# What apply-auto may have answered per owner, in REVIEW_OUTPUTS order: `false`
# (nothing left), `true` (something left, or the lane is not set up), or
# nothing at all (the leg died first, or the job was skipped).
REVIEW_CASES = [(a, b) for a in ("false", "true", "") for b in ("false", "true", "")]


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
                                for review in REVIEW_CASES:
                                    yield {
                                        "event": event, "client_id": client_id,
                                        "result": result, "needs_apply": needs_apply,
                                        "dry_run": dry_run, "force_apply": force_apply,
                                        "run_cancelled": run_cancelled,
                                        "review": review,
                                    }


def auto_should_run(sc):
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


def apply_should_run(sc):
    """The reviewed apply: the same conditions, and apply-auto did not answer
    `false` for every owner (docs/decisions/0019). Only `false` withholds the
    review, so a leg that never answered asks for it."""
    return auto_should_run(sc) and any(answer != "false" for answer in sc["review"])


def apply_runs(job, sc):
    context = {
        "vars.REPO_SETTINGS_APP_CLIENT_ID": sc["client_id"],
        "github.event_name": sc["event"],
        "needs.plan.result": sc["result"],
        "needs.plan.outputs.needs_apply": sc["needs_apply"],
        "inputs.dry_run": sc["dry_run"],
        "inputs.force_apply": sc["force_apply"],
    }
    for name, answer in zip(REVIEW_OUTPUTS, sc["review"]):
        context[f"needs.{AUTO_JOB}.outputs.{name}"] = answer
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

    def test_no_review_is_asked_for_when_every_owner_answered_false(self):
        asked = 0
        for sc in apply_scenarios():
            if not auto_should_run(sc):
                continue
            with self.subTest(**sc):
                expected = sc["review"] != ("false", "false")
                self.assertEqual(apply_runs(self.apply, sc), expected)
                asked += expected
        self.assertGreater(asked, 0)

    def test_the_if_is_the_unreviewed_jobs_plus_the_review_answer(self):
        jobs = load_workflow(WORKFLOW)["jobs"]
        auto = top_level_conjuncts(jobs[AUTO_JOB]["if"])
        reviewed = top_level_conjuncts(self.apply["if"])
        self.assertEqual(sorted(reviewed), sorted(auto + [REVIEW_CONJUNCT]))

    def test_schedule_asks_for_approval_only_on_drift_or_a_failed_plan(self):
        base = {"event": "schedule", "client_id": "x", "dry_run": None,
                "force_apply": None, "run_cancelled": False, "review": ("true", "")}
        self.assertFalse(apply_runs(self.apply, dict(base, result="success", needs_apply="false")))
        self.assertTrue(apply_runs(self.apply, dict(base, result="success", needs_apply="true")))
        for result in ("failure", "skipped", "cancelled"):
            with self.subTest(result=result):
                self.assertTrue(apply_runs(self.apply, dict(base, result=result, needs_apply="")))

    def test_push_applies_only_on_planned_drift(self):
        base = {"event": "push", "client_id": "x", "result": "success",
                "dry_run": None, "force_apply": None, "run_cancelled": False,
                "review": ("", "true")}
        self.assertTrue(apply_runs(self.apply, dict(base, needs_apply="true")))
        self.assertFalse(apply_runs(self.apply, dict(base, needs_apply="false")))
        self.assertFalse(apply_runs(self.apply, dict(base, needs_apply="true",
                                                     result="failure")))


class AutoApplyShapeTests(unittest.TestCase):
    """The unreviewed apply job (docs/decisions/0019)."""

    def setUp(self):
        self.doc = load_workflow(WORKFLOW)
        self.auto = self.doc["jobs"][AUTO_JOB]
        self.reviewed = self.doc["jobs"][APPLY_JOB]
        self.steps = self.auto["steps"]

    def test_it_never_runs_on_pull_request_and_keeps_the_admin_app_gate(self):
        self.assertEqual(event_gate(self.auto), "never-pr", self.auto.get("if"))
        self.assertIn("vars.REPO_SETTINGS_APP_CLIENT_ID != ''",
                      top_level_conjuncts(self.auto["if"]))

    def test_it_runs_on_the_three_conditions_exactly(self):
        count = 0
        for sc in apply_scenarios():
            count += 1
            with self.subTest(**sc):
                self.assertEqual(apply_runs(self.auto, sc), auto_should_run(sc))
        self.assertGreater(count, 100)

    def test_it_takes_the_key_from_its_own_environment(self):
        self.assertEqual(environment_name(self.auto), AUTO_ENVIRONMENT)
        self.assertNotEqual(AUTO_ENVIRONMENT, ENVIRONMENT)
        self.assertEqual(self.auto.get("needs"), PLAN_JOB)
        self.assertEqual(self.auto.get("permissions"), {"contents": "read", "actions": "read"})

    def test_it_does_not_queue_behind_a_reviewed_apply_waiting_for_approval(self):
        self.assertEqual(
            self.auto.get("concurrency"),
            {"group": "repo-settings-auto-${{ matrix.owner }}", "cancel-in-progress": False},
        )
        self.assertNotEqual(self.auto["concurrency"]["group"],
                            self.reviewed["concurrency"]["group"])

    def test_the_setup_check_is_first_and_unconditional(self):
        gate = self.steps[0]
        self.assertEqual(gate.get("id"), AUTO_GATE_STEP_ID)
        self.assertNotIn("if", gate)
        self.assertFalse(gate.get("continue-on-error"))
        self.assertEqual(gate["env"].get("ENVIRONMENT"), AUTO_ENVIRONMENT)
        self.assertEqual(gate["env"].get("REPO"), "${{ github.repository }}")
        # The check learns only WHETHER the key is there, never the key.
        self.assertEqual(gate["env"].get("HAS_KEY"),
                         "${{ secrets.REPO_SETTINGS_APP_PRIVATE_KEY != '' }}")
        self.assertNotIn("REPO_SETTINGS_APP_PRIVATE_KEY", gate["run"].replace(
            "no REPO_SETTINGS_APP_PRIVATE_KEY secret", ""))

    def test_nothing_touches_the_key_or_applies_unless_the_lane_is_set_up(self):
        guarded = 0
        for step in self.steps[1:]:
            if step.get("id") == "decide":
                continue
            with self.subTest(step=step.get("name")):
                self.assertIn(PROVISIONED, top_level_conjuncts(str(step.get("if"))))
                self.assertNotIn("always()", str(step.get("if")))
                guarded += 1
        self.assertEqual(guarded, len(self.steps) - 2)
        self.assertEqual(self.steps[-1].get("id"), "decide")
        self.assertFalse(references_admin_key(self.steps[-1]))

    def test_every_apply_refuses_weakening_and_records_its_result(self):
        applies = [s for s in self.steps if runs_apply(s)]
        self.assertEqual(len(applies), 2, "the admin apply and the cms-platform labels apply")
        seen = {}
        for step in applies:
            argv = shlex.split(step["run"], comments=True)
            with self.subTest(step=step.get("name")):
                self.assertIn("--refuse-weakening", argv)
                self.assertIn("--result-json", argv)
                self.assertNotIn("--dry-run", argv)
                seen[argv[argv.index("--cms-label-only") + 1]] = (
                    step, argv[argv.index("--result-json") + 1])
        self.assertEqual(set(seen), {"skip", "only"})
        self.assertEqual(seen["skip"][0]["env"]["GH_TOKEN"], "${{ steps.token.outputs.token }}")
        self.assertEqual(seen["only"][0]["env"]["GH_TOKEN"],
                         "${{ steps.token_labels.outputs.token }}")
        # The files the last step reads, outside the checkout.
        decide = self.steps[-1]["run"]
        for _, path in seen.values():
            self.assertTrue(path.startswith("$RUNNER_TEMP/"), path)
            self.assertIn(path, decide)

    def test_the_tokens_are_minted_as_in_the_reviewed_job(self):
        by_id = {s.get("id"): s for s in self.steps}
        reviewed = {s.get("id"): s for s in self.reviewed["steps"]}
        for step_id in ("token", "token_labels"):
            with self.subTest(step_id):
                self.assertEqual(by_id[step_id]["uses"], reviewed[step_id]["uses"])
                self.assertEqual(by_id[step_id]["with"], reviewed[step_id]["with"])
        self.assertEqual(len(mint_steps(self.auto)), 2)

    def test_each_owner_has_its_own_output(self):
        self.assertEqual(set(self.auto["strategy"]["matrix"]["owner"]), OWNERS)
        self.assertEqual(self.auto.get("outputs"), {
            name: "${{ steps.decide.outputs.%s }}" % name for name in REVIEW_OUTPUTS})
        decide = self.steps[-1]
        self.assertEqual(decide.get("if"), "${{ !cancelled() }}")
        self.assertEqual(decide["env"].get("OWNER"), "${{ matrix.owner }}")


# What `GET /repos/{repo}/compare/{sha}...main` answers. An apply runs only
# when main has not changed a file it reads since the run's commit.
SAME_COMMIT = {"status": "identical", "ahead_by": 0, "behind_by": 0, "files": []}
UNRELATED_COMMITS = {"status": "ahead", "ahead_by": 2, "behind_by": 0, "files": [
    {"filename": "README.md"}, {"filename": "docs/decisions/0019-x.md"},
    {"filename": "tests/test_write_risk.py", "previous_filename": "tests/old.py"}]}
STALE_COMPARES = {
    "main changed fleet.yml": {"ahead_by": 1, "behind_by": 0,
                               "files": [{"filename": "repo-settings/fleet.yml"}]},
    "main changed the engine": {"ahead_by": 1, "behind_by": 0, "files": [
        {"filename": "README.md"}, {"filename": "scripts/repo_settings.py"}]},
    "main changed this workflow": {"ahead_by": 1, "behind_by": 0, "files": [
        {"filename": ".github/workflows/repo-settings.yml"}]},
    "main changed requirements.txt": {"ahead_by": 1, "behind_by": 0,
                                      "files": [{"filename": "requirements.txt"}]},
    "main renamed fleet.yml away": {"ahead_by": 1, "behind_by": 0, "files": [
        {"filename": "repo-settings/other.yml",
         "previous_filename": "repo-settings/fleet.yml"}]},
    "this commit is not on main": {"ahead_by": 0, "behind_by": 1, "files": []},
    "more files than one page lists": {"ahead_by": 9, "behind_by": 0, "files": [
        {"filename": f"docs/{n}.md"} for n in range(300)]},
    "no file list": {"ahead_by": 0, "behind_by": 0},
    "no behind_by": {"ahead_by": 0, "files": []},
    "a file entry with no name": {"ahead_by": 1, "behind_by": 0, "files": [{}]},
    "not a comparison": "not json",
}
FAKE_SHA = "0123456789abcdef0123456789abcdef01234567"


def write_gh_stub(tmp, env, policies, compare, env_rc=0, policies_rc=0, compare_rc=0):
    """A `gh` that serves the three reads the two gate scripts make, and
    records the path of each call."""
    for name, body in (("env", env), ("policies", policies), ("compare", compare)):
        (tmp / f"{name}.json").write_text(body if isinstance(body, str) else json.dumps(body))
    stub = tmp / "gh"
    stub.write_text(
        "#!/bin/sh\n"
        f'echo "$2" >> "{tmp}/gh_calls"\n'
        'case "$2" in\n'
        f'  */compare/*) cat "{tmp}/compare.json"; exit {compare_rc} ;;\n'
        f'  */deployment-branch-policies) cat "{tmp}/policies.json"; exit {policies_rc} ;;\n'
        f'  *) cat "{tmp}/env.json"; exit {env_rc} ;;\n'
        "esac\n"
    )
    stub.chmod(0o755)


def gh_calls(tmp):
    calls = tmp / "gh_calls"
    return calls.read_text().splitlines() if calls.exists() else []


class _ScriptCase(unittest.TestCase):
    """Runs a step's real script, taken from the parsed workflow, under
    `bash -e` in a scratch directory."""

    def setUp(self):
        self.assertIsNotNone(shutil.which("jq"), "jq is required to run these scripts")
        self.steps = {s.get("id"): s for s in load_workflow(WORKFLOW)["jobs"][AUTO_JOB]["steps"]}

    def run_script(self, step_id, tmp, env):
        (tmp / "github_output").touch()
        (tmp / "summary.md").touch()
        (tmp / "runner_temp").mkdir(exist_ok=True)
        full = {"PATH": f"{tmp}:{os.environ['PATH']}",
                "GITHUB_OUTPUT": str(tmp / "github_output"),
                "GITHUB_STEP_SUMMARY": str(tmp / "summary.md"),
                "RUNNER_TEMP": str(tmp / "runner_temp"), **env}
        proc = subprocess.run(["bash", "-e", "-c", self.steps[step_id]["run"]], cwd=tmp,
                              env=full, capture_output=True, text=True, timeout=60)
        return proc, (tmp / "github_output").read_text(), (tmp / "summary.md").read_text()


AUTO_ENV = {
    "name": AUTO_ENVIRONMENT,
    "protection_rules": [{"type": "branch_policy"}],
    "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True},
}


class AutoSetupCheckScriptTests(_ScriptCase):
    """The unreviewed job's first step against a stub `gh`."""

    def check(self, has_key="true", env=AUTO_ENV, policies=None, compare=SAME_COMMIT,
              env_rc=0, policies_rc=0, compare_rc=0):
        policies = GOOD_POLICIES if policies is None else policies
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            write_gh_stub(tmp, env, policies, compare, env_rc, policies_rc, compare_rc)
            proc, output, _ = self.run_script(AUTO_GATE_STEP_ID, tmp, {
                "REPO": "example/example", "ENVIRONMENT": AUTO_ENVIRONMENT,
                "HAS_KEY": has_key, "GITHUB_SHA": FAKE_SHA,
                "APPLY_INPUTS": self.steps[AUTO_GATE_STEP_ID]["env"]["APPLY_INPUTS"]})
            self.calls = gh_calls(tmp)
            return proc, output.splitlines()

    def test_later_commits_that_change_nothing_an_apply_reads_do_not_matter(self):
        proc, output = self.check(compare=UNRELATED_COMMITS)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(output, ["provisioned=true"])
        self.assertIn(f"repos/example/example/compare/{FAKE_SHA}...main", self.calls)

    def test_a_run_main_has_moved_past_applies_nothing_and_fails(self):
        cases = dict({k: {"compare": v} for k, v in STALE_COMPARES.items()},
                     **{"the comparison cannot be read": {"compare_rc": 1}})
        for label, kwargs in cases.items():
            with self.subTest(label):
                proc, output = self.check(**kwargs)
                self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                self.assertEqual(output, ["provisioned=false"])
                self.assertIn("::error::Nothing applied", proc.stdout)

    def test_set_up_means_the_key_and_main_only(self):
        proc, output = self.check()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(output, ["provisioned=true"])

    def test_a_reviewer_on_the_environment_does_not_matter(self):
        proc, output = self.check(env=dict(GOOD_ENV, name=AUTO_ENVIRONMENT))
        self.assertEqual((proc.returncode, output), (0, ["provisioned=true"]))

    def test_no_key_is_not_set_up_and_not_a_failure(self):
        # Before the owner's one-time setup, and for an environment GitHub
        # created empty because the job named it.
        fresh = {"name": AUTO_ENVIRONMENT, "protection_rules": [],
                 "deployment_branch_policy": None}
        for label, kwargs in {
            "main-only, no key": {},
            "created empty by GitHub": {"env": fresh,
                                        "policies": {"total_count": 0, "branch_policies": []}},
            "unreadable": {"env_rc": 1},
        }.items():
            with self.subTest(label):
                proc, output = self.check(has_key="false", **kwargs)
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                self.assertEqual(output, ["provisioned=false"])
                self.assertIn("::notice", proc.stdout)

    def test_the_key_where_any_branch_may_deploy_fails_the_job(self):
        cases = {
            "any branch": {"env": dict(AUTO_ENV, deployment_branch_policy=None)},
            "protected branches": {"env": dict(AUTO_ENV, deployment_branch_policy={
                "protected_branches": True, "custom_branch_policies": False})},
            "another branch": {"policies": {"total_count": 1, "branch_policies": [
                {"name": "dev", "type": "branch"}]}},
            "main plus another": {"policies": {"total_count": 2, "branch_policies": [
                {"name": "main", "type": "branch"}, {"name": "dev", "type": "branch"}]}},
            "a pattern": {"policies": {"total_count": 1, "branch_policies": [
                {"name": "*", "type": "branch"}]}},
            "a tag named main": {"policies": {"total_count": 1, "branch_policies": [
                {"name": "main", "type": "tag"}]}},
            "the environment cannot be read": {"env_rc": 1},
            "the policies cannot be read": {"policies_rc": 1},
            "not json": {"env": "not json"},
        }
        for label, kwargs in cases.items():
            with self.subTest(label):
                proc, output = self.check(**kwargs)
                self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                self.assertEqual(output, ["provisioned=false"])


CHANGED = {"repo": "o/r", "setting": "actions.sha_pinning_required", "status": "changed",
           "current": False, "desired": True, "note": None}
LEFT = {"repo": "o/r", "setting": "repo.allow_auto_merge", "status": "gated",
        "current": False, "desired": True, "note": "adds a way to merge"}
# A write classified safe that then failed.
ERRORED = {"repo": "o/r", "setting": "label[x]", "status": "error",
           "current": None, "desired": {}, "note": "HTTP 500", "risk": "safe"}
# A setting the plan could not read, so nothing classified it.
UNREAD = {"repo": "o/r", "setting": "ruleset[default branch protection]", "status": "error",
          "current": None, "desired": {}, "note": "HTTP 502", "risk": None}


class AutoDecideScriptTests(_ScriptCase):
    """The unreviewed job's last step, run against the real engine's
    `apply-report`. Only `review_<OWNER>=false` withholds the reviewed apply."""

    def decide(self, admin=None, labels=None, in_checkout=None, **env):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "scripts").symlink_to(WORKFLOWS_DIR.parent.parent / "scripts")
            stub = tmp / "python"
            stub.write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')
            stub.chmod(0o755)
            results = tmp / "runner_temp"
            results.mkdir()
            for name, value in (("result-admin.json", admin), ("result-labels.json", labels)):
                if value is not None:
                    (results / name).write_text(
                        value if isinstance(value, str) else json.dumps(value))
            # A file of the same name in the checkout (the working directory).
            for name, value in (in_checkout or {}).items():
                (tmp / name).write_text(json.dumps(value))
            full = {"OWNER": "Adam-S-Daniel", "PROVISIONED": "true", "ADMIN_RC": "0",
                    "LABEL_REPOS_OUTCOME": "success", "LABEL_REPOS": "", "LABELS_RC": ""}
            full.update(env)
            proc, output, summary = self.run_script("decide", tmp, full)
            return proc.returncode, output.splitlines(), summary, proc.stdout + proc.stderr

    def test_nothing_left_answers_false(self):
        code, output, summary, log = self.decide(admin=[CHANGED])
        self.assertEqual((code, output), (0, ["review_ADAM_S_DANIEL=false"]), log)
        self.assertIn("## Applied without review", summary)
        self.assertIn("No approval is needed", summary)

    def test_the_other_owner_gets_its_own_key(self):
        code, output, _, log = self.decide(admin=[], OWNER="jodidaniel")
        self.assertEqual((code, output), (0, ["review_JODIDANIEL=false"]), log)
        self.assertEqual({o.split("=")[0] for o in ("review_ADAM_S_DANIEL=", "review_JODIDANIEL=")},
                         set(REVIEW_OUTPUTS))

    def test_a_change_left_behind_answers_true_without_failing(self):
        code, output, summary, log = self.decide(admin=[CHANGED, LEFT], ADMIN_RC="3")
        self.assertEqual((code, output), (0, ["review_ADAM_S_DANIEL=true"]), log)
        self.assertIn("adds a way to merge", summary)

    def test_a_change_left_behind_in_the_labels_leg_answers_true(self):
        code, output, _, log = self.decide(admin=[CHANGED], labels=[LEFT],
                                           LABEL_REPOS="site", LABELS_RC="3")
        self.assertEqual((code, output), (0, ["review_ADAM_S_DANIEL=true"]), log)

    def test_both_legs_clean_answers_false(self):
        code, output, _, log = self.decide(admin=[CHANGED], labels=[],
                                           LABEL_REPOS="site", LABELS_RC="0")
        self.assertEqual((code, output), (0, ["review_ADAM_S_DANIEL=false"]), log)

    def test_not_set_up_answers_true_without_failing(self):
        for provisioned in ("false", ""):
            with self.subTest(provisioned=provisioned):
                code, output, summary, log = self.decide(PROVISIONED=provisioned, ADMIN_RC="")
                self.assertEqual((code, output), (0, ["review_ADAM_S_DANIEL=true"]), log)
                self.assertIn("did not run", summary)
                self.assertIn("Every change waits for the reviewed apply", summary)

    def test_a_leg_that_did_not_finish_answers_true_and_fails(self):
        cases = {
            "the admin apply wrote no result": {"ADMIN_RC": ""},
            "the labels apply wrote no result": {"admin": [CHANGED], "LABEL_REPOS": "site"},
            # Ended after writing its file and before recording its code.
            "the admin apply recorded no exit code": {"admin": [CHANGED], "ADMIN_RC": ""},
            "the labels apply recorded no exit code": {
                "admin": [CHANGED], "labels": [], "LABEL_REPOS": "site", "LABELS_RC": ""},
            "the cms repo list step failed": {"admin": [CHANGED],
                                              "LABEL_REPOS_OUTCOME": "failure"},
            "the cms repo list step never ran": {"admin": [CHANGED],
                                                 "LABEL_REPOS_OUTCOME": "skipped"},
            "a result file is not a list": {"admin": {"status": "changed"}},
            "a result file is not json": {"admin": "[{"},
            "a result file is empty": {"admin": ""},
            # Only a result an apply step of this job wrote counts: one that
            # sits in the checkout is not this run's answer.
            "the result is in the checkout, not where the step writes it": {
                "in_checkout": {"result-admin.json": []}},
        }
        for label, kwargs in cases.items():
            with self.subTest(label):
                code, output, _, log = self.decide(**kwargs)
                self.assertNotEqual(code, 0, log)
                self.assertEqual(output, ["review_ADAM_S_DANIEL=true"], log)

    def test_a_failed_write_fails_the_job_and_does_not_by_itself_ask_for_review(self):
        # Approving would only repeat the failing write.
        code, output, summary, log = self.decide(admin=[CHANGED, ERRORED], ADMIN_RC="2")
        self.assertNotEqual(code, 0, log)
        self.assertEqual(output, ["review_ADAM_S_DANIEL=false"], log)
        self.assertIn("HTTP 500", summary)
        code, output, _, log = self.decide(admin=[LEFT, ERRORED], ADMIN_RC="2")
        self.assertNotEqual(code, 0, log)
        self.assertEqual(output, ["review_ADAM_S_DANIEL=true"], log)

        # A failed read is different: it can hide a change that would have
        # waited, so it asks for the review.
        code, output, summary, log = self.decide(admin=[CHANGED, UNREAD], ADMIN_RC="2")
        self.assertNotEqual(code, 0, log)
        self.assertEqual(output, ["review_ADAM_S_DANIEL=true"], log)
        self.assertNotIn("No approval is needed", summary)

    def test_a_crashed_apply_asks_for_the_review_whatever_is_on_disk(self):
        # 0, 2 and 3 are the engine's codes. Any other means it did not
        # finish, so a clean-looking result file must not withhold the review.
        for leg in ("admin", "labels"):
            for rc in ("1", "127", "137"):
                with self.subTest(leg=leg, rc=rc):
                    env = {"ADMIN_RC": rc} if leg == "admin" else {
                        "LABEL_REPOS": "site", "LABELS_RC": rc}
                    code, output, _, log = self.decide(admin=[CHANGED], labels=[], **env)
                    self.assertNotEqual(code, 0, log)
                    self.assertEqual(output, ["review_ADAM_S_DANIEL=true"], log)


class AutoApplyStepScriptTests(_ScriptCase):
    """The two apply steps record the engine's exit code and never fail by
    themselves: the last step decides."""

    def test_the_exit_code_is_recorded_and_the_step_passes(self):
        applies = [s for s in self.steps.values() if runs_apply(s)]
        self.assertEqual(len(applies), 2)
        for step in applies:
            for code in (0, 2, 3):
                with self.subTest(step=step.get("id"), code=code), \
                        tempfile.TemporaryDirectory() as tmp:
                    tmp = Path(tmp)
                    stub = tmp / "python"
                    stub.write_text(f"#!/bin/sh\nexit {code}\n")
                    stub.chmod(0o755)
                    proc, output, _ = self.run_script(step["id"], tmp, {"OWNER": "example"})
                    self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                    self.assertEqual(output.splitlines(), [f"rc={code}"])

    def test_a_result_left_from_before_is_removed_first(self):
        # The engine writes its result only when it finishes. If it crashes,
        # the last step must find no file, not an older one.
        for step in (s for s in self.steps.values() if runs_apply(s)):
            argv = shlex.split(step["run"], comments=True)
            name = Path(argv[argv.index("--result-json") + 1]).name
            with self.subTest(step=step.get("id")), tempfile.TemporaryDirectory() as tmp:
                tmp = Path(tmp)
                stub = tmp / "python"
                stub.write_text("#!/bin/sh\nexit 1\n")
                stub.chmod(0o755)
                (tmp / "runner_temp").mkdir()
                (tmp / "runner_temp" / name).write_text("[]")
                proc, output, _ = self.run_script(step["id"], tmp, {"OWNER": "example"})
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                self.assertEqual(output.splitlines(), ["rc=1"])
                self.assertFalse((tmp / "runner_temp" / name).exists())


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

    def run_check(self, env_json, policies_json, policies_rc=0, compare=SAME_COMMIT,
                  compare_rc=0):
        doc = load_workflow(WORKFLOW)
        step = next(s for s in doc["jobs"][APPLY_JOB]["steps"] if s.get("id") == GATE_STEP_ID)
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            write_gh_stub(tmp, env_json, policies_json, compare,
                          policies_rc=policies_rc, compare_rc=compare_rc)
            env = {
                "PATH": f"{tmp}:{os.environ['PATH']}",
                "REPO": "example/example",
                "ENVIRONMENT": ENVIRONMENT,
                "GITHUB_SHA": FAKE_SHA,
                "APPLY_INPUTS": step["env"]["APPLY_INPUTS"],
            }
            proc = subprocess.run(
                ["bash", "-e", "-c", gate_script(doc)],
                cwd=tmp, env=env, capture_output=True, text=True, timeout=30,
            )
            self.calls = gh_calls(tmp)
            return proc

    def check(self, env=GOOD_ENV, policies=GOOD_POLICIES, **kwargs):
        return self.run_check(json.dumps(env), json.dumps(policies), **kwargs)

    def test_passes_when_later_commits_change_nothing_an_apply_reads(self):
        proc = self.check(compare=UNRELATED_COMMITS)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(f"repos/example/example/compare/{FAKE_SHA}...main", self.calls)

    def test_refuses_an_approval_that_arrives_after_main_moved_on(self):
        # Approving an older run would put its config over what a newer
        # commit's unreviewed apply already tightened (docs/decisions/0019).
        for label, compare in STALE_COMPARES.items():
            with self.subTest(label):
                proc = self.check(compare=compare)
                self.assertRefused(proc)
                self.assertIn("::error::Not applied", proc.stdout)
        self.assertRefused(self.check(compare_rc=1))

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
