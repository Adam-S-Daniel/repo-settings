"""The admin App key is reachable only from the approval-gated apply job.

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
  mints with every `permission-*` input set to `read`.

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
# Lexical tokens inside expression strings, never a parse of the YAML.
ADMIN_KEY = re.compile(r"\bREPO_SETTINGS_APP_PRIVATE_KEY\b")
EVENT_CONJUNCT = re.compile(r"github\.event_name\s*(==|!=)\s*'([a-z_]+)'")


def top_level_conjuncts(expr):
    """Split a GitHub expression on its top-level `&&`, leaving any `&&`
    inside parentheses or a quoted string alone."""
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
        elif not quoted and depth == 0 and expr.startswith("&&", i):
            parts.append(expr[start:i].strip())
            start = i + 2
            i += 1
        i += 1
    parts.append(expr[start:].strip())
    return parts


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


def runs_apply(step):
    """True if the step's `run:` invokes `repo_settings.py apply`."""
    body = step.get("run")
    if not isinstance(body, str):
        return False
    tokens = shlex.split(body, comments=True)
    for i, token in enumerate(tokens[:-1]):
        if token.endswith("repo_settings.py") and tokens[i + 1] == "apply":
            return True
    return False


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
        self.assertIsNotNone(self.apply, f"{WORKFLOW.name}: no `{APPLY_JOB}` job")
        self.assertIsNotNone(self.drift, f"{WORKFLOW.name}: no `{DRIFT_JOB}` job")

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
        # needs actions: read and the nudge step still needs issues: write.
        perms = self.apply.get("permissions") or {}
        self.assertEqual(perms.get("actions"), "read")
        self.assertEqual(perms.get("issues"), "write")
        self.assertEqual(perms.get("contents"), "read")

    def test_self_check_runs_unconditionally_before_every_apply(self):
        steps = self.apply.get("steps") or []
        ids = [s.get("id") for s in steps]
        self.assertIn(GATE_STEP_ID, ids)
        gate_index = ids.index(GATE_STEP_ID)
        gate = steps[gate_index]
        self.assertNotIn("if", gate, "the self-check must never be skipped")
        self.assertFalse(gate.get("continue-on-error"), "the self-check must fail the job")
        apply_indexes = [i for i, s in enumerate(steps) if runs_apply(s)]
        self.assertGreaterEqual(len(apply_indexes), 2, "expected the apply and dry-run steps")
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
        mints = [s for s in self.drift.get("steps") or []
                 if str(s.get("uses", "")).startswith(MINT_ACTION)]
        self.assertEqual(len(mints), 1)
        inputs = mints[0].get("with") or {}
        self.assertEqual(inputs.get("client-id"), "${{ vars.REPO_SETTINGS_READ_APP_CLIENT_ID }}")
        self.assertEqual(inputs.get("private-key"),
                         "${{ secrets.REPO_SETTINGS_READ_APP_PRIVATE_KEY }}")
        perms = {k: v for k, v in inputs.items() if str(k).startswith("permission-")}
        self.assertLessEqual(REQUIRED_READ, set(perms))
        for key, value in perms.items():
            self.assertEqual(str(value), "read", f"{key}={value!r}")

    def test_drift_job_runs_diff_and_never_apply(self):
        steps = self.drift.get("steps") or []
        self.assertFalse(any(runs_apply(s) for s in steps))
        self.assertTrue(any("repo_settings.py diff" in str(s.get("run", "")) for s in steps))


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
