"""The `plan` job asks for approval only when there is something to apply.

The apply job waits for the owner's approval in `fleet-apply`, so every run
that reaches it costs a human click. `plan` runs first, holds no admin key,
and picks the owners that need an apply; the apply job's matrix is exactly
that list, and the job is skipped when the list is empty. These tests hold
the wiring in place and run the decide step's real script, taken from the
parsed workflow:

* push: real git histories and the real engine's `resolve`, so a
  comment-only fleet.yml edit picks no owner, a settings edit picks only the
  owner it touches, and a change to the engine, the workflow or
  requirements.txt picks every owner;
* schedule: a stub engine, so drift, an error, an undeclared repo or a
  missing read-only token each pick the owner, and only a clean report on
  both counts leaves it out;
* anything else (manual dispatch) picks every owner.

Every case the script cannot settle must pick every owner (fail closed).
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from test_repo_settings_workflow_token import (
    APPLY_JOB,
    MINT_ACTION,
    REQUIRED_READ,
    environment_name,
    event_gate,
    references_admin_key,
    top_level_conjuncts,
)
from test_required_checks import REPO_ROOT, WORKFLOWS_DIR, load_workflow

WORKFLOW = WORKFLOWS_DIR / "repo-settings.yml"
PLAN_JOB = "plan"
DECIDE_STEP_ID = "decide"
ENGINE = REPO_ROOT / "scripts" / "repo_settings.py"
OWNERS = ["Adam-S-Daniel", "jodidaniel"]

FLEET = """\
# test fleet
defaults:
  actions:
    sha_pinning_required: true
repos:
  - name: Adam-S-Daniel/one
    manage: ["all"]
  - name: jodidaniel/two
    manage: ["all"]
"""


def plan_job():
    return load_workflow(WORKFLOW)["jobs"][PLAN_JOB]


def decide_step():
    for step in plan_job().get("steps") or []:
        if step.get("id") == DECIDE_STEP_ID:
            return step
    raise AssertionError(f"no step with id: {DECIDE_STEP_ID}")


class PlanWiringTests(unittest.TestCase):
    def setUp(self):
        self.jobs = load_workflow(WORKFLOW)["jobs"]
        self.plan = self.jobs[PLAN_JOB]
        self.apply = self.jobs[APPLY_JOB]

    def test_plan_never_runs_on_pull_request_and_keeps_the_app_gate(self):
        self.assertEqual(event_gate(self.plan), "never-pr", self.plan.get("if"))
        self.assertIn("vars.REPO_SETTINGS_APP_CLIENT_ID != ''",
                      top_level_conjuncts(self.plan.get("if", "")))

    def test_plan_holds_no_admin_key_and_waits_for_no_approval(self):
        self.assertFalse(references_admin_key(self.plan))
        self.assertIsNone(environment_name(self.plan))

    def test_plan_mints_only_read_only_tokens(self):
        mints = [s for s in self.plan.get("steps") or []
                 if str(s.get("uses", "")).startswith(MINT_ACTION)]
        self.assertEqual(sorted(m["with"]["owner"] for m in mints), sorted(OWNERS))
        for mint in mints:
            inputs = mint["with"]
            self.assertEqual(inputs.get("client-id"),
                             "${{ vars.REPO_SETTINGS_READ_APP_CLIENT_ID }}")
            perms = {k: v for k, v in inputs.items() if str(k).startswith("permission-")}
            self.assertLessEqual(REQUIRED_READ, set(perms))
            for key, value in perms.items():
                self.assertEqual(str(value), "read", f"{key}={value!r}")
            # A failed mint must leave an empty token for the script to treat
            # as "cannot tell", not fail the job and skip the apply.
            self.assertTrue(mint.get("continue-on-error"))

    def test_decide_step_owners_match_the_mints(self):
        env = decide_step()["env"]
        self.assertEqual(env["OWNERS"].split(), OWNERS)
        for owner in OWNERS:
            self.assertIn(f"READ_TOKEN_{owner.replace('-', '_')}", env)

    def test_apply_runs_only_for_the_owners_plan_picked(self):
        self.assertEqual(self.apply.get("needs"), PLAN_JOB)
        self.assertIn("needs.plan.outputs.owners != '[]'",
                      top_level_conjuncts(self.apply.get("if", "")))
        self.assertEqual(self.apply["strategy"]["matrix"]["owner"],
                         "${{ fromJSON(needs.plan.outputs.owners) }}")
        self.assertEqual(self.plan["outputs"]["owners"],
                         "${{ steps.decide.outputs.owners }}")


class DecideScriptTests(unittest.TestCase):
    """Runs the decide step's script with `bash -e`, as GitHub does."""

    def setUp(self):
        self.assertIsNotNone(shutil.which("jq"), "jq is required to run the decide step")
        self.assertIsNotNone(shutil.which("git"), "git is required to run the decide step")
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.repo = self.tmp / "repo"
        self.repo.mkdir()

    # -- helpers ---------------------------------------------------------- #

    def git(self, *args):
        return subprocess.run(
            ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
            cwd=self.repo, check=True, capture_output=True, text=True,
        ).stdout.strip()

    def write(self, rel, text):
        path = self.repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def commit(self, message):
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)
        return self.git("rev-parse", "HEAD")

    def init_repo(self):
        self.git("init", "-q")
        self.write("scripts/repo_settings.py", ENGINE.read_text())
        self.write(".github/workflows/repo-settings.yml", WORKFLOW.read_text())
        self.write("requirements.txt", "PyYAML\n")
        self.write("repo-settings/fleet.yml", FLEET)
        return self.commit("base")

    def real_python(self):
        (self.bin / "python").symlink_to(sys.executable)

    def stub_python(self):
        # Exit code from STUB_<subcommand>_<owner>, default 0.
        stub = self.bin / "python"
        stub.write_text(
            "#!/bin/sh\n"
            'cmd="$2"; owner=""\n'
            'while [ $# -gt 0 ]; do [ "$1" = --owner ] && owner="$2"; shift; done\n'
            'var="STUB_${cmd}_$(echo "$owner" | tr - _)"\n'
            'eval "code=\\${$var:-0}"\n'
            'echo "stub $cmd $owner -> $code"\n'
            'exit "$code"\n'
        )
        stub.chmod(0o755)

    def run_decide(self, event, before="", after="", tokens=None):
        out = self.tmp / "github_output"
        out.write_text("")
        env = {
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "HOME": str(self.tmp),
            "GITHUB_OUTPUT": str(out),
            "RUNNER_TEMP": str(self.tmp),
            "EVENT": event,
            "BEFORE": before,
            "AFTER": after,
            "OWNERS": decide_step()["env"]["OWNERS"],
        }
        for owner in OWNERS:
            env[f"READ_TOKEN_{owner.replace('-', '_')}"] = (tokens or {}).get(owner, "")
        env.update(getattr(self, "extra_env", {}))
        proc = subprocess.run(
            ["bash", "-e", "-c", decide_step()["run"]],
            cwd=self.repo, env=env, capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        lines = [l for l in out.read_text().splitlines() if l.startswith("owners=")]
        self.assertEqual(len(lines), 1, out.read_text())
        return json.loads(lines[0][len("owners="):]), proc.stdout

    # -- push ------------------------------------------------------------- #

    def test_push_with_comment_only_fleet_change_picks_no_owner(self):
        self.real_python()
        before = self.init_repo()
        self.write("repo-settings/fleet.yml",
                   FLEET.replace("# test fleet", "# test fleet\n# a new comment") + "# trailing\n")
        self.write("docs/notes.md", "unrelated\n")
        after = self.commit("comments")
        owners, _ = self.run_decide("push", before, after)
        self.assertEqual(owners, [])

    def test_push_with_reordered_keys_picks_no_owner(self):
        self.real_python()
        before = self.init_repo()
        self.write("repo-settings/fleet.yml", FLEET.replace(
            '  - name: jodidaniel/two\n    manage: ["all"]\n',
            '  - manage: ["all"]\n    name: jodidaniel/two\n'))
        after = self.commit("reorder")
        owners, _ = self.run_decide("push", before, after)
        self.assertEqual(owners, [])

    def test_push_with_a_settings_change_picks_only_that_owner(self):
        self.real_python()
        before = self.init_repo()
        self.write("repo-settings/fleet.yml", FLEET.replace(
            '  - name: jodidaniel/two\n    manage: ["all"]\n',
            '  - name: jodidaniel/two\n    manage: []\n'))
        after = self.commit("unmanage two")
        owners, _ = self.run_decide("push", before, after)
        self.assertEqual(owners, ["jodidaniel"])

    def test_push_with_a_defaults_change_picks_every_owner(self):
        self.real_python()
        before = self.init_repo()
        self.write("repo-settings/fleet.yml",
                   FLEET.replace("sha_pinning_required: true", "sha_pinning_required: false"))
        after = self.commit("defaults")
        owners, _ = self.run_decide("push", before, after)
        self.assertEqual(owners, OWNERS)

    def test_push_changing_engine_workflow_or_requirements_picks_every_owner(self):
        self.real_python()
        for rel in ("scripts/repo_settings.py", ".github/workflows/repo-settings.yml",
                    "requirements.txt"):
            with self.subTest(rel=rel):
                shutil.rmtree(self.repo)
                self.repo.mkdir()
                before = self.init_repo()
                self.write(rel, (self.repo / rel).read_text() + "\n# touched\n")
                after = self.commit(f"touch {rel}")
                owners, out = self.run_decide("push", before, after)
                self.assertEqual(owners, OWNERS)
                self.assertIn(f"{rel} changed", out)

    def test_push_without_a_usable_base_picks_every_owner(self):
        self.real_python()
        after = self.init_repo()
        for before in ("", "0" * 40, "f" * 40, "not-a-sha"):
            with self.subTest(before=before):
                owners, _ = self.run_decide("push", before, after)
                self.assertEqual(owners, OWNERS)

    def test_push_when_the_old_config_is_refused_picks_every_owner(self):
        self.real_python()
        self.git("init", "-q")
        self.write("scripts/repo_settings.py", ENGINE.read_text())
        self.write("repo-settings/fleet.yml", "repos: [not, valid\n")
        before = self.commit("broken")
        self.write("repo-settings/fleet.yml", FLEET)
        after = self.commit("fixed")
        owners, _ = self.run_decide("push", before, after)
        self.assertEqual(owners, OWNERS)

    # -- schedule --------------------------------------------------------- #

    def schedule(self, tokens=None, **codes):
        self.stub_python()
        self.extra_env = codes
        all_tokens = {o: "t" for o in OWNERS}
        return self.run_decide("schedule", tokens=all_tokens if tokens is None else tokens)

    def test_schedule_with_no_drift_and_nothing_undeclared_picks_no_owner(self):
        owners, _ = self.schedule()
        self.assertEqual(owners, [])

    def test_schedule_picks_each_owner_with_drift_or_an_error(self):
        owners, _ = self.schedule(STUB_diff_jodidaniel="1")
        self.assertEqual(owners, ["jodidaniel"])
        owners, _ = self.schedule(STUB_diff_Adam_S_Daniel="2")
        self.assertEqual(owners, ["Adam-S-Daniel"])

    def test_schedule_picks_an_owner_with_undeclared_repos_or_failed_coverage(self):
        owners, _ = self.schedule(STUB_coverage_Adam_S_Daniel="1")
        self.assertEqual(owners, ["Adam-S-Daniel"])
        owners, _ = self.schedule(STUB_coverage_jodidaniel="2")
        self.assertEqual(owners, ["jodidaniel"])

    def test_schedule_without_a_read_only_token_picks_that_owner(self):
        owners, _ = self.schedule(tokens={"Adam-S-Daniel": "t"})
        self.assertEqual(owners, ["jodidaniel"])
        owners, _ = self.schedule(tokens={})
        self.assertEqual(owners, OWNERS)

    # -- everything else -------------------------------------------------- #

    def test_manual_dispatch_picks_every_owner(self):
        self.stub_python()
        owners, _ = self.run_decide("workflow_dispatch")
        self.assertEqual(owners, OWNERS)


if __name__ == "__main__":
    unittest.main()
