"""Behavioural tests for the Dependabot sweep's merge-state gate.

The sweep in `.github/workflows/dependabot-auto-merge.yml` used to gate on
`mergeable == MERGEABLE` (which only means "no merge conflict") plus its own
check rollup, and let `mergeStateStatus=BLOCKED` through as actionable. GitHub
had already refused, so the run logged a self-contradicting pair --

    act on #40 - mergeable, checks green, manifest clean (mergeStateStatus=BLOCKED)
    X ...#40 is not mergeable: the base branch policy prohibits the merge.
    ::error::#40 - merge was refused and the PR is not behind main; needs a human

-- and failed daily naming no cause (skills-evals run 32342667620, 2026-08-20).

cms-platform#437 hardened the sweep further, after #41 on THIS repo showed
`gh pr merge --auto` merges an already-immediately-mergeable PR on the spot
rather than arming, so a Dependabot PR could land before any real CI had
reported at all. Job `auto-merge` no longer attempts a merge; this sweep is
now the only unattended merge path, and it must not merge a PR whose only
green checks are its OWN prior jobs on this same workflow. The additions
here test that: a `SELF_WORKFLOW` identity that must be non-empty to run at
all, a floor that requires at least one check from OUTSIDE this workflow, a
40-hex-sha shape check on `headRefOid` before a merge is attempted, a merge
pinned to that sha with `--match-head-commit`, and a re-check that the head
has not moved out from under a refused, pinned merge attempt.

These tests EXECUTE the step's real shell script, extracted from the workflow
with a YAML parser (never a regex or line scan), against stubbed `gh`/`git`
binaries. No network, no sleeps, no wall-clock dependence.
"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "dependabot-auto-merge.yml"
STEP_NAME = "Sweep open Dependabot PRs"
DEFAULT_SELF_WORKFLOW = "Dependabot auto-merge"

# The verbatim `pull_request` rule parameters returned by
# GET repos/Adam-S-Daniel/skills-evals/rules/branches/main on 2026-08-20.
LIVE_PR_RULE = {
    "type": "pull_request",
    "parameters": {
        "required_approving_review_count": 0,
        "dismiss_stale_reviews_on_push": False,
        "required_reviewers": [],
        "require_code_owner_review": False,
        "require_last_push_approval": False,
        "required_review_thread_resolution": False,
        "require_extra_approval_for_unattributed_changes": True,
        "allowed_merge_methods": ["merge"],
    },
    "ruleset_source_type": "Repository",
    "ruleset_source": "Adam-S-Daniel/skills-evals",
    "ruleset_id": 18877855,
}

GH_STUB = r"""#!/usr/bin/env bash
# Stub `gh`. Records every invocation; answers from $FIXTURES.
set -uo pipefail
printf '%s\n' "$*" >> "$FIXTURES/calls.log"
case "$1 ${2:-}" in
  "pr list")
    cat "$FIXTURES/pr-numbers.txt"
    ;;
  "pr view")
    # First call for a given PR number answers with pr-N.json; every later
    # call answers with pr-N.after.json if the test provided one (the
    # sweep re-views a PR after a refused, pinned merge attempt to see
    # whether its head moved), else falls back to pr-N.json again.
    num="$3"
    count_file="$FIXTURES/pr-${num}.calls"
    count=0
    [ -f "$count_file" ] && count=$(cat "$count_file")
    count=$((count + 1))
    echo "$count" > "$count_file"
    if [ "$count" -gt 1 ] && [ -f "$FIXTURES/pr-${num}.after.json" ]; then
      cat "$FIXTURES/pr-${num}.after.json"
    else
      cat "$FIXTURES/pr-${num}.json"
    fi
    ;;
  "pr merge")
    num="${!#}"
    case " ${MERGE_FAILS:-} " in
      *" $num "*)
        echo "X Pull request owner/repo#$num is not mergeable: the base branch policy prohibits the merge." >&2
        exit 1
        ;;
    esac
    ;;
  "pr update-branch")
    ;;
  "api "*|"api")
    if [ -f "$FIXTURES/rules.json" ]; then
      cat "$FIXTURES/rules.json"
    else
      # gh api on an HTTP error prints the error BODY to STDOUT and exits 1.
      echo '{"message":"Not Found","status":"404"}'
      exit 1
    fi
    ;;
  *)
    echo "unstubbed gh call: $*" >&2
    exit 90
    ;;
esac
"""

GIT_STUB = r"""#!/usr/bin/env bash
set -uo pipefail
case "${1:-}" in
  fetch) exit 0 ;;
  diff)  echo ".github/workflows/tests.yml" ;;
  *)     exit 0 ;;
esac
"""


def sweep_script() -> str:
    """The sweep step's `run:` body, via a real YAML parser."""
    doc = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    step = next(
        s
        for s in doc["jobs"]["sweep"]["steps"]
        if s.get("name") == STEP_NAME
    )
    return step["run"]


class SweepGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # The sweep itself cannot run without these, so a box that cannot run
        # them cannot validate it either -- and reporting "skipped, all green"
        # for an unguarded gate is the exact failure mode this file exists to
        # stop.
        for tool in ("bash", "jq"):
            if shutil.which(tool) is None:
                raise unittest.SkipTest(  # pragma: no cover - environment guard
                    f"{tool} is required to exercise the sweep script"
                )
        cls.script = sweep_script()

    def _pr(self, number, merge_state, checks=("SUCCESS",), head_sha=None):
        def _entry(c):
            # A plain string keeps every pre-existing caller working exactly
            # as before -- a check with no `workflowName` at all, which the
            # sweep's "outside this workflow" gate correctly treats as
            # OUTSIDE (a legacy commit status carries no workflowName
            # either). A dict lets a new test name a specific workflow, e.g.
            # to simulate job `auto-merge`'s own SUCCESS check.
            if isinstance(c, dict):
                entry = {"conclusion": c.get("conclusion")}
                if "workflowName" in c:
                    entry["workflowName"] = c["workflowName"]
                if "name" in c:
                    entry["name"] = c["name"]
                return entry
            return {"conclusion": c}

        return {
            "number": number,
            "baseRefName": "main",
            "headRefOid": head_sha if head_sha is not None else "0" * 40,
            "mergeable": "MERGEABLE",
            "mergeStateStatus": merge_state,
            "statusCheckRollup": [_entry(c) for c in checks],
        }

    def _run(
        self,
        prs,
        rules=None,
        merge_fails=(),
        after=None,
        self_workflow=DEFAULT_SELF_WORKFLOW,
    ):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        fixtures = root / "fixtures"
        binp = root / "bin"
        fixtures.mkdir()
        binp.mkdir()

        (fixtures / "pr-numbers.txt").write_text(
            "".join(f"{p['number']}\n" for p in prs), encoding="utf-8"
        )
        for pr in prs:
            (fixtures / f"pr-{pr['number']}.json").write_text(
                json.dumps(pr), encoding="utf-8"
            )
        for num, payload in (after or {}).items():
            (fixtures / f"pr-{num}.after.json").write_text(
                json.dumps(payload), encoding="utf-8"
            )
        if rules is not None:
            (fixtures / "rules.json").write_text(json.dumps(rules), encoding="utf-8")
        (fixtures / "calls.log").write_text("", encoding="utf-8")

        for name, body in (("gh", GH_STUB), ("git", GIT_STUB)):
            path = binp / name
            path.write_text(body, encoding="utf-8")
            path.chmod(0o755)

        env = dict(os.environ)
        env.update(
            {
                "PATH": f"{binp}:{env['PATH']}",
                "FIXTURES": str(fixtures),
                "GITHUB_REPOSITORY": "Adam-S-Daniel/skills-evals",
                "MERGE_FAILS": " ".join(str(n) for n in merge_fails),
                "SELF_WORKFLOW": self_workflow,
            }
        )
        proc = subprocess.run(
            ["bash", "-c", self.script],
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        calls = (fixtures / "calls.log").read_text(encoding="utf-8")
        return proc, calls

    # -- the gate ---------------------------------------------------------- #
    def test_blocked_pr_is_not_merged(self):
        proc, calls = self._run([self._pr(40, "BLOCKED")], rules=[LIVE_PR_RULE])
        self.assertNotIn("pr merge", calls, "the sweep attempted a merge GitHub had already refused")

    def test_blocked_pr_stops_claiming_it_is_acting(self):
        proc, _ = self._run([self._pr(40, "BLOCKED")], rules=[LIVE_PR_RULE])
        self.assertNotIn("act on #40", proc.stdout)
        self.assertIn("blocked #40", proc.stdout)

    def test_blocked_pr_names_the_unattributed_changes_cause(self):
        proc, _ = self._run([self._pr(40, "BLOCKED")], rules=[LIVE_PR_RULE])
        self.assertIn(
            "require_extra_approval_for_unattributed_changes=true", proc.stdout
        )
        self.assertIn("fleet.yml", proc.stdout)

    def test_blocked_pr_is_counted_separately_from_failed(self):
        proc, _ = self._run([self._pr(40, "BLOCKED")], rules=[LIVE_PR_RULE])
        self.assertIn(
            "merged=0 updated=0 skipped=0 blocked=1 failed=0", proc.stdout
        )

    def test_blocked_pr_fails_the_run(self):
        # Deliberate: the state is clearable and finite, and this repo's
        # scheduled-run-health audit only sees failure/startup_failure/
        # timed_out -- an exit-0 sweep is invisible to it.
        proc, _ = self._run([self._pr(40, "BLOCKED")], rules=[LIVE_PR_RULE])
        self.assertEqual(proc.returncode, 1)

    def test_cause_is_probed_once_for_a_batch(self):
        prs = [self._pr(n, "BLOCKED") for n in (38, 39, 40)]
        proc, calls = self._run(prs, rules=[LIVE_PR_RULE])
        self.assertEqual(
            sum(1 for line in calls.splitlines() if line.startswith("api ")), 1
        )
        self.assertIn(
            "merged=0 updated=0 skipped=0 blocked=3 failed=0", proc.stdout
        )

    def test_unreadable_rules_still_skip_and_say_so(self):
        # No rules.json -> the stub reproduces gh's error-body-on-stdout
        # behaviour. The sweep must not treat that JSON as a rules payload.
        proc, calls = self._run([self._pr(40, "BLOCKED")], rules=None)
        self.assertNotIn("pr merge", calls)
        self.assertIn("could not read the effective branch rules", proc.stdout)
        self.assertNotIn("Not Found", proc.stdout)
        self.assertEqual(proc.returncode, 1)

    def test_rules_without_the_parameter_get_the_generic_cause(self):
        rule = json.loads(json.dumps(LIVE_PR_RULE))
        del rule["parameters"]["require_extra_approval_for_unattributed_changes"]
        proc, calls = self._run([self._pr(40, "BLOCKED")], rules=[rule])
        self.assertNotIn("pr merge", calls)
        self.assertIn("does not set require_extra_approval", proc.stdout)

    # -- states the gate must NOT swallow ---------------------------------- #
    def test_a_clean_pr_still_merges(self):
        proc, calls = self._run([self._pr(41, "CLEAN")])
        self.assertIn("act on #41", proc.stdout)
        self.assertIn("pr merge", calls)
        self.assertIn(
            "merged=1 updated=0 skipped=0 blocked=0 failed=0", proc.stdout
        )
        self.assertEqual(proc.returncode, 0)

    def test_a_behind_pr_is_still_refreshed_not_blocked(self):
        # BEHIND is a state this sweep can fix; the gate must not catch it.
        # No after.json for #42, so the post-refusal re-view falls back to
        # the same pr-42.json -- the head has NOT moved, so this must still
        # fall through to the BEHIND branch and refresh it.
        proc, calls = self._run([self._pr(42, "BEHIND")], merge_fails=(42,))
        self.assertIn("pr update-branch", calls)
        self.assertIn(
            "merged=0 updated=1 skipped=0 blocked=0 failed=0", proc.stdout
        )
        self.assertEqual(proc.returncode, 0)

    def test_an_unmergeable_pr_is_still_skipped_before_the_gate(self):
        pr = self._pr(43, "DIRTY")
        pr["mergeable"] = "CONFLICTING"
        proc, calls = self._run([pr])
        self.assertNotIn("pr merge", calls)
        self.assertIn(
            "merged=0 updated=0 skipped=1 blocked=0 failed=0", proc.stdout
        )
        self.assertEqual(proc.returncode, 0)

    def test_no_open_prs_reports_the_blocked_counter_too(self):
        proc, _ = self._run([])
        self.assertIn("merged=0 updated=0 skipped=0 blocked=0 failed=0", proc.stdout)
        self.assertEqual(proc.returncode, 0)

    # -- cms-platform#437 hardening: pin the merge, require an outside check #
    def test_a_real_ci_check_plus_the_own_workflow_check_still_merges(self):
        checks = [
            {"conclusion": "SUCCESS", "workflowName": "tests"},
            {"conclusion": "SUCCESS", "workflowName": DEFAULT_SELF_WORKFLOW},
        ]
        sha = "a" * 40
        pr = self._pr(50, "CLEAN", checks=checks, head_sha=sha)
        proc, calls = self._run([pr])
        merge_calls = [
            line for line in calls.splitlines() if line.startswith("pr merge")
        ]
        self.assertEqual(len(merge_calls), 1, msg=calls)
        self.assertIn(f"--match-head-commit {sha}", merge_calls[0])
        self.assertTrue(
            merge_calls[0].rstrip().endswith("50"),
            msg="the PR number must be the LAST argument -- the stub reads "
            f"it with ${{!#}}: {merge_calls[0]!r}",
        )
        self.assertIn(
            "merged=1 updated=0 skipped=0 blocked=0 failed=0", proc.stdout
        )
        self.assertEqual(proc.returncode, 0)

    def test_only_the_own_workflow_reporting_does_not_merge(self):
        checks = [{"conclusion": "SUCCESS", "workflowName": DEFAULT_SELF_WORKFLOW}]
        proc, calls = self._run([self._pr(51, "CLEAN", checks=checks)])
        self.assertNotIn("pr merge", calls)
        self.assertIn(
            "every check on its head comes from this workflow", proc.stdout
        )
        self.assertIn(
            "merged=0 updated=0 skipped=1 blocked=0 failed=0", proc.stdout
        )
        self.assertEqual(proc.returncode, 0)

    def test_a_still_running_outside_check_does_not_merge(self):
        checks = [{"conclusion": None, "workflowName": "tests"}]
        proc, calls = self._run([self._pr(52, "CLEAN", checks=checks)])
        self.assertNotIn("pr merge", calls)
        self.assertIn(
            "merged=0 updated=0 skipped=1 blocked=0 failed=0", proc.stdout
        )
        self.assertEqual(proc.returncode, 0)

    def test_head_moved_after_a_refused_pinned_merge_is_not_updated(self):
        original = "1" * 40
        moved = "2" * 40
        pr = self._pr(53, "BEHIND", head_sha=original)
        proc, calls = self._run(
            [pr], merge_fails=(53,), after={53: {"headRefOid": moved}}
        )
        self.assertNotIn("pr update-branch", calls)
        self.assertIn("its head moved", proc.stdout)
        self.assertIn(
            "merged=0 updated=0 skipped=1 blocked=0 failed=0", proc.stdout
        )
        self.assertEqual(proc.returncode, 0)

    def test_empty_self_workflow_refuses_to_run_at_all(self):
        proc, calls = self._run([self._pr(54, "CLEAN")], self_workflow="")
        self.assertNotIn("pr merge", calls)
        self.assertNotEqual(proc.returncode, 0)

    def test_non_sha_head_ref_oid_skips_rather_than_merging(self):
        proc, calls = self._run([self._pr(55, "CLEAN", head_sha="abc")])
        self.assertNotIn("pr merge", calls)
        self.assertIn(
            "merged=0 updated=0 skipped=1 blocked=0 failed=0", proc.stdout
        )
        self.assertEqual(proc.returncode, 0)


class AutoMergeJobMergesNothingTests(unittest.TestCase):
    """cms-platform#437: `gh pr merge --auto` merges an already-mergeable PR
    on the spot instead of arming (measured on this repo's own #41), so job
    `auto-merge` must never call `gh pr merge` at all -- only job `sweep`
    merges, and only after judging every check on the head. Parsed with a
    real YAML parser, never a regex or line scan, per this repo's own
    AST-always rule for anything reasoning about workflow SHAPE."""

    def test_auto_merge_job_steps_are_exactly_the_non_merging_set(self):
        doc = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
        steps = doc["jobs"]["auto-merge"]["steps"]
        names = [s.get("name") for s in steps]
        self.assertEqual(
            names,
            [
                "Checkout",
                "Fetch base ref",
                "Get Dependabot metadata",
                "Verify only manifest paths changed",
                "Disable auto-merge (path check failed)",
            ],
            msg="job `auto-merge` merges nothing (cms-platform#437) -- a "
            "merge-attempting step reappearing here needs a second look",
        )


class SweepTokenCanReadCheckRollupTests(unittest.TestCase):
    """The sweep reads `statusCheckRollup` through `gh pr view`. Without
    `checks: read` and `statuses: read` on the job's GITHUB_TOKEN, GraphQL
    answers "Resource not accessible by integration" and the sweep dies
    before judging a single PR (runs 36433063619 and 36571817487, issue #53).
    `gh` also resolves each check's `checkSuite.workflowRun` (the
    `workflowName` the sweep's outside-this-workflow floor reads), which
    needs `actions: read` (run 36623969002). An explicit `permissions:`
    block sets every unlisted scope to none, so all three must be named."""

    def test_sweep_job_token_grants_rollup_read_scopes(self):
        doc = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
        job = doc["jobs"]["sweep"]
        perms = job.get("permissions", doc.get("permissions"))
        self.assertIsInstance(perms, dict)
        for scope in ("actions", "checks", "statuses"):
            self.assertIn(
                perms.get(scope),
                ("read", "write"),
                msg=f"job `sweep` needs `{scope}: read` to read statusCheckRollup",
            )


if __name__ == "__main__":
    unittest.main()
