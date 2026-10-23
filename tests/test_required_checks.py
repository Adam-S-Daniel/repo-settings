"""Every pull-request job here is a required check or a documented exception.

The fleet rule makes every CI job that runs on pull requests a required check
unless this repo's AGENTS.md says why not (issue #86). These tests hold that in
place: they parse the workflows with `yaml` (never a regex over the YAML) and
read the required checks through the engine's own `resolve_targets`, so a
change to fleet.yml, a workflow or AGENTS.md that breaks the rule turns red
here. They fail closed: a trigger, ruleset or section they cannot find is a
failure, not a skip.

Nothing they check is enforced on GitHub while the repo is private (rulesets
answer 403); the declaration is kept anyway, per ADR 0002.
"""

import re
import sys
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import repo_settings as rs  # noqa: E402

WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
FLEET = REPO_ROOT / "repo-settings" / "fleet.yml"
AGENTS_MD = REPO_ROOT / "AGENTS.md"
THIS_REPO = "Adam-S-Daniel/repo-settings"
SECTION_HEADING = "## Repo-specific additions"


def load_workflow(path):
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def triggers(doc, path):
    """The workflow's `on:` block as a dict. PyYAML loads the bare key `on`
    as the boolean True, so read both spellings, and fail if neither is
    there rather than treating the workflow as having no triggers."""
    on = doc.get("on", doc.get(True))
    if on is None:
        raise AssertionError(f"{path.name}: no `on:` block found")
    if isinstance(on, str):
        return {on: None}
    if isinstance(on, list):
        return {name: None for name in on}
    if isinstance(on, dict):
        return on
    raise AssertionError(f"{path.name}: unreadable `on:` block {on!r}")


def pull_request_workflows():
    """{path: parsed doc} for every workflow triggered by pull_request."""
    found = {}
    for path in sorted(WORKFLOWS_DIR.glob("*.y*ml")):
        doc = load_workflow(path)
        if "pull_request" in triggers(doc, path):
            found[path] = doc
    return found


def pull_request_jobs():
    """[(workflow path, job id, job dict)] for every job in a PR workflow."""
    jobs = []
    for path, doc in pull_request_workflows().items():
        for job_id, job in (doc.get("jobs") or {}).items():
            jobs.append((path, job_id, job or {}))
    return jobs


def required_checks():
    with open(FLEET, encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)
    targets = [t for t in rs.resolve_targets(cfg, None) if t["repo"] == THIS_REPO]
    if len(targets) != 1:
        raise AssertionError(f"{THIS_REPO} appears {len(targets)} times in fleet.yml")
    ruleset = targets[0]["settings"].get("ruleset")
    if not ruleset:
        raise AssertionError(f"{THIS_REPO} resolves with no ruleset")
    checks = ruleset.get("required_status_checks")
    if not checks:
        raise AssertionError(f"{THIS_REPO}'s ruleset declares no required checks")
    return checks


def documented_job_ids():
    """Every backticked token in AGENTS.md's "Repo-specific additions"
    section. The managed section above it is overwritten by a sync, so an
    exception written there would not survive."""
    text = AGENTS_MD.read_text(encoding="utf-8")
    lines = text.splitlines()
    try:
        start = lines.index(SECTION_HEADING)
    except ValueError:
        raise AssertionError(f"AGENTS.md has no {SECTION_HEADING!r} line") from None
    section = []
    for line in lines[start + 1:]:
        if line.startswith("## "):
            break
        section.append(line)
    return set(re.findall(r"`([^`\n]+)`", "\n".join(section)))


class RequiredChecksTests(unittest.TestCase):
    def test_scan_finds_the_known_pull_request_workflows(self):
        # Guards the scan itself: if trigger parsing broke, every other test
        # here would pass vacuously over zero workflows.
        names = {p.name for p in pull_request_workflows()}
        self.assertIn("tests.yml", names)
        self.assertIn("agent-checks.yml", names)

    def test_tests_workflow_always_runs_on_pull_requests(self):
        path = WORKFLOWS_DIR / "tests.yml"
        doc = load_workflow(path)
        on = triggers(doc, path)
        self.assertIn("pull_request", on)
        pr = on["pull_request"] or {}
        self.assertNotIn("paths", pr, "a required check cannot use on.paths")
        self.assertNotIn("paths-ignore", pr, "a required check cannot use on.paths")

    def test_tests_workflow_has_no_concurrency_group(self):
        doc = load_workflow(WORKFLOWS_DIR / "tests.yml")
        self.assertNotIn("concurrency", doc)
        for job_id, job in (doc.get("jobs") or {}).items():
            self.assertNotIn("concurrency", job or {}, msg=job_id)

    def test_each_required_check_comes_from_exactly_one_pull_request_job(self):
        jobs = pull_request_jobs()
        for job_path, job_id, job in jobs:
            name = job.get("name")
            if isinstance(name, str) and "${{" in name:
                self.fail(
                    f"{job_path.name}:{job_id} has a templated name: {name!r}; "
                    "cannot tell which check context it reports"
                )
        for check in required_checks():
            producers = [
                (p, j, job)
                for p, j, job in jobs
                if j == check or job.get("name") == check
            ]
            self.assertEqual(
                len(producers),
                1,
                msg=f"{check!r} is produced by {[(p.name, j) for p, j, _ in producers]}",
            )
            path, job_id, job = producers[0]
            self.assertNotIn(
                "name", job, f"{path.name}:{job_id} overrides its name; check {check!r}"
            )
            self.assertNotIn(
                "matrix",
                job.get("strategy") or {},
                f"{path.name}:{job_id} is a matrix job; check {check!r}",
            )

    def test_every_pull_request_job_is_required_or_documented(self):
        required = set(required_checks())
        documented = documented_job_ids()
        for path, job_id, _job in pull_request_jobs():
            self.assertTrue(
                job_id in required or job_id in documented,
                msg=(
                    f"{path.name}:{job_id} runs on pull requests but is neither "
                    f"required in fleet.yml nor named in backticks under "
                    f"AGENTS.md's {SECTION_HEADING!r}"
                ),
            )


if __name__ == "__main__":
    unittest.main()
