"""Each workflow's `pip install` installs only the requirements file allowed it.

The workflows used to run an unpinned `pip install pyyaml`, so each run took
whatever PyYAML was newest. requirements.txt is now the one place a version is
written (requirements-dev.txt adds the test-only packages on top); these tests
keep it that way. The split is a secret boundary: repo-settings.yml holds the
App private key and installs requirements.txt alone, so test-only packages
(requirements-dev.txt, installed by tests.yml) never run beside that secret. Same approach as adam-agentskills'
scripts/test_workflow_dependency_pins.py, smaller: that one also covers
composite actions and heredocs, which this repo does not have.

Workflows are parsed with `yaml` and each `run:` body is tokenized as shell, so
a comment or quoted string that merely says "pip install" is not mistaken for a
command. It fails closed: a step this file cannot read, or a pip install that
is not exactly its workflow's allowed file, is a failure rather than a skip.
"""

import re
import shlex
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
WORKFLOWS = sorted(WORKFLOWS_DIR.glob("*.yml"))
REQUIREMENTS_FILES = [
    REPO_ROOT / "requirements.txt",
    REPO_ROOT / "requirements-dev.txt",
]

PIP_NAME = re.compile(r"(?:.*/)?pip(?:\d+(?:\.\d+)?)?$")
SEPARATORS = {"(", ")", ";", "<", ">", "|", "&", "\n", "{", "}"}
COMMAND_LINE_SHELLS = {None, "bash", "sh", "pwsh", "powershell", "cmd"}
# The only pip install each workflow may run. A workflow absent from this map
# that runs pip fails until it is added here on purpose.
ALLOWED_ARGS = {
    "repo-settings.yml": ["-r", "requirements.txt"],
    "tests.yml": ["-r", "requirements-dev.txt"],
}


def _steps(doc):
    for job_id, job in (doc.get("jobs") or {}).items():
        for index, step in enumerate(job.get("steps") or []):
            yield job_id, index, step


def _commands(body):
    lexer = shlex.shlex(body, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    command = []
    for token in lexer:
        if token and set(token) <= SEPARATORS:
            if command:
                yield command
            command = []
        else:
            command.append(token)
    if command:
        yield command


def pip_installs():
    """Return (where, args-after-install) for every pip install, and problems."""
    found, problems = [], []
    for path in WORKFLOWS:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        defaults_shell = ((doc.get("defaults") or {}).get("run") or {}).get("shell")
        for job_id, index, step in _steps(doc):
            body = step.get("run")
            if not isinstance(body, str):
                continue
            where = f"{path.name} job {job_id!r} step {index}"
            shell = step.get("shell", defaults_shell)
            if shell not in COMMAND_LINE_SHELLS:
                if "pip" in body:
                    problems.append(f"{where}: shell {shell!r} body names pip")
                continue
            try:
                commands = list(_commands(body))
            except ValueError as error:
                if "pip" in body:
                    problems.append(f"{where}: cannot tokenize ({error})")
                continue
            for command in commands:
                for i, token in enumerate(command):
                    if PIP_NAME.match(token) or (
                        token == "pip" or token.startswith("-mpip")
                    ):
                        if "install" in command[i + 1 :]:
                            args = command[command.index("install", i) + 1 :]
                            found.append((where, args))
                        break
    return found, problems


class WorkflowDependencyPinTests(unittest.TestCase):
    def test_every_pip_install_installs_only_its_allowed_file(self):
        found, problems = pip_installs()
        self.assertEqual(problems, [], "unreadable pip usage")
        for where, args in found:
            workflow = where.split(" ")[0]
            self.assertIn(
                workflow,
                ALLOWED_ARGS,
                f"{where}: runs pip but is not in ALLOWED_ARGS; add it on purpose",
            )
            self.assertEqual(
                args,
                ALLOWED_ARGS[workflow],
                f"{where}: pip install must be exactly "
                f"`python3 -m pip install {' '.join(ALLOWED_ARGS[workflow])}`, "
                "so every version lives only in the requirements files",
            )

    def test_repo_settings_workflow_never_references_the_dev_requirements(self):
        # The secret boundary: it holds the App private key.
        text = (WORKFLOWS_DIR / "repo-settings.yml").read_text(encoding="utf-8")
        self.assertNotIn("requirements-dev", text)

    def test_the_walk_finds_the_installs_it_guards(self):
        found, _ = pip_installs()
        names = {where.split(" ")[0] for where, _ in found}
        self.assertEqual(names, {"tests.yml", "repo-settings.yml"})

    def test_requirements_files_hold_only_includes_comments_and_exact_pins(self):
        for path in REQUIREMENTS_FILES:
            requirements = []
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.split("#", 1)[0].strip()
                if line:
                    requirements.append(line)
            self.assertTrue(requirements, f"{path.name} names no package")
            for requirement in requirements:
                self.assertRegex(
                    requirement,
                    r"^(-r [A-Za-z0-9._-]+\.txt|[A-Za-z0-9._-]+==[0-9][A-Za-z0-9.]*)$",
                    f"{path.name}: {requirement!r} must be `-r <file>` or pinned with `==`",
                )


if __name__ == "__main__":
    unittest.main()
