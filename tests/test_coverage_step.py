"""The coverage step must record its exit code even under `bash -e`.

GitHub runs `run:` steps as `bash -e {0}`, so a bare `cmd; rc=$?` dies on the
line of `cmd` when it exits nonzero: rc is never written, the report is never
printed, and the nudge step concludes "could not enumerate". This runs the
step's real script, taken from the parsed workflow, against a stub `python`.
The step covers every owner in `$OWNERS`, each with its own token
(`TOKEN_<KEY>`) and its own output (`rc_<KEY>`), where KEY is the owner
uppercased with `-` as `_` (issue #116 moved it into the unmatrixed plan job).
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parent.parent / ".github/workflows/repo-settings.yml"


def coverage_script():
    # PyYAML loads the `on:` key as True, so read only `jobs`.
    for job in yaml.safe_load(WORKFLOW.read_text())["jobs"].values():
        for step in job.get("steps", []):
            if step.get("id") == "coverage":
                return step["run"]
    raise AssertionError("no step with id: coverage")


class CoverageStepTest(unittest.TestCase):
    def run_with_exit(self, code):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            stub = tmp / "python"
            stub.write_text(
                f'#!/bin/sh\necho "stub report {code} token=$GH_TOKEN"\nexit {code}\n')
            stub.chmod(0o755)
            out = tmp / "github_output"
            out.touch()
            env = {
                "PATH": f"{tmp}:{os.environ['PATH']}",
                "GITHUB_OUTPUT": str(out),
                "OWNERS": "example other-owner",
                "TOKEN_EXAMPLE": "token-one",
                "TOKEN_OTHER_OWNER": "token-two",
            }
            proc = subprocess.run(
                ["bash", "-e", "-c", coverage_script()],
                cwd=tmp, env=env, capture_output=True, text=True, timeout=30,
            )
            return proc, out.read_text()

    def test_records_rc_and_prints_report_for_each_exit_code(self):
        for code in (0, 1, 2):
            with self.subTest(code=code):
                proc, output = self.run_with_exit(code)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(output.splitlines(),
                                 [f"rc_EXAMPLE={code}", f"rc_OTHER_OWNER={code}"])
                self.assertIn(f"stub report {code} token=token-one", proc.stdout)
                self.assertIn(f"stub report {code} token=token-two", proc.stdout)


if __name__ == "__main__":
    unittest.main()
