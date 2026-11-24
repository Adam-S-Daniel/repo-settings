"""The `secrets` surface (issue #231): the plan, the apply and the setter script.

Offline: gh is mocked at the `gh_api` / `subprocess.run` seams, so no test
touches the network, and none sends a signal. The fake secret below is invented.
"""
import argparse
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import repo_settings as rs
import set_privacy_denylist as sp

REPO = "o/r"
NAME = "PRIVACY_DENYLIST"
SOURCE_TS = "2026-11-20T12:00:00+00:00"
# Invented patterns, two lines, to prove neither the whole nor a line leaks.
VALUE = "example-host-alpha\nexample-person-beta"
SETTINGS = {"secrets": [{"name": NAME}]}


def _plan(live, *, source=SOURCE_TS, repo=None, gh_error=None):
    env = {rs.secret_updated_env(NAME): source} if source else {}
    repo_doc = {"private": False, "archived": False}
    repo_doc.update(repo or {})
    with patch.dict(os.environ, env, clear=False), \
            patch.object(rs, "read_repo_secret", side_effect=gh_error,
                         return_value=live), \
            patch.object(rs, "get_repo", return_value=repo_doc):
        if not source:
            os.environ.pop(rs.secret_updated_env(NAME), None)
        return rs.plan_repo(REPO, SETTINGS)


class SecretSpecTests(unittest.TestCase):
    def test_only_allowlisted_names(self):
        with self.assertRaises(SystemExit) as cm:
            rs.build_secret_specs({"secrets": [{"name": "REPO_SETTINGS_APP_PRIVATE_KEY"}]})
        self.assertIn("must be one of PRIVACY_DENYLIST", str(cm.exception.code))

    def test_duplicates_and_shapes_are_refused(self):
        for bad in ({"secrets": [{"name": NAME}, {"name": NAME}]},
                    {"secrets": "x"}, {"secrets": ["x"]}):
            with self.subTest(bad=bad), self.assertRaises(SystemExit):
                rs.build_secret_specs(bad)

    def test_unknown_key_in_an_entry_is_refused(self):
        cfg = {"repo": REPO, "secrets": [{"name": NAME, "value": "x"}]}
        with self.assertRaises(rs.ConfigError):
            rs.resolve_targets(cfg, None)

    def test_defaults_reach_a_managing_repo_and_not_a_labels_only_one(self):
        cfg = {"defaults": {"secrets": [{"name": NAME}]},
               "repos": [{"name": "o/a", "manage": ["all"]},
                         {"name": "o/b", "manage": ["labels"]},
                         {"name": "o/c", "manage": []}]}
        a, b, c = rs.resolve_targets(cfg, None)
        self.assertEqual(a["effective"]["secrets"], [{"name": NAME}])
        self.assertNotIn("secrets", b["effective"])
        self.assertNotIn("secrets", c["effective"])

    def test_fleet_yml_declares_it_for_every_repo(self):
        cfg = rs.load_config(str(Path(__file__).resolve().parent.parent
                                 / "repo-settings" / "fleet.yml"))
        self.assertEqual(cfg["defaults"]["secrets"], [{"name": NAME}])


class SecretPlanTests(unittest.TestCase):
    def test_missing_secret_is_drift_with_a_writer(self):
        (rec,) = _plan(None)
        self.assertEqual((rec["setting"], rec["status"]), (f"secret[{NAME}]", "drift"))
        self.assertEqual(rec["current"], {"present": False, "updated_at": None})
        self.assertEqual(rec["_writer"], ("secret", NAME, SOURCE_TS))

    def test_stale_secret_is_drift(self):
        (rec,) = _plan({"name": NAME, "updated_at": "2026-11-19T12:00:00Z"})
        self.assertEqual(rec["status"], "drift")
        self.assertEqual(rec["note"], "older than the source")

    def test_current_secret_matches_and_has_no_writer(self):
        for stamp in ("2026-11-20T12:00:00Z", "2026-11-21T00:00:00Z"):
            with self.subTest(stamp=stamp):
                (rec,) = _plan({"name": NAME, "updated_at": stamp})
                self.assertEqual(rec["status"], "match")
                self.assertNotIn("_writer", rec)

    def test_no_source_timestamp_leaves_a_present_secret_alone_and_fills_a_missing_one(self):
        (rec,) = _plan({"name": NAME, "updated_at": "2020-01-01T00:00:00Z"}, source=None)
        self.assertEqual(rec["status"], "match")
        (rec,) = _plan(None, source=None)
        self.assertEqual(rec["status"], "drift")
        self.assertIsNone(rec["desired"]["updated_at_not_before"])

    def test_a_present_secret_without_a_readable_age_is_refreshed(self):
        (rec,) = _plan({"name": NAME})
        self.assertEqual(rec["status"], "drift")

    def test_a_malformed_source_timestamp_is_an_error_not_drift(self):
        for bad in ("yesterday", "2026-11-20T12:00:00"):  # second has no offset
            with self.subTest(bad=bad):
                (rec,) = _plan(None, source=bad)
                self.assertEqual(rec["status"], "error")
                self.assertIn("UTC offset", rec["note"])

    def test_an_unreadable_secret_is_an_error_record(self):
        (rec,) = _plan(None, gh_error=rs.GhError(403, "Resource not accessible"))
        self.assertEqual(rec["status"], "error")

    def test_a_404_is_probed_against_the_repo(self):
        with patch.object(rs, "read_repo_secret", return_value=None), \
                patch.object(rs, "get_repo",
                             side_effect=rs.GhError(404, "Not Found")) as get_repo:
            (rec,) = rs.plan_repo(REPO, SETTINGS)
        self.assertEqual(rec["status"], "error")
        get_repo.assert_called()

    def test_an_archived_repo_is_skipped(self):
        (rec,) = _plan(None, repo={"archived": True})
        self.assertEqual(rec["status"], "skipped")

    def test_read_uses_the_metadata_endpoint(self):
        with patch.object(rs, "gh_api", return_value={"name": NAME}) as api:
            rs.read_repo_secret(REPO, NAME)
        api.assert_called_once_with("repos/o/r/actions/secrets/PRIVACY_DENYLIST")

    def test_read_maps_404_to_none_and_reraises_the_rest(self):
        with patch.object(rs, "gh_api", side_effect=rs.GhError(404, "x")):
            self.assertIsNone(rs.read_repo_secret(REPO, NAME))
        with patch.object(rs, "gh_api", side_effect=rs.GhError(500, "x")), \
                self.assertRaises(rs.GhError):
            rs.read_repo_secret(REPO, NAME)


class SecretWriteTests(unittest.TestCase):
    def _run(self, returncode=0, stderr=""):
        done = subprocess.CompletedProcess([], returncode, stdout="", stderr=stderr)
        return patch.object(rs.subprocess, "run", return_value=done)

    def test_value_goes_on_stdin_never_argv(self):
        with patch.dict(os.environ, {NAME: VALUE}), self._run() as run:
            rs.write_repo_secret(REPO, NAME)
        (argv,), kwargs = run.call_args
        self.assertEqual(argv, ["gh", "secret", "set", NAME, "--repo", REPO, "--app", "actions"])
        self.assertEqual(kwargs["input"], VALUE)
        self.assertNotIn("example-host-alpha", " ".join(argv))

    def test_missing_value_is_an_error_that_does_not_call_gh(self):
        with patch.dict(os.environ, {}, clear=False), self._run() as run:
            os.environ.pop(NAME, None)
            with self.assertRaises(rs.GhError):
                rs.write_repo_secret(REPO, NAME)
        run.assert_not_called()

    def test_failure_message_is_redacted(self):
        leak = f"HTTP 422: bad value {VALUE!r} and example-person-beta"
        with patch.dict(os.environ, {NAME: VALUE}), self._run(1, leak):
            with self.assertRaises(rs.GhError) as cm:
                rs.write_repo_secret(REPO, NAME)
        self.assertNotIn("example-host-alpha", cm.exception.message)
        self.assertNotIn("example-person-beta", cm.exception.message)
        self.assertEqual(cm.exception.status, 422)

    def test_apply_record_dispatches_the_secret_writer(self):
        with patch.object(rs, "write_repo_secret") as write:
            rs.apply_record(REPO, {"_writer": ("secret", NAME, SOURCE_TS)})
        write.assert_called_once_with(REPO, NAME)


class SecretRiskTests(unittest.TestCase):
    def test_an_allowlisted_secret_write_is_safe_and_anything_else_waits(self):
        def rec(name):
            return {"setting": f"secret[{name}]", "status": "drift", "current": {},
                    "desired": {}, "_writer": ("secret", name, None)}
        self.assertEqual(rs.write_risk(rec(NAME), [rec(NAME)])[0], rs.SAFE)
        self.assertEqual(rs.write_risk(rec("OTHER"), [rec("OTHER")])[0], rs.GATED)


class NoValueReachesOutputTests(unittest.TestCase):
    """diff and apply, end to end over the mocked seams: the value and every
    pattern line in it stay out of stdout, stderr and the changes file."""

    def _config(self):
        fh = tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False, encoding="utf-8")
        fh.write("defaults:\n  secrets:\n    - name: PRIVACY_DENYLIST\n"
                 "repos:\n  - name: o/r\n    manage: [secrets]\n")
        fh.close()
        self.addCleanup(os.remove, fh.name)
        return fh.name

    def test_diff_and_apply_print_no_value_or_pattern(self):
        path = self._config()
        out, err = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            changes, result = Path(tmp, "c.json"), Path(tmp, "r.json")
            env = {NAME: VALUE, rs.secret_updated_env(NAME): SOURCE_TS}
            done = subprocess.CompletedProcess([], 1, stdout="",
                                               stderr=f"HTTP 500 {VALUE}")
            with patch.dict(os.environ, env), \
                    patch.object(rs, "read_repo_secret", return_value=None), \
                    patch.object(rs, "get_repo",
                                 return_value={"private": False, "archived": False}), \
                    patch.object(rs.subprocess, "run", return_value=done), \
                    contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc_diff = rs.cmd_diff(argparse.Namespace(
                    config=path, repo=None, owner=None, changes_json=str(changes)))
                rc_apply = rs.cmd_apply(argparse.Namespace(
                    config=path, repo=None, owner=None, dry_run=False,
                    cms_label_only=None, refuse_weakening=True, result_json=str(result)))
            changes_text, result_text = changes.read_text(), result.read_text()
            files = changes_text + result_text
            json.loads(changes_text)
            json.loads(result_text)
        self.assertEqual(rc_diff, 1)
        # The write failed (gh exited 1), which is an error, not a silent pass.
        self.assertEqual(rc_apply, 2)
        everything = out.getvalue() + err.getvalue() + files
        self.assertIn("secret[PRIVACY_DENYLIST]", everything)
        for needle in ("example-host-alpha", "example-person-beta"):
            self.assertNotIn(needle, everything)
        self.assertIn("[redacted]", everything)


class SetterScriptTests(unittest.TestCase):
    def test_refuses_a_file_inside_a_git_work_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(["git", "init", "-q", tmp], check=True)
            path = Path(tmp, "denylist.txt")
            path.write_text(VALUE, encoding="utf-8")
            with self.assertRaises(sp.SetError) as cm:
                sp.read_source(path, io.StringIO())
        self.assertIn("inside a git work tree", str(cm.exception))
        self.assertNotIn("example-host-alpha", str(cm.exception))

    def test_reads_a_file_outside_any_work_tree_and_stdin(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "denylist.txt")
            path.write_text(VALUE, encoding="utf-8")
            with patch.object(sp, "inside_git_work_tree", return_value=False):
                self.assertEqual(sp.read_source(path, io.StringIO()), VALUE)
        self.assertEqual(sp.read_source(None, io.StringIO(VALUE)), VALUE)

    def test_empty_value_is_refused(self):
        with self.assertRaises(sp.SetError):
            sp.read_source(None, io.StringIO("  \n"))

    def test_store_sets_each_environment_then_the_timestamp(self):
        calls = []

        def fake(argv, input=None, capture_output=None, text=None):
            calls.append((argv, input))
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        now = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)
        with patch.object(sp.subprocess, "run", side_effect=fake):
            stamp = sp.store(VALUE, "o/repo", ("e1", "e2"), now=now)
        self.assertEqual(stamp, "2026-11-20T12:00:00+00:00")
        self.assertEqual(
            [c[0] for c in calls],
            [["gh", "secret", "set", NAME, "--repo", "o/repo", "--env", "e1"],
             ["gh", "secret", "set", NAME, "--repo", "o/repo", "--env", "e2"],
             ["gh", "variable", "set", "PRIVACY_DENYLIST_UPDATED_AT", "--repo", "o/repo",
              "--body", stamp]],
        )
        self.assertEqual([c[1] for c in calls], [VALUE, VALUE, None])
        self.assertTrue(all("example-host-alpha" not in " ".join(c[0]) for c in calls))

    def test_main_prints_no_value_even_when_gh_fails(self):
        done = subprocess.CompletedProcess([], 1, stdout="", stderr=f"boom {VALUE}")
        out, err = io.StringIO(), io.StringIO()
        with patch.object(sp.subprocess, "run", return_value=done), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = sp.main([], stdin=io.StringIO(VALUE))
        self.assertEqual(rc, 1)
        shown = out.getvalue() + err.getvalue()
        self.assertNotIn("example-host-alpha", shown)
        self.assertNotIn("example-person-beta", shown)

    def test_main_success_prints_names_and_a_timestamp_only(self):
        done = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        out = io.StringIO()
        with patch.object(sp.subprocess, "run", return_value=done), \
                contextlib.redirect_stdout(out):
            rc = sp.main([], stdin=io.StringIO(VALUE))
        self.assertEqual(rc, 0)
        self.assertIn("fleet-apply, fleet-apply-auto", out.getvalue())
        self.assertNotIn("example-host-alpha", out.getvalue())


if __name__ == "__main__":
    unittest.main()
