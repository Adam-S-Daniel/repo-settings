# Offline tests of the pure config -> ruleset-body logic (no gh/network).
import argparse
import contextlib
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import repo_settings as rs


class BuildRulesetBodyTests(unittest.TestCase):
    def test_default_config_admin_only_bypass(self):
        body = rs.build_ruleset_body({})
        self.assertEqual(
            body["bypass_actors"],
            [{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}],
        )

    def test_admin_bypass_false_yields_empty_bypass_actors(self):
        body = rs.build_ruleset_body({"admin_bypass": False})
        self.assertEqual(body["bypass_actors"], [])

    def test_bypass_actors_entry_coerces_string_id_and_defaults_mode(self):
        body = rs.build_ruleset_body(
            {"bypass_actors": [{"actor_type": "Integration", "actor_id": "123456"}]}
        )
        self.assertIn(
            {"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"},
            body["bypass_actors"],
        )
        self.assertIn(
            {"actor_id": 123456, "actor_type": "Integration", "bypass_mode": "always"},
            body["bypass_actors"],
        )

    def test_explicit_bypass_mode_preserved(self):
        body = rs.build_ruleset_body(
            {
                "bypass_actors": [
                    {
                        "actor_type": "Integration",
                        "actor_id": "123456",
                        "bypass_mode": "pull_request",
                    }
                ]
            }
        )
        self.assertIn(
            {
                "actor_id": 123456,
                "actor_type": "Integration",
                "bypass_mode": "pull_request",
            },
            body["bypass_actors"],
        )

    def test_bypass_actors_entry_duplicating_admin_appears_once(self):
        body = rs.build_ruleset_body(
            {
                "admin_bypass": True,
                "bypass_actors": [
                    {
                        "actor_type": "RepositoryRole",
                        "actor_id": 5,
                        "bypass_mode": "always",
                    }
                ],
            }
        )
        self.assertEqual(
            body["bypass_actors"],
            [{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}],
        )

    def test_invalid_actor_type_raises_system_exit(self):
        with self.assertRaises(SystemExit):
            rs.build_ruleset_body(
                {"bypass_actors": [{"actor_type": "Bogus", "actor_id": 1}]}
            )

    def test_non_mapping_bypass_actor_raises_system_exit(self):
        with self.assertRaises(SystemExit):
            rs.build_ruleset_body({"bypass_actors": ["Integration"]})

    def test_missing_actor_id_raises_system_exit(self):
        with self.assertRaises(SystemExit):
            rs.build_ruleset_body(
                {"bypass_actors": [{"actor_type": "Integration"}]}
            )

    def test_normalize_ruleset_includes_integration_bypass_tuple(self):
        body = rs.build_ruleset_body(
            {"bypass_actors": [{"actor_type": "Integration", "actor_id": "123456"}]}
        )
        norm = rs.normalize_ruleset(body)
        self.assertIn(("Integration", 123456, "always"), norm["bypass"])


class RulesetDocTests(unittest.TestCase):
    def test_admin_only_body_has_no_bypass_actors_key(self):
        body = rs.build_ruleset_body({"name": "default branch protection"})
        doc = rs.ruleset_doc(body)
        self.assertTrue(doc["admin_bypass"])
        self.assertNotIn("bypass_actors", doc)

    def test_admin_plus_integration_body_round_trips_extra_actor(self):
        body = rs.build_ruleset_body(
            {
                "name": "default branch protection",
                "bypass_actors": [{"actor_type": "Integration", "actor_id": "123456"}],
            }
        )
        doc = rs.ruleset_doc(body)
        self.assertTrue(doc["admin_bypass"])
        self.assertEqual(
            doc["bypass_actors"],
            [{"actor_type": "Integration", "actor_id": 123456, "bypass_mode": "always"}],
        )

    def test_round_trip_through_generate_and_apply(self):
        cfg = {
            "name": "default branch protection",
            "bypass_actors": [{"actor_type": "Integration", "actor_id": "123456"}],
        }
        body = rs.build_ruleset_body(cfg)
        doc = rs.ruleset_doc(body)
        round_tripped = rs.build_ruleset_body(doc)
        self.assertEqual(
            rs.normalize_ruleset(round_tripped), rs.normalize_ruleset(body)
        )


class FaultIsolationTests(unittest.TestCase):
    def test_plan_repo_records_isolates_gh_error(self):
        with patch.object(rs, "plan_repo", side_effect=rs.GhError(404, "Not Found")):
            records = rs.plan_repo_records("o/r", {})
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["status"], "error")
        self.assertIn("Not Found", records[0]["note"])

    def test_cmd_diff_continues_past_failing_repo(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yml", delete=False
        ) as fh:
            fh.write("repos:\n  - name: o/repo1\n  - name: o/repo2\n")
            config_path = fh.name
        self.addCleanup(os.remove, config_path)
        ns = argparse.Namespace(config=config_path, repo=None, owner=None)
        with patch.object(
            rs, "plan_repo", side_effect=[rs.GhError(404, "Not Found"), []]
        ) as mock_plan:
            with contextlib.redirect_stdout(io.StringIO()):
                result = rs.cmd_diff(ns)
        self.assertEqual(result, 2)
        self.assertEqual(mock_plan.call_count, 2)


if __name__ == "__main__":
    unittest.main()
