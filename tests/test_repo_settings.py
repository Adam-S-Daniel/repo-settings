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


class AllowAutoMergeTests(unittest.TestCase):
    def test_drift_when_desired_true_and_live_false(self):
        with patch.object(rs, "get_repo", return_value={"private": False, "allow_auto_merge": False}):
            records = rs.plan_repo("o/r", {"repo": {"allow_auto_merge": True}})
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertEqual(rec["setting"], "repo.allow_auto_merge")
        self.assertEqual(rec["status"], "drift")
        self.assertEqual(rec["current"], False)
        self.assertEqual(rec["desired"], True)

    def test_match_when_desired_true_and_live_true(self):
        with patch.object(rs, "get_repo", return_value={"private": False, "allow_auto_merge": True}):
            records = rs.plan_repo("o/r", {"repo": {"allow_auto_merge": True}})
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["status"], "match")

    def test_omitted_key_is_unmanaged(self):
        with patch.object(rs, "get_repo") as mock_get_repo:
            records = rs.plan_repo("o/r", {"repo": {}})
            records_no_block = rs.plan_repo("o/r", {})
        self.assertEqual(records, [])
        self.assertEqual(records_no_block, [])
        mock_get_repo.assert_not_called()

    def test_explicit_null_is_unmanaged(self):
        with patch.object(rs, "get_repo") as mock_get_repo:
            records = rs.plan_repo("o/r", {"repo": {"allow_auto_merge": None}})
        self.assertEqual(records, [])
        mock_get_repo.assert_not_called()

    def test_absent_field_is_skipped_not_a_crash(self):
        # A KeyError here would escape both this block's `except GhError` and
        # plan_repo_records' GhError-only guard, turning one repo's odd payload
        # into a fleet-wide abort.
        with patch.object(rs, "get_repo", return_value={"private": False, "name": "r"}):
            records = rs.plan_repo("o/r", {"repo": {"allow_auto_merge": True}})
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertEqual(rec["setting"], "repo.allow_auto_merge")
        self.assertEqual(rec["status"], "skipped")
        self.assertIn("allow_auto_merge", rec["note"])

    def test_absent_field_does_not_abort_fleet_run(self):
        with patch.object(rs, "get_repo", return_value={"private": False, "name": "r"}):
            records = rs.plan_repo_records("o/r", {"repo": {"allow_auto_merge": True}})
        self.assertEqual([r["status"] for r in records], ["skipped"])

    def test_read_failure_isolated_into_error_record(self):
        # is_private() reads the repo before the allow_auto_merge block's own
        # try/except, so a read failure propagates out of plan_repo -- exactly
        # as it already did for fork_pr_approval. plan_repo_records is the
        # isolation boundary, and that is what must not let one repo's failure
        # abort the fleet run.
        with patch.object(rs, "get_repo", side_effect=rs.GhError(500, "boom")):
            records = rs.plan_repo_records("o/r", {"repo": {"allow_auto_merge": True}})
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertEqual(rec["status"], "error")
        self.assertIn("boom", rec["note"])

    def test_private_repo_is_skipped_not_applied(self):
        # Auto-merge is Pro/Team/Enterprise-only on private repos; below that
        # the PATCH returns 200 and is silently ignored. Measured 2026-08-11:
        # four private repos reported CHANGED -> True and read back False,
        # while a public repo in the same run stuck. Without this skip they
        # drift forever and the PR drift check can never go green.
        with patch.object(rs, "get_repo", return_value={"private": True,
                                                        "allow_auto_merge": False}):
            records = rs.plan_repo("o/r", {"repo": {"allow_auto_merge": True}})
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertEqual(rec["setting"], "repo.allow_auto_merge")
        self.assertEqual(rec["status"], "skipped")
        self.assertIn("Pro", rec["note"])
        # and crucially it must carry no writer, so apply can never issue the
        # PATCH that would report a false CHANGED
        self.assertNotIn("_writer", rec)

    def test_private_repo_skip_survives_a_true_live_value(self):
        # Belt and braces: even if a private repo somehow already reads True,
        # the setting stays unmanaged rather than flipping to "match" -- we
        # cannot manage what the plan will not honour.
        with patch.object(rs, "get_repo", return_value={"private": True,
                                                        "allow_auto_merge": True}):
            records = rs.plan_repo("o/r", {"repo": {"allow_auto_merge": True}})
        self.assertEqual([r["status"] for r in records], ["skipped"])

    def test_apply_record_writes_via_gh_api_patch(self):
        with patch.object(rs, "get_repo", return_value={"private": False, "allow_auto_merge": False}):
            records = rs.plan_repo("o/r", {"repo": {"allow_auto_merge": True}})
        self.assertEqual(records[0]["status"], "drift")
        with patch.object(rs, "gh_api") as mock_gh_api:
            rs.apply_record("o/r", records[0])
        mock_gh_api.assert_called_once_with(
            "repos/o/r", method="PATCH", body={"allow_auto_merge": True}
        )


class RulesetMergeMethodTests(unittest.TestCase):
    MERGE_ONLY_CFG = {
        "enabled": True,
        "name": "default branch protection",
        "require_pull_request": {
            "required_approving_review_count": 0,
            "allowed_merge_methods": ["merge"],
        },
    }

    def _pr_params(self, body):
        return next(r["parameters"] for r in body["rules"] if r["type"] == "pull_request")

    def test_default_is_still_all_three(self):
        # An existing config that never mentioned merge methods must render
        # exactly the ruleset it rendered before.
        body = rs.build_ruleset_body(
            {"enabled": True, "name": "n", "require_pull_request": {}}
        )
        self.assertEqual(
            self._pr_params(body)["allowed_merge_methods"],
            ["merge", "squash", "rebase"],
        )

    def test_config_narrows_the_ruleset(self):
        body = rs.build_ruleset_body(dict(self.MERGE_ONLY_CFG))
        self.assertEqual(self._pr_params(body)["allowed_merge_methods"], ["merge"])

    def test_merge_methods_are_drift_compared(self):
        # Absent from normalize_ruleset, a UI edit adding squash back produced
        # no drift and nothing ever said so.
        merge_only = rs.build_ruleset_body(dict(self.MERGE_ONLY_CFG))
        widened = rs.build_ruleset_body(
            {**self.MERGE_ONLY_CFG,
             "require_pull_request": {"required_approving_review_count": 0,
                                      "allowed_merge_methods": ["merge", "squash"]}}
        )
        self.assertNotEqual(
            rs.normalize_ruleset(merge_only), rs.normalize_ruleset(widened)
        )

    def test_order_alone_is_not_drift(self):
        a = rs.build_ruleset_body(
            {**self.MERGE_ONLY_CFG,
             "require_pull_request": {"required_approving_review_count": 0,
                                      "allowed_merge_methods": ["merge", "squash"]}}
        )
        b = rs.build_ruleset_body(
            {**self.MERGE_ONLY_CFG,
             "require_pull_request": {"required_approving_review_count": 0,
                                      "allowed_merge_methods": ["squash", "merge"]}}
        )
        self.assertEqual(rs.normalize_ruleset(a), rs.normalize_ruleset(b))

    def test_a_narrowed_ruleset_round_trips_through_generate(self):
        # Without ruleset_doc carrying the list, `generate` on a merge-only repo
        # emitted a config that rebuilt into an all-three ruleset -- silently
        # widening it back on the next apply.
        body = rs.build_ruleset_body(dict(self.MERGE_ONLY_CFG))
        round_tripped = rs.build_ruleset_body(rs.ruleset_doc(body))
        self.assertEqual(
            rs.normalize_ruleset(round_tripped), rs.normalize_ruleset(body)
        )
        self.assertEqual(
            self._pr_params(round_tripped)["allowed_merge_methods"], ["merge"]
        )


class MergeMethodTests(unittest.TestCase):
    LIVE_ALL_ON = {
        "private": False,
        "allow_merge_commit": True,
        "allow_squash_merge": True,
        "allow_rebase_merge": True,
    }
    MERGE_ONLY = {
        "allow_merge_commit": True,
        "allow_squash_merge": False,
        "allow_rebase_merge": False,
    }

    def test_drift_is_reported_per_toggle(self):
        with patch.object(rs, "get_repo", return_value=dict(self.LIVE_ALL_ON)):
            records = rs.plan_repo("o/r", {"repo": dict(self.MERGE_ONLY)})
        by_setting = {r["setting"]: r for r in records}
        self.assertEqual(by_setting["repo.allow_merge_commit"]["status"], "match")
        self.assertEqual(by_setting["repo.allow_squash_merge"]["status"], "drift")
        self.assertEqual(by_setting["repo.allow_rebase_merge"]["status"], "drift")

    def test_match_when_already_merge_only(self):
        live = {"private": False, **self.MERGE_ONLY}
        with patch.object(rs, "get_repo", return_value=live):
            records = rs.plan_repo("o/r", {"repo": dict(self.MERGE_ONLY)})
        self.assertEqual({r["status"] for r in records}, {"match"})

    def test_omitted_keys_are_unmanaged(self):
        with patch.object(rs, "get_repo") as mock_get_repo:
            records = rs.plan_repo("o/r", {"repo": {}})
        self.assertEqual(records, [])
        mock_get_repo.assert_not_called()

    def test_explicit_null_is_unmanaged(self):
        with patch.object(rs, "get_repo") as mock_get_repo:
            records = rs.plan_repo("o/r", {"repo": {"allow_squash_merge": None}})
        self.assertEqual(records, [])
        mock_get_repo.assert_not_called()

    def test_private_repos_are_managed_too(self):
        # Unlike allow_auto_merge, these are not plan-gated -- a private repo
        # honours them, so skipping it would leave the fleet's private repos
        # silently unmanaged.
        live = {"private": True, "allow_merge_commit": True,
                "allow_squash_merge": True, "allow_rebase_merge": True}
        with patch.object(rs, "get_repo", return_value=live):
            records = rs.plan_repo("o/r", {"repo": dict(self.MERGE_ONLY)})
        self.assertIn("drift", {r["status"] for r in records})

    def test_absent_field_is_skipped_not_a_crash(self):
        with patch.object(rs, "get_repo", return_value={"private": False, "name": "r"}):
            records = rs.plan_repo("o/r", {"repo": dict(self.MERGE_ONLY)})
        self.assertEqual({r["status"] for r in records}, {"skipped"})
        self.assertIn("allow_squash_merge",
                      [r["note"] for r in records if "squash" in r["setting"]][0])

    def test_read_failure_isolated_into_error_records(self):
        with patch.object(rs, "get_repo", side_effect=rs.GhError(500, "boom")):
            records = rs.plan_repo_records("o/r", {"repo": dict(self.MERGE_ONLY)})
        self.assertEqual({r["status"] for r in records}, {"error"})

    def test_disabling_every_method_is_refused_rather_than_applied(self):
        # GitHub 422s a repo with no merge method at all. Refusing here means a
        # human reading the config finds out, rather than every repo in the
        # fleet failing its apply.
        allnone = {key: False for key in rs.MERGE_METHOD_KEYS}
        with patch.object(rs, "get_repo") as mock_get_repo:
            records = rs.plan_repo("o/r", {"repo": allnone})
        self.assertEqual({r["status"] for r in records}, {"skipped"})
        self.assertTrue(all("at least one" in r["note"] for r in records))
        for rec in records:
            self.assertNotIn("_writer", rec)
        mock_get_repo.assert_not_called()

    def test_apply_patches_the_whole_group_in_one_call(self):
        # One call, not one per toggle: a per-toggle apply passes through the
        # zero-methods state GitHub rejects whenever a run both enables one and
        # disables another.
        with patch.object(rs, "get_repo", return_value=dict(self.LIVE_ALL_ON)):
            records = rs.plan_repo("o/r", {"repo": dict(self.MERGE_ONLY)})
        drifted = [r for r in records if r["status"] == "drift"]
        with patch.object(rs, "gh_api") as mock_gh_api:
            rs.apply_record("o/r", drifted[0])
        mock_gh_api.assert_called_once_with(
            "repos/o/r", method="PATCH", body=dict(self.MERGE_ONLY)
        )

    def test_every_record_in_the_group_carries_the_whole_group(self):
        # Whichever record apply happens to reach first must produce the same
        # complete PATCH, or the repo lands in a partial state.
        with patch.object(rs, "get_repo", return_value=dict(self.LIVE_ALL_ON)):
            records = rs.plan_repo("o/r", {"repo": dict(self.MERGE_ONLY)})
        writers = [r["_writer"][2] for r in records]
        self.assertEqual(writers, [dict(self.MERGE_ONLY)] * len(records))

    def test_a_partial_group_only_patches_what_the_config_names(self):
        # Managing one toggle must not silently assert a value for the others.
        with patch.object(rs, "get_repo", return_value=dict(self.LIVE_ALL_ON)):
            records = rs.plan_repo("o/r", {"repo": {"allow_squash_merge": False}})
        self.assertEqual(len(records), 1)
        with patch.object(rs, "gh_api") as mock_gh_api:
            rs.apply_record("o/r", records[0])
        mock_gh_api.assert_called_once_with(
            "repos/o/r", method="PATCH", body={"allow_squash_merge": False}
        )


class SingleRepoRepoBlockTests(unittest.TestCase):
    def test_string_identifier_still_works_unmanaged(self):
        cfg = {"repo": "o/r", "actions": {"sha_pinning_required": True}}
        targets = rs.resolve_targets(cfg, None)
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["repo"], "o/r")
        self.assertNotIn("repo", targets[0]["settings"])

    def test_repo_mapping_requires_repo_arg_for_identifier(self):
        cfg = {"repo": {"allow_auto_merge": True}}
        targets = rs.resolve_targets(cfg, "o/r")
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["repo"], "o/r")
        self.assertEqual(targets[0]["settings"]["repo"], {"allow_auto_merge": True})

    def test_repo_mapping_without_repo_arg_raises(self):
        cfg = {"repo": {"allow_auto_merge": True}}
        with self.assertRaises(SystemExit):
            rs.resolve_targets(cfg, None)


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
