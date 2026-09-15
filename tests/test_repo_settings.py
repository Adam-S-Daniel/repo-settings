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
import argparse
import contextlib
import io

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


class DeleteBranchOnMergeTests(unittest.TestCase):
    """"Automatically delete head branches" — the fleet-wide backstop that keeps
    fixed-branch-name bots working.

    A bot proposing from a fixed branch refuses to force-push a branch of that
    name whose content it did not write. Correct — but it cannot tell a
    reviewer's commit from the residue of a PR that merged and was never
    deleted, so the second case disables the bot for that repo permanently with
    nothing going red. Measured 2026-08-25: five of ten lock-carrying repos,
    stuck since 2026-08-21.
    """

    def test_drift_when_desired_true_and_live_false(self):
        with patch.object(rs, "get_repo",
                          return_value={"private": False, "delete_branch_on_merge": False}):
            records = rs.plan_repo("o/r", {"repo": {"delete_branch_on_merge": True}})
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertEqual(rec["setting"], "repo.delete_branch_on_merge")
        self.assertEqual(rec["status"], "drift")
        self.assertEqual(rec["current"], False)
        self.assertEqual(rec["desired"], True)

    def test_match_when_desired_true_and_live_true(self):
        with patch.object(rs, "get_repo",
                          return_value={"private": False, "delete_branch_on_merge": True}):
            records = rs.plan_repo("o/r", {"repo": {"delete_branch_on_merge": True}})
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["status"], "match")

    def test_private_repo_is_managed_not_skipped(self):
        """The distinction from allow_auto_merge, and the reason this has no
        private gate: GitHub honours this one on every plan. Skipping private
        repos here would leave exactly the repos that went stale unmanaged —
        four of the five measured were private."""
        with patch.object(rs, "get_repo",
                          return_value={"private": True, "delete_branch_on_merge": False}):
            records = rs.plan_repo("o/r", {"repo": {"delete_branch_on_merge": True}})
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["status"], "drift")

    def test_omitted_key_is_unmanaged(self):
        with patch.object(rs, "get_repo") as mock_get_repo:
            records = rs.plan_repo("o/r", {"repo": {}})
        self.assertEqual(records, [])
        mock_get_repo.assert_not_called()

    def test_explicit_null_is_unmanaged(self):
        with patch.object(rs, "get_repo") as mock_get_repo:
            records = rs.plan_repo("o/r", {"repo": {"delete_branch_on_merge": None}})
        self.assertEqual(records, [])
        mock_get_repo.assert_not_called()

    def test_absent_field_is_skipped_not_a_crash(self):
        """This is one of the MERGE-SETTING fields GitHub withholds from a
        low-scope token — absent, not false. A subscript would KeyError past
        plan_repo_records' GhError-only guard and abort the fleet run."""
        with patch.object(rs, "get_repo", return_value={"private": False, "name": "r"}):
            records = rs.plan_repo("o/r", {"repo": {"delete_branch_on_merge": True}})
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertEqual(rec["setting"], "repo.delete_branch_on_merge")
        self.assertEqual(rec["status"], "skipped")
        self.assertIn("delete_branch_on_merge", rec["note"])

    def test_absent_field_does_not_abort_fleet_run(self):
        with patch.object(rs, "get_repo", return_value={"private": False, "name": "r"}):
            records = rs.plan_repo_records("o/r", {"repo": {"delete_branch_on_merge": True}})
        self.assertEqual([r["status"] for r in records], ["skipped"])

    def test_read_failure_isolated_into_error_record(self):
        with patch.object(rs, "get_repo", side_effect=rs.GhError(500, "boom")):
            records = rs.plan_repo_records("o/r", {"repo": {"delete_branch_on_merge": True}})
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["status"], "error")

    def test_apply_patches_the_repo(self):
        """The writer is reachable from the record the planner emits — a plan
        whose _writer nothing dispatches is drift that never converges."""
        with patch.object(rs, "get_repo",
                          return_value={"private": False, "delete_branch_on_merge": False}):
            rec = rs.plan_repo("o/r", {"repo": {"delete_branch_on_merge": True}})[0]
        with patch.object(rs, "gh_api") as mock_api:
            rs.apply_record("o/r", rec)
        mock_api.assert_called_once_with(
            "repos/o/r", method="PATCH", body={"delete_branch_on_merge": True})


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


class RulesetUnattributedApprovalTests(unittest.TestCase):
    """`require_extra_approval_for_unattributed_changes`.

    The parameter that blocked the nightly Dependabot sweep fleet-wide
    (skills-evals run 32342667620, 2026-08-20: three PRs mergeable with green
    checks, `merged=0 updated=0 skipped=0 failed=3`). It is INDEPENDENT of
    `required_approving_review_count` -- 0 approvals required and still an
    approval demanded, because Dependabot's commits are unattributed.

    The discriminator is attributed-vs-unattributed AUTHORSHIP, not the
    presence of a required status check: agentskills has one
    (`pytest-windows`) and measured this parameter true anyway.
    """

    KEY = "require_extra_approval_for_unattributed_changes"

    # Verbatim shape of the live `pull_request` rule parameters, as returned by
    # GET repos/Adam-S-Daniel/skills-evals/rules/branches/main on 2026-08-20.
    LIVE_PR_PARAMS = {
        "required_approving_review_count": 0,
        "dismiss_stale_reviews_on_push": False,
        "required_reviewers": [],
        "require_code_owner_review": False,
        "require_last_push_approval": False,
        "required_review_thread_resolution": False,
        "require_extra_approval_for_unattributed_changes": True,
        "allowed_merge_methods": ["merge"],
    }

    OFF_CFG = {
        "enabled": True,
        "name": "default branch protection",
        "require_pull_request": {
            "required_approving_review_count": 0,
            "allowed_merge_methods": ["merge"],
            "require_extra_approval_for_unattributed_changes": False,
        },
    }

    def _pr_params(self, body):
        return next(
            r["parameters"] for r in body["rules"] if r["type"] == "pull_request"
        )

    def _live(self, params):
        return {
            "enforcement": "active",
            "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
            "rules": [
                {"type": "deletion"},
                {"type": "non_fast_forward"},
                {"type": "pull_request", "parameters": params},
            ],
            "bypass_actors": [
                {"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}
            ],
        }

    def test_body_always_states_the_key(self):
        # write_ruleset PUTs the whole body, so a key that is only sometimes
        # emitted is a key GitHub re-defaults to true on the next apply.
        body = rs.build_ruleset_body(
            {"enabled": True, "name": "n", "require_pull_request": {}}
        )
        self.assertIn(self.KEY, self._pr_params(body))

    def test_default_is_githubs_default_true(self):
        # A config that never mentioned the key must render exactly the ruleset
        # it rendered before the engine learned the field.
        body = rs.build_ruleset_body(
            {"enabled": True, "name": "n", "require_pull_request": {}}
        )
        self.assertIs(self._pr_params(body)[self.KEY], True)

    def test_config_switches_it_off(self):
        body = rs.build_ruleset_body(dict(self.OFF_CFG))
        self.assertIs(self._pr_params(body)[self.KEY], False)

    def test_it_is_drift_compared(self):
        # Absent from normalize_ruleset the field was invisible to `diff`, so
        # the daily drift report could never report it.
        on = rs.build_ruleset_body(
            {"enabled": True, "name": "n", "require_pull_request": {}}
        )
        off = rs.build_ruleset_body(dict(self.OFF_CFG))
        self.assertNotEqual(rs.normalize_ruleset(on), rs.normalize_ruleset(off))

    def test_live_fleet_state_is_drift_against_the_declared_config(self):
        live = self._live(dict(self.LIVE_PR_PARAMS))
        desired = rs.build_ruleset_body(dict(self.OFF_CFG))
        n_live = rs.normalize_ruleset(live)
        n_want = rs.normalize_ruleset(desired)
        self.assertIs(n_live["pr_extra_approval_unattributed"], True)
        self.assertIs(n_want["pr_extra_approval_unattributed"], False)
        self.assertNotEqual(n_live, n_want)

    def test_a_payload_without_the_key_reads_as_true_not_false(self):
        # Guessing False for an absent key would report a CLEAN audit for a
        # rule GitHub is in fact enforcing.
        params = dict(self.LIVE_PR_PARAMS)
        del params[self.KEY]
        norm = rs.normalize_ruleset(self._live(params))
        self.assertIs(norm["pr_extra_approval_unattributed"], True)

    def test_it_round_trips_through_generate(self):
        # Without ruleset_doc carrying it, `generate` against a repo where it
        # is off emits a config that rebuilds with the True default -- silently
        # re-arming the rule on the next apply.
        body = rs.build_ruleset_body(dict(self.OFF_CFG))
        round_tripped = rs.build_ruleset_body(rs.ruleset_doc(body))
        self.assertEqual(
            rs.normalize_ruleset(round_tripped), rs.normalize_ruleset(body)
        )
        self.assertIs(self._pr_params(round_tripped)[self.KEY], False)

    def test_a_ruleset_without_a_pull_request_rule_is_unaffected(self):
        body = rs.build_ruleset_body(
            {"enabled": True, "name": "n", "require_pull_request": None}
        )
        self.assertNotIn(
            "pull_request", [r["type"] for r in body["rules"]]
        )
        # Still normalizes without raising, and reports GitHub's default.
        self.assertIs(
            rs.normalize_ruleset(body)["pr_extra_approval_unattributed"], True
        )


class FleetConfigTests(unittest.TestCase):
    """The declaration itself, parsed -- never regex-scanned."""

    FLEET = Path(__file__).resolve().parent.parent / "repo-settings" / "fleet.yml"

    def setUp(self):
        import yaml

        with open(self.FLEET, encoding="utf-8") as fh:
            self.cfg = yaml.safe_load(fh)

    def test_defaults_declare_unattributed_approval_off(self):
        pr = self.cfg["defaults"]["ruleset"]["require_pull_request"]
        self.assertIs(
            pr["require_extra_approval_for_unattributed_changes"], False
        )

    def test_defaults_render_into_a_ruleset_body_that_states_it(self):
        body = rs.build_ruleset_body(self.cfg["defaults"]["ruleset"])
        params = next(
            r["parameters"] for r in body["rules"] if r["type"] == "pull_request"
        )
        self.assertIs(
            params["require_extra_approval_for_unattributed_changes"], False
        )

    def test_no_repo_override_silently_re_arms_it(self):
        # A per-repo override deep-merges over defaults; one that re-enabled
        # the rule would re-break that repo's unattended path without saying so.
        for entry in self.cfg["repos"]:
            if isinstance(entry, str) or not entry.get("overrides"):
                continue
            merged = rs.deep_merge(self.cfg["defaults"], entry["overrides"])
            pr = (merged.get("ruleset") or {}).get("require_pull_request")
            if not pr:
                continue
            self.assertIs(
                pr["require_extra_approval_for_unattributed_changes"],
                False,
                msg=f"{entry['name']} re-enables the unattributed-changes rule",
            )

    def test_defaults_declare_the_default_merge_commit_message(self):
        repo_defaults = self.cfg["defaults"]["repo"]
        self.assertEqual(repo_defaults["merge_commit_title"], "MERGE_MESSAGE")
        self.assertEqual(repo_defaults["merge_commit_message"], "PR_TITLE")

    def test_no_repo_override_changes_the_merge_commit_message(self):
        # Same shape as test_no_repo_override_silently_re_arms_it: a per-repo
        # override deep-merges over defaults, and one that switched this pair
        # would change a repo's merge-commit message without saying so.
        for entry in self.cfg["repos"]:
            if isinstance(entry, str) or not entry.get("overrides"):
                continue
            merged = rs.deep_merge(self.cfg["defaults"], entry["overrides"])
            repo = merged.get("repo") or {}
            self.assertEqual(
                repo.get("merge_commit_title"),
                "MERGE_MESSAGE",
                msg=f"{entry['name']} overrides merge_commit_title",
            )
            self.assertEqual(
                repo.get("merge_commit_message"),
                "PR_TITLE",
                msg=f"{entry['name']} overrides merge_commit_message",
            )


class RequiredStatusChecksFleetConfigTests(unittest.TestCase):
    """cms-platform#437: five more fleet repos gain a required status check
    (agentskills already carried the fleet's only one, `pytest-windows`).
    Parsed from the shipped fleet.yml -- never regex-scanned -- and rendered
    through the engine's OWN resolve_targets/build_ruleset_body so a
    mismerge between an override and the shared defaults is a red here, not
    something an operator discovers from a live drift report."""

    FLEET = Path(__file__).resolve().parent.parent / "repo-settings" / "fleet.yml"

    EXPECTED = {
        "Adam-S-Daniel/claude-memory-map": ["test"],
        "Adam-S-Daniel/skills-evals": ["test"],
        "Adam-S-Daniel/fastmail-actions": ["pester"],
        "Adam-S-Daniel/GHA-bench": ["test"],
        "Adam-S-Daniel/_agent-guidance": ["test"],
    }
    PRE_EXISTING = {"Adam-S-Daniel/agentskills": ["pytest-windows"]}

    def setUp(self):
        import yaml

        with open(self.FLEET, encoding="utf-8") as fh:
            self.cfg = yaml.safe_load(fh)
        self.targets = {t["repo"]: t for t in rs.resolve_targets(self.cfg, None)}

    def test_the_five_declare_exactly_the_named_contexts(self):
        for repo, checks in self.EXPECTED.items():
            settings = self.targets[repo]["settings"]
            self.assertEqual(
                (settings.get("ruleset") or {}).get("required_status_checks"),
                checks,
                msg=repo,
            )

    def test_no_other_managed_repo_gained_a_required_check(self):
        allowed = dict(self.EXPECTED)
        allowed.update(self.PRE_EXISTING)
        for repo, target in self.targets.items():
            if not target["manage"]:
                continue
            checks = (target["settings"].get("ruleset") or {}).get(
                "required_status_checks"
            )
            if repo in allowed:
                self.assertEqual(checks, allowed[repo], msg=repo)
            else:
                self.assertFalse(
                    checks,
                    msg=f"{repo} unexpectedly declares required_status_checks: {checks!r}",
                )

    def test_each_renders_a_required_status_checks_rule_with_exactly_those_contexts(self):
        for repo, checks in self.EXPECTED.items():
            ruleset_cfg = self.targets[repo]["settings"]["ruleset"]
            body = rs.build_ruleset_body(ruleset_cfg)
            rsc = next(
                r for r in body["rules"] if r["type"] == "required_status_checks"
            )
            self.assertEqual(
                rsc["parameters"]["required_status_checks"],
                [{"context": c} for c in checks],
                msg=repo,
            )
            self.assertIs(
                rsc["parameters"]["strict_required_status_checks_policy"],
                False,
                msg=repo,
            )

    def test_each_still_inherits_the_shared_ruleset_defaults(self):
        # The override touches ONLY required_status_checks -- everything else
        # in the rendered ruleset must still be the shared fleet default,
        # not something a careless override silently dropped or reset.
        for repo in self.EXPECTED:
            ruleset_cfg = self.targets[repo]["settings"]["ruleset"]
            body = rs.build_ruleset_body(ruleset_cfg)
            pr_params = next(
                r["parameters"] for r in body["rules"] if r["type"] == "pull_request"
            )
            self.assertIs(
                pr_params["require_extra_approval_for_unattributed_changes"],
                False,
                msg=repo,
            )
            self.assertEqual(pr_params["allowed_merge_methods"], ["merge"], msg=repo)
            self.assertIn(
                {
                    "actor_type": "Integration",
                    "actor_id": 4268639,
                    "bypass_mode": "always",
                },
                body["bypass_actors"],
                msg=repo,
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


class MergeCommitMessageTests(unittest.TestCase):
    """`merge_commit_title` / `merge_commit_message` -- the two repo fields
    behind GitHub's "Allow merge commits" message choice. The fleet wants
    GitHub's own "Default message" pair, MERGE_MESSAGE/PR_TITLE, everywhere:
    a PR description carried into a merge commit becomes commit text, and a
    closing keyword closes its issue from there even inside backticks --
    commit text is not markdown. See fleet.yml's comment on this leaf.

    Like write_merge_methods, both keys are written in ONE call so the repo
    never holds a half-applied pair the config did not choose.
    """

    DEFAULT_PAIR = {
        "merge_commit_title": "MERGE_MESSAGE",
        "merge_commit_message": "PR_TITLE",
    }

    def test_drift_is_reported_per_key(self):
        live = {
            "private": False,
            "merge_commit_title": "PR_TITLE",
            "merge_commit_message": "PR_BODY",
        }
        with patch.object(rs, "get_repo", return_value=live):
            records = rs.plan_repo("o/r", {"repo": dict(self.DEFAULT_PAIR)})
        by_setting = {r["setting"]: r for r in records}
        self.assertEqual(
            set(by_setting), {"repo.merge_commit_title", "repo.merge_commit_message"}
        )
        title = by_setting["repo.merge_commit_title"]
        self.assertEqual(title["status"], "drift")
        self.assertEqual(title["current"], "PR_TITLE")
        self.assertEqual(title["desired"], "MERGE_MESSAGE")
        message = by_setting["repo.merge_commit_message"]
        self.assertEqual(message["status"], "drift")
        self.assertEqual(message["current"], "PR_BODY")
        self.assertEqual(message["desired"], "PR_TITLE")

    def test_match_when_already_default(self):
        live = {"private": False, **self.DEFAULT_PAIR}
        with patch.object(rs, "get_repo", return_value=live):
            records = rs.plan_repo("o/r", {"repo": dict(self.DEFAULT_PAIR)})
        self.assertEqual({r["status"] for r in records}, {"match"})

    def test_omitted_keys_are_unmanaged(self):
        with patch.object(rs, "get_repo") as mock_get_repo:
            records = rs.plan_repo("o/r", {"repo": {}})
        self.assertEqual(records, [])
        mock_get_repo.assert_not_called()

    def test_explicit_null_is_unmanaged(self):
        with patch.object(rs, "get_repo") as mock_get_repo:
            records = rs.plan_repo(
                "o/r",
                {"repo": {"merge_commit_title": None, "merge_commit_message": None}},
            )
        self.assertEqual(records, [])
        mock_get_repo.assert_not_called()

    def test_one_key_alone_is_refused_rather_than_applied(self):
        with patch.object(rs, "get_repo") as mock_get_repo:
            records = rs.plan_repo(
                "o/r", {"repo": {"merge_commit_message": "PR_TITLE"}}
            )
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertEqual(rec["status"], "skipped")
        self.assertIn("together", rec["note"])
        self.assertNotIn("_writer", rec)
        mock_get_repo.assert_not_called()

    def test_a_pair_github_does_not_offer_is_refused(self):
        with patch.object(rs, "get_repo") as mock_get_repo:
            records = rs.plan_repo(
                "o/r",
                {
                    "repo": {
                        "merge_commit_title": "MERGE_MESSAGE",
                        "merge_commit_message": "PR_BODY",
                    }
                },
            )
        self.assertEqual(len(records), 2)
        self.assertEqual({r["status"] for r in records}, {"skipped"})
        for rec in records:
            self.assertNotIn("_writer", rec)
        mock_get_repo.assert_not_called()

    def test_private_repos_are_managed_too(self):
        live = {
            "private": True,
            "merge_commit_title": "PR_TITLE",
            "merge_commit_message": "PR_BODY",
        }
        with patch.object(rs, "get_repo", return_value=live):
            records = rs.plan_repo("o/r", {"repo": dict(self.DEFAULT_PAIR)})
        self.assertIn("drift", {r["status"] for r in records})

    def test_absent_field_is_skipped_not_a_crash(self):
        with patch.object(rs, "get_repo", return_value={"private": False, "name": "r"}):
            records = rs.plan_repo("o/r", {"repo": dict(self.DEFAULT_PAIR)})
        self.assertEqual({r["status"] for r in records}, {"skipped"})
        title_note = [r["note"] for r in records if r["setting"] == "repo.merge_commit_title"][0]
        self.assertIn("merge_commit_title", title_note)

    def test_read_failure_isolated_into_error_records(self):
        with patch.object(rs, "get_repo", side_effect=rs.GhError(500, "boom")):
            records = rs.plan_repo_records("o/r", {"repo": dict(self.DEFAULT_PAIR)})
        self.assertEqual({r["status"] for r in records}, {"error"})

    def test_apply_patches_the_pair_in_one_call(self):
        live = {
            "private": False,
            "merge_commit_title": "PR_TITLE",
            "merge_commit_message": "PR_BODY",
        }
        with patch.object(rs, "get_repo", return_value=live):
            records = rs.plan_repo("o/r", {"repo": dict(self.DEFAULT_PAIR)})
        drifted = [r for r in records if r["status"] == "drift"]
        with patch.object(rs, "gh_api") as mock_gh_api:
            rs.apply_record("o/r", drifted[0])
        mock_gh_api.assert_called_once_with(
            "repos/o/r", method="PATCH", body=dict(self.DEFAULT_PAIR)
        )

    def test_every_record_carries_the_whole_pair(self):
        live = {
            "private": False,
            "merge_commit_title": "PR_TITLE",
            "merge_commit_message": "PR_BODY",
        }
        with patch.object(rs, "get_repo", return_value=live):
            records = rs.plan_repo("o/r", {"repo": dict(self.DEFAULT_PAIR)})
        self.assertEqual(len(records), 2)
        for rec in records:
            self.assertEqual(
                rec["_writer"], ("merge_commit_message", None, dict(self.DEFAULT_PAIR))
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


class CoverageTests(unittest.TestCase):
    """`coverage` answers a question no other command asks: which repos this
    credential can administer that the config never mentions.

    Declared, not managed. A repo carrying `manage: false` is a decision
    somebody wrote down; a repo absent from the file is a decision nobody has
    made, and from the outside those looked identical.
    """

    CFG = {
        "defaults": {},
        "repos": [
            {"name": "acme/declared-managed"},
            {"name": "acme/declared-unmanaged", "manage": False},
        ],
    }

    def _run(self, reachable, owner=None):
        args = argparse.Namespace(config="ignored.yml", owner=owner)
        with patch.object(rs, "load_config", return_value=self.CFG), \
             patch.object(rs, "installation_repos", return_value=reachable):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
                rc = rs.cmd_coverage(args)
        return rc, buf.getvalue()

    def test_every_reachable_repo_declared_is_clean(self):
        rc, out = self._run(["acme/declared-managed", "acme/declared-unmanaged"])
        self.assertEqual(rc, 0)
        self.assertNotIn("UNDECLARED", out)
        self.assertIn("2 reachable, 2 declared, 0 undeclared", out)

    def test_an_undeclared_repo_is_reported_and_exits_one(self):
        rc, out = self._run(
            ["acme/declared-managed", "acme/declared-unmanaged", "acme/brand-new"]
        )
        self.assertEqual(rc, 1)
        self.assertIn("UNDECLARED  acme/brand-new", out)
        self.assertIn("3 reachable, 2 declared, 1 undeclared", out)

    def test_manage_false_is_declared_not_undeclared(self):
        """The whole distinction. A repo deliberately left unmanaged has been
        decided about, and reporting it would train the reader to ignore the
        report -- which is how a nudge stops being a nudge."""
        rc, out = self._run(["acme/declared-unmanaged"])
        self.assertEqual(rc, 0)
        self.assertIn("declared, manage: false", out)
        self.assertNotIn("UNDECLARED", out)

    def test_an_empty_enumeration_refuses_rather_than_certifying(self):
        """Never pass vacuously: a clean line over zero repos reads exactly
        like a clean line over all of them."""
        rc, _ = self._run([])
        self.assertEqual(rc, 2)

    def test_a_single_repo_config_has_no_fleet_to_be_complete_about(self):
        args = argparse.Namespace(config="ignored.yml", owner=None)
        with patch.object(rs, "load_config", return_value={"repo": "acme/one"}), \
             patch.object(rs, "installation_repos") as enumerate_mock:
            with contextlib.redirect_stderr(io.StringIO()):
                rc = rs.cmd_coverage(args)
        self.assertEqual(rc, 2)
        # And it did not spend an API call establishing that.
        enumerate_mock.assert_not_called()

    def test_comparison_is_case_insensitive(self):
        """GitHub preserves the case an owner typed and matches irrespective of
        it, so a config that spells a name differently from the API is the same
        repo -- reporting it undeclared would send someone to add a duplicate."""
        rc, out = self._run(["ACME/Declared-Managed", "acme/declared-unmanaged"])
        self.assertEqual(rc, 0)
        self.assertNotIn("UNDECLARED", out)


class InstallationReposTests(unittest.TestCase):
    """The enumeration itself: pagination, shape, and the owner filter."""

    @staticmethod
    def _page(names):
        return {"repositories": [{"full_name": n} for n in names]}

    def test_owner_filter_keeps_only_that_account(self):
        with patch.object(rs, "gh_api", return_value=self._page(
                ["acme/one", "other/two", "ACME/three"])):
            self.assertEqual(
                rs.installation_repos("acme"), ["ACME/three", "acme/one"]
            )

    def test_no_owner_keeps_everything(self):
        with patch.object(rs, "gh_api", return_value=self._page(
                ["acme/one", "other/two"])):
            self.assertEqual(rs.installation_repos(None), ["acme/one", "other/two"])

    def test_it_pages(self):
        """A full page means there may be another. Stopping at the first would
        silently truncate the denominator, which is the failure this whole
        command exists to prevent -- one level down."""
        first = self._page([f"acme/r{i:03d}" for i in range(100)])
        second = self._page(["acme/last"])
        with patch.object(rs, "gh_api", side_effect=[first, second]) as api:
            got = rs.installation_repos(None)
        self.assertEqual(len(got), 101)
        self.assertIn("acme/last", got)
        self.assertEqual(api.call_count, 2)
        self.assertIn("page=2", api.call_args_list[1].args[0])

    def test_a_short_page_ends_the_walk(self):
        with patch.object(rs, "gh_api", return_value=self._page(["acme/one"])) as api:
            rs.installation_repos(None)
        self.assertEqual(api.call_count, 1)

    def test_an_empty_response_is_not_an_infinite_loop(self):
        with patch.object(rs, "gh_api", return_value={"repositories": []}) as api:
            self.assertEqual(rs.installation_repos(None), [])
        self.assertEqual(api.call_count, 1)

    def test_a_null_payload_is_survivable(self):
        """`gh api` returns None for an empty body. Reaching into that with
        .get would be an AttributeError dressed up as an enumeration failure."""
        with patch.object(rs, "gh_api", return_value=None):
            self.assertEqual(rs.installation_repos(None), [])


class VulnerabilityAlertsReaderTests(unittest.TestCase):
    """`read_vulnerability_alerts` -- the whole answer lives in the HTTP
    status, never a JSON body, and success/404/403/other-error each has to
    land in a different bucket."""

    def test_204_empty_body_reads_as_enabled(self):
        # gh_api returns None for an empty 204 body; success at all (no raise)
        # is the enabled signal here, there is nothing else to inspect.
        with patch.object(rs, "gh_api", return_value=None) as api:
            self.assertIs(rs.read_vulnerability_alerts("o/r"), True)
        api.assert_called_once_with("repos/o/r/vulnerability-alerts")

    def test_404_reads_as_disabled(self):
        with patch.object(rs, "gh_api", side_effect=rs.GhError(404, "Not Found")):
            self.assertIs(rs.read_vulnerability_alerts("o/r"), False)

    def test_403_reads_as_unreadable_none(self):
        # Not "not there" -- the read itself could not be answered. plan_repo
        # turns this into a `skipped` record, never a silent "disabled".
        with patch.object(rs, "gh_api", side_effect=rs.GhError(403, "Forbidden")):
            self.assertIsNone(rs.read_vulnerability_alerts("o/r"))

    def test_other_ghz_error_propagates(self):
        # A 500 (or anything not in the two documented shapes) must reach
        # plan_repo_records as a real error record, not get silently folded
        # into disabled or skipped.
        with patch.object(rs, "gh_api", side_effect=rs.GhError(500, "boom")):
            with self.assertRaises(rs.GhError):
                rs.read_vulnerability_alerts("o/r")


class AutomatedSecurityFixesReaderTests(unittest.TestCase):
    """`read_automated_security_fixes` -- tolerates both the current
    200-JSON-with-`enabled` shape and the legacy 204-empty-body shape, and
    must never silently guess at an unrecognised payload."""

    def test_dict_enabled_true(self):
        with patch.object(rs, "gh_api", return_value={"enabled": True, "paused": False}):
            self.assertIs(rs.read_automated_security_fixes("o/r"), True)

    def test_dict_enabled_false(self):
        with patch.object(rs, "gh_api", return_value={"enabled": False, "paused": False}):
            self.assertIs(rs.read_automated_security_fixes("o/r"), False)

    def test_paused_is_ignored_either_way(self):
        # paused is deliberately not managed -- it must not change the
        # enabled reading in either direction.
        with patch.object(rs, "gh_api", return_value={"enabled": True, "paused": True}):
            self.assertIs(rs.read_automated_security_fixes("o/r"), True)

    def test_legacy_204_empty_body_reads_as_enabled(self):
        with patch.object(rs, "gh_api", return_value=None):
            self.assertIs(rs.read_automated_security_fixes("o/r"), True)

    def test_404_reads_as_disabled(self):
        with patch.object(rs, "gh_api", side_effect=rs.GhError(404, "Not Found")):
            self.assertIs(rs.read_automated_security_fixes("o/r"), False)

    def test_403_reads_as_unreadable_none(self):
        with patch.object(rs, "gh_api", side_effect=rs.GhError(403, "Forbidden")):
            self.assertIsNone(rs.read_automated_security_fixes("o/r"))

    def test_other_ghz_error_propagates(self):
        with patch.object(rs, "gh_api", side_effect=rs.GhError(500, "boom")):
            with self.assertRaises(rs.GhError):
                rs.read_automated_security_fixes("o/r")

    def test_empty_dict_without_enabled_key_reads_as_enabled(self):
        # Treated the same as the legacy 204-empty success, not as the
        # unexpected-shape case below.
        with patch.object(rs, "gh_api", return_value={}):
            self.assertIs(rs.read_automated_security_fixes("o/r"), True)

    def test_nonempty_dict_missing_enabled_key_raises_rather_than_guesses(self):
        # A shape that matches neither documented vintage must never silently
        # become a value the audit reports with confidence it does not have.
        with patch.object(rs, "gh_api", return_value={"paused": False}):
            with self.assertRaises(rs.GhError):
                rs.read_automated_security_fixes("o/r")


class SecurityWritersTests(unittest.TestCase):
    """The METHOD carries the value here, unlike every other writer in this
    file -- PUT to enable, DELETE to disable, and no body either way."""

    def test_write_vulnerability_alerts_true_is_a_bare_put(self):
        with patch.object(rs, "gh_api") as api:
            rs.write_vulnerability_alerts("o/r", True)
        api.assert_called_once_with("repos/o/r/vulnerability-alerts", method="PUT")
        # No body kwarg at all -- assert_called_once_with above already
        # enforces this (a body= kwarg would fail the equality check), stated
        # explicitly since it is the whole point of the shape.
        self.assertNotIn("body", api.call_args.kwargs)

    def test_write_vulnerability_alerts_false_is_a_bare_delete(self):
        with patch.object(rs, "gh_api") as api:
            rs.write_vulnerability_alerts("o/r", False)
        api.assert_called_once_with("repos/o/r/vulnerability-alerts", method="DELETE")
        self.assertNotIn("body", api.call_args.kwargs)

    def test_write_automated_security_fixes_true_is_a_bare_put(self):
        with patch.object(rs, "gh_api") as api:
            rs.write_automated_security_fixes("o/r", True)
        api.assert_called_once_with("repos/o/r/automated-security-fixes", method="PUT")
        self.assertNotIn("body", api.call_args.kwargs)

    def test_write_automated_security_fixes_false_is_a_bare_delete(self):
        with patch.object(rs, "gh_api") as api:
            rs.write_automated_security_fixes("o/r", False)
        api.assert_called_once_with("repos/o/r/automated-security-fixes", method="DELETE")
        self.assertNotIn("body", api.call_args.kwargs)


class SecurityPlanRecordsTests(unittest.TestCase):
    """`plan_repo`'s `security` section: match/drift/skip/error for the two
    applyable leaves, built from the readers directly rather than gh_api --
    the readers' own contract is covered above."""

    CFG_BOTH_ON = {"vulnerability_alerts": True, "automated_security_fixes": True}

    def test_match_when_live_already_matches_desired(self):
        with patch.object(rs, "read_vulnerability_alerts", return_value=True), \
             patch.object(rs, "read_automated_security_fixes", return_value=True):
            records = rs.plan_repo("o/r", {"security": dict(self.CFG_BOTH_ON)})
        by_setting = {r["setting"]: r for r in records}
        self.assertEqual(by_setting["security.vulnerability_alerts"]["status"], "match")
        self.assertEqual(by_setting["security.automated_security_fixes"]["status"], "match")
        for r in records:
            self.assertNotIn("skipped", r["status"])
            self.assertNotEqual(r["status"], "error")

    def test_drift_when_both_off_and_desired_on(self):
        with patch.object(rs, "read_vulnerability_alerts", return_value=False), \
             patch.object(rs, "read_automated_security_fixes", return_value=False):
            records = rs.plan_repo("o/r", {"security": dict(self.CFG_BOTH_ON)})
        by_setting = {r["setting"]: r for r in records}
        self.assertEqual(len(records), 2)
        va = by_setting["security.vulnerability_alerts"]
        af = by_setting["security.automated_security_fixes"]
        self.assertEqual(va["status"], "drift")
        self.assertEqual(va["current"], False)
        self.assertEqual(va["desired"], True)
        self.assertEqual(va["_writer"], ("vuln_alerts", None, True))
        self.assertEqual(af["status"], "drift")
        self.assertEqual(af["current"], False)
        self.assertEqual(af["desired"], True)
        self.assertEqual(af["_writer"], ("auto_sec_fixes", None, True))

    def test_omitted_keys_are_unmanaged(self):
        with patch.object(rs, "read_vulnerability_alerts") as va, \
             patch.object(rs, "read_automated_security_fixes") as af:
            records = rs.plan_repo("o/r", {"security": {}})
            records_no_block = rs.plan_repo("o/r", {})
        self.assertEqual(records, [])
        self.assertEqual(records_no_block, [])
        va.assert_not_called()
        af.assert_not_called()

    def test_403_on_vulnerability_alerts_is_a_skip_naming_403(self):
        with patch.object(rs, "read_vulnerability_alerts", return_value=None), \
             patch.object(rs, "read_automated_security_fixes", return_value=True):
            records = rs.plan_repo(
                "o/r", {"security": {"vulnerability_alerts": True}}
            )
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertEqual(rec["setting"], "security.vulnerability_alerts")
        self.assertEqual(rec["status"], "skipped")
        self.assertIn("403", rec["note"])
        self.assertNotIn("_writer", rec)

    def test_403_on_automated_security_fixes_is_a_skip_naming_403(self):
        with patch.object(rs, "read_automated_security_fixes", return_value=None):
            records = rs.plan_repo(
                "o/r", {"security": {"automated_security_fixes": True}}
            )
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertEqual(rec["setting"], "security.automated_security_fixes")
        self.assertEqual(rec["status"], "skipped")
        self.assertIn("403", rec["note"])
        self.assertNotIn("_writer", rec)

    def test_read_failure_becomes_an_error_record_not_a_crash(self):
        with patch.object(rs, "read_vulnerability_alerts",
                          side_effect=rs.GhError(500, "boom")):
            records = rs.plan_repo(
                "o/r", {"security": {"vulnerability_alerts": True}}
            )
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["status"], "error")
        self.assertIn("boom", records[0]["note"])

    def test_read_failure_is_isolated_by_plan_repo_records(self):
        with patch.object(rs, "read_vulnerability_alerts",
                          side_effect=rs.GhError(500, "boom")):
            records = rs.plan_repo_records(
                "o/r", {"security": {"vulnerability_alerts": True}}
            )
        self.assertEqual([r["status"] for r in records], ["error"])


class SecurityApplyOrderRegressionGuardTests(unittest.TestCase):
    """Dependabot security updates require alerts to already be on, and
    `cmd_apply` walks drift records in LIST ORDER -- so the order `plan_repo`
    appends these two records in IS the write order. If this regresses, an
    apply could enable automated_security_fixes before vulnerability_alerts
    (or disable the prerequisite out from under the dependent), landing a
    repo in a state Dependabot itself rejects."""

    def _settings(self, desired):
        return {
            "security": {
                "vulnerability_alerts": desired,
                "automated_security_fixes": desired,
            }
        }

    def test_enabling_orders_alerts_before_security_fixes(self):
        with patch.object(rs, "read_vulnerability_alerts", return_value=False), \
             patch.object(rs, "read_automated_security_fixes", return_value=False):
            records = rs.plan_repo("o/r", self._settings(True))
        self.assertEqual(
            [r["setting"] for r in records],
            ["security.vulnerability_alerts", "security.automated_security_fixes"],
        )
        self.assertTrue(all(r["status"] == "drift" for r in records))

    def test_disabling_orders_security_fixes_before_alerts(self):
        with patch.object(rs, "read_vulnerability_alerts", return_value=True), \
             patch.object(rs, "read_automated_security_fixes", return_value=True):
            records = rs.plan_repo("o/r", self._settings(False))
        self.assertEqual(
            [r["setting"] for r in records],
            ["security.automated_security_fixes", "security.vulnerability_alerts"],
        )
        self.assertTrue(all(r["status"] == "drift" for r in records))


class GroupedSecurityUpdatesTests(unittest.TestCase):
    """No API exists for this leaf at any scope -- it must always report
    `skipped` and must never carry a `_writer` (there is nothing
    `apply_record` could dispatch to)."""

    def test_declared_true_is_always_skipped_never_drift(self):
        records = rs.plan_repo(
            "o/r", {"security": {"grouped_security_updates": True}}
        )
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertEqual(rec["setting"], "security.grouped_security_updates")
        self.assertEqual(rec["status"], "skipped")
        self.assertNotIn("_writer", rec)

    def test_declared_false_is_still_skipped_not_match(self):
        # There is no live value to compare against -- any declared value
        # produces the same unenforceable skip, never a match/drift verdict
        # the engine has no way to have earned.
        records = rs.plan_repo(
            "o/r", {"security": {"grouped_security_updates": False}}
        )
        self.assertEqual([r["status"] for r in records], ["skipped"])

    def test_note_names_the_absence_of_an_api(self):
        records = rs.plan_repo(
            "o/r", {"security": {"grouped_security_updates": True}}
        )
        note = records[0]["note"]
        self.assertIn("no REST endpoint", note)
        self.assertIn("dependabot.yml", note)

    def test_omitted_key_is_unmanaged(self):
        records = rs.plan_repo("o/r", {"security": {}})
        self.assertEqual(records, [])

    def test_apply_never_attempts_a_writer_for_it(self):
        # apply_record dispatches purely on rec["_writer"][0] -- confirm the
        # planned record genuinely carries none, so a future refactor of
        # apply_record can't accidentally invent a call for this kind.
        records = rs.plan_repo(
            "o/r", {"security": {"grouped_security_updates": True}}
        )
        for r in records:
            self.assertNotIn("_writer", r)


class SecurityApplyRecordDispatchTests(unittest.TestCase):
    """`apply_record`'s two new branches -- the writer reachable from the
    record the planner emits, same shape as the existing dispatch tests for
    every other kind in this file."""

    def test_vuln_alerts_kind_calls_the_vuln_alerts_writer(self):
        rec = {"setting": "security.vulnerability_alerts", "status": "drift",
               "current": False, "desired": True,
               "_writer": ("vuln_alerts", None, True)}
        with patch.object(rs, "write_vulnerability_alerts") as writer:
            rs.apply_record("o/r", rec)
        writer.assert_called_once_with("o/r", True)

    def test_auto_sec_fixes_kind_calls_the_auto_sec_fixes_writer(self):
        rec = {"setting": "security.automated_security_fixes", "status": "drift",
               "current": False, "desired": True,
               "_writer": ("auto_sec_fixes", None, True)}
        with patch.object(rs, "write_automated_security_fixes") as writer:
            rs.apply_record("o/r", rec)
        writer.assert_called_once_with("o/r", True)

    def test_end_to_end_via_gh_api_for_vuln_alerts(self):
        # Belt and braces: the same call chain MergeMethodTests and
        # DeleteBranchOnMergeTests exercise for their own kinds, down to the
        # actual gh_api call rather than stopping at the writer mock.
        with patch.object(rs, "read_vulnerability_alerts", return_value=False):
            rec = rs.plan_repo(
                "o/r", {"security": {"vulnerability_alerts": True}}
            )[0]
        with patch.object(rs, "gh_api") as api:
            rs.apply_record("o/r", rec)
        api.assert_called_once_with("repos/o/r/vulnerability-alerts", method="PUT")

    def test_end_to_end_via_gh_api_for_auto_sec_fixes(self):
        with patch.object(rs, "read_automated_security_fixes", return_value=False):
            rec = rs.plan_repo(
                "o/r", {"security": {"automated_security_fixes": True}}
            )[0]
        with patch.object(rs, "gh_api") as api:
            rs.apply_record("o/r", rec)
        api.assert_called_once_with("repos/o/r/automated-security-fixes", method="PUT")


class SecurityFleetConfigTests(unittest.TestCase):
    """The `security` group in the shipped fleet.yml, parsed -- never
    regex-scanned. Guards the exact gap the group exists to close: on
    2026-08-31 the fleet's Dependabot-alerts posture was undeclared and
    measurably split (403 "disabled" on four repos, apparently enabled on a
    fifth) with nothing anywhere recording that as a decision."""

    FLEET = Path(__file__).resolve().parent.parent / "repo-settings" / "fleet.yml"

    def setUp(self):
        import yaml

        with open(self.FLEET, encoding="utf-8") as fh:
            self.cfg = yaml.safe_load(fh)

    def test_defaults_declare_all_three_security_settings_true(self):
        security = self.cfg["defaults"]["security"]
        self.assertIs(security["vulnerability_alerts"], True)
        self.assertIs(security["automated_security_fixes"], True)
        self.assertIs(security["grouped_security_updates"], True)

    def test_every_managed_repo_resolves_the_security_defaults(self):
        # A per-repo override COULD, in principle, silently drop a leaf the
        # way an override could re-enable squash (see FleetConfigTests
        # above) -- assert the settings resolve_targets actually hands each
        # MANAGED repo carries all three, not just that defaults: declares
        # them once at the top of the file.
        for target in rs.resolve_targets(self.cfg, None):
            if not target["manage"]:
                continue
            security = target["settings"].get("security") or {}
            self.assertIn("vulnerability_alerts", security, msg=target["repo"])
            self.assertIn("automated_security_fixes", security, msg=target["repo"])
            self.assertIn("grouped_security_updates", security, msg=target["repo"])
            self.assertIs(security["vulnerability_alerts"], True, msg=target["repo"])
            self.assertIs(security["automated_security_fixes"], True, msg=target["repo"])
            self.assertIs(security["grouped_security_updates"], True, msg=target["repo"])
