# Offline tests of the pure config -> ruleset-body logic (no gh/network).
import argparse
import contextlib
import copy
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
    """cms-platform#437's five repos plus ai-usage-dashboard declare checks
    (agentskills already carried the fleet's original `pytest-windows` check),
    and this repo itself declares `unit` beside `agent-checks` (issue #86;
    unenforced while it is private, declared per ADR 0002).
    Parsed from the shipped fleet.yml -- never regex-scanned -- and rendered
    through the engine's OWN resolve_targets/build_ruleset_body so a
    mismerge between an override and the shared defaults is a red here, not
    something an operator discovers from a live drift report."""

    FLEET = Path(__file__).resolve().parent.parent / "repo-settings" / "fleet.yml"

    EXPECTED = {
        "Adam-S-Daniel/claude-memory-map": ["test", "agent-checks"],
        "Adam-S-Daniel/skills-evals": ["test", "agent-checks"],
        "Adam-S-Daniel/fastmail-actions": ["pester", "agent-checks"],
        "Adam-S-Daniel/GHA-bench": ["test"],
        "Adam-S-Daniel/_agent-guidance": ["test", "agent-checks"],
        "Adam-S-Daniel/ai-usage-dashboard": ["node-test", "pester", "agent-checks"],
        "Adam-S-Daniel/repo-settings": ["agent-checks", "unit"],
    }
    PRE_EXISTING = {
        "Adam-S-Daniel/agentskills": ["pytest-windows"],
        # adam-agentskills: new public registry replacing agentskills above,
        # onboarded with a required check from day one -- not part of the
        # cms-platform#437 batch this class otherwise tests, so it belongs in
        # this "allowed but not asserted exactly by the other tests" bucket
        # rather than EXPECTED. `plugin-runtime-approval` (2026-10-08) is its
        # owner-approval gate for plugin runtime changes (its ADR 0016/0017).
        "Adam-S-Daniel/adam-agentskills": ["privacy", "pytest", "pytest-windows", "plugin-runtime-approval", "agent-checks"],
    }
    # The fleet default (_agent-guidance ADR 0021): every other managed repo
    # with a ruleset requires the delivered agent-checks job and nothing else.
    DEFAULT = ["agent-checks"]

    def setUp(self):
        import yaml

        with open(self.FLEET, encoding="utf-8") as fh:
            self.cfg = yaml.safe_load(fh)
        self.targets = {t["repo"]: t for t in rs.resolve_targets(self.cfg, None)}

    def test_declared_repos_declare_exactly_the_named_contexts(self):
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
            elif (target["settings"].get("ruleset") or {}).get("enabled") is False:
                continue
            else:
                self.assertEqual(
                    checks,
                    self.DEFAULT,
                    msg=f"{repo} declares required_status_checks {checks!r}, not the fleet default",
                )

    def test_every_override_keeps_the_fleet_default_check(self):
        # deep_merge REPLACES lists, so an override that forgets to repeat
        # agent-checks silently drops it for that repo.
        for repo, target in self.targets.items():
            if not target["manage"] or repo == "Adam-S-Daniel/GHA-bench":
                continue
            ruleset = target["settings"].get("ruleset") or {}
            if ruleset.get("enabled") is False:
                continue
            self.assertIn("agent-checks", ruleset.get("required_status_checks") or [], msg=repo)

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


ROSTER_APP_ID = 5116415
EXTRA_CFG = {
    "name": "roster proposal branch",
    "target_branches": ["roster/proposal"],
    "rules": ["creation", "update", "deletion", "non_fast_forward"],
    "bypass_actors": [
        {"actor_type": "Integration", "actor_id": ROSTER_APP_ID, "bypass_mode": "always"},
        {"actor_type": "RepositoryRole", "actor_id": 5, "bypass_mode": "always"},
    ],
}


def _extra(**over):
    cfg = dict(EXTRA_CFG)
    cfg.update(over)
    return cfg


class ExtraRulesetBodyTests(unittest.TestCase):
    def test_body_shape(self):
        body = rs.build_extra_ruleset_body(EXTRA_CFG)
        self.assertEqual(body["name"], "roster proposal branch")
        self.assertEqual(body["target"], "branch")
        self.assertEqual(body["enforcement"], "active")
        self.assertEqual(
            body["conditions"],
            {"ref_name": {"include": ["refs/heads/roster/proposal"], "exclude": []}},
        )
        self.assertEqual(
            body["bypass_actors"],
            [
                {"actor_id": ROSTER_APP_ID, "actor_type": "Integration", "bypass_mode": "always"},
                {"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"},
            ],
        )

    def test_each_rule_type_renders(self):
        for t in ("creation", "deletion", "non_fast_forward"):
            body = rs.build_extra_ruleset_body(_extra(rules=[t]))
            self.assertEqual(body["rules"], [{"type": t}])

    def test_update_carries_its_parameter(self):
        body = rs.build_extra_ruleset_body(_extra(rules=["update"]))
        self.assertEqual(
            body["rules"],
            [{"type": "update", "parameters": {"update_allows_fetch_and_merge": False}}],
        )

    def test_unknown_rule_type_rejected(self):
        for bad in ("pull_request", "required_status_checks", "bogus"):
            with self.assertRaises(SystemExit) as cm:
                rs.build_extra_ruleset_body(_extra(rules=["update", bad]))
            self.assertIn(bad, str(cm.exception))

    def test_missing_name_rejected(self):
        cfg = _extra()
        del cfg["name"]
        with self.assertRaises(SystemExit):
            rs.build_extra_ruleset_body(cfg)

    def test_missing_or_empty_targets_or_rules_rejected(self):
        for key in ("target_branches", "rules"):
            for val in (None, []):
                cfg = _extra()
                if val is None:
                    del cfg[key]
                else:
                    cfg[key] = val
                with self.assertRaises(SystemExit, msg=f"{key}={val}"):
                    rs.build_extra_ruleset_body(cfg)

    def test_bad_bypass_actor_rejected(self):
        with self.assertRaises(SystemExit):
            rs.build_extra_ruleset_body(
                _extra(bypass_actors=[{"actor_type": "Nope", "actor_id": 1}])
            )
        with self.assertRaises(SystemExit):
            rs.build_extra_ruleset_body(
                _extra(bypass_actors=[{"actor_type": "Integration"}])
            )

    def test_no_implicit_admin_bypass(self):
        body = rs.build_extra_ruleset_body(_extra(bypass_actors=[]))
        self.assertEqual(body["bypass_actors"], [])


class ExtraRulesetValidationTests(unittest.TestCase):
    def test_duplicate_names_rejected(self):
        with self.assertRaises(SystemExit):
            rs.build_extra_ruleset_bodies({"extra_rulesets": [EXTRA_CFG, EXTRA_CFG]})

    def test_collision_with_default_ruleset_name_rejected(self):
        with self.assertRaises(SystemExit):
            rs.build_extra_ruleset_bodies(
                {"extra_rulesets": [_extra(name=rs.DEFAULT_RULESET_NAME)]}
            )
        with self.assertRaises(SystemExit):
            rs.build_extra_ruleset_bodies(
                {
                    "ruleset": {"enabled": True, "name": "custom"},
                    "extra_rulesets": [_extra(name="custom")],
                }
            )

    def test_absent_means_none(self):
        self.assertEqual(rs.build_extra_ruleset_bodies({}), [])

    def test_rejected_under_defaults(self):
        cfg = {"defaults": {"extra_rulesets": [EXTRA_CFG]}, "repos": [{"name": "o/r"}]}
        with self.assertRaises(SystemExit) as cm:
            rs.resolve_targets(cfg, None)
        self.assertIn("extra_rulesets", str(cm.exception))

    def test_per_repo_override_flows_to_settings(self):
        cfg = {
            "defaults": {},
            "repos": [{"name": "o/r", "overrides": {"extra_rulesets": [EXTRA_CFG]}}],
        }
        (t,) = rs.resolve_targets(cfg, None)
        self.assertEqual(t["settings"]["extra_rulesets"], [EXTRA_CFG])


class NormalizeExtraRulesetTests(unittest.TestCase):
    def test_order_insensitive(self):
        a = rs.build_extra_ruleset_body(EXTRA_CFG)
        b = rs.build_extra_ruleset_body(
            _extra(
                rules=["non_fast_forward", "deletion", "update", "creation"],
                bypass_actors=list(reversed(EXTRA_CFG["bypass_actors"])),
            )
        )
        self.assertEqual(rs.normalize_extra_ruleset(a), rs.normalize_extra_ruleset(b))

    def test_live_shape_without_parameters_key_matches(self):
        desired = rs.build_extra_ruleset_body(_extra(rules=["deletion"]))
        live = dict(desired, id=7, rules=[{"type": "deletion"}])
        self.assertEqual(
            rs.normalize_extra_ruleset(live), rs.normalize_extra_ruleset(desired)
        )

    def test_live_update_without_parameters_matches_explicit_false(self):
        # GitHub omits update_allows_fetch_and_merge: false when storing the
        # rule; the drift report showed a permanent false DRIFT before this.
        desired = rs.build_extra_ruleset_body(_extra(rules=["update"]))
        live = dict(desired, id=7, rules=[{"type": "update"}])
        self.assertEqual(
            rs.normalize_extra_ruleset(live), rs.normalize_extra_ruleset(desired)
        )

    def test_detects_differences(self):
        base = rs.normalize_extra_ruleset(rs.build_extra_ruleset_body(EXTRA_CFG))
        for change in (
            {"rules": ["creation"]},
            {"bypass_actors": EXTRA_CFG["bypass_actors"][:1]},
            {"target_branches": ["other"]},
            {"enforcement": "disabled"},
        ):
            other = rs.normalize_extra_ruleset(
                rs.build_extra_ruleset_body(_extra(**change))
            )
            self.assertNotEqual(base, other, msg=str(change))

    def test_update_parameter_drift_detected(self):
        desired = rs.build_extra_ruleset_body(_extra(rules=["update"]))
        live = dict(desired)
        live["rules"] = [
            {"type": "update", "parameters": {"update_allows_fetch_and_merge": True}}
        ]
        self.assertNotEqual(
            rs.normalize_extra_ruleset(live), rs.normalize_extra_ruleset(desired)
        )


class ExtraRulesetPlanTests(unittest.TestCase):
    """plan_repo with mocked gh: only the extra ruleset is configured."""

    REPO = "o/r"

    def _plan(self, live):
        """live: list of full rulesets that exist (each with id and name)."""
        summaries = [{"id": r["id"], "name": r["name"], "target": "branch"} for r in live]
        by_id = {r["id"]: r for r in live}
        with patch.object(rs, "list_rulesets", return_value=summaries), patch.object(
            rs, "get_ruleset", side_effect=lambda repo, i: by_id[i]
        ), patch.object(rs, "get_repo", return_value={"private": False}):
            return rs.plan_repo(self.REPO, {"extra_rulesets": [EXTRA_CFG]})

    def test_missing_plans_post(self):
        (rec,) = self._plan([])
        self.assertEqual(rec["setting"], "ruleset[roster proposal branch]")
        self.assertEqual(rec["status"], "drift")
        self.assertIsNone(rec["current"])
        kind, body, existing_id = rec["_writer"]
        self.assertEqual((kind, existing_id), ("ruleset", None))
        self.assertEqual(body["name"], "roster proposal branch")

    def test_drift_plans_put(self):
        live = dict(rs.build_extra_ruleset_body(EXTRA_CFG), id=42, rules=[{"type": "deletion"}])
        (rec,) = self._plan([live])
        self.assertEqual(rec["status"], "drift")
        self.assertEqual(rec["_writer"][2], 42)

    def test_match_is_no_write(self):
        live = dict(rs.build_extra_ruleset_body(EXTRA_CFG), id=42)
        live["rules"] = list(reversed(live["rules"]))
        (rec,) = self._plan([live])
        self.assertEqual(rec["status"], "match")

    def test_undeclared_live_ruleset_is_untouched(self):
        other = {
            "id": 9, "name": "something else", "target": "branch",
            "enforcement": "active", "rules": [], "bypass_actors": [],
            "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        }
        records = self._plan([other])
        self.assertEqual([r["setting"] for r in records], ["ruleset[roster proposal branch]"])
        self.assertEqual(records[0]["_writer"][2], None)

    def test_apply_record_posts_and_puts(self):
        body = rs.build_extra_ruleset_body(EXTRA_CFG)
        with patch.object(rs, "gh_api") as api:
            rs.apply_record("o/r", {"_writer": ("ruleset", body, None)})
            rs.apply_record("o/r", {"_writer": ("ruleset", body, 42)})
        self.assertEqual(
            [(c.args[0], c.kwargs.get("method", "GET")) for c in api.call_args_list],
            [("repos/o/r/rulesets", "POST"), ("repos/o/r/rulesets/42", "PUT")],
        )

    def test_private_no_pro_is_skipped(self):
        with patch.object(rs, "list_rulesets", side_effect=rs.GhError(403, "Upgrade")), patch.object(
            rs, "get_repo", return_value={"private": True}
        ):
            (rec,) = rs.plan_repo(self.REPO, {"extra_rulesets": [EXTRA_CFG]})
        self.assertEqual(rec["status"], "skipped")

    def test_other_error_is_reported(self):
        with patch.object(rs, "list_rulesets", side_effect=rs.GhError(500, "boom")), patch.object(
            rs, "get_repo", return_value={"private": False}
        ):
            (rec,) = rs.plan_repo(self.REPO, {"extra_rulesets": [EXTRA_CFG]})
        self.assertEqual(rec["status"], "error")


class GenerateDefaultRulesetByNameTests(unittest.TestCase):
    def test_extra_ruleset_is_not_misattributed_as_default(self):
        extra = dict(rs.build_extra_ruleset_body(EXTRA_CFG), id=1)
        default_body = rs.build_ruleset_body({"enabled": True})
        default = dict(default_body, id=2)
        summaries = [
            {"id": 1, "name": extra["name"], "target": "branch"},
            {"id": 2, "name": default["name"], "target": "branch"},
        ]
        by_id = {1: extra, 2: default}
        args = argparse.Namespace(repo="o/r")
        buf = io.StringIO()
        with patch.object(rs, "get_repo", return_value={"private": False}), patch.object(
            rs, "read_actions", return_value={}
        ), patch.object(rs, "read_fork_approval", return_value=None), patch.object(
            rs, "read_workflow_permissions", return_value={}
        ), patch.object(rs, "list_rulesets", return_value=summaries), patch.object(
            rs, "get_ruleset", side_effect=lambda repo, i: by_id[i]
        ), contextlib.redirect_stdout(buf):
            rs.cmd_generate(args)
        import yaml

        doc = yaml.safe_load(buf.getvalue())
        self.assertEqual(doc["ruleset"]["name"], rs.DEFAULT_RULESET_NAME)


class ExtraRulesetsFleetConfigTests(unittest.TestCase):
    FLEET = Path(__file__).resolve().parent.parent / "repo-settings" / "fleet.yml"

    def setUp(self):
        import yaml

        with open(self.FLEET, encoding="utf-8") as fh:
            self.cfg = yaml.safe_load(fh)
        self.targets = rs.resolve_targets(self.cfg, None)

    def test_defaults_declare_none(self):
        self.assertNotIn("extra_rulesets", self.cfg["defaults"])

    def test_skills_evals_declares_the_roster_and_persistent_rulesets(self):
        (t,) = [t for t in self.targets if t["repo"] == "Adam-S-Daniel/skills-evals"]
        self.assertEqual(
            [r["name"] for r in t["settings"]["extra_rulesets"]],
            [EXTRA_CFG["name"], "persistent branches"],
        )
        self.assertEqual(t["settings"]["extra_rulesets"][0], EXTRA_CFG)

    def test_skills_evals_declares_deletion_only_persistent_ruleset(self):
        # docs/decisions/0007: deletion blocked, no bypass actors.
        (t,) = [t for t in self.targets if t["repo"] == "Adam-S-Daniel/skills-evals"]
        bodies = {b["name"]: b for b in rs.build_extra_ruleset_bodies(t["settings"])}
        body = bodies["persistent branches"]
        self.assertEqual(body["conditions"]["ref_name"]["include"], ["refs/heads/persistent/**"])
        self.assertEqual(body["rules"], [{"type": "deletion"}])
        self.assertEqual(body["bypass_actors"], [])

    def test_only_known_repos_declare_extras(self):
        repos = {t["repo"] for t in self.targets if t["settings"].get("extra_rulesets")}
        self.assertEqual(
            repos, {
                "Adam-S-Daniel/skills-evals",
                "Adam-S-Daniel/_agent-guidance",
                "Adam-S-Daniel/GHA-bench",
            }
        )

    def test_agent_guidance_declares_deletion_only_persistent_ruleset(self):
        # docs/decisions/0007: deletion blocked, no bypass actors.
        (t,) = [t for t in self.targets if t["repo"] == "Adam-S-Daniel/_agent-guidance"]
        (body,) = rs.build_extra_ruleset_bodies(t["settings"])
        self.assertEqual(body["name"], "persistent branches")
        self.assertEqual(body["conditions"]["ref_name"]["include"], ["refs/heads/persistent/**"])
        self.assertEqual(body["rules"], [{"type": "deletion"}])
        self.assertEqual(body["bypass_actors"], [])

    def test_gha_bench_declares_deletion_only_persistent_ruleset(self):
        # docs/decisions/0007: deletion blocked, no bypass actors.
        # benchmark result branches persistent/benchmark-fable5 and
        # persistent/benchmark-sonnet5 are preserved results.
        (t,) = [t for t in self.targets if t["repo"] == "Adam-S-Daniel/GHA-bench"]
        (body,) = rs.build_extra_ruleset_bodies(t["settings"])
        self.assertEqual(body["name"], "persistent branches")
        self.assertEqual(body["conditions"]["ref_name"]["include"], ["refs/heads/persistent/**"])
        self.assertEqual(body["rules"], [{"type": "deletion"}])
        self.assertEqual(body["bypass_actors"], [])

    def test_every_declared_extra_builds(self):
        for t in self.targets:
            rs.build_extra_ruleset_bodies(t["settings"])

    def test_no_extra_ruleset_bypass_beyond_the_roster_app_and_admin(self):
        # github-actions (Integration id 15368) is also the Dependabot job's
        # identity; it must never bypass the roster ruleset.
        for t in self.targets:
            for body in rs.build_extra_ruleset_bodies(t["settings"]):
                for a in body["bypass_actors"]:
                    if a["actor_type"] == "Integration":
                        self.assertEqual(a["actor_id"], ROSTER_APP_ID, msg=t["repo"])
                    else:
                        self.assertEqual(
                            (a["actor_type"], a["actor_id"]), ("RepositoryRole", rs.ADMIN_ROLE_ID),
                            msg=t["repo"],
                        )

    def test_roster_admin_role_matches_default_ruleset_encoding(self):
        default = rs.build_ruleset_body({"enabled": True})
        admin = default["bypass_actors"][0]
        self.assertIn(admin, rs.build_extra_ruleset_body(EXTRA_CFG)["bypass_actors"])


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


class WorkflowPermissionsTests(unittest.TestCase):
    """Settings -> Actions -> General -> Workflow permissions: the GITHUB_TOKEN
    default scope and "Allow GitHub Actions to create and approve pull
    requests" (issue #51). One endpoint,
    `repos/{repo}/actions/permissions/workflow`, carries both."""

    LIVE = {"default_workflow_permissions": "read",
            "can_approve_pull_request_reviews": False}

    def _plan(self, actions, live=None, side_effect=None):
        with patch.object(rs, "gh_api",
                          return_value=dict(live if live is not None else self.LIVE),
                          side_effect=side_effect) as mock_api:
            records = rs.plan_repo_records("o/r", {"actions": actions})
        return records, mock_api

    def test_reads_the_workflow_permissions_endpoint(self):
        _, mock_api = self._plan({"can_approve_pull_request_reviews": False})
        mock_api.assert_called_once_with("repos/o/r/actions/permissions/workflow")

    def test_match_when_live_equals_desired(self):
        records, _ = self._plan({"default_workflow_permissions": "read",
                                 "can_approve_pull_request_reviews": False})
        self.assertEqual(
            [(r["setting"], r["status"]) for r in records],
            [("actions.default_workflow_permissions", "match"),
             ("actions.can_approve_pull_request_reviews", "match")],
        )

    def test_drift_is_reported_per_field(self):
        records, _ = self._plan({"default_workflow_permissions": "read",
                                 "can_approve_pull_request_reviews": True})
        by = {r["setting"]: r for r in records}
        self.assertEqual(by["actions.default_workflow_permissions"]["status"], "match")
        rec = by["actions.can_approve_pull_request_reviews"]
        self.assertEqual(rec["status"], "drift")
        self.assertIs(rec["current"], False)
        self.assertIs(rec["desired"], True)

    def test_omitted_keys_are_unmanaged(self):
        records, mock_api = self._plan({})
        self.assertEqual(records, [])
        mock_api.assert_not_called()

    def test_explicit_null_is_unmanaged(self):
        records, mock_api = self._plan({"can_approve_pull_request_reviews": None,
                                        "default_workflow_permissions": None})
        self.assertEqual(records, [])
        mock_api.assert_not_called()

    def test_a_value_github_does_not_accept_is_refused_at_plan_time(self):
        records, mock_api = self._plan({"default_workflow_permissions": "admin"})
        self.assertEqual([r["status"] for r in records], ["skipped"])
        self.assertIn("read", records[0]["note"])
        mock_api.assert_not_called()

    def test_absent_field_is_skipped_not_a_crash(self):
        records, _ = self._plan({"can_approve_pull_request_reviews": False}, live={})
        self.assertEqual([r["status"] for r in records], ["skipped"])
        self.assertIn("can_approve_pull_request_reviews", records[0]["note"])

    def test_empty_body_is_skipped_not_a_crash(self):
        with patch.object(rs, "gh_api", return_value=None):
            records = rs.plan_repo_records("o/r", {"actions": {"can_approve_pull_request_reviews": False}})
        self.assertEqual([r["status"] for r in records], ["skipped"])

    def test_403_is_a_skip_not_an_abort(self):
        records, _ = self._plan(
            {"default_workflow_permissions": "read",
             "can_approve_pull_request_reviews": False},
            side_effect=rs.GhError(403, "Resource not accessible by integration"),
        )
        self.assertEqual([r["status"] for r in records], ["skipped", "skipped"])

    def test_other_read_failure_is_an_error_record_per_field(self):
        records, _ = self._plan(
            {"default_workflow_permissions": "read",
             "can_approve_pull_request_reviews": False},
            side_effect=rs.GhError(500, "boom"),
        )
        self.assertEqual([r["status"] for r in records], ["error", "error"])

    def test_private_repos_are_managed_too(self):
        # No plan gate: the endpoint works on every plan. The planner must not
        # even ask whether the repo is private.
        with patch.object(rs, "get_repo") as mock_get_repo, \
                patch.object(rs, "gh_api", return_value=dict(self.LIVE)):
            records = rs.plan_repo("o/r", {"actions": {"can_approve_pull_request_reviews": True}})
        mock_get_repo.assert_not_called()
        self.assertEqual([r["status"] for r in records], ["drift"])

    def test_apply_puts_the_whole_declared_group_in_one_call(self):
        records, _ = self._plan({"default_workflow_permissions": "read",
                                 "can_approve_pull_request_reviews": True})
        rec = next(r for r in records if r["status"] == "drift")
        with patch.object(rs, "gh_api") as mock_api:
            rs.apply_record("o/r", rec)
        mock_api.assert_called_once_with(
            "repos/o/r/actions/permissions/workflow",
            method="PUT",
            body={"default_workflow_permissions": "read",
                  "can_approve_pull_request_reviews": True},
        )

    def test_a_partial_group_only_puts_what_the_config_names(self):
        records, _ = self._plan({"can_approve_pull_request_reviews": True})
        with patch.object(rs, "gh_api") as mock_api:
            rs.apply_record("o/r", records[0])
        mock_api.assert_called_once_with(
            "repos/o/r/actions/permissions/workflow",
            method="PUT",
            body={"can_approve_pull_request_reviews": True},
        )

    def test_apply_dry_run_and_live_run_through_cmd_apply(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = Path(d) / "c.yml"
            cfg.write_text(
                "repo: o/r\nactions:\n  can_approve_pull_request_reviews: true\n",
                encoding="utf-8",
            )
            calls = []

            def fake(path, method="GET", body=None):
                calls.append((path, method, body))
                return dict(self.LIVE)

            args = argparse.Namespace(config=str(cfg), repo=None, owner=None, dry_run=False)
            with patch.object(rs, "gh_api", side_effect=fake), \
                    contextlib.redirect_stdout(io.StringIO()):
                rc = rs.cmd_apply(args)
        self.assertEqual(rc, 0)
        self.assertIn(
            ("repos/o/r/actions/permissions/workflow", "PUT",
             {"can_approve_pull_request_reviews": True}),
            calls,
        )

    def test_generate_emits_both_fields(self):
        def fake(path, method="GET", body=None, api_version=None):
            if path == "repos/o/r":
                return {"private": True}
            if path == "repos/o/r/actions/permissions":
                return {"sha_pinning_required": True}
            if path == "repos/o/r/actions/permissions/workflow":
                return {"default_workflow_permissions": "write",
                        "can_approve_pull_request_reviews": True}
            if path == "repos/o/r/rulesets":
                raise rs.GhError(403, "upgrade")
            if path.startswith("repos/o/r/actions/policies"):
                raise rs.GhError(403, "no admin")
            raise AssertionError(path)

        out = io.StringIO()
        with patch.object(rs, "gh_api", side_effect=fake), contextlib.redirect_stdout(out):
            rs.cmd_generate(argparse.Namespace(repo="o/r"))
        import yaml
        doc = yaml.safe_load(out.getvalue())
        self.assertEqual(doc["actions"]["default_workflow_permissions"], "write")
        self.assertIs(doc["actions"]["can_approve_pull_request_reviews"], True)

    def test_generate_survives_an_unreadable_endpoint(self):
        def fake(path, method="GET", body=None, api_version=None):
            if path == "repos/o/r":
                return {"private": True}
            if path == "repos/o/r/actions/permissions":
                return {"sha_pinning_required": True}
            if path == "repos/o/r/actions/permissions/workflow":
                raise rs.GhError(403, "nope")
            if path == "repos/o/r/rulesets":
                raise rs.GhError(403, "upgrade")
            if path.startswith("repos/o/r/actions/policies"):
                raise rs.GhError(403, "no admin")
            raise AssertionError(path)

        out = io.StringIO()
        with patch.object(rs, "gh_api", side_effect=fake), contextlib.redirect_stdout(out):
            rc = rs.cmd_generate(argparse.Namespace(repo="o/r"))
        self.assertEqual(rc, 0)
        import yaml
        self.assertNotIn("can_approve_pull_request_reviews", yaml.safe_load(out.getvalue())["actions"])


class WorkflowPermissionsFleetConfigTests(unittest.TestCase):
    """issue #51: the fleet default, with no repo declared as an exception.
    Parsed and resolved through the engine, never regex-scanned."""

    FLEET = Path(__file__).resolve().parent.parent / "repo-settings" / "fleet.yml"
    # Repos allowed to let GITHUB_TOKEN create and approve PRs: skills-evals
    # only, so its scaffold gate can open draft fixture PRs (ADR 0008). Its
    # roster PR still goes through a dedicated GitHub App (ADR 0003 as
    # amended). Adding a repo is a policy decision (fleet.yml's bot-write block,
    # ADR 0001), not a config tweak.
    MAY_APPROVE = {"Adam-S-Daniel/skills-evals"}

    def setUp(self):
        import yaml

        with open(self.FLEET, encoding="utf-8") as fh:
            self.cfg = yaml.safe_load(fh)
        self.targets = [t for t in rs.resolve_targets(self.cfg, None) if t["manage"]]

    def test_approving_repos_require_no_approving_reviews(self):
        # With can_approve_pull_request_reviews true, GITHUB_TOKEN can submit an
        # approving review. That grants nothing only while the ruleset needs no
        # approvals; raising the count (or requiring approval for unattributed
        # changes) must revisit the setting first (ADR 0008).
        for t in self.targets:
            if t["settings"]["actions"]["can_approve_pull_request_reviews"] is not True:
                continue
            pr = t["settings"]["ruleset"]["require_pull_request"]
            self.assertEqual(pr["required_approving_review_count"], 0, msg=t["repo"])
            self.assertIs(pr["require_extra_approval_for_unattributed_changes"], False,
                          msg=t["repo"])

    def test_skills_evals_override_keeps_the_other_workflow_permission_default(self):
        (t,) = [t for t in self.targets if t["repo"] == "Adam-S-Daniel/skills-evals"]
        self.assertEqual(t["settings"]["actions"]["default_workflow_permissions"], "read")
        self.assertIs(t["settings"]["actions"]["can_approve_pull_request_reviews"], True)

    def test_defaults_declare_read_and_no_pr_approval(self):
        actions = self.cfg["defaults"]["actions"]
        self.assertEqual(actions["default_workflow_permissions"], "read")
        self.assertIs(actions["can_approve_pull_request_reviews"], False)

    def test_no_managed_repo_may_approve(self):
        allowed = {
            t["repo"] for t in self.targets
            if t["settings"]["actions"]["can_approve_pull_request_reviews"] is True
        }
        self.assertEqual(allowed, self.MAY_APPROVE)

    def test_every_managed_repo_declares_both_fields(self):
        for t in self.targets:
            actions = t["settings"]["actions"]
            self.assertIn(actions.get("default_workflow_permissions"), ("read", "write"),
                          msg=t["repo"])
            self.assertIsInstance(actions.get("can_approve_pull_request_reviews"), bool,
                                  msg=t["repo"])


class LabelSpecTests(unittest.TestCase):
    CFG = {"name": "eval-scaffold", "color": "C5DEF5",
           "description": "Draft real-work fixture opened by the scaffold gate"}

    def test_color_is_lowercased_and_description_kept(self):
        (spec,) = rs.build_label_specs({"labels": [self.CFG]})
        self.assertEqual(spec, {"name": "eval-scaffold", "color": "c5def5",
                                "description": self.CFG["description"]})

    def test_description_defaults_to_empty(self):
        (spec,) = rs.build_label_specs({"labels": [{"name": "x", "color": "000000"}]})
        self.assertEqual(spec["description"], "")

    def test_no_labels_is_no_specs(self):
        self.assertEqual(rs.build_label_specs({}), [])
        self.assertEqual(rs.build_label_specs({"labels": None}), [])

    def test_invalid_entries_are_refused(self):
        for bad in (
            "not a mapping",
            {"color": "000000"},
            {"name": " ", "color": "000000"},
            {"name": "x"},
            {"name": "x", "color": "#c5def5"},
            {"name": "x", "color": "c5def"},
            {"name": "x", "color": "gggggg"},
            {"name": "x", "color": "000000", "description": 5},
            {"name": "x", "color": "000000", "description": "d" * 101},
        ):
            with self.subTest(bad=bad), self.assertRaises(SystemExit):
                rs.build_label_specs({"labels": [bad]})

    def test_labels_must_be_a_list(self):
        with self.assertRaises(SystemExit):
            rs.build_label_specs({"labels": {"name": "x", "color": "000000"}})

    def test_names_are_unique_case_insensitively(self):
        with self.assertRaises(SystemExit):
            rs.build_label_specs({"labels": [
                {"name": "Eval", "color": "000000"}, {"name": "eval", "color": "111111"}]})

    DEFAULT = {"name": "agent-authored", "color": "D4C5F9"}

    def test_default_labels_reach_a_repo_with_none_of_its_own(self):
        cfg = {"defaults": {"labels": [self.DEFAULT]}, "repos": [{"name": "o/r"}, "o/s"]}
        for t in rs.resolve_targets(cfg, None):
            self.assertEqual(t["settings"]["labels"], [self.DEFAULT])

    def test_default_labels_merge_with_repo_labels(self):
        cfg = {"defaults": {"labels": [self.DEFAULT]},
               "repos": [{"name": "o/r", "overrides": {"labels": [self.CFG]}}]}
        (t,) = rs.resolve_targets(cfg, None)
        self.assertEqual(t["settings"]["labels"], [self.DEFAULT, self.CFG])

    def test_repo_label_wins_a_name_clash_case_insensitively(self):
        mine = {"name": "Agent-Authored", "color": "000000"}
        cfg = {"defaults": {"labels": [self.DEFAULT]},
               "repos": [{"name": "o/r", "overrides": {"labels": [mine]}}]}
        (t,) = rs.resolve_targets(cfg, None)
        self.assertEqual(t["settings"]["labels"], [mine])

    def test_merging_does_not_mutate_the_defaults(self):
        cfg = {"defaults": {"labels": [self.DEFAULT]},
               "repos": [{"name": "o/r", "overrides": {"labels": [self.CFG]}}]}
        rs.resolve_targets(cfg, None)
        self.assertEqual(cfg["defaults"]["labels"], [self.DEFAULT])

    def test_a_repo_override_carries_labels(self):
        cfg = {"defaults": {}, "repos": [{"name": "o/r", "overrides": {"labels": [self.CFG]}}]}
        (t,) = rs.resolve_targets(cfg, None)
        self.assertEqual(t["settings"]["labels"], [self.CFG])

    def test_single_repo_shape_carries_labels(self):
        (t,) = rs.resolve_targets({"repo": "o/r", "labels": [self.CFG]}, None)
        self.assertEqual(t["settings"]["labels"], [self.CFG])


class LabelPlanTests(unittest.TestCase):
    """plan_repo with mocked gh: only labels are configured."""

    REPO = "o/r"
    CFG = LabelSpecTests.CFG
    LIVE = {"name": "eval-scaffold", "color": "c5def5",
            "description": CFG["description"], "id": 1, "url": "ignored"}

    def _plan(self, side_effect=None, return_value=None, repo_side_effect=None):
        with patch.object(rs, "gh_api", side_effect=side_effect, return_value=return_value) as api, \
                patch.object(rs, "get_repo", return_value={"private": False},
                             side_effect=repo_side_effect) as get_repo:
            records = rs.plan_repo(self.REPO, {"labels": [self.CFG]})
        return records, api, get_repo

    def test_match_is_a_read_only_no_write(self):
        records, api, get_repo = self._plan(return_value=dict(self.LIVE))
        (rec,) = records
        self.assertEqual((rec["setting"], rec["status"]), ("label[eval-scaffold]", "match"))
        api.assert_called_once_with("repos/o/r/labels/eval-scaffold")
        get_repo.assert_not_called()

    def test_match_ignores_color_case_and_a_null_description(self):
        live = dict(self.LIVE, color="C5DEF5")
        (rec,), _, _ = self._plan(return_value=live)
        self.assertEqual(rec["status"], "match")
        cfg = {"name": "x", "color": "000000"}
        with patch.object(rs, "gh_api", return_value={"name": "x", "color": "000000",
                                                      "description": None}):
            (rec,) = rs.plan_repo(self.REPO, {"labels": [cfg]})
        self.assertEqual(rec["status"], "match")

    def test_missing_label_plans_a_create_after_probing_the_repo(self):
        records, _, get_repo = self._plan(side_effect=rs.GhError(404, "Not Found"))
        (rec,) = records
        self.assertEqual(rec["status"], "drift")
        self.assertIsNone(rec["current"])
        kind, spec, exists = rec["_writer"]
        self.assertEqual((kind, exists), ("label", False))
        self.assertEqual(spec["name"], "eval-scaffold")
        get_repo.assert_called_once_with(self.REPO)

    def test_404_on_an_invisible_repo_is_an_error_not_a_create(self):
        records, _, _ = self._plan(side_effect=rs.GhError(404, "Not Found"),
                                   repo_side_effect=rs.GhError(404, "Not Found"))
        (rec,) = records
        self.assertEqual(rec["status"], "error")
        self.assertNotIn("_writer", rec)

    def test_drifted_color_or_description_plans_a_patch(self):
        for live in (dict(self.LIVE, color="000000"), dict(self.LIVE, description="old")):
            with self.subTest(live=live):
                (rec,), _, _ = self._plan(return_value=live)
                self.assertEqual(rec["status"], "drift")
                self.assertEqual(rec["_writer"][0], "label")
                self.assertIs(rec["_writer"][2], True)

    def test_a_name_differing_only_in_case_is_drift(self):
        (rec,), _, _ = self._plan(return_value=dict(self.LIVE, name="Eval-Scaffold"))
        self.assertEqual(rec["status"], "drift")

    def test_other_read_errors_are_reported_per_label(self):
        (rec,), _, _ = self._plan(side_effect=rs.GhError(403, "Resource not accessible"))
        self.assertEqual(rec["status"], "error")

    def test_names_are_url_quoted(self):
        cfg = {"name": "needs review/x y", "color": "000000"}
        with patch.object(rs, "gh_api", return_value={"name": cfg["name"], "color": "000000",
                                                      "description": ""}) as api:
            rs.plan_repo(self.REPO, {"labels": [cfg]})
        api.assert_called_once_with("repos/o/r/labels/needs%20review%2Fx%20y")

    def test_unmanaged_when_undeclared(self):
        with patch.object(rs, "gh_api") as api, patch.object(rs, "get_repo") as get_repo:
            self.assertEqual(rs.plan_repo(self.REPO, {"repo": {}}), [])
        api.assert_not_called()
        get_repo.assert_not_called()

    def test_apply_posts_a_new_label(self):
        (rec,), _, _ = self._plan(side_effect=rs.GhError(404, "Not Found"))
        with patch.object(rs, "gh_api") as api:
            rs.apply_record(self.REPO, rec)
        api.assert_called_once_with(
            "repos/o/r/labels", method="POST",
            body={"name": "eval-scaffold", "color": "c5def5",
                  "description": self.CFG["description"]})

    def test_apply_patches_an_existing_label(self):
        (rec,), _, _ = self._plan(return_value=dict(self.LIVE, color="000000"))
        with patch.object(rs, "gh_api") as api:
            rs.apply_record(self.REPO, rec)
        api.assert_called_once_with(
            "repos/o/r/labels/eval-scaffold", method="PATCH",
            body={"color": "c5def5", "description": self.CFG["description"],
                  "new_name": "eval-scaffold"})

    def test_dry_run_through_cmd_apply_writes_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = Path(d) / "c.yml"
            cfg.write_text(
                "defaults: {}\nrepos:\n  - name: o/r\n    overrides:\n      labels:\n"
                "        - {name: eval-scaffold, color: C5DEF5}\n",
                encoding="utf-8",
            )
            calls = []

            def fake(path, method="GET", body=None):
                calls.append((method, path))
                if method == "GET" and "labels" in path:
                    raise rs.GhError(404, "Not Found")
                return {"private": False}

            args = argparse.Namespace(config=str(cfg), repo=None, owner=None, dry_run=True)
            with patch.object(rs, "gh_api", side_effect=fake), \
                    contextlib.redirect_stdout(io.StringIO()) as out:
                rc = rs.cmd_apply(args)
        self.assertEqual(rc, 0)
        self.assertIn("would change", out.getvalue())
        self.assertEqual({m for m, _ in calls}, {"GET"})


class LabelsFleetConfigTests(unittest.TestCase):
    FLEET = Path(__file__).resolve().parent.parent / "repo-settings" / "fleet.yml"

    def setUp(self):
        import yaml

        with open(self.FLEET, encoding="utf-8") as fh:
            self.cfg = yaml.safe_load(fh)
        self.targets = rs.resolve_targets(self.cfg, None)

    AGENT = {"name": "agent-authored", "color": "d4c5f9",
             "description": "Opened by an AI agent on the owner's behalf"}

    def test_defaults_declare_the_agent_authored_label(self):
        self.assertEqual(rs.build_label_specs(self.cfg["defaults"]), [self.AGENT])

    def test_every_managed_repo_gets_the_agent_authored_label(self):
        for t in self.targets:
            self.assertIn(self.AGENT, rs.build_label_specs(t["settings"]), msg=t["repo"])

    def test_only_skills_evals_declares_its_own_labels(self):
        own = {e["name"] for e in self.cfg["repos"]
               if isinstance(e, dict) and (e.get("overrides") or {}).get("labels")}
        self.assertEqual(own, {"Adam-S-Daniel/skills-evals"})

    def test_skills_evals_declares_the_scaffold_label(self):
        (t,) = [t for t in self.targets if t["repo"] == "Adam-S-Daniel/skills-evals"]
        self.assertEqual(
            rs.build_label_specs(t["settings"]),
            [self.AGENT,
             {"name": "eval-scaffold", "color": "c5def5",
              "description": "Draft real-work fixture opened by the scaffold gate"}],
        )


class GhApiVersionHeaderTests(unittest.TestCase):
    def _cmd(self, **kwargs):
        done = argparse.Namespace(returncode=0, stdout="{}", stderr="")
        with patch.object(rs.subprocess, "run", return_value=done) as run:
            rs.gh_api("repos/o/r", **kwargs)
        return run.call_args.args[0]

    def test_api_version_adds_the_header(self):
        cmd = self._cmd(api_version="2026-03-10")
        i = cmd.index("-H")
        self.assertEqual(cmd[i + 1], "X-GitHub-Api-Version: 2026-03-10")

    def test_header_comes_before_the_stdin_flag(self):
        done = argparse.Namespace(returncode=0, stdout="{}", stderr="")
        with patch.object(rs.subprocess, "run", return_value=done) as run:
            rs.gh_api("repos/o/r", method="POST", body={"a": 1}, api_version="2026-03-10")
        cmd = run.call_args.args[0]
        self.assertLess(cmd.index("-H"), cmd.index("--input"))

    def test_no_api_version_no_header(self):
        self.assertNotIn("-H", self._cmd())


POLICY_CFG = {
    "name": "plugin-runtime-review: allow pull_request_target",
    "enforcement": "active",
    "workflow_paths": {
        "include": [".github/workflows/plugin-runtime-review.yml"],
        "exclude": [],
    },
    "allowed_events": ["pull_request_target"],
}


def _policy_cfg(**changes):
    cfg = copy.deepcopy(POLICY_CFG)
    cfg.update(changes)
    return cfg


class ActionsPolicyBodyTests(unittest.TestCase):
    def test_fleet_entry_builds_the_exact_body(self):
        self.assertEqual(
            rs.build_actions_policy_body(POLICY_CFG),
            {
                "name": "plugin-runtime-review: allow pull_request_target",
                "enforcement": "active",
                "conditions": {
                    "workflow_path": {
                        "include": [".github/workflows/plugin-runtime-review.yml"],
                        "exclude": [],
                    }
                },
                "rules": [
                    {
                        "type": "restrict_action_events",
                        "parameters": {"allowed_events": ["pull_request_target"]},
                    }
                ],
            },
        )

    def test_enforcement_defaults_to_active(self):
        cfg = _policy_cfg()
        del cfg["enforcement"]
        self.assertEqual(rs.build_actions_policy_body(cfg)["enforcement"], "active")

    def test_disabled_is_accepted_and_exclude_defaults_empty(self):
        cfg = _policy_cfg(enforcement="disabled", workflow_paths={"include": ["a.yml"]})
        body = rs.build_actions_policy_body(cfg)
        self.assertEqual(body["enforcement"], "disabled")
        self.assertEqual(body["conditions"]["workflow_path"]["exclude"], [])

    def test_config_list_order_is_preserved(self):
        cfg = _policy_cfg(allowed_events=["push", "pull_request"],
                          workflow_paths={"include": ["b.yml", "a.yml"], "exclude": ["z.yml", "y.yml"]})
        body = rs.build_actions_policy_body(cfg)
        self.assertEqual(body["rules"][0]["parameters"]["allowed_events"], ["push", "pull_request"])
        self.assertEqual(body["conditions"]["workflow_path"],
                         {"include": ["b.yml", "a.yml"], "exclude": ["z.yml", "y.yml"]})

    def test_evaluate_is_refused_as_enterprise_only(self):
        with self.assertRaises(SystemExit) as cm:
            rs.build_actions_policy_body(_policy_cfg(enforcement="evaluate"))
        self.assertIn("Enterprise Cloud", str(cm.exception))

    def test_bogus_enforcement_is_refused(self):
        with self.assertRaises(SystemExit):
            rs.build_actions_policy_body(_policy_cfg(enforcement="loud"))

    def test_bad_name_is_refused(self):
        for bad in (None, "", "  ", 7):
            with self.subTest(name=bad), self.assertRaises(SystemExit):
                rs.build_actions_policy_body(_policy_cfg(name=bad))
        cfg = _policy_cfg()
        del cfg["name"]
        with self.assertRaises(SystemExit):
            rs.build_actions_policy_body(cfg)

    def test_non_mapping_entry_is_refused(self):
        with self.assertRaises(SystemExit):
            rs.build_actions_policy_body("plugin-runtime-review")

    def test_unknown_top_level_key_is_refused_and_named(self):
        cfg = _policy_cfg()
        del cfg["enforcement"]
        cfg["enforcment"] = "disabled"
        with self.assertRaises(SystemExit) as cm:
            rs.build_actions_policy_body(cfg)
        self.assertIn("enforcment", str(cm.exception))

    def test_unknown_workflow_paths_key_is_refused(self):
        cfg = _policy_cfg(workflow_paths={"include": ["a.yml"], "inlcude": ["b.yml"]})
        with self.assertRaises(SystemExit):
            rs.build_actions_policy_body(cfg)

    def test_workflow_paths_must_be_a_mapping(self):
        for bad in (None, ["a.yml"]):
            with self.subTest(bad=bad), self.assertRaises(SystemExit):
                rs.build_actions_policy_body(_policy_cfg(workflow_paths=bad))

    def test_include_must_be_a_non_empty_list_of_strings(self):
        for bad in (None, [], "a.yml", [""], [1]):
            with self.subTest(include=bad), self.assertRaises(SystemExit):
                rs.build_actions_policy_body(_policy_cfg(workflow_paths={"include": bad}))

    def test_all_with_another_path_is_refused_but_alone_is_accepted(self):
        with self.assertRaises(SystemExit):
            rs.build_actions_policy_body(_policy_cfg(workflow_paths={"include": ["~ALL", "a.yml"]}))
        body = rs.build_actions_policy_body(_policy_cfg(workflow_paths={"include": ["~ALL"]}))
        self.assertEqual(body["conditions"]["workflow_path"]["include"], ["~ALL"])

    def test_exclude_must_be_a_list_of_strings(self):
        for bad in ("a.yml", None, [""], [1]):
            with self.subTest(exclude=bad), self.assertRaises(SystemExit):
                rs.build_actions_policy_body(
                    _policy_cfg(workflow_paths={"include": ["a.yml"], "exclude": bad}))

    def test_allowed_events_must_be_a_non_empty_unique_list_of_strings(self):
        for bad in (None, [], "push", [""], [1], ["push", "push"]):
            with self.subTest(events=bad), self.assertRaises(SystemExit):
                rs.build_actions_policy_body(_policy_cfg(allowed_events=bad))

    def test_bodies_absent_is_empty(self):
        self.assertEqual(rs.build_actions_policy_bodies({}), [])
        self.assertEqual(rs.build_actions_policy_bodies({"actions_policies": None}), [])

    def test_bodies_must_be_a_list(self):
        with self.assertRaises(SystemExit):
            rs.build_actions_policy_bodies({"actions_policies": POLICY_CFG})

    def test_duplicate_names_across_entries_are_refused(self):
        with self.assertRaises(SystemExit):
            rs.build_actions_policy_bodies({"actions_policies": [POLICY_CFG, _policy_cfg()]})


class NormalizeActionsPolicyTests(unittest.TestCase):
    DESIRED = rs.normalize_actions_policy(rs.build_actions_policy_body(
        _policy_cfg(workflow_paths={"include": ["a.yml", "b.yml"], "exclude": ["c.yml", "d.yml"]},
                    allowed_events=["pull_request_target", "push"])))

    def _live(self, **changes):
        live = {
            "id": 42,
            "node_id": "N_1",
            "name": POLICY_CFG["name"],
            "target": "actions",
            "source_type": "Repository",
            "source": "o/r",
            "enforcement": "active",
            "conditions": {"workflow_path": {"include": ["b.yml", "a.yml"],
                                             "exclude": ["d.yml", "c.yml"]}},
            "rules": [{"type": "restrict_action_events",
                       "parameters": {"allowed_events": ["push", "pull_request_target"]}}],
            "_links": {"self": {"href": "https://api.github.com/x"}},
            "created_at": "2026-10-01T00:00:00Z",
            "updated_at": "2026-10-02T00:00:00Z",
        }
        live.update(changes)
        return live

    def test_live_payload_normalizes_equal_to_desired(self):
        self.assertEqual(rs.normalize_actions_policy(self._live()), self.DESIRED)

    def test_none_is_none(self):
        self.assertIsNone(rs.normalize_actions_policy(None))

    def test_absent_or_null_sections_do_not_raise(self):
        for changes in ({"conditions": None}, {"rules": None},
                        {"conditions": {"workflow_path": None}},
                        {"rules": [{"type": "restrict_action_events", "parameters": None}]},
                        {"rules": [{"type": "restrict_action_events"}]}):
            with self.subTest(changes=changes):
                self.assertIsInstance(rs.normalize_actions_policy(self._live(**changes)), dict)
        self.assertIsInstance(rs.normalize_actions_policy({}), dict)

    def test_different_events_normalize_different(self):
        live = self._live(rules=[{"type": "restrict_action_events",
                                  "parameters": {"allowed_events": ["push"]}}])
        self.assertNotEqual(rs.normalize_actions_policy(live), self.DESIRED)

    def test_an_extra_actors_rule_normalizes_different(self):
        live = self._live()
        live["rules"].append({"type": "restrict_actions_actors",
                              "parameters": {"allowed_actors": ["octocat"]}})
        self.assertNotEqual(rs.normalize_actions_policy(live), self.DESIRED)

    def test_enforcement_and_paths_are_compared(self):
        self.assertNotEqual(rs.normalize_actions_policy(self._live(enforcement="disabled")),
                            self.DESIRED)
        live = self._live(conditions={"workflow_path": {"include": ["a.yml"], "exclude": []}})
        self.assertNotEqual(rs.normalize_actions_policy(live), self.DESIRED)


class ActionsPolicyPlanTests(unittest.TestCase):
    """plan_repo with mocked gh: only actions_policies is configured."""

    REPO = "o/r"
    BODY = rs.build_actions_policy_body(POLICY_CFG)
    V = rs.ACTIONS_POLICIES_API_VERSION

    def _live(self, id=42, name=POLICY_CFG["name"], **changes):
        return dict(copy.deepcopy(self.BODY), id=id, name=name, source_type="Repository", **changes)

    def _plan(self, listing, by_id=None, cfgs=(POLICY_CFG,), list_error=None):
        """listing: payload for the policies list (or an exception to raise)."""
        by_id = by_id or {}
        calls = []

        def fake(path, method="GET", body=None, api_version=None):
            calls.append((path, method, api_version))
            if "/actions/policies?" in path:
                if isinstance(listing, Exception):
                    raise listing
                return listing
            pid = path.rsplit("/", 1)[1]
            value = by_id[int(pid)]
            if isinstance(value, Exception):
                raise value
            return value

        with patch.object(rs, "gh_api", side_effect=fake), \
                patch.object(rs, "get_repo") as get_repo:
            records = rs.plan_repo(self.REPO, {"actions_policies": list(cfgs)})
        get_repo.assert_not_called()
        return records, calls

    def _listing(self, *policies):
        return {"total_count": len(policies), "policies": list(policies)}

    def test_absent_plans_a_create(self):
        (rec,), calls = self._plan(self._listing())
        self.assertEqual(rec["setting"], f"actions_policy[{POLICY_CFG['name']}]")
        self.assertEqual(rec["status"], "drift")
        self.assertIsNone(rec["current"])
        self.assertEqual(rec["_writer"], ("actions_policy", self.BODY, None))
        self.assertTrue(calls)
        self.assertTrue(all(v == self.V for _, _, v in calls))

    def test_present_and_equal_matches_with_no_write(self):
        live = self._live(node_id="N", _links={}, created_at="x", updated_at="y")
        (rec,), calls = self._plan(self._listing(live), {42: live})
        self.assertEqual(rec["status"], "match")
        self.assertEqual([m for _, m, _ in calls], ["GET", "GET"])
        self.assertTrue(calls[1][0].endswith("/actions/policies/42"))
        self.assertTrue(all(v == self.V for _, _, v in calls))

    def test_present_and_different_plans_a_put_on_the_live_id(self):
        live = self._live(enforcement="disabled")
        (rec,), _ = self._plan(self._listing(live), {42: live})
        self.assertEqual(rec["status"], "drift")
        self.assertEqual(rec["_writer"], ("actions_policy", self.BODY, 42))

    def test_unreadable_list_is_skipped_per_declared_policy(self):
        second = _policy_cfg(name="second")
        for status in (403, 404, 422):
            with self.subTest(status=status):
                recs, _ = self._plan(rs.GhError(status, "nope"), cfgs=(POLICY_CFG, second))
                self.assertEqual([r["status"] for r in recs], ["skipped", "skipped"])
                self.assertIn(f"HTTP {status}", recs[0]["note"])
                self.assertTrue(all("_writer" not in r for r in recs))

    def test_other_list_failure_is_an_error(self):
        (rec,), _ = self._plan(rs.GhError(500, "boom"))
        self.assertEqual(rec["status"], "error")

    def test_payload_without_a_policies_list_is_skipped(self):
        for payload in ({}, None, [], {"policies": None}, {"total_count": 0}):
            with self.subTest(payload=payload):
                (rec,), _ = self._plan(payload)
                self.assertEqual(rec["status"], "skipped")
                self.assertNotIn("_writer", rec)

    def test_two_live_policies_with_the_name_is_an_error(self):
        a, b = self._live(id=1), self._live(id=2)
        (rec,), calls = self._plan(self._listing(a, b), {})
        self.assertEqual(rec["status"], "error")
        self.assertNotIn("_writer", rec)
        self.assertIn("2 repository Actions policies", rec["note"])
        self.assertEqual(len(calls), 1)  # the list only; neither fetched by id

    def test_undeclared_live_policy_is_ignored_and_never_fetched(self):
        other = self._live(id=9, name="something else")
        (rec,), calls = self._plan(self._listing(other))
        self.assertEqual(rec["status"], "drift")
        self.assertIsNone(rec["_writer"][2])
        self.assertFalse(any(p.endswith("/9") for p, _, _ in calls))

    def test_inherited_policy_with_the_same_name_is_ignored(self):
        inherited = self._live(id=7)
        inherited["source_type"] = "Organization"
        (rec,), calls = self._plan(self._listing(inherited))
        self.assertEqual(rec["status"], "drift")
        self.assertIsNone(rec["_writer"][2])
        self.assertEqual(len(calls), 1)

    def test_a_match_without_an_id_is_skipped(self):
        live = self._live()
        del live["id"]
        (rec,), _ = self._plan(self._listing(live))
        self.assertEqual(rec["status"], "skipped")
        self.assertIn("id", rec["note"])

    def test_get_by_id_403_is_skipped(self):
        live = self._live()
        (rec,), _ = self._plan(self._listing(live), {42: rs.GhError(403, "nope")})
        self.assertEqual(rec["status"], "skipped")

    def test_get_by_id_500_is_an_error(self):
        live = self._live()
        (rec,), _ = self._plan(self._listing(live), {42: rs.GhError(500, "boom")})
        self.assertEqual(rec["status"], "error")

    def test_one_policy_failing_does_not_stop_the_next(self):
        second_cfg = _policy_cfg(name="second")
        first = self._live(id=1)
        second = dict(self._live(id=2, name="second"))
        recs, _ = self._plan(self._listing(first, second),
                             {1: rs.GhError(403, "nope"), 2: second}, cfgs=(POLICY_CFG, second_cfg))
        self.assertEqual([r["status"] for r in recs], ["skipped", "match"])

    def test_pagination_reads_page_two_when_page_one_is_full(self):
        full = [self._live(id=i, name=f"p{i}") for i in range(100)]
        pages = []

        def fake(path, method="GET", body=None, api_version=None):
            pages.append(path)
            if path.endswith("page=1"):
                return {"total_count": 101, "policies": full}
            return {"total_count": 101, "policies": [self._live(id=500)]}

        with patch.object(rs, "gh_api", side_effect=fake):
            out = rs.list_actions_policies(self.REPO)
        self.assertEqual(len(out), 101)
        self.assertEqual([p.rsplit("&", 1)[1] for p in pages], ["page=1", "page=2"])

    def test_a_short_page_stops_pagination(self):
        with patch.object(rs, "gh_api", return_value=self._listing(self._live())) as api:
            rs.list_actions_policies(self.REPO)
        api.assert_called_once()

    def test_undeclared_config_makes_no_gh_calls(self):
        with patch.object(rs, "gh_api") as api, patch.object(rs, "get_repo") as get_repo:
            self.assertEqual(rs.plan_repo(self.REPO, {}), [])
        api.assert_not_called()
        get_repo.assert_not_called()


class ActionsPolicyApplyTests(unittest.TestCase):
    BODY = rs.build_actions_policy_body(POLICY_CFG)

    def test_create_posts_the_full_body(self):
        with patch.object(rs, "gh_api") as api:
            rs.apply_record("o/r", {"_writer": ("actions_policy", self.BODY, None)})
        api.assert_called_once_with("repos/o/r/actions/policies", method="POST",
                                    body=self.BODY, api_version="2026-03-10")

    def test_update_puts_the_full_body_on_the_id(self):
        with patch.object(rs, "gh_api") as api:
            rs.apply_record("o/r", {"_writer": ("actions_policy", self.BODY, 42)})
        api.assert_called_once_with("repos/o/r/actions/policies/42", method="PUT",
                                    body=self.BODY, api_version="2026-03-10")

    def _run(self, cmd, **ns):
        with tempfile.TemporaryDirectory() as d:
            cfg = Path(d) / "c.yml"
            cfg.write_text(
                "defaults: {}\nrepos:\n  - name: o/r\n    overrides:\n      actions_policies:\n"
                "        - name: p\n          workflow_paths: {include: [a.yml]}\n"
                "          allowed_events: [pull_request_target]\n",
                encoding="utf-8",
            )
            calls = []

            def fake(path, method="GET", body=None, api_version=None):
                calls.append((method, path))
                return {"total_count": 0, "policies": []}

            args = argparse.Namespace(config=str(cfg), repo=None, owner=None, **ns)
            with patch.object(rs, "gh_api", side_effect=fake), \
                    contextlib.redirect_stdout(io.StringIO()) as out:
                rc = cmd(args)
        return rc, out.getvalue(), calls

    def test_dry_run_through_cmd_apply_issues_only_gets(self):
        rc, out, calls = self._run(rs.cmd_apply, dry_run=True)
        self.assertEqual(rc, 0)
        self.assertIn("would change", out)
        self.assertEqual({m for m, _ in calls}, {"GET"})

    def test_cmd_diff_reports_drift(self):
        rc, out, _ = self._run(rs.cmd_diff)
        self.assertEqual(rc, 1)
        self.assertIn("DRIFT", out)


class ActionsPolicyGenerateTests(unittest.TestCase):
    def _live(self, **changes):
        live = dict(rs.build_actions_policy_body(POLICY_CFG), id=42, source_type="Repository")
        live.update(changes)
        return live

    def test_doc_round_trips(self):
        live = self._live(rules=[
            {"type": "restrict_action_events", "parameters": {"allowed_events": ["push", "schedule"]}},
            {"type": "restrict_action_events", "parameters": {"allowed_events": ["schedule", "pull_request"]}},
        ])
        doc = rs.actions_policy_doc(live)
        self.assertEqual(doc["allowed_events"], ["push", "schedule", "pull_request"])
        self.assertEqual(
            rs.normalize_actions_policy(rs.build_actions_policy_body(doc)),
            rs.normalize_actions_policy(dict(live, rules=[{
                "type": "restrict_action_events",
                "parameters": {"allowed_events": ["push", "schedule", "pull_request"]}}])),
        )
        self.assertEqual(rs.actions_policy_doc(self._live()), POLICY_CFG)

    def test_inexpressible_policies_return_none(self):
        actors = {"type": "restrict_actions_actors", "parameters": {"allowed_actors": ["x"]}}
        events = self._live()["rules"]
        cases = {
            "actors rule": self._live(rules=events + [actors]),
            "no rules": self._live(rules=[]),
            "null rules": self._live(rules=None),
            "evaluate": self._live(enforcement="evaluate"),
            "empty include": self._live(conditions={"workflow_path": {"include": [], "exclude": []}}),
            "no conditions": self._live(conditions=None),
        }
        for label, live in cases.items():
            with self.subTest(label):
                self.assertIsNone(rs.actions_policy_doc(live))

    def _generate(self, summaries, by_id):
        import yaml

        def get(repo, pid):
            value = by_id[pid]
            if isinstance(value, Exception):
                raise value
            return value

        out, err = io.StringIO(), io.StringIO()
        with patch.object(rs, "get_repo", return_value={"private": True}), \
                patch.object(rs, "read_actions", return_value={"sha_pinning_required": True}), \
                patch.object(rs, "read_fork_approval", return_value=None), \
                patch.object(rs, "read_workflow_permissions", return_value={}), \
                patch.object(rs, "list_rulesets", return_value=[]), \
                patch.object(rs, "list_actions_policies", return_value=summaries), \
                patch.object(rs, "get_actions_policy", side_effect=get), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rs.cmd_generate(argparse.Namespace(repo="o/r"))
        return yaml.safe_load(out.getvalue()), err.getvalue()

    def test_generate_emits_the_expressible_policy_and_notes_the_rest(self):
        good = self._live()
        bad = self._live(id=43, name="actors", rules=[
            {"type": "restrict_actions_actors", "parameters": {"allowed_actors": ["x"]}}])
        doc, err = self._generate(
            [{"id": 42, "name": good["name"]}, {"id": 43, "name": "actors"}], {42: good, 43: bad})
        self.assertEqual(doc["actions_policies"], [POLICY_CFG])
        self.assertIn("generate: skipping Actions policy 'actors' -- not expressible in "
                      "actions_policies", err)

    def test_generate_notes_a_policy_it_cannot_read(self):
        doc, err = self._generate([{"id": 42, "name": "p"}], {42: rs.GhError(403, "nope")})
        self.assertNotIn("actions_policies", doc)
        self.assertIn("generate: skipping Actions policy 'p' -- ", err)

    def test_generate_omits_the_block_when_policies_are_unavailable(self):
        doc, err = self._generate(None, {})
        self.assertNotIn("actions_policies", doc)
        self.assertEqual(err, "")


class ActionsPoliciesFleetConfigTests(unittest.TestCase):
    FLEET = Path(__file__).resolve().parent.parent / "repo-settings" / "fleet.yml"

    def setUp(self):
        import yaml

        with open(self.FLEET, encoding="utf-8") as fh:
            self.cfg = yaml.safe_load(fh)
        self.targets = rs.resolve_targets(self.cfg, None)

    def test_defaults_declare_none(self):
        self.assertNotIn("actions_policies", self.cfg["defaults"])

    def test_only_adam_agentskills_declares_policies(self):
        repos = {t["repo"] for t in self.targets if t["settings"].get("actions_policies")}
        self.assertEqual(repos, {"Adam-S-Daniel/adam-agentskills"})

    def test_adam_agentskills_allows_only_pull_request_target_on_its_review_workflow(self):
        (t,) = [t for t in self.targets if t["repo"] == "Adam-S-Daniel/adam-agentskills"]
        self.assertEqual(
            rs.build_actions_policy_bodies(t["settings"]),
            [{"name": "plugin-runtime-review: allow pull_request_target",
              "enforcement": "active",
              "conditions": {"workflow_path": {
                  "include": [".github/workflows/plugin-runtime-review.yml"], "exclude": []}},
              "rules": [{"type": "restrict_action_events",
                         "parameters": {"allowed_events": ["pull_request_target"]}}]}],
        )

    def test_no_declared_policy_uses_all(self):
        # `allowed_events` is an allowlist for every workflow a policy covers: a
        # ~ALL policy would block each event it does not list, repo-wide.
        for t in self.targets:
            for body in rs.build_actions_policy_bodies(t["settings"]):
                self.assertNotIn("~ALL", body["conditions"]["workflow_path"]["include"])


class ActionsPoliciesDefaultsTests(unittest.TestCase):
    def test_defaults_level_actions_policies_is_refused(self):
        cfg = {"defaults": {"actions_policies": [POLICY_CFG]}, "repos": [{"name": "o/r"}]}
        with self.assertRaises(SystemExit) as cm:
            rs.resolve_targets(cfg, None)
        self.assertIn("per-repo only", str(cm.exception))

    def test_single_repo_config_carries_the_key(self):
        cfg = {"repo": "o/r", "actions_policies": [POLICY_CFG]}
        (t,) = rs.resolve_targets(cfg, None)
        self.assertEqual(t["settings"]["actions_policies"], [POLICY_CFG])
