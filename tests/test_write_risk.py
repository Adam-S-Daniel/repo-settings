"""Which planned writes the unreviewed apply may make (docs/decisions/0019).

`write_risk` is an allowlist: a write is SAFE only when it is shown that it
cannot leave a repo with fewer constraints than it has now, and everything
else is GATED and waits for the reviewed apply. These tests hold both halves:
the directions that are safe, and that anything unknown fails closed. They are
offline (no gh, no network).

The live ruleset bodies below have the shape GitHub returned for the fleet's
rulesets on 2026-11-17, with invented ids.
"""

import argparse
import ast
import copy
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import repo_settings as rs

SAFE, GATED = rs.SAFE, rs.GATED

BOT = {"actor_type": "Integration", "actor_id": 1234567, "bypass_mode": "always"}
RULESET_CFG = {
    "enabled": True,
    "name": "default branch protection",
    "admin_bypass": "always",
    "bypass_actors": [BOT],
    "require_pull_request": {
        "required_approving_review_count": 0,
        "allowed_merge_methods": ["merge"],
        "require_extra_approval_for_unattributed_changes": False,
    },
    "required_status_checks": ["test", "agent-checks"],
}


def live_default(**changes):
    """The live `default branch protection` ruleset RULESET_CFG converges to."""
    body = {
        "id": 111,
        "name": "default branch protection",
        "target": "branch",
        "source_type": "Repository",
        "source": "example/example",
        "enforcement": "active",
        "conditions": {"ref_name": {"exclude": [], "include": ["~DEFAULT_BRANCH"]}},
        "rules": [
            {"type": "deletion"},
            {"type": "non_fast_forward"},
            {"type": "pull_request", "parameters": {
                "required_approving_review_count": 0,
                "dismiss_stale_reviews_on_push": False,
                "required_reviewers": [],
                "require_code_owner_review": False,
                "require_last_push_approval": False,
                "required_review_thread_resolution": False,
                "require_extra_approval_for_unattributed_changes": False,
                "allowed_merge_methods": ["merge"],
            }},
            {"type": "required_status_checks", "parameters": {
                "strict_required_status_checks_policy": False,
                "do_not_enforce_on_create": False,
                "required_status_checks": [{"context": "test"}, {"context": "agent-checks"}],
            }},
        ],
        "node_id": "RRS_example",
        "created_at": "2026-10-01T00:00:00Z",
        "updated_at": "2026-10-02T00:00:00Z",
        "bypass_actors": [
            {"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"},
            {"actor_id": 1234567, "actor_type": "Integration", "bypass_mode": "always"},
        ],
        "current_user_can_bypass": "always",
        "_links": {"self": {"href": "https://api.github.com/x"}},
    }
    body.update(changes)
    return body


def rule(body, rule_type):
    return next(r for r in body["rules"] if r["type"] == rule_type)


def ruleset_record(live, cfg):
    """The drift record plan_ruleset builds for `cfg` against `live`."""
    body = rs.build_ruleset_body(cfg)
    return {
        "setting": f"ruleset[{body['name']}]",
        "status": "drift",
        "current": rs.normalize_ruleset(live),
        "desired": rs.normalize_ruleset(body),
        "_writer": ("ruleset", body, live["id"] if live else None),
        "_live": live,
    }


def cfg_with(**changes):
    cfg = copy.deepcopy(RULESET_CFG)
    for key, value in changes.items():
        if isinstance(value, dict) and isinstance(cfg.get(key), dict):
            cfg[key].update(value)
        else:
            cfg[key] = value
    return cfg


class RulesetRiskTests(unittest.TestCase):
    def risk(self, live, cfg):
        rec = ruleset_record(live, cfg)
        return rs.write_risk(rec, [rec])

    def assertSafe(self, live, cfg):
        verdict, reason = self.risk(live, cfg)
        self.assertEqual(verdict, SAFE, reason)

    def assertGated(self, live, cfg, *words):
        verdict, reason = self.risk(live, cfg)
        self.assertEqual(verdict, GATED, reason)
        for word in words:
            self.assertIn(word, reason)

    def test_the_fixture_is_what_the_config_converges_to(self):
        # Otherwise every case below would differ from live in more than the
        # one thing it names.
        body = rs.build_ruleset_body(RULESET_CFG)
        self.assertEqual(rs.normalize_ruleset(live_default()), rs.normalize_ruleset(body))

    def test_adding_a_required_check_is_safe(self):
        # The plan of repo-settings run 44204576489, which waited for approval.
        self.assertSafe(live_default(),
                        cfg_with(required_status_checks=["test", "agent-checks", "starter-suites"]))

    def test_removing_or_renaming_a_required_check_gates(self):
        self.assertGated(live_default(), cfg_with(required_status_checks=["test"]),
                         "agent-checks", "removed")
        self.assertGated(live_default(),
                         cfg_with(required_status_checks=["test", "agent-checks-v2"]),
                         "agent-checks", "removed")

    def test_dropping_the_whole_checks_rule_gates(self):
        self.assertGated(live_default(), cfg_with(required_status_checks=[]),
                         "required_status_checks", "removed")

    def test_adding_a_rule_is_safe(self):
        live = live_default()
        live["rules"] = [r for r in live["rules"] if r["type"] != "required_status_checks"]
        self.assertSafe(live, RULESET_CFG)

    def test_removing_a_rule_gates(self):
        self.assertGated(live_default(), cfg_with(block_force_pushes=False),
                         "non_fast_forward", "removed")
        self.assertGated(live_default(), cfg_with(require_pull_request=None),
                         "pull_request", "removed")

    def test_an_added_bypass_actor_gates_and_is_named(self):
        other = {"actor_type": "Integration", "actor_id": 7654321, "bypass_mode": "always"}
        self.assertGated(live_default(), cfg_with(bypass_actors=[BOT, other]),
                         "bypass actor(s) added", "7654321")

    def test_a_changed_bypass_mode_gates(self):
        # always -> pull_request narrows, but the triple is new; not worth a
        # second rule to save one approval.
        self.assertGated(live_default(), cfg_with(admin_bypass="pull_request"),
                         "bypass actor(s) added")

    def test_removing_a_bypass_actor_is_safe(self):
        self.assertSafe(live_default(), cfg_with(bypass_actors=[]))
        self.assertSafe(live_default(), cfg_with(admin_bypass="none"))

    def test_hidden_or_unreadable_live_bypass_actors_gate(self):
        hidden = live_default()
        del hidden["bypass_actors"]
        change = cfg_with(required_status_checks=["test", "agent-checks", "more"])
        self.assertGated(hidden, change, "bypass actors")
        self.assertGated(live_default(bypass_actors=None), change, "bypass actors")
        odd = live_default()
        odd["bypass_actors"][0]["extra"] = 1
        self.assertGated(odd, change, "bypass actors")

    def test_a_record_planned_with_bypass_unknown_gates(self):
        rec = ruleset_record(live_default(), cfg_with(required_status_checks=["test", "agent-checks", "more"]))
        rec["bypass_unknown"] = True
        self.assertEqual(rs.write_risk(rec, [rec])[0], GATED)

    def test_changing_which_refs_are_covered_gates(self):
        self.assertGated(live_default(), cfg_with(target_branches=["main"]), "conditions")
        excluded = live_default()
        excluded["conditions"]["ref_name"]["exclude"] = ["refs/heads/x"]
        self.assertGated(excluded, cfg_with(required_status_checks=["test", "agent-checks", "more"]),
                         "conditions")
        odd = live_default()
        odd["conditions"]["repository_name"] = {"include": ["x"]}
        self.assertGated(odd, RULESET_CFG, "conditions")

    def test_enforcement_may_only_move_to_active(self):
        self.assertSafe(live_default(enforcement="disabled"), RULESET_CFG)
        self.assertSafe(live_default(enforcement="evaluate"), RULESET_CFG)
        self.assertGated(live_default(), cfg_with(enforcement="disabled"), "enforcement")
        self.assertGated(live_default(), cfg_with(enforcement="evaluate"), "enforcement")

    def test_pull_request_parameters_may_only_get_stricter(self):
        pr = RULESET_CFG["require_pull_request"]
        self.assertSafe(live_default(), cfg_with(
            require_pull_request=dict(pr, required_approving_review_count=1)))
        self.assertSafe(live_default(), cfg_with(
            require_pull_request=dict(pr, require_extra_approval_for_unattributed_changes=True)))
        self.assertSafe(live_default(), cfg_with(
            require_pull_request=dict(pr, dismiss_stale_reviews=True)))

        stricter = live_default()
        rule(stricter, "pull_request")["parameters"].update(
            required_approving_review_count=1,
            require_extra_approval_for_unattributed_changes=True,
            dismiss_stale_reviews_on_push=True)
        add_check = ["test", "agent-checks", "more"]
        for key, value, word in (
            ("required_approving_review_count", 1, None),
            ("require_extra_approval_for_unattributed_changes", True, None),
        ):
            with self.subTest(relaxed=key):
                cfg = cfg_with(required_status_checks=add_check,
                               require_pull_request=dict(
                                   pr, required_approving_review_count=1,
                                   require_extra_approval_for_unattributed_changes=True,
                                   dismiss_stale_reviews=True))
                cfg["require_pull_request"][key] = (0 if value == 1 else False)
                self.assertGated(stricter, cfg, key)

    def test_merge_methods_may_only_narrow(self):
        pr = RULESET_CFG["require_pull_request"]
        wide = live_default()
        rule(wide, "pull_request")["parameters"]["allowed_merge_methods"] = ["merge", "squash", "rebase"]
        self.assertSafe(wide, RULESET_CFG)
        self.assertGated(live_default(), cfg_with(
            require_pull_request=dict(pr, allowed_merge_methods=["merge", "squash"])),
            "allowed_merge_methods")
        self.assertGated(live_default(), cfg_with(
            require_pull_request=dict(pr, allowed_merge_methods=["squash"])),
            "allowed_merge_methods")

    def test_a_reordered_list_is_not_a_change(self):
        live = live_default()
        rule(live, "pull_request")["parameters"]["allowed_merge_methods"] = ["squash", "merge"]
        rule(live, "required_status_checks")["parameters"]["required_status_checks"].reverse()
        pr = RULESET_CFG["require_pull_request"]
        self.assertSafe(live, cfg_with(
            bypass_actors=[],
            require_pull_request=dict(pr, allowed_merge_methods=["merge", "squash"])))

    def test_a_live_setting_the_write_would_reset_gates(self):
        # The engine's body always sends these as off. A PUT made for another
        # reason would switch them off with nothing in the plan saying so.
        change = cfg_with(required_status_checks=["test", "agent-checks", "more"])
        cases = {
            "strict up-to-date policy": ("required_status_checks",
                                         "strict_required_status_checks_policy", True),
            "code owner review": ("pull_request", "require_code_owner_review", True),
            "last push approval": ("pull_request", "require_last_push_approval", True),
            "thread resolution": ("pull_request", "required_review_thread_resolution", True),
        }
        for label, (rule_type, key, value) in cases.items():
            with self.subTest(label):
                live = live_default()
                rule(live, rule_type)["parameters"][key] = value
                self.assertGated(live, change, key)

    def test_live_parameters_the_write_does_not_send_gate_unless_known_harmless(self):
        change = cfg_with(required_status_checks=["test", "agent-checks", "more"])
        reviewers = live_default()
        rule(reviewers, "pull_request")["parameters"]["required_reviewers"] = [{"reviewer": {"id": 1}}]
        self.assertGated(reviewers, change, "required_reviewers")
        new_param = live_default()
        rule(new_param, "pull_request")["parameters"]["a_parameter_github_adds_later"] = False
        self.assertGated(new_param, change, "a_parameter_github_adds_later")
        new_check_param = live_default()
        rule(new_check_param, "required_status_checks")["parameters"]["another_new_one"] = False
        self.assertGated(new_check_param, change, "another_new_one")
        # Skipping checks on branch creation: off is stricter, so either live
        # value is fine for a write that does not send it.
        on_create = live_default()
        rule(on_create, "required_status_checks")["parameters"]["do_not_enforce_on_create"] = True
        self.assertSafe(on_create, change)
        # The other owner's rulesets carry a review-dismissal restriction,
        # switched off: nothing a write without it could relax. Switched on,
        # or naming someone, it waits.
        off = live_default()
        rule(off, "pull_request")["parameters"]["dismissal_restriction"] = {
            "enabled": False, "allowed_actors": []}
        self.assertSafe(off, change)
        for label, value in {
            "enabled": {"enabled": True, "allowed_actors": []},
            "names an actor": {"enabled": False, "allowed_actors": [{"id": 1}]},
            "a field GitHub adds later": {"enabled": False, "allowed_actors": [], "x": 1},
        }.items():
            with self.subTest(label):
                on = live_default()
                rule(on, "pull_request")["parameters"]["dismissal_restriction"] = value
                self.assertGated(on, change, "dismissal_restriction")

    def test_a_parameter_missing_from_the_live_rule_gates(self):
        live = live_default()
        del rule(live, "pull_request")["parameters"]["require_extra_approval_for_unattributed_changes"]
        self.assertGated(live, cfg_with(required_status_checks=["test", "agent-checks", "more"]),
                         "require_extra_approval_for_unattributed_changes")

    def test_a_live_check_pinned_to_an_app_gates(self):
        live = live_default()
        rule(live, "required_status_checks")["parameters"]["required_status_checks"][0]["integration_id"] = 15368
        self.assertGated(live, cfg_with(required_status_checks=["test", "agent-checks", "more"]),
                         "pinned")
        # An explicit null pin is no pin.
        live = live_default()
        rule(live, "required_status_checks")["parameters"]["required_status_checks"][0]["integration_id"] = None
        self.assertSafe(live, cfg_with(required_status_checks=["test", "agent-checks", "more"]))

    def test_unknown_shapes_fail_closed(self):
        change = cfg_with(required_status_checks=["test", "agent-checks", "more"])
        with self.subTest("an unknown top-level live field"):
            self.assertGated(live_default(a_field_github_adds_later=True), change,
                             "a_field_github_adds_later")
        with self.subTest("a live rule type the config does not declare"):
            live = live_default()
            live["rules"].append({"type": "required_signatures"})
            self.assertGated(live, change, "required_signatures", "removed")
        with self.subTest("the same rule type twice"):
            live = live_default()
            live["rules"].append({"type": "deletion"})
            self.assertGated(live, change, "rules")
        with self.subTest("a rule with an unknown key"):
            live = live_default()
            rule(live, "deletion")["extra"] = 1
            self.assertGated(live, change, "rules")
        with self.subTest("a parameterless rule that has parameters"):
            live = live_default()
            rule(live, "deletion")["parameters"] = {"x": 1}
            self.assertGated(live, change, "deletion")
        with self.subTest("a check entry with a field this classifier does not know"):
            live = live_default()
            rule(live, "required_status_checks")["parameters"]["required_status_checks"][0]["extra"] = 1
            self.assertGated(live, change, "shape")
        with self.subTest("no live body at all"):
            rec = ruleset_record(live_default(), change)
            rec["_live"] = None
            self.assertEqual(rs.write_risk(rec, [rec])[0], GATED)
        with self.subTest("another target"):
            self.assertGated(live_default(target="tag"), change, "target")

    def test_true_is_not_one(self):
        # 1 == True in Python; a count of 1 must not pass for a flag, nor a
        # flag for a count.
        live = live_default()
        rule(live, "pull_request")["parameters"]["required_approving_review_count"] = True
        self.assertGated(live, cfg_with(required_status_checks=["test", "agent-checks", "more"]),
                         "required_approving_review_count")

    def test_a_new_ruleset_is_safe(self):
        body = rs.build_ruleset_body(RULESET_CFG)
        rec = {"setting": "ruleset[default branch protection]", "status": "drift",
               "current": None, "desired": rs.normalize_ruleset(body),
               "_writer": ("ruleset", body, None), "_live": None}
        verdict, reason = rs.write_risk(rec, [rec])
        self.assertEqual(verdict, SAFE, reason)
        self.assertIn("new ruleset", reason)

    def test_an_existing_id_without_a_live_body_is_not_a_new_ruleset(self):
        body = rs.build_ruleset_body(RULESET_CFG)
        rec = {"setting": "ruleset[x]", "status": "drift", "current": None,
               "desired": rs.normalize_ruleset(body),
               "_writer": ("ruleset", body, 111), "_live": None}
        self.assertEqual(rs.write_risk(rec, [rec])[0], GATED)


class ExtraRulesetRiskTests(unittest.TestCase):
    CFG = {
        "name": "roster proposal branch",
        "target_branches": ["roster/proposal"],
        "rules": ["creation", "update", "deletion", "non_fast_forward"],
        "bypass_actors": [
            {"actor_type": "Integration", "actor_id": 1234567, "bypass_mode": "always"},
            {"actor_type": "RepositoryRole", "actor_id": 5, "bypass_mode": "always"},
        ],
    }

    def live(self, **changes):
        body = {
            "id": 222, "name": "roster proposal branch", "target": "branch",
            "source_type": "Repository", "source": "example/example",
            "enforcement": "active",
            "conditions": {"ref_name": {"exclude": [], "include": ["refs/heads/roster/proposal"]}},
            # GitHub stores `update` with its default parameter as a bare rule.
            "rules": [{"type": "creation"}, {"type": "update"}, {"type": "deletion"},
                      {"type": "non_fast_forward"}],
            "node_id": "RRS_example2", "created_at": "x", "updated_at": "y",
            "bypass_actors": [
                {"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"},
                {"actor_id": 1234567, "actor_type": "Integration", "bypass_mode": "always"},
            ],
            "current_user_can_bypass": "always", "_links": {},
        }
        body.update(changes)
        return body

    def risk(self, live, cfg):
        body = rs.build_extra_ruleset_body(cfg)
        rec = {"setting": f"ruleset[{body['name']}]", "status": "drift",
               "current": rs.normalize_extra_ruleset(live),
               "desired": rs.normalize_extra_ruleset(body),
               "_writer": ("ruleset", body, live["id"]), "_live": live}
        return rs.write_risk(rec, [rec])

    def test_the_bare_update_rule_is_not_a_change(self):
        fewer = dict(self.CFG, bypass_actors=self.CFG["bypass_actors"][:1])
        verdict, reason = self.risk(self.live(), fewer)
        self.assertEqual(verdict, SAFE, reason)

    def test_an_update_rule_that_allows_fetch_and_merge_gates(self):
        live = self.live()
        live["rules"][1] = {"type": "update",
                            "parameters": {"update_allows_fetch_and_merge": True}}
        fewer = dict(self.CFG, bypass_actors=self.CFG["bypass_actors"][:1])
        verdict, reason = self.risk(live, fewer)
        self.assertEqual(verdict, GATED, reason)
        self.assertIn("update", reason)

    def test_dropping_a_rule_or_adding_an_actor_gates(self):
        verdict, reason = self.risk(self.live(), dict(self.CFG, rules=["deletion"]))
        self.assertEqual(verdict, GATED, reason)
        more = dict(self.CFG, bypass_actors=self.CFG["bypass_actors"] + [
            {"actor_type": "Integration", "actor_id": 99, "bypass_mode": "always"}])
        verdict, reason = self.risk(self.live(), more)
        self.assertEqual(verdict, GATED, reason)


def rec(setting, writer, current, desired, status="drift"):
    return {"setting": setting, "status": status, "current": current,
            "desired": desired, "_writer": writer}


class SimpleWriterRiskTests(unittest.TestCase):
    ACTIONS = {"enabled": True, "allowed_actions": "all", "sha_pinning_required": False}

    def one(self, record, siblings=()):
        return rs.write_risk(record, [record, *siblings])

    def test_each_direction(self):
        cases = [
            ("sha pinning on", rec("actions.sha_pinning_required", ("sha", self.ACTIONS, True), False, True), SAFE),
            ("sha pinning off", rec("actions.sha_pinning_required", ("sha", self.ACTIONS, False), True, False), GATED),
            ("sha pinning, read lacks enabled",
             rec("actions.sha_pinning_required", ("sha", {"allowed_actions": "all"}, True), False, True), GATED),
            ("fork approval stricter",
             rec("actions.fork_pr_approval", ("fork", None, "all_external_contributors"),
                 "first_time_contributors", "all_external_contributors"), SAFE),
            ("fork approval looser",
             rec("actions.fork_pr_approval", ("fork", None, "first_time_contributors"),
                 "all_external_contributors", "first_time_contributors"), GATED),
            ("fork approval, live unknown",
             rec("actions.fork_pr_approval", ("fork", None, "all_external_contributors"),
                 None, "all_external_contributors"), GATED),
            ("fork approval, a value GitHub adds later",
             rec("actions.fork_pr_approval", ("fork", None, "everyone"),
                 "first_time_contributors", "everyone"), GATED),
            ("auto-merge off", rec("repo.allow_auto_merge", ("auto_merge", None, False), True, False), SAFE),
            ("auto-merge on: it merges only what the rules allow",
             rec("repo.allow_auto_merge", ("auto_merge", None, True), False, True), SAFE),
            ("delete branch on merge on",
             rec("repo.delete_branch_on_merge", ("delete_branch_on_merge", None, True), False, True), SAFE),
            ("delete branch on merge off",
             rec("repo.delete_branch_on_merge", ("delete_branch_on_merge", None, False), True, False), GATED),
            ("Dependabot alerts on",
             rec("security.vulnerability_alerts", ("vuln_alerts", None, True), False, True), SAFE),
            ("Dependabot alerts off",
             rec("security.vulnerability_alerts", ("vuln_alerts", None, False), True, False), GATED),
            ("security updates on",
             rec("security.automated_security_fixes", ("auto_sec_fixes", None, True), False, True), SAFE),
            ("security updates off",
             rec("security.automated_security_fixes", ("auto_sec_fixes", None, False), True, False), GATED),
            ("a new label",
             rec("label[agent-authored]", ("label", {"name": "agent-authored", "color": "0e8a16",
                                                     "description": "d"}, False), None, {}), SAFE),
            ("a label's color",
             rec("label[agent-authored]", ("label", {"name": "agent-authored", "color": "0e8a16",
                                                     "description": "d"}, True),
                 {"name": "agent-authored", "color": "ffffff", "description": "d"},
                 {"name": "agent-authored", "color": "0e8a16", "description": "d"}), SAFE),
            ("a label whose live name differs in case, which the write renames",
             rec("label[agent-authored]", ("label", {"name": "agent-authored", "color": "0e8a16",
                                                     "description": "d"}, True),
                 {"name": "Agent-Authored", "color": "0e8a16", "description": "d"},
                 {"name": "agent-authored", "color": "0e8a16", "description": "d"}), SAFE),
            ("an existing label read without its name",
             rec("label[agent-authored]", ("label", {"name": "agent-authored", "color": "0e8a16",
                                                     "description": "d"}, True), {}, {}), GATED),
            ("an Actions policy, which allows events",
             rec("actions_policy[p]", ("actions_policy", {"name": "p"}, None), None, {}), GATED),
            ("the merge commit message, which has no direction",
             rec("repo.merge_commit_title",
                 ("merge_commit_message", None, {"merge_commit_title": "PR_TITLE",
                                                 "merge_commit_message": "BLANK"}),
                 "MERGE_MESSAGE", "PR_TITLE"), SAFE),
            ("a merge commit message write with an unknown key",
             rec("repo.merge_commit_title",
                 ("merge_commit_message", None, {"merge_commit_title": "PR_TITLE", "x": "y"}),
                 "MERGE_MESSAGE", "PR_TITLE"), GATED),
            ("a writer added later", rec("x.y", ("something_new", None, True), False, True), GATED),
        ]
        for label, record, expected in cases:
            with self.subTest(label):
                verdict, reason = self.one(record)
                self.assertEqual(verdict, expected, reason)
                self.assertTrue(reason)

    def test_one_is_not_true(self):
        for writer in (("sha", self.ACTIONS, 1), ("vuln_alerts", None, 1),
                       ("delete_branch_on_merge", None, 1)):
            with self.subTest(writer[0]):
                self.assertEqual(self.one(rec("s", writer, False, True))[0], GATED)
        self.assertEqual(self.one(rec("s", ("auto_merge", None, 0), True, False))[0], GATED)

    def test_only_a_planned_drift_record_can_be_safe(self):
        for status in ("match", "skipped", "error", "changed"):
            with self.subTest(status):
                record = rec("actions.sha_pinning_required", ("sha", self.ACTIONS, True),
                             False, True, status=status)
                self.assertEqual(self.one(record)[0], GATED)
        no_writer = {"setting": "x", "status": "drift", "current": 1, "desired": 2}
        self.assertEqual(self.one(no_writer)[0], GATED)

    def test_every_writer_apply_record_knows_is_classified_on_purpose(self):
        """A writer added to apply_record must be given a direction here, or
        named as always gated. Read from the function's AST, so the list
        cannot fall behind the dispatch."""
        tree = ast.parse(Path(rs.__file__).read_text(encoding="utf-8"))
        func = next(n for n in ast.walk(tree)
                    if isinstance(n, ast.FunctionDef) and n.name == "apply_record")
        kinds = set()
        for node in ast.walk(func):
            if (isinstance(node, ast.Compare) and isinstance(node.left, ast.Name)
                    and node.left.id == "kind" and len(node.comparators) == 1
                    and isinstance(node.comparators[0], ast.Constant)):
                kinds.add(node.comparators[0].value)
        self.assertGreaterEqual(len(kinds), 14, kinds)
        has_a_safe_direction = {
            "sha", "fork", "workflow_permissions", "ruleset", "label", "auto_merge",
            "merge_methods", "delete_branch_on_merge", "vuln_alerts", "auto_sec_fixes",
            "secret_scanning", "codeql",
        }
        has_a_safe_direction.add("merge_commit_message")
        always_gated = {"actions_policy"}
        self.assertEqual(kinds, has_a_safe_direction | always_gated)
        for kind in always_gated:
            with self.subTest(kind):
                self.assertEqual(self.one(rec("s", (kind, None, True), False, True))[0], GATED)


class GroupWriterRiskTests(unittest.TestCase):
    """Writers that send every declared key in one call: a key is safe when
    its value is the stricter one, or when the plan read it as already set."""

    def test_workflow_permissions(self):
        wanted = {"default_workflow_permissions": "read",
                  "can_approve_pull_request_reviews": False}
        a = rec("actions.default_workflow_permissions", ("workflow_permissions", None, wanted),
                "write", "read")
        b = rec("actions.can_approve_pull_request_reviews", ("workflow_permissions", None, wanted),
                True, False)
        for record in (a, b):
            self.assertEqual(rs.write_risk(record, [a, b])[0], SAFE)

    def test_a_looser_sibling_gates_the_whole_group(self):
        wanted = {"default_workflow_permissions": "read",
                  "can_approve_pull_request_reviews": True}
        a = rec("actions.default_workflow_permissions", ("workflow_permissions", None, wanted),
                "write", "read")
        b = rec("actions.can_approve_pull_request_reviews", ("workflow_permissions", None, wanted),
                False, True)
        for record in (a, b):
            verdict, reason = rs.write_risk(record, [a, b])
            self.assertEqual(verdict, GATED, reason)
            self.assertIn("can_approve_pull_request_reviews", reason)

    def test_a_looser_value_already_live_does_not_gate(self):
        # The fleet's merge-only policy: merge commits stay on, squash goes off.
        wanted = {"allow_merge_commit": True, "allow_squash_merge": False,
                  "allow_rebase_merge": False}
        writer = ("merge_methods", None, wanted)
        merge = rec("repo.allow_merge_commit", writer, True, True, status="match")
        squash = rec("repo.allow_squash_merge", writer, True, False)
        rebase = rec("repo.allow_rebase_merge", writer, False, False, status="match")
        verdict, reason = rs.write_risk(squash, [merge, squash, rebase])
        self.assertEqual(verdict, SAFE, reason)

    def test_a_looser_value_the_plan_could_not_read_gates(self):
        wanted = {"allow_merge_commit": True, "allow_squash_merge": False}
        writer = ("merge_methods", None, wanted)
        squash = rec("repo.allow_squash_merge", writer, True, False)
        for sibling_status in ("skipped", "error", "drift"):
            with self.subTest(sibling_status):
                merge = rec("repo.allow_merge_commit", writer, None, True, status=sibling_status)
                self.assertEqual(rs.write_risk(squash, [merge, squash])[0], GATED)
        with self.subTest("no sibling record at all"):
            self.assertEqual(rs.write_risk(squash, [squash])[0], GATED)

    def test_secret_scanning(self):
        on = {"secret_scanning": True, "secret_scanning_push_protection": True}
        a = rec("security.secret_scanning", ("secret_scanning", None, on), False, True)
        self.assertEqual(rs.write_risk(a, [a])[0], SAFE)
        off = {"secret_scanning": True, "secret_scanning_push_protection": False}
        b = rec("security.secret_scanning", ("secret_scanning", None, off), False, True)
        self.assertEqual(rs.write_risk(b, [b])[0], GATED)

    def test_an_unknown_key_or_shape_gates(self):
        extra = rec("repo.allow_squash_merge",
                    ("merge_methods", None, {"allow_squash_merge": False, "new_key": False}),
                    True, False)
        self.assertEqual(rs.write_risk(extra, [extra])[0], GATED)
        for wanted in (None, {}, ["allow_squash_merge"]):
            with self.subTest(wanted=wanted):
                bad = rec("repo.allow_squash_merge", ("merge_methods", None, wanted), True, False)
                self.assertEqual(rs.write_risk(bad, [bad])[0], GATED)

    def test_codeql(self):
        def setup(current, wanted):
            return rec("security.codeql_default_setup", ("codeql", None, wanted),
                       current, wanted.get("codeql_default_setup"))

        def suite(current, wanted, status="drift"):
            return rec("security.codeql_query_suite", ("codeql", None, wanted),
                       current, wanted.get("codeql_query_suite"), status=status)

        on_default = {"codeql_default_setup": True, "codeql_query_suite": "default"}
        on_extended = {"codeql_default_setup": True, "codeql_query_suite": "extended"}
        off = {"codeql_default_setup": False}
        with self.subTest("turning it on enables a security feature"):
            a, b = setup(False, on_default), suite(None, on_default)
            for record in (a, b):
                verdict, reason = rs.write_risk(record, [a, b])
                self.assertEqual(verdict, SAFE, reason)
            a, b = setup(False, on_extended), suite(None, on_extended)
            self.assertEqual(rs.write_risk(a, [a, b])[0], SAFE)
        with self.subTest("the larger suite, setup already on"):
            a = rec("security.codeql_default_setup", ("codeql", None, on_extended),
                    True, True, status="match")
            b = suite("default", on_extended)
            self.assertEqual(rs.write_risk(b, [a, b])[0], SAFE)
        with self.subTest("the larger suite, only the suite declared"):
            only = {"codeql_query_suite": "extended"}
            b = suite("default", only)
            self.assertEqual(rs.write_risk(b, [b])[0], SAFE)
        with self.subTest("only the suite declared, and nothing live: it turns setup on"):
            only = {"codeql_query_suite": "extended"}
            b = suite(None, only)
            self.assertEqual(rs.write_risk(b, [b])[0], SAFE)
        with self.subTest("the smaller suite"):
            b = suite("extended", on_default)
            verdict, reason = rs.write_risk(b, [b])
            self.assertEqual(verdict, GATED, reason)
            self.assertIn("fewer queries", reason)
        with self.subTest("turning it off"):
            a = setup(True, off)
            self.assertEqual(rs.write_risk(a, [a])[0], GATED)
        with self.subTest("an unknown key"):
            a = setup(False, dict(on_extended, languages=["python"]))
            self.assertEqual(rs.write_risk(a, [a])[0], GATED)


class FleetStandardTests(unittest.TestCase):
    """The owner's rule (2026-11-20): a plan that sets a repo up (it creates
    the repo's managed ruleset) applies every write that puts a setting at the
    fleet standard, even one that would otherwise wait. A repo's own
    overrides, and repos already set up, keep the gate, so a loosening edit
    to `defaults:` still waits on every existing repo."""

    DEFAULTS = {
        "repo": {"delete_branch_on_merge": True, "merge_commit_title": "MERGE_MESSAGE",
                 "merge_commit_message": "PR_TITLE"},
        "actions": {"sha_pinning_required": True},
        "ruleset": dict(RULESET_CFG),
        "labels": [{"name": "agent-authored", "color": "d4c5f9"}],
    }

    def new_ruleset(self, name="default branch protection", first=True):
        body = rs.build_ruleset_body(dict(RULESET_CFG, name=name))
        return {"setting": f"ruleset[{name}]", "status": "drift",
                "current": None, "desired": rs.normalize_ruleset(body),
                "_writer": ("ruleset", body, None), "_live": None,
                "_first_ruleset": first}

    def existing_ruleset(self):
        return ruleset_record(live_default(), cfg_with(
            required_status_checks=["test", "agent-checks", "more"]))

    def loosening(self):
        # Gated on its own merits: it would switch a setting off.
        return rec("repo.delete_branch_on_merge", ("delete_branch_on_merge", None, False),
                   True, False)

    def classify(self, records, overrides):
        rs.classify_records(records, self.DEFAULTS, overrides)
        return records

    def test_setting_up_a_repo_applies_the_fleet_standard(self):
        records = self.classify([self.new_ruleset(), self.loosening()], {})
        self.assertEqual(records[1]["risk"], SAFE, records[1]["risk_reason"])
        self.assertIn("fleet standard", records[1]["risk_reason"])

    def test_a_repo_override_still_waits(self):
        records = self.classify([self.new_ruleset(), self.loosening()],
                                {"repo": {"delete_branch_on_merge": False}})
        self.assertEqual(records[1]["risk"], GATED)

    def test_a_repo_already_set_up_still_waits(self):
        for label, extra in (("no ruleset in the plan", []),
                             ("an existing ruleset changes", [self.existing_ruleset()]),
                             ("the ruleset already matches",
                              [dict(self.new_ruleset(), status="match")])):
            with self.subTest(label):
                records = self.classify([*extra, self.loosening()], {})
                self.assertEqual(records[-1]["risk"], GATED)

    def test_a_new_ruleset_on_a_repo_that_has_one_is_not_set_up(self):
        # Review finding: an extra ruleset, a renamed default, or a managed
        # ruleset deleted while others remain must not open the gate.
        for label, ruleset in (
                ("the default ruleset, but the repo already has another",
                 self.new_ruleset(first=False)),
                ("an extra ruleset", self.new_ruleset(name="persistent branches")),
                ("the first-ruleset flag missing",
                 {k: v for k, v in self.new_ruleset().items() if k != "_first_ruleset"})):
            with self.subTest(label):
                records = self.classify([ruleset, self.loosening()], {})
                self.assertEqual(records[-1]["risk"], GATED)

    def test_a_group_write_carrying_an_override_still_waits(self):
        # Review finding: a group writer sends every declared key, so a
        # sibling from defaults must not carry the repo's own override.
        defaults = dict(self.DEFAULTS, actions={
            "sha_pinning_required": True, "default_workflow_permissions": "read",
            "can_approve_pull_request_reviews": False})
        group = {"default_workflow_permissions": "write",
                 "can_approve_pull_request_reviews": False}
        sibling = rec("actions.can_approve_pull_request_reviews",
                      ("workflow_permissions", None, group), True, False)
        records = [self.new_ruleset(), sibling]
        overrides = {"actions": {"default_workflow_permissions": "write"}}
        rs.classify_records(records, defaults, overrides)
        self.assertEqual(sibling["risk"], GATED, sibling["risk_reason"])
        with self.subTest("the same group with no override is the standard"):
            group = {"default_workflow_permissions": "read",
                     "can_approve_pull_request_reviews": False}
            sibling = rec("actions.can_approve_pull_request_reviews",
                          ("workflow_permissions", None, group), True, False)
            records = [self.new_ruleset(), sibling]
            rs.classify_records(records, defaults, {})
            self.assertEqual(sibling["risk"], SAFE, sibling["risk_reason"])

    def test_without_a_fleet_config_nothing_changes(self):
        records = [self.new_ruleset(), self.loosening()]
        rs.classify_records(records)
        self.assertEqual(records[1]["risk"], GATED)

    def test_an_unseen_bypass_list_is_never_waved_through(self):
        loose = dict(self.loosening(), bypass_unknown=True)
        records = self.classify([self.new_ruleset(), loose], {})
        self.assertEqual(records[1]["risk"], GATED)

    def test_fleet_standard_mapping(self):
        d, f = self.DEFAULTS, rs.fleet_standard
        self.assertTrue(f("repo.delete_branch_on_merge", d, {}))
        self.assertTrue(f("repo.merge_commit_message", d, {}))
        self.assertFalse(f("repo.merge_commit_message", d,
                           {"repo": {"merge_commit_title": "PR_TITLE"}}))
        self.assertTrue(f("actions.sha_pinning_required", d, {}))
        self.assertFalse(f("actions.fork_pr_approval", d, {}), "not in defaults")
        self.assertTrue(f("ruleset[default branch protection]", d, {}))
        self.assertFalse(f("ruleset[default branch protection]", d,
                           {"ruleset": {"required_status_checks": ["x"]}}))
        self.assertFalse(f("ruleset[persistent branches]", d, {}), "an extra ruleset")
        self.assertTrue(f("label[Agent-Authored]", d, {}))
        self.assertFalse(f("label[agent-authored]", d, {"labels": [{"name": "agent-authored"}]}))
        self.assertFalse(f("actions_policy[p]", d, {}))
        self.assertFalse(f("something", d, {}))
        self.assertFalse(f("repo.delete_branch_on_merge", None, {}))


class PlanCarriesTheLiveRulesetTests(unittest.TestCase):
    def test_plan_ruleset_keeps_the_live_body_and_the_new_check_is_safe(self):
        cfg = cfg_with(required_status_checks=["test", "agent-checks", "starter-suites"])
        live = live_default()
        with patch.object(rs, "find_ruleset", return_value=live), \
             patch.object(rs, "get_repo", return_value={"private": False}):
            records = rs.plan_repo("example/example", {"ruleset": cfg})
        self.assertEqual([r["status"] for r in records], ["drift"])
        self.assertIs(records[0]["_live"], live)
        rs.classify_records(records)
        self.assertEqual(records[0]["risk"], SAFE, records[0]["risk_reason"])

    def test_a_missing_ruleset_records_whether_the_repo_has_any(self):
        cfg = cfg_with(required_status_checks=["test", "agent-checks"])
        for live_list, first in (([], True), ([{"id": 9, "name": "other"}], False)):
            with self.subTest(first=first), \
                 patch.object(rs, "find_ruleset", return_value=None), \
                 patch.object(rs, "list_rulesets", return_value=live_list), \
                 patch.object(rs, "get_repo", return_value={"private": False}):
                records = rs.plan_repo("example/example", {"ruleset": cfg})
            self.assertIs(records[0]["_first_ruleset"], first)

    def test_a_ruleset_read_without_bypass_actors_gates(self):
        cfg = cfg_with(required_status_checks=["test", "agent-checks", "starter-suites"])
        live = live_default()
        del live["bypass_actors"]
        with patch.object(rs, "find_ruleset", return_value=live), \
             patch.object(rs, "get_repo", return_value={"private": False}):
            records = rs.plan_repo("example/example", {"ruleset": cfg})
        rs.classify_records(records)
        self.assertEqual(records[0]["risk"], GATED)
        self.assertIn("bypass actors", records[0]["risk_reason"])


class ApplyRefuseWeakeningTests(unittest.TestCase):
    CFG = {"repos": [{"name": "o/r", "manage": ["all"]}]}
    ACTIONS = {"enabled": True, "allowed_actions": "all"}

    def records(self):
        return [
            rec("actions.sha_pinning_required", ("sha", self.ACTIONS, True), False, True),
            rec("repo.delete_branch_on_merge", ("delete_branch_on_merge", None, False), True, False),
            rec("security.vulnerability_alerts", ("vuln_alerts", None, True), True, True,
                status="match"),
        ]

    def run_apply(self, records, **flags):
        args = argparse.Namespace(config="x", repo=None, owner=None, dry_run=False,
                                  cms_label_only=None, refuse_weakening=False,
                                  result_json=None)
        for key, value in flags.items():
            setattr(args, key, value)
        written = []
        with patch.object(rs, "load_config", return_value=self.CFG), \
             patch.object(rs, "plan_repo_records", return_value=records), \
             patch.object(rs, "apply_record",
                          side_effect=lambda repo, r: written.append(r["setting"])), \
             redirect_stdout(io.StringIO()) as out:
            code = rs.cmd_apply(args)
        return code, written, out.getvalue()

    def test_without_the_flag_every_drift_is_written(self):
        code, written, _ = self.run_apply(self.records())
        self.assertEqual(code, 0)
        self.assertEqual(written, ["actions.sha_pinning_required", "repo.delete_branch_on_merge"])

    def test_with_the_flag_only_safe_writes_are_made_and_the_exit_code_says_so(self):
        records = self.records()
        code, written, out = self.run_apply(records, refuse_weakening=True)
        self.assertEqual(code, 3)
        self.assertEqual(written, ["actions.sha_pinning_required"])
        self.assertEqual([r["status"] for r in records], ["changed", "gated", "match"])
        self.assertIn("LEFT FOR REVIEW", out)
        self.assertIn("repo.delete_branch_on_merge -> false", out)

    def test_nothing_left_exits_zero(self):
        code, written, _ = self.run_apply(self.records()[:1], refuse_weakening=True)
        self.assertEqual((code, written), (0, ["actions.sha_pinning_required"]))

    def test_an_error_outranks_what_was_left(self):
        records = self.records()
        with patch.object(rs, "load_config", return_value=self.CFG), \
             patch.object(rs, "plan_repo_records", return_value=records), \
             patch.object(rs, "apply_record", side_effect=rs.GhError(500, "boom")), \
             redirect_stdout(io.StringIO()):
            code = rs.cmd_apply(argparse.Namespace(
                config="x", repo=None, owner=None, dry_run=False, cms_label_only=None,
                refuse_weakening=True, result_json=None))
        self.assertEqual(code, 2)
        self.assertEqual([r["status"] for r in records], ["error", "gated", "match"])

    def test_a_dry_run_makes_no_write_and_still_reports_what_would_wait(self):
        records = self.records()
        code, written, _ = self.run_apply(records, refuse_weakening=True, dry_run=True)
        self.assertEqual((code, written), (3, []))
        self.assertEqual([r["status"] for r in records], ["would-change", "gated", "match"])

    def test_the_verdicts_are_taken_before_the_first_write(self):
        # A verdict reads sibling statuses as planned, and a write changes
        # them, so every record is classified before anything is written.
        on = {"secret_scanning": True, "secret_scanning_push_protection": True}
        records = [
            rec("security.secret_scanning", ("secret_scanning", None, on), False, True),
            rec("security.secret_scanning_push_protection", ("secret_scanning", None, on),
                False, True),
        ]
        events = []
        real_risk = rs.write_risk

        def risk(record, plan):
            events.append("classify")
            return real_risk(record, plan)

        with patch.object(rs, "load_config", return_value=self.CFG), \
             patch.object(rs, "plan_repo_records", return_value=records), \
             patch.object(rs, "write_risk", side_effect=risk), \
             patch.object(rs, "apply_record",
                          side_effect=lambda repo, r: events.append("write")), \
             redirect_stdout(io.StringIO()):
            code = rs.cmd_apply(argparse.Namespace(
                config="x", repo=None, owner=None, dry_run=False, cms_label_only=None,
                refuse_weakening=True, result_json=None))
        self.assertEqual(code, 0)
        self.assertEqual(events, ["classify", "classify", "write", "write"])

    def test_an_unclassified_record_is_never_written(self):
        # Belt and braces: if classify_records ever skipped a record, the
        # write-time check must still leave it.
        records = self.records()[:1]
        with patch.object(rs, "classify_records"):
            code, written, _ = self.run_apply(records, refuse_weakening=True)
        self.assertEqual((code, written), (3, []))
        self.assertEqual(records[0]["note"], "not classified")

    def test_a_ruleset_read_without_bypass_actors_stays_an_error(self):
        record = ruleset_record(live_default(), RULESET_CFG)
        record["bypass_unknown"] = True
        code, written, _ = self.run_apply([record], refuse_weakening=True)
        self.assertEqual((code, written), (2, []))
        self.assertEqual(record["status"], "error")

    def test_the_result_file_records_each_planned_change(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "result.json")
            self.run_apply(self.records(), refuse_weakening=True, result_json=path)
            with open(path) as fh:
                result = json.load(fh)
        self.assertEqual([(r["repo"], r["setting"], r["status"]) for r in result], [
            ("o/r", "actions.sha_pinning_required", "changed"),
            ("o/r", "repo.delete_branch_on_merge", "gated"),
        ])
        self.assertEqual(result[0]["risk"], SAFE)
        self.assertEqual(result[1]["risk"], GATED)
        self.assertIn("repo.delete_branch_on_merge -> false", result[1]["note"])

    def test_the_cli_accepts_the_flags(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "result.json")
            argv = ["repo_settings.py", "apply", "--config", "x", "--refuse-weakening",
                    "--result-json", path]
            with patch.object(sys, "argv", argv), \
                 patch.object(rs, "load_config", return_value=self.CFG), \
                 patch.object(rs, "plan_repo_records", return_value=self.records()), \
                 patch.object(rs, "apply_record") as write, \
                 redirect_stdout(io.StringIO()):
                self.assertEqual(rs.main(), 3)
            self.assertEqual(write.call_count, 1)
            self.assertTrue(os.path.exists(path))


class ApplyReportTests(unittest.TestCase):
    RESULTS = [
        {"repo": "o/a", "setting": "actions.sha_pinning_required", "status": "changed",
         "current": False, "desired": True, "note": None},
        {"repo": "o/b", "setting": "ruleset[default branch protection]", "status": "gated",
         "current": {"checks": ["a", "b"]}, "desired": {"checks": ["a"]},
         "note": 'required check "b" removed | really'},
        # A write classified safe that then failed.
        {"repo": "o/c", "setting": "label[x]", "status": "error", "current": None,
         "desired": {}, "note": "HTTP 500", "risk": SAFE},
    ]
    # A setting the plan could not read: nothing classified it.
    UNREAD = {"repo": "o/d", "setting": "ruleset[default branch protection]",
              "status": "error", "current": None, "desired": {}, "note": "HTTP 502",
              "risk": None}

    def test_markdown_separates_what_was_applied_from_what_waits(self):
        md = rs.apply_markdown(self.RESULTS)
        applied, waiting = md.split("## Left for the reviewed apply")
        self.assertIn("| o/a | actions.sha_pinning_required |", applied)
        self.assertNotIn("o/b", applied)
        self.assertIn("| o/b | ruleset[default branch protection] |", waiting)
        self.assertIn('required check "b" removed \\| really', waiting)
        self.assertIn("o/c: label[x] (HTTP 500)", waiting)

    def test_markdown_says_when_no_approval_is_needed(self):
        md = rs.apply_markdown(self.RESULTS[:1])
        self.assertIn("No approval is needed", md)
        self.assertIn("Nothing.", rs.apply_markdown([]))

    def run_report(self, results_by_file, fmt):
        with tempfile.TemporaryDirectory() as d:
            paths = []
            for i, results in enumerate(results_by_file):
                path = os.path.join(d, f"r{i}.json")
                with open(path, "w") as fh:
                    json.dump(results, fh)
                paths.append(path)
            argv = ["repo_settings.py", "apply-report", *paths, "--format", fmt]
            with patch.object(sys, "argv", argv), redirect_stdout(io.StringIO()) as out:
                code = rs.main()
        return code, out.getvalue()

    def test_needs_review_is_true_when_any_file_holds_a_gated_change(self):
        self.assertEqual(self.run_report([self.RESULTS[:1], self.RESULTS[1:]], "needs-review"),
                         (0, "true\n"))
        self.assertEqual(self.run_report([self.RESULTS[:1], []], "needs-review"), (0, "false\n"))
        # A failed write that was classified safe: approving would only
        # repeat it, so it fails the job without asking for the review.
        self.assertEqual(self.run_report([[self.RESULTS[0], self.RESULTS[2]]], "needs-review"),
                         (0, "false\n"))

    def test_a_setting_that_could_not_be_read_or_classified_asks_for_the_review(self):
        # It may hide a change that would have waited.
        gated_risk = dict(self.UNREAD, risk=GATED)
        no_risk_key = {k: v for k, v in self.UNREAD.items() if k != "risk"}
        for label, result in (("unread", self.UNREAD), ("refused", gated_risk),
                              ("no verdict recorded", no_risk_key)):
            with self.subTest(label):
                self.assertEqual(
                    self.run_report([[self.RESULTS[0]], [result]], "needs-review"),
                    (0, "true\n"))
                md = rs.apply_markdown([self.RESULTS[0], result])
                self.assertNotIn("No approval is needed", md)
                self.assertIn("the reviewed apply is still asked for", md)

    def test_a_file_that_is_not_a_result_list_is_refused(self):
        for bad in ("a string", {"status": "gated"}, [["gated"]], [{"status": "gated"}]):
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as d:
                path = os.path.join(d, "r.json")
                with open(path, "w") as fh:
                    json.dump(bad, fh)
                argv = ["repo_settings.py", "apply-report", path, "--format", "needs-review"]
                with patch.object(sys, "argv", argv), \
                     redirect_stdout(io.StringIO()) as out, \
                     patch.object(sys, "stderr", io.StringIO()):
                    self.assertEqual(rs.main(), 2)
                self.assertEqual(out.getvalue(), "")

    def test_the_cli_prints_the_markdown(self):
        code, out = self.run_report([self.RESULTS], "markdown")
        self.assertEqual(code, 0)
        self.assertEqual(out, rs.apply_markdown(self.RESULTS))


class PlanSummaryReviewColumnTests(unittest.TestCase):
    def change(self, **fields):
        base = {"repo": "o/r", "setting": "s", "status": "drift", "current": 1,
                "desired": 2, "note": None}
        base.update(fields)
        return base

    def test_the_plan_says_which_changes_need_a_review(self):
        md = rs.changes_markdown([
            self.change(setting="a", risk=SAFE, risk_reason="fine"),
            self.change(setting="b", risk=GATED, risk_reason="check removed | x"),
        ])
        self.assertIn("| Repo | Setting | From | To | Review |", md)
        row_a = next(l for l in md.splitlines() if l.startswith("| o/r | a |"))
        row_b = next(l for l in md.splitlines() if l.startswith("| o/r | b |"))
        self.assertTrue(row_a.endswith("| not needed |"), row_a)
        self.assertTrue(row_b.endswith("| needed: check removed \\| x |"), row_b)

    def test_a_change_with_no_verdict_reads_as_needing_one(self):
        # A changes file written before the column existed.
        row = next(l for l in rs.changes_markdown([self.change()]).splitlines()
                   if l.startswith("| o/r |"))
        self.assertTrue(row.endswith("| needed: not classified |"), row)


if __name__ == "__main__":
    unittest.main()
