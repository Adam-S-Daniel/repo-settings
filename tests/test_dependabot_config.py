"""Schema-shape tests for `.github/dependabot.yml`.

GitHub validates this file only after it reaches `main` — a PR that breaks it
shows nothing on that PR, and the whole file goes inert rather than just the
bad key. That is exactly what happened here: `cooldown.semver-major-days` is
not a supported option for the `github-actions` ecosystem, so shipping it on
2026-08-10 silently disabled every Dependabot update in this repo until the
fix (#35). Because GitHub's own validation cannot run pre-merge, this file is
the pre-merge guard for the shape of `.github/dependabot.yml`.
"""

from pathlib import Path

import unittest

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEPENDABOT_CONFIG = REPO_ROOT / ".github" / "dependabot.yml"

UNSUPPORTED_COOLDOWN_KEYS = (
    "semver-major-days",
    "semver-minor-days",
    "semver-patch-days",
)

CMS_PLATFORM_DEPENDENCY_NAME = "Adam-S-Daniel/cms-platform/*"


def _load_config():
    return yaml.safe_load(DEPENDABOT_CONFIG.read_text(encoding="utf-8"))


def _github_actions_entries(doc):
    return [
        (index, entry)
        for index, entry in enumerate(doc["updates"])
        if entry.get("package-ecosystem") == "github-actions"
    ]


class DependabotConfigTests(unittest.TestCase):
    def test_file_parses_with_a_github_actions_update(self):
        doc = _load_config()
        self.assertEqual(doc["version"], 2)
        self.assertIsInstance(doc["updates"], list)
        self.assertTrue(doc["updates"], "updates must be a non-empty list")
        entries = _github_actions_entries(doc)
        self.assertTrue(
            entries,
            "expected at least one update entry with "
            "package-ecosystem: github-actions",
        )

    def test_github_actions_cooldown_has_no_unsupported_semver_tier_keys(self):
        doc = _load_config()
        for index, entry in _github_actions_entries(doc):
            cooldown = entry.get("cooldown")
            if not cooldown:
                continue
            for key in UNSUPPORTED_COOLDOWN_KEYS:
                self.assertNotIn(
                    key,
                    cooldown,
                    f"updates[{index}].cooldown.{key} is not supported for "
                    "the github-actions ecosystem. GitHub rejects the whole "
                    "dependabot.yml as a schema validation error when this "
                    "key is present -- it does not just ignore the key -- so "
                    "every Dependabot update in this repo stops running. "
                    "See the open upstream request to add per-SemVer-tier "
                    "cooldown support for this ecosystem: "
                    "dependabot/dependabot-core#14628.",
                )


if __name__ == "__main__":
    unittest.main()
