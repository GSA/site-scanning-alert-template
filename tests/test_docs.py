#!/usr/bin/env python3
"""Tests for documentation accuracy (CI enforcement)."""

import os
import re
import unittest


class TestDocumentation(unittest.TestCase):
    def setUp(self):
        """Load files for testing."""
        self.repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

        with open(os.path.join(self.repo_root, "README.md"), "r") as f:
            self.readme = f.read()

        with open(os.path.join(self.repo_root, "action.yml"), "r") as f:
            self.action_yml = f.read()

    def test_input_table_matches_action_yml(self):
        """
        Verify README input table matches action.yml inputs.

        This catches the GITHUB_TOKEN vs ISSUE_TOKEN failure mode.
        """
        # Extract inputs from action.yml (simple YAML parser for flat inputs:)
        action_inputs = {}
        in_inputs = False
        current_input = None

        for line in self.action_yml.split("\n"):
            stripped = line.strip()

            if stripped == "inputs:":
                in_inputs = True
                continue

            if in_inputs and stripped == "runs:":
                break

            if in_inputs and stripped.endswith(":") and not stripped.startswith("#"):
                # New input definition
                current_input = stripped.rstrip(":")
                action_inputs[current_input] = {}
            elif current_input and stripped.startswith("default:"):
                # Extract default value
                default_val = stripped.split(":", 1)[1].strip()
                action_inputs[current_input]["default"] = default_val

        # Extract input table from README
        # Look for markdown table between "| Input |" header and next ##
        table_started = False
        readme_inputs = set()

        for line in self.readme.split("\n"):
            if "| Input |" in line or "| `Input` |" in line:
                table_started = True
                continue

            if table_started:
                if line.startswith("##"):
                    break

                # Parse table row: | `input_name` | ...
                if line.startswith("|") and "`" in line:
                    match = re.search(r"\|\s*`([^`]+)`\s*\|", line)
                    if match:
                        readme_inputs.add(match.group(1))

        # Compare: every action input should be in README
        action_input_names = set(action_inputs.keys())

        missing_from_readme = action_input_names - readme_inputs
        extra_in_readme = readme_inputs - action_input_names

        self.assertEqual(
            len(missing_from_readme),
            0,
            f"Inputs in action.yml but not in README table: {missing_from_readme}",
        )
        self.assertEqual(
            len(extra_in_readme),
            0,
            f"Inputs in README table but not in action.yml: {extra_in_readme}",
        )

    def test_internal_links_resolve(self):
        """Verify relative links point to existing files."""
        # Find all markdown links: [text](path)
        links = re.findall(r"\[([^\]]+)\]\(([^)]+)\)", self.readme)

        broken = []
        for link_text, link_path in links:
            # Skip external links (http/https)
            if link_path.startswith("http://") or link_path.startswith("https://"):
                continue

            # Skip anchor-only links
            if link_path.startswith("#"):
                continue

            # Resolve relative to repo root
            full_path = os.path.join(self.repo_root, link_path.split("#")[0])
            if not os.path.exists(full_path):
                broken.append((link_text, link_path))

        self.assertEqual(len(broken), 0, f"Broken internal links in README: {broken}")

    def test_quickstart_workflow_matches_template(self):
        """
        Verify quickstart YAML in README matches actual workflow file.

        Checks action reference and key top-level settings, including
        indentation-sensitive structure for copy/paste safety.
        """
        yaml_blocks = []
        current = []
        in_yaml = False

        for line in self.readme.split("\n"):
            stripped = line.strip()
            if stripped == "```yaml":
                in_yaml = True
                current = []
                continue
            if in_yaml and stripped == "```":
                yaml_blocks.append("\n".join(current))
                in_yaml = False
                continue
            if in_yaml:
                current.append(line[3:] if line.startswith("   ") else line)

        # Find the block that contains "GSA/site-scanning-alert-template"
        quickstart_yaml = None
        for block in yaml_blocks:
            if "site-scanning-alert-template" in block:
                quickstart_yaml = block
                break

        if not quickstart_yaml:
            self.skipTest("No quickstart YAML found in README")

        # Basic checks: contains action reference
        self.assertIn("uses:", quickstart_yaml)
        self.assertIn("site-scanning-alert-template@", quickstart_yaml)

        # Check top-level workflow keys are copy/pasteable at column 1.
        self.assertRegex(quickstart_yaml, r"(?m)^permissions:$")
        self.assertRegex(quickstart_yaml, r"(?m)^  issues: write$")
        self.assertRegex(quickstart_yaml, r"(?m)^  contents: read$")
        self.assertRegex(quickstart_yaml, r"(?m)^concurrency:$")
        self.assertRegex(quickstart_yaml, r"(?m)^  group: site-scanning-alerts-")
        self.assertRegex(quickstart_yaml, r"(?m)^  cancel-in-progress: false$")

        # A hung run must not sit indefinitely: with cancel-in-progress:
        # false (above), a stuck job parks the whole concurrency group and
        # every subsequent scheduled run queues behind it.
        self.assertIn("timeout-minutes:", quickstart_yaml)


class TestWorkflowConcurrency(unittest.TestCase):
    """
    Regression for finding #8: without a concurrency guard, an overlapping
    scheduled run and a manually dispatched run can both observe no
    matching open issue and each create one (find_open_issue is
    non-atomic with create_issue). Serializing runs at the workflow level
    is the practical fix, since the GitHub issues API has no
    create-if-absent primitive.
    """

    def setUp(self):
        self.repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        workflow_path = os.path.join(
            self.repo_root,
            ".github",
            "workflows",
            "site-scanning-alerts.yml",
        )
        with open(workflow_path, "r") as f:
            self.workflow = f.read()

    def test_workflow_has_concurrency_guard(self):
        self.assertIn("concurrency:", self.workflow)
        self.assertIn("cancel-in-progress: false", self.workflow)

    def test_concurrency_guard_precedes_jobs(self):
        # Concurrency must be a top-level key (applies to the whole
        # workflow), not nested under a single job, so scheduled and
        # workflow_dispatch runs of this same workflow always serialize.
        concurrency_idx = self.workflow.index("concurrency:")
        jobs_idx = self.workflow.index("\njobs:")
        self.assertLess(concurrency_idx, jobs_idx)

    def test_alert_job_has_timeout(self):
        """
        cancel-in-progress: false means a hung run parks the concurrency
        group - every subsequent scheduled run queues behind it, a silent
        multi-day monitoring gap. timeout-minutes is what makes that
        design safe.
        """
        self.assertIn("timeout-minutes:", self.workflow)


class TestWorkflowTimeouts(unittest.TestCase):
    """Regression: a hung test/lint job has no other backstop against
    eating the org's Actions minutes."""

    def setUp(self):
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        workflow_path = os.path.join(repo_root, ".github", "workflows", "test.yml")
        with open(workflow_path, "r") as f:
            self.workflow = f.read()

    def test_both_jobs_have_a_timeout(self):
        self.assertEqual(self.workflow.count("timeout-minutes:"), 2)


class TestExternalLinks(unittest.TestCase):
    """
    External link validation.

    Run separately from main tests; should warn but not block on transient failures.
    """

    @unittest.skip("External link checking is scheduled separately to avoid blocking PRs")
    def test_external_links_reachable(self):
        """Check that external links return 2xx/3xx status codes."""
        # This would use urllib to HEAD external links
        # Skipped in default test run to avoid network dependency
        pass


if __name__ == "__main__":
    unittest.main()
