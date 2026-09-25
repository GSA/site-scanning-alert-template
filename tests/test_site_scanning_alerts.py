#!/usr/bin/env python3
"""
Tests for site_scanning_alerts.py (main entrypoint).

main() previously had zero test coverage - every guard, exit path, and mode
dispatch lived only in manual dry-run testing. These tests drive main()
through its real INPUT_* env-var interface, stubbing out network access
(download_snapshot) and, where relevant, issue filing (file_alert), and
assert on GITHUB_STEP_SUMMARY output.
"""

import csv
import os
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import site_scanning_alerts as ssa

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
ACTION_YML = os.path.join(os.path.dirname(__file__), "..", "action.yml")


def load_fixture_rows(name):
    with open(os.path.join(FIXTURES_DIR, name), newline="") as f:
        return list(csv.DictReader(f))


LATEST_ROWS = load_fixture_rows("latest.csv")
PREVIOUS_ROWS = load_fixture_rows("previous.csv")

BASE_ENV = {
    "INPUT_MODE": "both",
    "INPUT_MAX_SNAPSHOT_AGE_DAYS": "3650",  # fixtures predate "today"; freshness isn't under test here
    "INPUT_DRY_RUN": "true",
    "INPUT_ALERT_ON_STATUS_CODES": "500,502,503,504",
    "INPUT_FIELDS": "live,status_code,primary_scan_status",
}


class SiteScanningAlertsTestCase(unittest.TestCase):
    """Common env/watchlist/summary-file scaffolding for main() tests."""

    def setUp(self):
        self.watchlist_file = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
        self.summary_file = tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False)
        self.summary_file.close()

    def tearDown(self):
        os.unlink(self.watchlist_file.name)
        os.unlink(self.summary_file.name)

    def _write_watchlist(self, entries):
        self.watchlist_file.write("\n".join(entries) + "\n")
        self.watchlist_file.close()

    def _read_summary(self):
        with open(self.summary_file.name) as f:
            return f.read()

    def _run_main(self, env_overrides, download_side_effect):
        env = dict(BASE_ENV)
        env["INPUT_WATCHLIST"] = self.watchlist_file.name
        env["GITHUB_STEP_SUMMARY"] = self.summary_file.name
        env.update(env_overrides)

        with (
            patch.dict(os.environ, env, clear=True),
            patch.object(ssa, "download_snapshot", side_effect=download_side_effect),
        ):
            with self.assertRaises(SystemExit) as cm:
                ssa.main()
        return cm.exception.code


class TestStalledRotationStillRunsStateChecks(SiteScanningAlertsTestCase):
    """
    Regression for finding #3: a stalled rotation must not skip state-mode
    checks. Simulated by returning the same rows for both the latest and
    previous snapshot URLs, so has_snapshot_rotated is False.
    """

    def test_state_alert_still_fires_when_rotation_stalled(self):
        self._write_watchlist(["base:test4.gov"])

        def fake_download(url, wanted_columns=None, optional_columns=None, **kwargs):
            return LATEST_ROWS  # identical rows regardless of url -> stalled rotation

        code = self._run_main({}, fake_download)

        self.assertEqual(code, 0)
        summary = self._read_summary()
        self.assertIn("Snapshot has not rotated", summary)
        self.assertIn("sub.test4.gov", summary)
        self.assertIn("503", summary)

    def test_no_alerts_touches_no_issue_lifecycle(self):
        """
        A stalled rotation with zero state findings must exit without ever
        invoking file_alert for the 'alerts' stream.
        """
        self._write_watchlist(["test1.gov"])  # status_code 200, live true - nothing to alert on

        def fake_download(url, wanted_columns=None, optional_columns=None, **kwargs):
            return LATEST_ROWS

        calls = []

        def fake_file_alert(client, title, body, labels, stream="alerts"):
            calls.append(stream)
            return {"action": "no-op", "issue_url": None}

        env = {
            "INPUT_DRY_RUN": "false",
            "INPUT_TOKEN": "fake-token",
        }
        full_env = dict(BASE_ENV)
        full_env.update(env)
        full_env["INPUT_WATCHLIST"] = self.watchlist_file.name
        full_env["GITHUB_STEP_SUMMARY"] = self.summary_file.name

        with (
            patch.dict(os.environ, full_env, clear=True),
            patch.dict(os.environ, {"GITHUB_REPOSITORY": "owner/repo"}),
            patch.object(ssa, "download_snapshot", side_effect=fake_download),
            patch.object(ssa, "file_alert", side_effect=fake_file_alert),
        ):
            with self.assertRaises(SystemExit) as cm:
                ssa.main()

        self.assertEqual(cm.exception.code, 0)
        # The 'alerts' stream must never be touched on a stalled run with
        # no findings.
        self.assertNotIn("alerts", calls)
        summary = self._read_summary()
        self.assertIn("No new information this run", summary)


class TestNotLiveAlertsByDefault(SiteScanningAlertsTestCase):
    """
    Regression: with the shipped defaults, a fully unreachable site (live=false,
    blank status_code, a primary_scan_status outside the empty-by-default
    alert_on_scan_status set) produced zero state alerts, so mode: both went
    silent after the day-1 change alert. dedupe_alerts collapses a state alert
    into a same-field change alert, so this is only observable on day 2+ of an
    outage - simulated here the same way TestStalledRotationStillRunsStateChecks
    does, by returning identical rows for both snapshot URLs.
    """

    DOWN_ROW = {
        "initial_domain": "down.gov",
        "initial_base_domain": "down.gov",
        "live": "false",
        "status_code": "",
        "primary_scan_status": "connection_refused",
        "scan_date": "2026-09-02T10:00:00Z",
    }

    def test_sustained_not_live_site_alerts_without_pinning_the_input(self):
        self._write_watchlist(["down.gov"])

        def fake_download(url, wanted_columns=None, optional_columns=None, **kwargs):
            return [self.DOWN_ROW]

        code = self._run_main({}, fake_download)

        self.assertEqual(code, 0)
        summary = self._read_summary()
        self.assertIn("down.gov", summary)
        self.assertIn("`live`", summary)

    def test_alert_on_not_live_false_still_opts_out(self):
        self._write_watchlist(["down.gov"])

        def fake_download(url, wanted_columns=None, optional_columns=None, **kwargs):
            return [self.DOWN_ROW]

        code = self._run_main({"INPUT_ALERT_ON_NOT_LIVE": "false"}, fake_download)

        self.assertEqual(code, 0)
        summary = self._read_summary()
        self.assertIn("No new information this run", summary)


class TestBooleanDefaultsMatchActionYml(unittest.TestCase):
    """
    Regression: read_config()'s boolean fields must agree with action.yml's
    defaults. _env_flag previously hardcoded "false" regardless of what the
    caller wanted, so read_config() and action.yml could silently disagree -
    this pins every known boolean input against a real parse of action.yml
    so a future one can't drift the same way.
    """

    # Maps an action.yml input name to the Config field it feeds.
    BOOLEAN_INPUTS = {
        "alert_on_not_live": "alert_on_not_live",
        "ignore_blank_transitions": "ignore_blank_transitions",
        "fail_on_alert": "fail_on_alert",
        "dry_run": "dry_run",
    }

    def _action_yml_default(self, input_name):
        with open(ACTION_YML) as f:
            text = f.read()
        match = re.search(rf"\n  {re.escape(input_name)}:\n(?:.*\n)*?    default: '(\w+)'", text)
        self.assertIsNotNone(match, f"Could not find a default for {input_name} in action.yml")
        return match.group(1)

    def test_env_flag_defaults_match_action_yml(self):
        with patch.dict(os.environ, {}, clear=True):
            config = ssa.read_config()

        for input_name, field_name in self.BOOLEAN_INPUTS.items():
            with self.subTest(input_name=input_name):
                expected = self._action_yml_default(input_name) == "true"
                self.assertEqual(getattr(config, field_name), expected)


class TestStalenessFailOnAlert(SiteScanningAlertsTestCase):
    """Stale snapshot alerts must honor fail_on_alert like regular alerts."""

    def test_stale_snapshot_fails_when_staleness_issue_created(self):
        self._write_watchlist(["test1.gov"])

        stale_rows = [dict(row, scan_date="2000-01-01") for row in LATEST_ROWS]

        def fake_download(url, wanted_columns=None, optional_columns=None, **kwargs):
            return stale_rows

        def fake_file_alert(client, title, body, labels, stream="alerts"):
            return {"action": "created", "issue_url": "https://x/1"}

        env = dict(BASE_ENV)
        env.update(
            {
                "INPUT_DRY_RUN": "false",
                "INPUT_TOKEN": "fake-token",
                "INPUT_FAIL_ON_ALERT": "true",
                "INPUT_MAX_SNAPSHOT_AGE_DAYS": "3",
            }
        )
        env["INPUT_WATCHLIST"] = self.watchlist_file.name
        env["GITHUB_STEP_SUMMARY"] = self.summary_file.name

        with (
            patch.dict(os.environ, env, clear=True),
            patch.dict(os.environ, {"GITHUB_REPOSITORY": "owner/repo"}),
            patch.object(ssa, "download_snapshot", side_effect=fake_download),
            patch.object(ssa, "file_alert", side_effect=fake_file_alert),
        ):
            with self.assertRaises(SystemExit) as cm:
                ssa.main()

        self.assertEqual(cm.exception.code, 1)
        summary = self._read_summary()
        self.assertIn("Snapshot is stale", summary)

    def test_stale_snapshot_noop_still_fails(self):
        self._write_watchlist(["test1.gov"])

        stale_rows = [dict(row, scan_date="2000-01-01") for row in LATEST_ROWS]

        def fake_download(url, wanted_columns=None, optional_columns=None, **kwargs):
            return stale_rows

        def fake_file_alert(client, title, body, labels, stream="alerts"):
            return {"action": "no-op", "issue_url": "https://x/1"}

        env = dict(BASE_ENV)
        env.update(
            {
                "INPUT_DRY_RUN": "false",
                "INPUT_TOKEN": "fake-token",
                "INPUT_FAIL_ON_ALERT": "true",
                "INPUT_MAX_SNAPSHOT_AGE_DAYS": "3",
            }
        )
        env["INPUT_WATCHLIST"] = self.watchlist_file.name
        env["GITHUB_STEP_SUMMARY"] = self.summary_file.name

        with (
            patch.dict(os.environ, env, clear=True),
            patch.dict(os.environ, {"GITHUB_REPOSITORY": "owner/repo"}),
            patch.object(ssa, "download_snapshot", side_effect=fake_download),
            patch.object(ssa, "file_alert", side_effect=fake_file_alert),
        ):
            with self.assertRaises(SystemExit) as cm:
                ssa.main()

        self.assertEqual(cm.exception.code, 1)


class TestStalenessMissingClientHardFails(SiteScanningAlertsTestCase):
    """
    Regression for finding #9: a stale snapshot with no token/repo (not a
    dry run) must hard-fail like the main alert-filing path does, rather
    than silently exiting 0 as if filing had succeeded.
    """

    def test_stale_snapshot_without_client_fails_loudly(self):
        self._write_watchlist(["test1.gov"])

        stale_rows = [dict(row, scan_date="2000-01-01") for row in LATEST_ROWS]

        def fake_download(url, wanted_columns=None, optional_columns=None, **kwargs):
            return stale_rows

        env = dict(BASE_ENV)
        env.update(
            {
                "INPUT_DRY_RUN": "false",
                "INPUT_TOKEN": "",
                "INPUT_MAX_SNAPSHOT_AGE_DAYS": "3",
            }
        )
        env["INPUT_WATCHLIST"] = self.watchlist_file.name
        env["GITHUB_STEP_SUMMARY"] = self.summary_file.name

        with (
            patch.dict(os.environ, env, clear=True),
            patch.dict(os.environ, {"GITHUB_REPOSITORY": ""}),
            patch.object(ssa, "download_snapshot", side_effect=fake_download),
        ):
            with self.assertRaises(SystemExit) as cm:
                ssa.main()

        self.assertEqual(cm.exception.code, 1)

    def test_stale_snapshot_dry_run_without_client_still_exits_clean(self):
        self._write_watchlist(["test1.gov"])

        stale_rows = [dict(row, scan_date="2000-01-01") for row in LATEST_ROWS]

        def fake_download(url, wanted_columns=None, optional_columns=None, **kwargs):
            return stale_rows

        env = dict(BASE_ENV)
        env.update(
            {
                "INPUT_DRY_RUN": "true",
                "INPUT_TOKEN": "",
                "INPUT_MAX_SNAPSHOT_AGE_DAYS": "3",
            }
        )
        env["INPUT_WATCHLIST"] = self.watchlist_file.name
        env["GITHUB_STEP_SUMMARY"] = self.summary_file.name

        with (
            patch.dict(os.environ, env, clear=True),
            patch.dict(os.environ, {"GITHUB_REPOSITORY": ""}),
            patch.object(ssa, "download_snapshot", side_effect=fake_download),
        ):
            with self.assertRaises(SystemExit) as cm:
                ssa.main()

        self.assertEqual(cm.exception.code, 0)


class TestCustomFieldWarning(SiteScanningAlertsTestCase):
    """Regression for finding #7: unrecognized custom fields must be reported, not silently no-op'd."""

    def test_unrecognized_field_is_warned_and_skipped(self):
        self._write_watchlist(["test1.gov"])

        def fake_download(url, wanted_columns=None, optional_columns=None, **kwargs):
            if "previous" in url:
                return PREVIOUS_ROWS
            return LATEST_ROWS

        code = self._run_main(
            {"INPUT_FIELDS": "live,status_code,bogus_field"},
            fake_download,
        )

        self.assertEqual(code, 0)
        summary = self._read_summary()
        self.assertIn("Unrecognized monitoring field(s) skipped", summary)
        self.assertIn("bogus_field", summary)


class TestUnmatchedWatchlistWarning(SiteScanningAlertsTestCase):
    """Regression for finding #6: a typo'd watchlist entry must be named, not silently dropped."""

    def test_unmatched_entry_is_named_in_summary(self):
        self._write_watchlist(["test1.gov", "typo-domain.gov"])

        def fake_download(url, wanted_columns=None, optional_columns=None, **kwargs):
            if "previous" in url:
                return PREVIOUS_ROWS
            return LATEST_ROWS

        code = self._run_main({}, fake_download)

        self.assertEqual(code, 0)
        summary = self._read_summary()
        self.assertIn("watchlist entries matched nothing", summary)
        unmatched_block = summary.split("matched nothing**")[1].split("\n\n")[1]
        self.assertIn("typo-domain.gov", unmatched_block)
        self.assertNotIn("test1.gov", unmatched_block)


class TestEmptyLabelsFallback(SiteScanningAlertsTestCase):
    """
    Regression for finding #2: an empty `labels` input must not cause the
    action to create a brand-new issue on every run. It should fall back
    to the default label and warn, rather than silently passing an empty
    list into the issue lifecycle.
    """

    def test_empty_labels_falls_back_to_default_and_warns(self):
        self._write_watchlist(["sub.test4.gov"])  # status_code 503 -> real alert

        def fake_download(url, wanted_columns=None, optional_columns=None, **kwargs):
            if "previous" in url:
                return PREVIOUS_ROWS
            return LATEST_ROWS

        captured = {}

        def fake_file_alert(client, title, body, labels, stream="alerts"):
            captured[stream] = labels
            return {"action": "created", "issue_url": "https://x/1"}

        env = dict(BASE_ENV)
        env.update(
            {
                "INPUT_LABELS": "",
                "INPUT_DRY_RUN": "false",
                "INPUT_TOKEN": "fake-token",
            }
        )
        env["INPUT_WATCHLIST"] = self.watchlist_file.name
        env["GITHUB_STEP_SUMMARY"] = self.summary_file.name

        with (
            patch.dict(os.environ, env, clear=True),
            patch.dict(os.environ, {"GITHUB_REPOSITORY": "owner/repo"}),
            patch.object(ssa, "download_snapshot", side_effect=fake_download),
            patch.object(ssa, "file_alert", side_effect=fake_file_alert),
        ):
            with self.assertRaises(SystemExit) as cm:
                ssa.main()

        self.assertEqual(cm.exception.code, 0)
        self.assertEqual(captured.get("alerts"), ["site-scanning-alert"])
        summary = self._read_summary()
        self.assertIn("labels", summary.lower())
        self.assertIn("site-scanning-alert", summary)


class TestInvalidModeRejected(SiteScanningAlertsTestCase):
    """Regression for finding #7: an invalid mode must not fall through to a false clear."""

    def test_invalid_mode_exits_with_error_before_any_download(self):
        self._write_watchlist(["test1.gov"])

        def fake_download(url, wanted_columns=None, optional_columns=None, **kwargs):
            raise AssertionError("download_snapshot must not be called for an invalid mode")

        code = self._run_main({"INPUT_MODE": "bogus"}, fake_download)

        self.assertEqual(code, 1)
        summary = self._read_summary()
        self.assertIn("mode", summary.lower())
        self.assertIn("bogus", summary)

    def test_valid_modes_are_accepted(self):
        self._write_watchlist(["test1.gov"])

        for mode in ("change", "state", "both"):
            with self.subTest(mode=mode):

                def fake_download(url, wanted_columns=None, optional_columns=None, **kwargs):
                    if "previous" in url:
                        return PREVIOUS_ROWS
                    return LATEST_ROWS

                env = dict(BASE_ENV)
                env["INPUT_MODE"] = mode
                env["INPUT_WATCHLIST"] = self.watchlist_file.name
                env["GITHUB_STEP_SUMMARY"] = self.summary_file.name

                with (
                    patch.dict(os.environ, env, clear=True),
                    patch.object(ssa, "download_snapshot", side_effect=fake_download),
                ):
                    with self.assertRaises(SystemExit) as cm:
                        ssa.main()
                self.assertEqual(cm.exception.code, 0)


class TestInvalidIntegerInputsRejected(SiteScanningAlertsTestCase):
    """
    Regression: max_changes and max_snapshot_age_days were coerced with a
    bare int() in read_config(), which main() calls outside its try block.
    A bad value escaped as a raw ValueError traceback on stderr, with nothing
    written to the step summary.
    """

    def _assert_rejected_before_download(self, env_name, bad_value, expected):
        self._write_watchlist(["test1.gov"])

        def fake_download(url, wanted_columns=None, optional_columns=None, **kwargs):
            raise AssertionError(f"download_snapshot must not be called for a bad {env_name}")

        code = self._run_main({env_name: bad_value}, fake_download)

        self.assertEqual(code, 1)
        self.assertIn(expected, self._read_summary())

    def test_non_integer_max_changes_is_rejected(self):
        self._assert_rejected_before_download(
            "INPUT_MAX_CHANGES",
            "twenty",
            "Invalid `max_changes`: `twenty`",
        )

    def test_zero_max_changes_is_rejected(self):
        self._assert_rejected_before_download(
            "INPUT_MAX_CHANGES",
            "0",
            "Invalid `max_changes`: `0`",
        )

    def test_negative_max_snapshot_age_days_is_rejected(self):
        self._assert_rejected_before_download(
            "INPUT_MAX_SNAPSHOT_AGE_DAYS",
            "-1",
            "Invalid `max_snapshot_age_days`: `-1`",
        )

    def test_empty_max_snapshot_age_days_is_rejected(self):
        # An empty code span renders as nothing in Markdown, so the message
        # names the empty value explicitly.
        self._assert_rejected_before_download(
            "INPUT_MAX_SNAPSHOT_AGE_DAYS",
            "",
            "Invalid `max_snapshot_age_days`: (empty)",
        )

    def test_valid_integers_still_pass_through(self):
        self._write_watchlist(["test1.gov"])

        def fake_download(url, wanted_columns=None, optional_columns=None, **kwargs):
            if "previous" in url:
                return PREVIOUS_ROWS
            return LATEST_ROWS

        code = self._run_main(
            {"INPUT_MAX_CHANGES": "100", "INPUT_MAX_SNAPSHOT_AGE_DAYS": "0"}, fake_download
        )

        # The fixtures are older than 0 days, so reaching the stale-snapshot
        # exit proves the value was parsed and used, not just not rejected.
        self.assertEqual(code, 0)
        self.assertIn("Snapshot is stale", self._read_summary())


class TestNoAlertsSkipsFiling(SiteScanningAlertsTestCase):
    """
    With no rolling comments, there's no "clear" action to file - zero
    findings just means nothing gets filed, regardless of mode.
    """

    def test_change_mode_with_no_diff_files_nothing(self):
        self._write_watchlist(["test1.gov"])  # identical in latest/previous fixtures

        def fake_download(url, wanted_columns=None, optional_columns=None, **kwargs):
            if "previous" in url:
                return PREVIOUS_ROWS
            return LATEST_ROWS

        calls = []

        def fake_file_alert(client, title, body, labels, stream="alerts"):
            calls.append(stream)
            return {"action": "no-op", "issue_url": None}

        env = dict(BASE_ENV)
        env.update(
            {
                "INPUT_MODE": "change",
                "INPUT_DRY_RUN": "false",
                "INPUT_TOKEN": "fake-token",
            }
        )
        env["INPUT_WATCHLIST"] = self.watchlist_file.name
        env["GITHUB_STEP_SUMMARY"] = self.summary_file.name

        with (
            patch.dict(os.environ, env, clear=True),
            patch.dict(os.environ, {"GITHUB_REPOSITORY": "owner/repo"}),
            patch.object(ssa, "download_snapshot", side_effect=fake_download),
            patch.object(ssa, "file_alert", side_effect=fake_file_alert),
        ):
            with self.assertRaises(SystemExit) as cm:
                ssa.main()

        self.assertEqual(cm.exception.code, 0)
        self.assertNotIn("alerts", calls)
        summary = self._read_summary()
        self.assertIn("no alerts this run", summary.lower())

    def test_both_mode_with_no_diff_and_no_state_findings_files_nothing(self):
        self._write_watchlist(["test1.gov"])

        def fake_download(url, wanted_columns=None, optional_columns=None, **kwargs):
            if "previous" in url:
                return PREVIOUS_ROWS
            return LATEST_ROWS

        calls = []

        def fake_file_alert(client, title, body, labels, stream="alerts"):
            calls.append(stream)
            return {"action": "no-op", "issue_url": None}

        env = dict(BASE_ENV)
        env.update(
            {
                "INPUT_MODE": "both",
                "INPUT_DRY_RUN": "false",
                "INPUT_TOKEN": "fake-token",
            }
        )
        env["INPUT_WATCHLIST"] = self.watchlist_file.name
        env["GITHUB_STEP_SUMMARY"] = self.summary_file.name

        with (
            patch.dict(os.environ, env, clear=True),
            patch.dict(os.environ, {"GITHUB_REPOSITORY": "owner/repo"}),
            patch.object(ssa, "download_snapshot", side_effect=fake_download),
            patch.object(ssa, "file_alert", side_effect=fake_file_alert),
        ):
            with self.assertRaises(SystemExit) as cm:
                ssa.main()

        self.assertEqual(cm.exception.code, 0)
        self.assertNotIn("alerts", calls)

    def test_change_mode_still_alerts_when_changes_exist(self):
        self._write_watchlist(["sub.test4.gov"])  # status_code 200 -> 503

        def fake_download(url, wanted_columns=None, optional_columns=None, **kwargs):
            if "previous" in url:
                return PREVIOUS_ROWS
            return LATEST_ROWS

        calls = []

        def fake_file_alert(client, title, body, labels, stream="alerts"):
            calls.append(stream)
            return {"action": "created", "issue_url": "https://x/1"}

        env = dict(BASE_ENV)
        env.update(
            {
                "INPUT_MODE": "change",
                "INPUT_DRY_RUN": "false",
                "INPUT_TOKEN": "fake-token",
            }
        )
        env["INPUT_WATCHLIST"] = self.watchlist_file.name
        env["GITHUB_STEP_SUMMARY"] = self.summary_file.name

        with (
            patch.dict(os.environ, env, clear=True),
            patch.dict(os.environ, {"GITHUB_REPOSITORY": "owner/repo"}),
            patch.object(ssa, "download_snapshot", side_effect=fake_download),
            patch.object(ssa, "file_alert", side_effect=fake_file_alert),
        ):
            with self.assertRaises(SystemExit) as cm:
                ssa.main()

        self.assertEqual(cm.exception.code, 0)
        self.assertIn("alerts", calls)

    def test_fail_on_alert_fails_when_existing_alert_is_noop(self):
        self._write_watchlist(["sub.test4.gov"])  # status_code 200 -> 503

        def fake_download(url, wanted_columns=None, optional_columns=None, **kwargs):
            if "previous" in url:
                return PREVIOUS_ROWS
            return LATEST_ROWS

        def fake_file_alert(client, title, body, labels, stream="alerts"):
            return {"action": "no-op", "issue_url": "https://x/1"}

        env = dict(BASE_ENV)
        env.update(
            {
                "INPUT_MODE": "change",
                "INPUT_DRY_RUN": "false",
                "INPUT_TOKEN": "fake-token",
                "INPUT_FAIL_ON_ALERT": "true",
            }
        )
        env["INPUT_WATCHLIST"] = self.watchlist_file.name
        env["GITHUB_STEP_SUMMARY"] = self.summary_file.name

        with (
            patch.dict(os.environ, env, clear=True),
            patch.dict(os.environ, {"GITHUB_REPOSITORY": "owner/repo"}),
            patch.object(ssa, "download_snapshot", side_effect=fake_download),
            patch.object(ssa, "file_alert", side_effect=fake_file_alert),
        ):
            with self.assertRaises(SystemExit) as cm:
                ssa.main()

        self.assertEqual(cm.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
