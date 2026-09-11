#!/usr/bin/env python3
"""
Tests for site_scanning_alerts.py (main entrypoint).

main() previously had zero test coverage - every guard, exit path, and mode
dispatch lived only in manual dry-run testing. These tests drive main()
through its real INPUT_* env-var interface, stubbing out network access
(download_snapshot) and, where relevant, the GitHub issue lifecycle
(handle_alert_lifecycle), and assert on GITHUB_STEP_SUMMARY output.
"""
import unittest
import os
import sys
import csv
import tempfile
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

import site_scanning_alerts as ssa

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), 'fixtures')


def load_fixture_rows(name):
    with open(os.path.join(FIXTURES_DIR, name), newline='') as f:
        return list(csv.DictReader(f))


LATEST_ROWS = load_fixture_rows('latest.csv')
PREVIOUS_ROWS = load_fixture_rows('previous.csv')

BASE_ENV = {
    'INPUT_MODE': 'both',
    'INPUT_MAX_SNAPSHOT_AGE_DAYS': '3650',  # fixtures predate "today"; freshness isn't under test here
    'INPUT_DRY_RUN': 'true',
    'INPUT_ALERT_ON_STATUS_CODES': '500,502,503,504',
    'INPUT_FIELDS': 'live,status_code,primary_scan_status',
}


class SiteScanningAlertsTestCase(unittest.TestCase):
    """Common env/watchlist/summary-file scaffolding for main() tests."""

    def setUp(self):
        self.watchlist_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
        self.summary_file = tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False)
        self.summary_file.close()

    def tearDown(self):
        os.unlink(self.watchlist_file.name)
        os.unlink(self.summary_file.name)

    def _write_watchlist(self, entries):
        self.watchlist_file.write('\n'.join(entries) + '\n')
        self.watchlist_file.close()

    def _read_summary(self):
        with open(self.summary_file.name) as f:
            return f.read()

    def _run_main(self, env_overrides, download_side_effect):
        env = dict(BASE_ENV)
        env['INPUT_WATCHLIST'] = self.watchlist_file.name
        env['GITHUB_STEP_SUMMARY'] = self.summary_file.name
        env.update(env_overrides)

        with patch.dict(os.environ, env, clear=True), \
             patch.object(ssa, 'download_snapshot', side_effect=download_side_effect):
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
        self._write_watchlist(['base:test4.gov'])

        def fake_download(url, wanted_columns=None, optional_columns=None, **kwargs):
            return LATEST_ROWS  # identical rows regardless of url -> stalled rotation

        code = self._run_main({}, fake_download)

        self.assertEqual(code, 0)
        summary = self._read_summary()
        self.assertIn('Snapshot has not rotated', summary)
        self.assertIn('sub.test4.gov', summary)
        self.assertIn('503', summary)

    def test_no_alerts_touches_no_issue_lifecycle(self):
        """
        A stalled rotation with zero state findings must exit without ever
        invoking the 'alerts' stream lifecycle - a stalled snapshot is not
        evidence a condition cleared.
        """
        self._write_watchlist(['test1.gov'])  # status_code 200, live true - nothing to alert on

        def fake_download(url, wanted_columns=None, optional_columns=None, **kwargs):
            return LATEST_ROWS

        calls = []

        def fake_lifecycle(client, title, body, labels, is_clear, comment_on_clear=True, stream='alerts'):
            calls.append(stream)
            return {'action': 'no-op', 'issue_url': None, 'fingerprint': 'x'}

        env = {
            'INPUT_DRY_RUN': 'false',
            'INPUT_TOKEN': 'fake-token',
        }
        full_env = dict(BASE_ENV)
        full_env.update(env)
        full_env['INPUT_WATCHLIST'] = self.watchlist_file.name
        full_env['GITHUB_STEP_SUMMARY'] = self.summary_file.name

        with patch.dict(os.environ, full_env, clear=True), \
             patch.dict(os.environ, {'GITHUB_REPOSITORY': 'owner/repo'}), \
             patch.object(ssa, 'download_snapshot', side_effect=fake_download), \
             patch.object(ssa, 'handle_alert_lifecycle', side_effect=fake_lifecycle):
            with self.assertRaises(SystemExit) as cm:
                ssa.main()

        self.assertEqual(cm.exception.code, 0)
        # The staleness-clear check runs on every fresh run (harmless no-op
        # here), but the 'alerts' stream must never be touched.
        self.assertNotIn('alerts', calls)
        summary = self._read_summary()
        self.assertIn('No new information this run', summary)


class TestCustomFieldWarning(SiteScanningAlertsTestCase):
    """Regression for finding #7: unrecognized custom fields must be reported, not silently no-op'd."""

    def test_unrecognized_field_is_warned_and_skipped(self):
        self._write_watchlist(['test1.gov'])

        def fake_download(url, wanted_columns=None, optional_columns=None, **kwargs):
            if 'previous' in url:
                return PREVIOUS_ROWS
            return LATEST_ROWS

        code = self._run_main(
            {'INPUT_FIELDS': 'live,status_code,bogus_field'},
            fake_download
        )

        self.assertEqual(code, 0)
        summary = self._read_summary()
        self.assertIn('Unrecognized monitoring field(s) skipped', summary)
        self.assertIn('bogus_field', summary)


class TestUnmatchedWatchlistWarning(SiteScanningAlertsTestCase):
    """Regression for finding #6: a typo'd watchlist entry must be named, not silently dropped."""

    def test_unmatched_entry_is_named_in_summary(self):
        self._write_watchlist(['test1.gov', 'typo-domain.gov'])

        def fake_download(url, wanted_columns=None, optional_columns=None, **kwargs):
            if 'previous' in url:
                return PREVIOUS_ROWS
            return LATEST_ROWS

        code = self._run_main({}, fake_download)

        self.assertEqual(code, 0)
        summary = self._read_summary()
        self.assertIn('watchlist entries matched nothing', summary)
        unmatched_block = summary.split('matched nothing**')[1].split('\n\n')[1]
        self.assertIn('typo-domain.gov', unmatched_block)
        self.assertNotIn('test1.gov', unmatched_block)


class TestEmptyLabelsFallback(SiteScanningAlertsTestCase):
    """
    Regression for finding #2: an empty `labels` input must not cause the
    action to create a brand-new issue on every run. It should fall back
    to the default label and warn, rather than silently passing an empty
    list into the issue lifecycle.
    """

    def test_empty_labels_falls_back_to_default_and_warns(self):
        self._write_watchlist(['sub.test4.gov'])  # status_code 503 -> real alert

        def fake_download(url, wanted_columns=None, optional_columns=None, **kwargs):
            if 'previous' in url:
                return PREVIOUS_ROWS
            return LATEST_ROWS

        captured = {}

        def fake_lifecycle(client, title, body, labels, is_clear, comment_on_clear=True, stream='alerts'):
            captured[stream] = labels
            return {'action': 'created', 'issue_url': 'https://x/1', 'fingerprint': 'x'}

        env = dict(BASE_ENV)
        env.update({
            'INPUT_LABELS': '',
            'INPUT_DRY_RUN': 'false',
            'INPUT_TOKEN': 'fake-token',
        })
        env['INPUT_WATCHLIST'] = self.watchlist_file.name
        env['GITHUB_STEP_SUMMARY'] = self.summary_file.name

        with patch.dict(os.environ, env, clear=True), \
             patch.dict(os.environ, {'GITHUB_REPOSITORY': 'owner/repo'}), \
             patch.object(ssa, 'download_snapshot', side_effect=fake_download), \
             patch.object(ssa, 'handle_alert_lifecycle', side_effect=fake_lifecycle):
            with self.assertRaises(SystemExit) as cm:
                ssa.main()

        self.assertEqual(cm.exception.code, 0)
        self.assertEqual(captured.get('alerts'), ['site-scanning-alert'])
        summary = self._read_summary()
        self.assertIn('labels', summary.lower())
        self.assertIn('site-scanning-alert', summary)


class TestInvalidModeRejected(SiteScanningAlertsTestCase):
    """Regression for finding #7: an invalid mode must not fall through to a false clear."""

    def test_invalid_mode_exits_with_error_before_any_download(self):
        self._write_watchlist(['test1.gov'])

        def fake_download(url, wanted_columns=None, optional_columns=None, **kwargs):
            raise AssertionError("download_snapshot must not be called for an invalid mode")

        code = self._run_main({'INPUT_MODE': 'bogus'}, fake_download)

        self.assertEqual(code, 1)
        summary = self._read_summary()
        self.assertIn('mode', summary.lower())
        self.assertIn('bogus', summary)

    def test_valid_modes_are_accepted(self):
        for mode in ('change', 'state', 'both'):
            with self.subTest(mode=mode):
                wl = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
                wl.write('test1.gov\n')
                wl.close()
                summary = tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False)
                summary.close()

                def fake_download(url, wanted_columns=None, optional_columns=None, **kwargs):
                    if 'previous' in url:
                        return PREVIOUS_ROWS
                    return LATEST_ROWS

                env = dict(BASE_ENV)
                env['INPUT_MODE'] = mode
                env['INPUT_WATCHLIST'] = wl.name
                env['GITHUB_STEP_SUMMARY'] = summary.name

                try:
                    with patch.dict(os.environ, env, clear=True), \
                         patch.object(ssa, 'download_snapshot', side_effect=fake_download):
                        with self.assertRaises(SystemExit) as cm:
                            ssa.main()
                    self.assertEqual(cm.exception.code, 0)
                finally:
                    os.unlink(wl.name)
                    os.unlink(summary.name)


class TestChangeModeCannotConfirmRecovery(SiteScanningAlertsTestCase):
    """
    Regression for finding #5: mode=change with zero detected changes must
    not report the alert condition as cleared - the absence of a diff is
    not evidence of recovery, only a state check can establish that.
    """

    def test_change_mode_with_no_diff_skips_alert_lifecycle(self):
        self._write_watchlist(['test1.gov'])  # identical in latest/previous fixtures

        def fake_download(url, wanted_columns=None, optional_columns=None, **kwargs):
            if 'previous' in url:
                return PREVIOUS_ROWS
            return LATEST_ROWS

        calls = []

        def fake_lifecycle(client, title, body, labels, is_clear, comment_on_clear=True, stream='alerts'):
            calls.append(stream)
            return {'action': 'no-op', 'issue_url': None, 'fingerprint': 'x'}

        env = dict(BASE_ENV)
        env.update({
            'INPUT_MODE': 'change',
            'INPUT_DRY_RUN': 'false',
            'INPUT_TOKEN': 'fake-token',
        })
        env['INPUT_WATCHLIST'] = self.watchlist_file.name
        env['GITHUB_STEP_SUMMARY'] = self.summary_file.name

        with patch.dict(os.environ, env, clear=True), \
             patch.dict(os.environ, {'GITHUB_REPOSITORY': 'owner/repo'}), \
             patch.object(ssa, 'download_snapshot', side_effect=fake_download), \
             patch.object(ssa, 'handle_alert_lifecycle', side_effect=fake_lifecycle):
            with self.assertRaises(SystemExit) as cm:
                ssa.main()

        self.assertEqual(cm.exception.code, 0)
        self.assertNotIn('alerts', calls)
        summary = self._read_summary()
        self.assertIn('cannot confirm recovery', summary.lower())

    def test_both_mode_with_no_diff_still_clears_via_state_check(self):
        """Guard against over-correcting: `both` mode must still clear normally."""
        self._write_watchlist(['test1.gov'])

        def fake_download(url, wanted_columns=None, optional_columns=None, **kwargs):
            if 'previous' in url:
                return PREVIOUS_ROWS
            return LATEST_ROWS

        calls = []

        def fake_lifecycle(client, title, body, labels, is_clear, comment_on_clear=True, stream='alerts'):
            calls.append((stream, is_clear))
            return {'action': 'no-op', 'issue_url': None, 'fingerprint': 'x'}

        env = dict(BASE_ENV)
        env.update({
            'INPUT_MODE': 'both',
            'INPUT_DRY_RUN': 'false',
            'INPUT_TOKEN': 'fake-token',
        })
        env['INPUT_WATCHLIST'] = self.watchlist_file.name
        env['GITHUB_STEP_SUMMARY'] = self.summary_file.name

        with patch.dict(os.environ, env, clear=True), \
             patch.dict(os.environ, {'GITHUB_REPOSITORY': 'owner/repo'}), \
             patch.object(ssa, 'download_snapshot', side_effect=fake_download), \
             patch.object(ssa, 'handle_alert_lifecycle', side_effect=fake_lifecycle):
            with self.assertRaises(SystemExit) as cm:
                ssa.main()

        self.assertEqual(cm.exception.code, 0)
        self.assertIn(('alerts', True), calls)

    def test_change_mode_still_alerts_when_changes_exist(self):
        self._write_watchlist(['sub.test4.gov'])  # status_code 200 -> 503

        def fake_download(url, wanted_columns=None, optional_columns=None, **kwargs):
            if 'previous' in url:
                return PREVIOUS_ROWS
            return LATEST_ROWS

        calls = []

        def fake_lifecycle(client, title, body, labels, is_clear, comment_on_clear=True, stream='alerts'):
            calls.append((stream, is_clear))
            return {'action': 'created', 'issue_url': 'https://x/1', 'fingerprint': 'x'}

        env = dict(BASE_ENV)
        env.update({
            'INPUT_MODE': 'change',
            'INPUT_DRY_RUN': 'false',
            'INPUT_TOKEN': 'fake-token',
        })
        env['INPUT_WATCHLIST'] = self.watchlist_file.name
        env['GITHUB_STEP_SUMMARY'] = self.summary_file.name

        with patch.dict(os.environ, env, clear=True), \
             patch.dict(os.environ, {'GITHUB_REPOSITORY': 'owner/repo'}), \
             patch.object(ssa, 'download_snapshot', side_effect=fake_download), \
             patch.object(ssa, 'handle_alert_lifecycle', side_effect=fake_lifecycle):
            with self.assertRaises(SystemExit) as cm:
                ssa.main()

        self.assertEqual(cm.exception.code, 0)
        self.assertIn(('alerts', False), calls)


if __name__ == '__main__':
    unittest.main()
