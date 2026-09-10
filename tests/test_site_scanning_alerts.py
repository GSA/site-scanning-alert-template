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


if __name__ == '__main__':
    unittest.main()
