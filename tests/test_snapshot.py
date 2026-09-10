#!/usr/bin/env python3
"""Tests for snapshot.py"""
import unittest
import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from snapshot import (
    download_snapshot,
    filter_to_watchlist,
    find_unmatched_entries,
    parse_scan_date,
    check_snapshot_freshness,
    has_snapshot_rotated,
    REQUIRED_COLUMNS,
    SnapshotError
)
from datetime import datetime, timedelta


class FakeHttpResponse:
    """Minimal stand-in for the context manager urllib.request.urlopen returns."""

    def __init__(self, data: bytes):
        self._data = data

    def read(self):
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _csv_bytes(header, rows):
    lines = [','.join(header)] + [','.join(row) for row in rows]
    return ('\n'.join(lines)).encode('utf-8')


class TestSnapshotFiltering(unittest.TestCase):
    
    def test_filter_exact_match(self):
        rows = [
            {'initial_domain': 'test1.gov', 'initial_base_domain': 'test1.gov'},
            {'initial_domain': 'test2.gov', 'initial_base_domain': 'test2.gov'},
            {'initial_domain': 'other.gov', 'initial_base_domain': 'other.gov'},
        ]
        watchlist = ['test1.gov', 'test2.gov']
        
        filtered = filter_to_watchlist(rows, watchlist)
        
        self.assertEqual(len(filtered), 2)
        domains = [r['initial_domain'] for r in filtered]
        self.assertIn('test1.gov', domains)
        self.assertIn('test2.gov', domains)
    
    def test_filter_base_domain(self):
        rows = [
            {'initial_domain': 'www.test.gov', 'initial_base_domain': 'test.gov'},
            {'initial_domain': 'sub.test.gov', 'initial_base_domain': 'test.gov'},
            {'initial_domain': 'other.gov', 'initial_base_domain': 'other.gov'},
        ]
        watchlist = ['base:test.gov']
        
        filtered = filter_to_watchlist(rows, watchlist)
        
        self.assertEqual(len(filtered), 2)
        bases = [r['initial_base_domain'] for r in filtered]
        self.assertEqual(bases, ['test.gov', 'test.gov'])
    
    def test_filter_mixed(self):
        rows = [
            {'initial_domain': 'exact.gov', 'initial_base_domain': 'exact.gov'},
            {'initial_domain': 'www.base.gov', 'initial_base_domain': 'base.gov'},
            {'initial_domain': 'sub.base.gov', 'initial_base_domain': 'base.gov'},
            {'initial_domain': 'other.gov', 'initial_base_domain': 'other.gov'},
        ]
        watchlist = ['exact.gov', 'base:base.gov']
        
        filtered = filter_to_watchlist(rows, watchlist)
        
        self.assertEqual(len(filtered), 3)


class TestDownloadSnapshotColumnProjection(unittest.TestCase):
    """
    Regression coverage for finding #7: a user's custom `fields` input
    must not be silently discarded by column projection, but a genuinely
    missing *required* column must still hard-fail.
    """

    def test_optional_column_kept_when_present(self):
        csv_bytes = _csv_bytes(
            REQUIRED_COLUMNS + ['https_enforced'],
            [['test.gov', 'test.gov', 'true', '200', 'completed', '2026-09-02', 'true']]
        )
        with patch('snapshot.urllib.request.urlopen', return_value=FakeHttpResponse(csv_bytes)):
            rows = download_snapshot(
                'http://example.test/latest.csv', REQUIRED_COLUMNS,
                optional_columns=['https_enforced']
            )

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['https_enforced'], 'true')

    def test_optional_column_dropped_silently_when_absent(self):
        csv_bytes = _csv_bytes(
            REQUIRED_COLUMNS,
            [['test.gov', 'test.gov', 'true', '200', 'completed', '2026-09-02']]
        )
        with patch('snapshot.urllib.request.urlopen', return_value=FakeHttpResponse(csv_bytes)):
            rows = download_snapshot(
                'http://example.test/latest.csv', REQUIRED_COLUMNS,
                optional_columns=['bogus_field']
            )

        self.assertEqual(len(rows), 1)
        self.assertNotIn('bogus_field', rows[0])

    def test_missing_required_column_still_raises(self):
        csv_bytes = _csv_bytes(['initial_domain'], [['test.gov']])
        with patch('snapshot.urllib.request.urlopen', return_value=FakeHttpResponse(csv_bytes)):
            with self.assertRaises(SnapshotError):
                download_snapshot('http://example.test/latest.csv', REQUIRED_COLUMNS, retry_count=1)


class TestFindUnmatchedEntries(unittest.TestCase):
    """Regression coverage for finding #6: typo'd/missing watchlist entries must be reported."""

    def test_all_matched_returns_empty(self):
        rows = [{'initial_domain': 'test1.gov', 'initial_base_domain': 'test1.gov'}]
        self.assertEqual(find_unmatched_entries(rows, ['test1.gov']), [])

    def test_typo_domain_is_reported(self):
        rows = [{'initial_domain': 'test1.gov', 'initial_base_domain': 'test1.gov'}]
        self.assertEqual(find_unmatched_entries(rows, ['test1.gov', 'tset1.gov']), ['tset1.gov'])

    def test_base_prefix_matched_and_unmatched(self):
        rows = [{'initial_domain': 'www.test.gov', 'initial_base_domain': 'test.gov'}]
        self.assertEqual(
            find_unmatched_entries(rows, ['base:test.gov', 'base:other.gov']),
            ['base:other.gov']
        )

    def test_case_insensitive_match(self):
        rows = [{'initial_domain': 'Test1.gov', 'initial_base_domain': 'Test1.gov'}]
        self.assertEqual(find_unmatched_entries(rows, ['test1.gov']), [])


class TestScanDateParsing(unittest.TestCase):
    
    def test_parse_iso_with_tz(self):
        result = parse_scan_date('2026-09-02T08:11:41.911Z')
        self.assertIsNotNone(result)
        self.assertEqual(result.year, 2026)
        self.assertEqual(result.month, 9)
        self.assertEqual(result.day, 2)
    
    def test_parse_date_only(self):
        result = parse_scan_date('2026-09-02')
        self.assertIsNotNone(result)
        self.assertEqual(result.year, 2026)
    
    def test_parse_empty(self):
        result = parse_scan_date('')
        self.assertIsNone(result)


class TestSnapshotFreshness(unittest.TestCase):
    
    def test_fresh_snapshot(self):
        today = datetime.now().strftime('%Y-%m-%dT10:00:00Z')
        rows = [
            {'scan_date': today},
            {'scan_date': today},
        ]
        
        is_fresh, date_str, date_obj = check_snapshot_freshness(rows, max_age_days=3)
        
        self.assertTrue(is_fresh)
        self.assertIsNotNone(date_str)
    
    def test_stale_snapshot(self):
        old_date = (datetime.now() - timedelta(days=5)).strftime('%Y-%m-%dT10:00:00Z')
        rows = [
            {'scan_date': old_date},
        ]
        
        is_fresh, date_str, date_obj = check_snapshot_freshness(rows, max_age_days=3)
        
        self.assertFalse(is_fresh)


class TestSnapshotRotation(unittest.TestCase):
    
    def test_rotation_occurred(self):
        latest = [{'scan_date': '2026-09-02T10:00:00Z'}]
        previous = [{'scan_date': '2026-09-01T10:00:00Z'}]
        
        self.assertTrue(has_snapshot_rotated(latest, previous))
    
    def test_no_rotation(self):
        same_date = '2026-09-02T10:00:00Z'
        latest = [{'scan_date': same_date}]
        previous = [{'scan_date': same_date}]
        
        self.assertFalse(has_snapshot_rotated(latest, previous))


if __name__ == '__main__':
    unittest.main()
