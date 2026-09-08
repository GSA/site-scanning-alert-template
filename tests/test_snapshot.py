#!/usr/bin/env python3
"""Tests for snapshot.py"""
import unittest
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from snapshot import (
    filter_to_watchlist,
    parse_scan_date,
    check_snapshot_freshness,
    has_snapshot_rotated
)
from datetime import datetime, timedelta


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
