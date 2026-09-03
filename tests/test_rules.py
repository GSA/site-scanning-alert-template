#!/usr/bin/env python3
"""Tests for rules.py"""
import unittest
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from rules import (
    Alert,
    evaluate_change_diff,
    evaluate_state_check,
    parse_ignore_transitions,
    render_alerts
)


class TestAlertRendering(unittest.TestCase):
    
    def test_alert_to_line_change(self):
        alert = Alert('test.gov', 'live', 'true', 'false', 'change')
        line = alert.to_line()
        self.assertIn('test.gov', line)
        self.assertIn('live: true -> false', line)
    
    def test_alert_blank_rendering(self):
        alert = Alert('test.gov', 'status_code', '200', '', 'change')
        line = alert.to_line()
        self.assertIn('(no data)', line)


class TestChangeDiff(unittest.TestCase):
    
    def test_detects_changes(self):
        latest = [{'initial_domain': 'test.gov', 'live': 'false', 'status_code': '403'}]
        previous = [{'initial_domain': 'test.gov', 'live': 'true', 'status_code': '200'}]
        
        alerts = evaluate_change_diff(latest, previous, ['live', 'status_code'])
        
        self.assertEqual(len(alerts), 2)
        fields = [a.field for a in alerts]
        self.assertIn('live', fields)
        self.assertIn('status_code', fields)
    
    def test_ignores_blank_transitions(self):
        latest = [{'initial_domain': 'test.gov', 'live': '', 'status_code': '200'}]
        previous = [{'initial_domain': 'test.gov', 'live': 'true', 'status_code': '200'}]
        
        alerts = evaluate_change_diff(latest, previous, ['live'], ignore_blank_transitions=True)
        
        self.assertEqual(len(alerts), 0)
    
    def test_ignores_specific_transitions(self):
        latest = [{'initial_domain': 'test.gov', 'primary_scan_status': 'timeout'}]
        previous = [{'initial_domain': 'test.gov', 'primary_scan_status': 'execution_context_destroyed'}]
        
        ignore = {('primary_scan_status', 'execution_context_destroyed', 'timeout')}
        alerts = evaluate_change_diff(latest, previous, ['primary_scan_status'], ignore_transitions=ignore)
        
        self.assertEqual(len(alerts), 0)
    
    def test_detects_new_domain(self):
        latest = [{'initial_domain': 'new.gov'}]
        previous = []
        
        alerts = evaluate_change_diff(latest, previous, [])
        
        self.assertEqual(len(alerts), 1)
        self.assertIn('newly in snapshot', alerts[0].new_value)
    
    def test_detects_removed_domain(self):
        latest = []
        previous = [{'initial_domain': 'old.gov'}]
        
        alerts = evaluate_change_diff(latest, previous, [])
        
        self.assertEqual(len(alerts), 1)
        self.assertIn('no longer in snapshot', alerts[0].new_value)


class TestStateCheck(unittest.TestCase):
    
    def test_alert_on_status_code(self):
        rows = [
            {'initial_domain': 'test1.gov', 'status_code': '503', 'primary_scan_status': 'completed', 'live': 'true'},
            {'initial_domain': 'test2.gov', 'status_code': '200', 'primary_scan_status': 'completed', 'live': 'true'},
        ]
        
        alerts = evaluate_state_check(rows, {'503'}, set(), False)
        
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].domain, 'test1.gov')
    
    def test_alert_on_not_live(self):
        rows = [
            {'initial_domain': 'test.gov', 'status_code': '403', 'primary_scan_status': 'completed', 'live': 'false'},
        ]
        
        alerts = evaluate_state_check(rows, set(), set(), True)
        
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].field, 'live')


class TestParseIgnoreTransitions(unittest.TestCase):
    
    def test_parse_single(self):
        result = parse_ignore_transitions('primary_scan_status:timeout->completed')
        self.assertEqual(len(result), 1)
        self.assertIn(('primary_scan_status', 'timeout', 'completed'), result)
    
    def test_parse_multiple(self):
        result = parse_ignore_transitions('live:true->false,status_code:200->503')
        self.assertEqual(len(result), 2)
    
    def test_parse_empty(self):
        result = parse_ignore_transitions('')
        self.assertEqual(len(result), 0)


class TestRenderAlerts(unittest.TestCase):
    
    def test_render_below_max(self):
        alerts = [
            Alert('test1.gov', 'live', 'true', 'false', 'change'),
            Alert('test2.gov', 'status_code', '200', '503', 'change'),
        ]
        
        body = render_alerts(alerts, max_changes=10)
        
        self.assertIn('test1.gov', body)
        self.assertIn('test2.gov', body)
        self.assertIn('live: true -> false', body)
    
    def test_render_exceeds_max(self):
        alerts = [Alert(f'test{i}.gov', 'live', 'true', 'false', 'change') for i in range(30)]
        
        body = render_alerts(alerts, max_changes=25)
        
        self.assertIn('30 total changes', body)
        self.assertIn('exceeds max_changes', body)
    
    def test_render_cleared(self):
        alerts = []
        
        body = render_alerts(alerts, max_changes=25)
        
        self.assertIn('returned to normal', body)


if __name__ == '__main__':
    unittest.main()
