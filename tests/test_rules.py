#!/usr/bin/env python3
"""Tests for rules.py"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from rules import (
    Alert,
    dedupe_alerts,
    evaluate_change_diff,
    evaluate_state_check,
    parse_ignore_transitions,
    render_alerts,
    render_footer,
)


class TestAlertRendering(unittest.TestCase):
    def test_alert_to_line_change(self):
        alert = Alert("test.gov", "live", "true", "false", "change")
        line = alert.to_line()
        self.assertIn("test.gov", line)
        self.assertIn("live: true -> false", line)

    def test_alert_blank_rendering(self):
        alert = Alert("test.gov", "status_code", "200", "", "change")
        bullet = alert.to_bullet()
        self.assertIn("(no data)", bullet)

    def test_alert_to_bullet_state(self):
        alert = Alert("test.gov", "status_code", "", "503", "state")
        bullet = alert.to_bullet()
        self.assertIn("`status_code`: 503", bullet)
        self.assertIn("current value", bullet)

    def test_alert_to_bullet_corpus(self):
        alert = Alert("test.gov", "", "", "newly in snapshot", "corpus")
        bullet = alert.to_bullet()
        self.assertIn("newly in snapshot", bullet)


class TestChangeDiff(unittest.TestCase):
    def test_detects_changes(self):
        latest = [{"initial_domain": "test.gov", "live": "false", "status_code": "403"}]
        previous = [{"initial_domain": "test.gov", "live": "true", "status_code": "200"}]

        alerts = evaluate_change_diff(latest, previous, ["live", "status_code"])

        self.assertEqual(len(alerts), 2)
        fields = [a.field for a in alerts]
        self.assertIn("live", fields)
        self.assertIn("status_code", fields)

    def test_ignores_blank_transitions(self):
        latest = [{"initial_domain": "test.gov", "live": "", "status_code": "200"}]
        previous = [{"initial_domain": "test.gov", "live": "true", "status_code": "200"}]

        alerts = evaluate_change_diff(latest, previous, ["live"], ignore_blank_transitions=True)

        self.assertEqual(len(alerts), 0)

    def test_ignores_specific_transitions(self):
        latest = [{"initial_domain": "test.gov", "primary_scan_status": "timeout"}]
        previous = [
            {"initial_domain": "test.gov", "primary_scan_status": "execution_context_destroyed"}
        ]

        ignore = {("primary_scan_status", "execution_context_destroyed", "timeout")}
        alerts = evaluate_change_diff(
            latest, previous, ["primary_scan_status"], ignore_transitions=ignore
        )

        self.assertEqual(len(alerts), 0)

    def test_detects_new_domain(self):
        latest = [{"initial_domain": "new.gov"}]
        previous = []

        alerts = evaluate_change_diff(latest, previous, [])

        self.assertEqual(len(alerts), 1)
        self.assertIn("newly in snapshot", alerts[0].new_value)

    def test_detects_removed_domain(self):
        latest = []
        previous = [{"initial_domain": "old.gov"}]

        alerts = evaluate_change_diff(latest, previous, [])

        self.assertEqual(len(alerts), 1)
        self.assertIn("no longer in snapshot", alerts[0].new_value)


class TestStateCheck(unittest.TestCase):
    def test_alert_on_status_code(self):
        rows = [
            {
                "initial_domain": "test1.gov",
                "status_code": "503",
                "primary_scan_status": "completed",
                "live": "true",
            },
            {
                "initial_domain": "test2.gov",
                "status_code": "200",
                "primary_scan_status": "completed",
                "live": "true",
            },
        ]

        alerts = evaluate_state_check(rows, {"503"}, set(), False)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].domain, "test1.gov")

    def test_alert_on_not_live(self):
        rows = [
            {
                "initial_domain": "test.gov",
                "status_code": "403",
                "primary_scan_status": "completed",
                "live": "false",
            },
        ]

        alerts = evaluate_state_check(rows, set(), set(), True)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].field, "live")


class TestDedupeAlerts(unittest.TestCase):
    """
    Regression coverage for finding #4: `both` mode can raise a change
    alert and a state alert for the same underlying failure.
    """

    def test_change_wins_over_state_for_same_domain_field(self):
        alerts = [
            Alert("test.gov", "status_code", "200", "503", "change"),
            Alert("test.gov", "status_code", "", "503", "state"),
        ]

        result = dedupe_alerts(alerts)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].alert_type, "change")
        self.assertEqual(result[0].old_value, "200")

    def test_change_wins_regardless_of_append_order(self):
        alerts = [
            Alert("test.gov", "status_code", "", "503", "state"),
            Alert("test.gov", "status_code", "200", "503", "change"),
        ]

        result = dedupe_alerts(alerts)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].alert_type, "change")

    def test_distinct_fields_both_survive(self):
        alerts = [
            Alert("test.gov", "status_code", "200", "503", "change"),
            Alert("test.gov", "primary_scan_status", "", "timeout", "state"),
        ]

        result = dedupe_alerts(alerts)

        self.assertEqual(len(result), 2)

    def test_distinct_domains_never_collapse(self):
        alerts = [
            Alert("a.gov", "status_code", "200", "503", "change"),
            Alert("b.gov", "status_code", "", "503", "state"),
        ]

        result = dedupe_alerts(alerts)

        self.assertEqual(len(result), 2)

    def test_two_corpus_alerts_on_one_domain_both_survive(self):
        alerts = [
            Alert("a.gov", "", "", "newly in snapshot", "corpus"),
            Alert("a.gov", "", "", "no longer in snapshot", "corpus"),
        ]

        result = dedupe_alerts(alerts)

        self.assertEqual(len(result), 2)

    def test_state_alone_survives_when_no_matching_change(self):
        alerts = [Alert("test.gov", "status_code", "", "503", "state")]

        result = dedupe_alerts(alerts)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].alert_type, "state")


class TestParseIgnoreTransitions(unittest.TestCase):
    def test_parse_single(self):
        result = parse_ignore_transitions("primary_scan_status:timeout->completed")
        self.assertEqual(len(result), 1)
        self.assertIn(("primary_scan_status", "timeout", "completed"), result)

    def test_parse_multiple(self):
        result = parse_ignore_transitions("live:true->false,status_code:200->503")
        self.assertEqual(len(result), 2)

    def test_parse_empty(self):
        result = parse_ignore_transitions("")
        self.assertEqual(len(result), 0)

    def test_parse_strips_whitespace(self):
        """
        Regression for finding #4: conventionally spaced entries like
        'live: true -> false' must strip whitespace from each part, or
        the parsed tuple never matches actual snapshot values.
        """
        result = parse_ignore_transitions(" live : true -> false ")
        self.assertIn(("live", "true", "false"), result)

    def test_parse_multiple_strips_whitespace_each(self):
        result = parse_ignore_transitions("live: true -> false, status_code: 200 -> 503")
        self.assertEqual(len(result), 2)
        self.assertIn(("live", "true", "false"), result)
        self.assertIn(("status_code", "200", "503"), result)


class TestRenderAlerts(unittest.TestCase):
    def test_render_below_max(self):
        alerts = [
            Alert("test1.gov", "live", "true", "false", "change"),
            Alert("test2.gov", "status_code", "200", "503", "change"),
        ]

        body = render_alerts(alerts, max_changes=10)

        self.assertIn("test1.gov", body)
        self.assertIn("test2.gov", body)
        self.assertIn("live: true -> false", body)
        self.assertIn("2 of your monitored website(s)", body)
        self.assertIn("2 findings", body)

    def test_render_groups_multiple_findings_under_one_domain_heading(self):
        alerts = [
            Alert("test.gov", "live", "true", "false", "change"),
            Alert("test.gov", "status_code", "200", "503", "change"),
        ]

        body = render_alerts(alerts, max_changes=10)

        # Domain heading appears exactly once even though it has 2 findings.
        self.assertEqual(body.count("**test.gov**"), 1)
        self.assertIn("1 of your monitored website(s)", body)
        self.assertIn("2 findings", body)

    def test_render_singular_finding(self):
        alerts = [Alert("test.gov", "live", "true", "false", "change")]

        body = render_alerts(alerts, max_changes=10)

        self.assertIn("1 finding", body)
        self.assertNotIn("1 findings", body)

    def test_render_exceeds_max(self):
        alerts = [Alert(f"test{i}.gov", "live", "true", "false", "change") for i in range(30)]
        body = render_alerts(alerts, max_changes=25)

        self.assertIn("30 total changes", body)
        self.assertIn("exceeds max_changes", body)

    def test_render_cleared(self):
        alerts = []

        body = render_alerts(alerts, max_changes=25)

        self.assertIn("returned to normal", body)


class TestRenderFooter(unittest.TestCase):
    def test_includes_snapshot_date_when_known(self):
        footer = render_footer("2026-09-21")
        self.assertIn("2026-09-21", footer)
        self.assertIn("Scan statuses", footer)
        self.assertIn("Data dictionary", footer)

    def test_omits_date_clause_when_unknown(self):
        footer = render_footer(None)
        self.assertNotIn("Snapshot date", footer)
        self.assertIn("Scan statuses", footer)


if __name__ == "__main__":
    unittest.main()
