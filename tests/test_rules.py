#!/usr/bin/env python3
"""Tests for rules.py"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from rules import (
    Alert,
    _is_recovery,
    dedupe_alerts,
    evaluate_change_diff,
    evaluate_state_check,
    parse_ignore_transitions,
    render_alerts,
)


class TestAlertRendering(unittest.TestCase):
    def test_alert_to_bullet_change(self):
        alert = Alert("test.gov", "live", "true", "false", "change")
        # The domain is deliberately absent - render_alerts supplies it as the
        # parent bullet. Leading indent nests this inside that bullet.
        self.assertEqual(alert.to_bullet(), "  - `live`: true → false")

    def test_alert_blank_rendering(self):
        alert = Alert("test.gov", "status_code", "200", "", "change")
        bullet = alert.to_bullet()
        self.assertIn("(no data)", bullet)

    def test_state_alert_bullet_has_no_transition(self):
        alert = Alert("test.gov", "status_code", "", "503", "state")
        self.assertEqual(alert.to_bullet(), "  - `status_code`: 503 (current value)")

    def test_corpus_alert_bullet_is_capitalized_message(self):
        alert = Alert("test.gov", "", "", "newly in snapshot", "corpus")
        self.assertEqual(alert.to_bullet(), "  - Newly in snapshot")


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

    def test_recovery_is_suppressed_when_report_recoveries_false(self):
        latest = [{"initial_domain": "test.gov", "primary_scan_status": "completed"}]
        previous = [{"initial_domain": "test.gov", "primary_scan_status": "timeout"}]

        alerts = evaluate_change_diff(
            latest, previous, ["primary_scan_status"], report_recoveries=False
        )

        self.assertEqual(len(alerts), 0)

    def test_recovery_is_reported_when_report_recoveries_true(self):
        latest = [{"initial_domain": "test.gov", "primary_scan_status": "completed"}]
        previous = [{"initial_domain": "test.gov", "primary_scan_status": "timeout"}]

        alerts = evaluate_change_diff(
            latest, previous, ["primary_scan_status"], report_recoveries=True
        )

        self.assertEqual(len(alerts), 1)

    def test_bad_direction_change_is_reported_either_way(self):
        latest = [{"initial_domain": "test.gov", "status_code": "503"}]
        previous = [{"initial_domain": "test.gov", "status_code": "200"}]

        for report_recoveries in (True, False):
            with self.subTest(report_recoveries=report_recoveries):
                alerts = evaluate_change_diff(
                    latest, previous, ["status_code"], report_recoveries=report_recoveries
                )
                self.assertEqual(len(alerts), 1)

    def test_custom_field_good_direction_is_reported_either_way(self):
        """
        The action has no direction knowledge for a user-configured custom
        field, so a good-looking transition on one is never treated as a
        recovery - it's reported regardless of report_recoveries.
        """
        latest = [{"initial_domain": "test.gov", "https_enforced": "true"}]
        previous = [{"initial_domain": "test.gov", "https_enforced": "false"}]

        for report_recoveries in (True, False):
            with self.subTest(report_recoveries=report_recoveries):
                alerts = evaluate_change_diff(
                    latest, previous, ["https_enforced"], report_recoveries=report_recoveries
                )
                self.assertEqual(len(alerts), 1)

    def test_corpus_alerts_are_unaffected_by_report_recoveries(self):
        latest = [{"initial_domain": "new.gov"}]
        previous = []

        alerts = evaluate_change_diff(latest, previous, [], report_recoveries=False)

        self.assertEqual(len(alerts), 1)
        self.assertIn("newly in snapshot", alerts[0].new_value)


class TestIsRecovery(unittest.TestCase):
    """
    _is_recovery is an allowlist, not a heuristic: only fields the action has
    real direction knowledge for (live, status_code, primary_scan_status)
    can ever be recoveries. Anything else - including user-configured
    custom `fields` - is never suppressed, since the action has no basis
    for judging its direction.
    """

    def test_live_becoming_true_is_a_recovery(self):
        self.assertTrue(_is_recovery("live", "false", "true"))
        self.assertTrue(_is_recovery("live", "", "true"))
        self.assertTrue(_is_recovery("live", "FALSE", "TRUE"))

    def test_live_becoming_false_is_not(self):
        self.assertFalse(_is_recovery("live", "true", "false"))
        self.assertFalse(_is_recovery("live", "true", ""))

    def test_status_code_becoming_healthy_is_a_recovery(self):
        self.assertTrue(_is_recovery("status_code", "503", "200"))
        self.assertTrue(_is_recovery("status_code", "403", "204"))
        self.assertTrue(_is_recovery("status_code", "", "200"))
        self.assertTrue(_is_recovery("status_code", "302", "200"))

    def test_status_code_becoming_a_redirect_is_not(self):
        # A redirect is often an outage's maintenance page, so it can't
        # confirm the site came back.
        self.assertFalse(_is_recovery("status_code", "503", "302"))
        self.assertFalse(_is_recovery("status_code", "403", "301"))
        self.assertFalse(_is_recovery("status_code", "", "307"))

    def test_status_code_staying_unhealthy_is_not(self):
        self.assertFalse(_is_recovery("status_code", "500", "503"))
        self.assertFalse(_is_recovery("status_code", "200", ""))
        self.assertFalse(_is_recovery("status_code", "200", "403"))

    def test_scan_status_becoming_completed_is_a_recovery(self):
        self.assertTrue(_is_recovery("primary_scan_status", "timeout", "completed"))
        self.assertTrue(_is_recovery("primary_scan_status", "", "completed"))

    def test_scan_status_leaving_completed_is_not(self):
        self.assertFalse(_is_recovery("primary_scan_status", "completed", "timeout"))

    def test_unknown_field_is_never_a_recovery(self):
        self.assertFalse(_is_recovery("https_enforced", "false", "true"))
        self.assertFalse(_is_recovery("hsts", "", "true"))


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

        self.assertIn("- **test1.gov**", body)
        self.assertIn("- **test2.gov**", body)
        self.assertIn("  - `live`: true → false", body)

    def test_render_uses_no_markdown_headings(self):
        """
        An issue body starts below the issue title, so headings injected here
        land at the wrong level in the document outline. Sites are nested list
        items instead.
        """
        alerts = [
            Alert("test.gov", "live", "true", "false", "change"),
            Alert("other.gov", "", "", "newly in snapshot", "corpus"),
        ]

        body = render_alerts(alerts, max_changes=10)

        for line in body.splitlines():
            self.assertFalse(line.startswith("#"), f"heading in body: {line!r}")

    def test_render_groups_multiple_findings_under_one_site(self):
        """Findings for one site share a parent bullet - the point of grouping."""
        alerts = [
            Alert("test.gov", "live", "true", "false", "change"),
            Alert("test.gov", "status_code", "200", "502", "change"),
            Alert("test.gov", "primary_scan_status", "completed", "timeout", "change"),
        ]

        body = render_alerts(alerts, max_changes=10)

        self.assertEqual(body.count("- **test.gov**"), 1)
        self.assertIn(
            "- **test.gov**\n"
            "  - `live`: true → false\n"
            "  - `status_code`: 200 → 502\n"
            "  - `primary_scan_status`: completed → timeout",
            body,
        )

    def test_render_orders_sites_alphabetically(self):
        alerts = [
            Alert("zebra.gov", "live", "true", "false", "change"),
            Alert("apple.gov", "live", "true", "false", "change"),
            Alert("mango.gov", "live", "true", "false", "change"),
        ]

        body = render_alerts(alerts, max_changes=10)

        self.assertLess(body.index("apple.gov"), body.index("mango.gov"))
        self.assertLess(body.index("mango.gov"), body.index("zebra.gov"))

    def test_render_keeps_sites_in_one_tight_list(self):
        """No blank line between sites, so it renders as one list, not many."""
        alerts = [
            Alert("a.gov", "live", "true", "false", "change"),
            Alert("b.gov", "live", "true", "false", "change"),
        ]

        body = render_alerts(alerts, max_changes=10)

        self.assertIn("  - `live`: true → false\n- **b.gov**", body)

    def test_render_keeps_intro_and_closing(self):
        alerts = [Alert("test.gov", "live", "true", "false", "change")]

        body = render_alerts(alerts, max_changes=10)

        self.assertIn("Site Scanning results have changed", body)
        self.assertIn("Please investigate as appropriate.", body)

    def test_render_exceeds_max(self):
        alerts = [Alert(f"test{i}.gov", "live", "true", "false", "change") for i in range(30)]

        body = render_alerts(alerts, max_changes=25)

        self.assertIn("30 total changes", body)
        self.assertIn("exceeds max_changes", body)

    def test_render_cleared(self):
        alerts = []

        body = render_alerts(alerts, max_changes=25)

        self.assertIn("returned to normal", body)


if __name__ == "__main__":
    unittest.main()
