#!/usr/bin/env python3
"""Tests for issues.py"""

import io
import os
import sys
import unittest
import urllib.error
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from issues import (
    MAX_ISSUE_PAGES,
    IssueClient,
    alert_marker,
    compute_fingerprint,
    file_alert,
)


class FakeJsonResponse:
    """Minimal stand-in for the context manager urllib.request.urlopen returns."""

    def __init__(self, data: bytes):
        self._data = data

    def read(self):
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _http_error(code, body=b"", headers=None):
    """Build a real HTTPError, so .code/.read()/.headers all behave like the real thing."""
    return urllib.error.HTTPError(
        "https://api.github.com/x", code, "reason", headers or {}, io.BytesIO(body)
    )


class TestFingerprinting(unittest.TestCase):
    def test_compute_fingerprint_stable(self):
        body = "Test alert body"
        fp1 = compute_fingerprint(body)
        fp2 = compute_fingerprint(body)

        self.assertEqual(fp1, fp2)
        self.assertEqual(len(fp1), 12)

    def test_different_bodies_different_fingerprints(self):
        fp1 = compute_fingerprint("Body one")
        fp2 = compute_fingerprint("Body two")

        self.assertNotEqual(fp1, fp2)

    def test_alert_marker_distinguishes_stream_and_fingerprint(self):
        fp = compute_fingerprint("something is wrong")

        alerts_marker = alert_marker("alerts", fp)
        staleness_marker = alert_marker("staleness", fp)

        self.assertNotEqual(alerts_marker, staleness_marker)
        self.assertIn(fp, alerts_marker)


class TestIssueClientMock(unittest.TestCase):
    """
    Test IssueClient with mocked HTTP calls.

    Full integration tests would require a real GitHub token and repo;
    these tests verify the client's structure and basic logic.
    """

    def test_client_init(self):
        client = IssueClient("owner/repo", "token")

        self.assertEqual(client.repo, "owner/repo")
        self.assertEqual(client.token, "token")
        self.assertEqual(client.base_url, "https://api.github.com/repos/owner/repo")

    def test_find_open_issue_paginates(self):
        """A matching issue on page 2 must still be found."""
        client = IssueClient("owner/repo", "token")

        page_1 = [{"number": n, "html_url": f"u{n}", "body": "no marker here"} for n in range(100)]
        page_2 = [
            {
                "number": 100,
                "html_url": "u100",
                "body": "<!-- site-scanning-alert: alerts:abc123 -->\n\nbody",
            }
        ]

        with patch.object(client, "_request", side_effect=[page_1, page_2]) as mock_request:
            result = client.find_open_issue(
                ["site-scanning-alert"], "<!-- site-scanning-alert: alerts:abc123 -->"
            )

        self.assertIsNotNone(result)
        self.assertEqual(result["number"], 100)
        self.assertEqual(mock_request.call_count, 2)
        self.assertIn("page=2", mock_request.call_args_list[1][0][1])

    def test_find_open_issue_stops_when_page_short(self):
        client = IssueClient("owner/repo", "token")

        page_1 = [{"number": 1, "html_url": "u1", "body": "no marker"}]

        with patch.object(client, "_request", return_value=page_1) as mock_request:
            result = client.find_open_issue(["site-scanning-alert"], "<!-- site-scanning-alert:")

        self.assertIsNone(result)
        mock_request.assert_called_once()

    def test_find_open_issue_stops_at_page_ceiling(self):
        """A repo with unbounded matching open issues must not be walked forever."""
        client = IssueClient("owner/repo", "token")

        full_page = [
            {"number": n, "html_url": f"u{n}", "body": "no marker here"} for n in range(100)
        ]

        with patch.object(client, "_request", return_value=full_page) as mock_request:
            result = client.find_open_issue(["site-scanning-alert"], "<!-- site-scanning-alert:")

        self.assertIsNone(result)
        self.assertEqual(mock_request.call_count, MAX_ISSUE_PAGES)

    def test_find_open_issue_skips_null_body_without_crashing(self):
        """
        Regression for finding #1: GitHub returns body: null for issues
        created without a description. `marker in None` must not raise
        TypeError - it should just be treated as non-matching.
        """
        client = IssueClient("owner/repo", "token")

        issues = [
            {"number": 1, "html_url": "u1", "body": None},
            {
                "number": 2,
                "html_url": "u2",
                "body": "<!-- site-scanning-alert: alerts:abc123 -->\n\nbody",
            },
        ]

        with patch.object(client, "_request", return_value=issues):
            result = client.find_open_issue(
                ["site-scanning-alert"], "<!-- site-scanning-alert: alerts:abc123 -->"
            )

        self.assertIsNotNone(result)
        self.assertEqual(result["number"], 2)

    def test_find_open_issue_all_null_bodies_returns_none(self):
        client = IssueClient("owner/repo", "token")

        issues = [{"number": 1, "html_url": "u1", "body": None}]

        with patch.object(client, "_request", return_value=issues):
            result = client.find_open_issue(["site-scanning-alert"], "<!-- site-scanning-alert:")

        self.assertIsNone(result)

    def test_find_open_issue_url_encodes_labels(self):
        """Labels with spaces/commas must not produce a malformed query string."""
        client = IssueClient("owner/repo", "token")

        with patch.object(client, "_request", return_value=[]) as mock_request:
            client.find_open_issue(["needs encoding"], "<!-- site-scanning-alert:")

        path = mock_request.call_args_list[0][0][1]
        self.assertNotIn(" ", path)
        self.assertIn("needs+encoding", path)

    def test_ensure_label_url_encodes_label(self):
        client = IssueClient("owner/repo", "token")

        with patch.object(client, "_request", return_value={}) as mock_request:
            client.ensure_label("needs encoding")

        method, path = mock_request.call_args_list[0][0][:2]
        self.assertEqual(method, "GET")
        self.assertNotIn(" ", path)
        self.assertIn("needs%20encoding", path)


class TestRequestRetries(unittest.TestCase):
    """
    Retry behavior of IssueClient._request. Deliberately asymmetric: GET
    retries 5xx, rate limits, and network errors, but POST retries only
    rate limits. A 5xx or network error on POST may arrive after the issue
    was already created server-side, and retrying it risks a duplicate.
    """

    def test_get_retries_on_500_then_succeeds(self):
        client = IssueClient("owner/repo", "token")
        ok = FakeJsonResponse(b'{"ok": true}')

        with (
            patch("issues.urllib.request.urlopen", side_effect=[_http_error(500), ok]),
            patch("issues.time.sleep") as mock_sleep,
        ):
            result = client._request("GET", "/issues")

        self.assertEqual(result, {"ok": True})
        mock_sleep.assert_called_once()

    def test_get_retries_on_429_then_succeeds(self):
        client = IssueClient("owner/repo", "token")
        ok = FakeJsonResponse(b'{"ok": true}')

        with (
            patch("issues.urllib.request.urlopen", side_effect=[_http_error(429), ok]),
            patch("issues.time.sleep"),
        ):
            result = client._request("GET", "/issues")

        self.assertEqual(result, {"ok": True})

    def test_get_retries_on_secondary_rate_limit_403(self):
        client = IssueClient("owner/repo", "token")
        ok = FakeJsonResponse(b'{"ok": true}')
        secondary_403 = _http_error(403, body=b"You have exceeded a secondary rate limit")

        with (
            patch("issues.urllib.request.urlopen", side_effect=[secondary_403, ok]),
            patch("issues.time.sleep"),
        ):
            result = client._request("GET", "/issues")

        self.assertEqual(result, {"ok": True})

    def test_plain_403_is_not_retried(self):
        """A permissions 403 will never succeed on retry - fail fast."""
        client = IssueClient("owner/repo", "token")
        plain_403 = _http_error(403, body=b"Resource not accessible by integration")

        with (
            patch("issues.urllib.request.urlopen", side_effect=plain_403) as mock_urlopen,
            patch("issues.time.sleep") as mock_sleep,
        ):
            with self.assertRaises(RuntimeError):
                client._request("GET", "/issues")

        self.assertEqual(mock_urlopen.call_count, 1)
        mock_sleep.assert_not_called()

    def test_404_is_not_retried_and_keeps_http_404_substring(self):
        """
        ensure_label sniffs "HTTP 404" out of the raised message to decide
        a label doesn't exist yet - that substring must survive.
        """
        client = IssueClient("owner/repo", "token")

        with (
            patch("issues.urllib.request.urlopen", side_effect=_http_error(404)) as mock_urlopen,
            patch("issues.time.sleep") as mock_sleep,
        ):
            with self.assertRaises(RuntimeError) as cm:
                client._request("GET", "/labels/x")

        self.assertIn("HTTP 404", str(cm.exception))
        self.assertEqual(mock_urlopen.call_count, 1)
        mock_sleep.assert_not_called()

    def test_get_retries_on_url_error_then_succeeds(self):
        client = IssueClient("owner/repo", "token")
        ok = FakeJsonResponse(b'{"ok": true}')

        with (
            patch(
                "issues.urllib.request.urlopen",
                side_effect=[urllib.error.URLError("boom"), ok],
            ),
            patch("issues.time.sleep") as mock_sleep,
        ):
            result = client._request("GET", "/issues")

        self.assertEqual(result, {"ok": True})
        mock_sleep.assert_called_once()

    def test_get_retries_on_timeout_error_then_succeeds(self):
        """urlopen raises a bare TimeoutError (not a URLError) on a read timeout."""
        client = IssueClient("owner/repo", "token")
        ok = FakeJsonResponse(b'{"ok": true}')

        with (
            patch("issues.urllib.request.urlopen", side_effect=[TimeoutError(), ok]),
            patch("issues.time.sleep") as mock_sleep,
        ):
            result = client._request("GET", "/issues")

        self.assertEqual(result, {"ok": True})
        mock_sleep.assert_called_once()

    def test_post_is_not_retried_on_network_error(self):
        """
        The duplicate-issue guard: a POST may have already succeeded
        server-side before a URLError/timeout was raised locally, so
        retrying it risks filing a second issue.
        """
        for error in (urllib.error.URLError("boom"), TimeoutError()):
            with self.subTest(error=type(error).__name__):
                client = IssueClient("owner/repo", "token")

                with (
                    patch("issues.urllib.request.urlopen", side_effect=error) as mock_urlopen,
                    patch("issues.time.sleep") as mock_sleep,
                ):
                    with self.assertRaises(RuntimeError):
                        client.create_issue("title", "body", ["label"])

                self.assertEqual(mock_urlopen.call_count, 1)
                mock_sleep.assert_not_called()

    def test_post_is_not_retried_on_5xx(self):
        """
        A 502/504 from GitHub's front end, or a 500, can arrive after the
        backend already saved the issue - same maybe-applied risk as a
        network error.
        """
        client = IssueClient("owner/repo", "token")

        with (
            patch("issues.urllib.request.urlopen", side_effect=_http_error(502)) as mock_urlopen,
            patch("issues.time.sleep") as mock_sleep,
        ):
            with self.assertRaises(RuntimeError) as cm:
                client.create_issue("title", "body", ["label"])

        self.assertIn("HTTP 502", str(cm.exception))
        self.assertEqual(mock_urlopen.call_count, 1)
        mock_sleep.assert_not_called()

    def test_post_is_retried_on_rate_limit(self):
        """GitHub rejects a rate-limited request before doing any work, so it's safe to resend."""
        secondary_403 = _http_error(403, body=b"You have exceeded a secondary rate limit")
        for error in (_http_error(429), secondary_403):
            with self.subTest(code=error.code):
                client = IssueClient("owner/repo", "token")
                ok = FakeJsonResponse(b'{"number": 1, "html_url": "u1"}')

                with (
                    patch("issues.urllib.request.urlopen", side_effect=[error, ok]),
                    patch("issues.time.sleep"),
                ):
                    result = client.create_issue("title", "body", ["label"])

                self.assertEqual(result, {"number": 1, "html_url": "u1"})

    def test_retry_after_header_is_honored_and_capped(self):
        client = IssueClient("owner/repo", "token")
        ok = FakeJsonResponse(b'{"ok": true}')
        rate_limited = _http_error(429, headers={"Retry-After": "600"})

        with (
            patch("issues.urllib.request.urlopen", side_effect=[rate_limited, ok]),
            patch("issues.time.sleep") as mock_sleep,
        ):
            client._request("GET", "/issues")

        mock_sleep.assert_called_once_with(60.0)

    def test_retry_after_falls_back_to_backoff_when_not_a_plain_integer(self):
        client = IssueClient("owner/repo", "token")
        ok = FakeJsonResponse(b'{"ok": true}')
        rate_limited = _http_error(429, headers={"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"})

        with (
            patch("issues.urllib.request.urlopen", side_effect=[rate_limited, ok]),
            patch("issues.time.sleep") as mock_sleep,
        ):
            client._request("GET", "/issues")

        mock_sleep.assert_called_once_with(2.0)

    def test_retry_after_falls_back_to_backoff_when_negative_or_not_finite(self):
        # time.sleep raises ValueError on a negative value, which would
        # escape as an unexpected error instead of a RuntimeError.
        for raw in ("-5", "nan", "inf"):
            with self.subTest(retry_after=raw):
                client = IssueClient("owner/repo", "token")
                ok = FakeJsonResponse(b'{"ok": true}')
                rate_limited = _http_error(429, headers={"Retry-After": raw})

                with (
                    patch("issues.urllib.request.urlopen", side_effect=[rate_limited, ok]),
                    patch("issues.time.sleep") as mock_sleep,
                ):
                    client._request("GET", "/issues")

                mock_sleep.assert_called_once_with(2.0)

    def test_ensure_label_still_creates_on_404_without_sleeping(self):
        client = IssueClient("owner/repo", "token")
        created = FakeJsonResponse(b'{"name": "x"}')

        with (
            patch(
                "issues.urllib.request.urlopen", side_effect=[_http_error(404), created]
            ) as mock_urlopen,
            patch("issues.time.sleep") as mock_sleep,
        ):
            client.ensure_label("x")

        self.assertEqual(mock_urlopen.call_count, 2)  # GET 404, then POST create
        mock_sleep.assert_not_called()

    def test_exhausted_retries_raise_with_status_and_body(self):
        client = IssueClient("owner/repo", "token")
        # A fresh HTTPError per attempt: a real urlopen() call produces a
        # new response (and a new, unconsumed .fp) each time, unlike
        # reusing one exception instance across retries.
        errors = [_http_error(503, body=b"down") for _ in range(3)]

        with (
            patch("issues.urllib.request.urlopen", side_effect=errors),
            patch("issues.time.sleep"),
        ):
            with self.assertRaises(RuntimeError) as cm:
                client._request("GET", "/issues")

        self.assertIn("HTTP 503", str(cm.exception))
        self.assertIn("down", str(cm.exception))


class MarkerFilteringFakeClient:
    """
    In-memory fake that filters find_open_issue by marker the way the real
    client does, so it can exercise fingerprint dedupe and stream isolation
    without HTTP.
    """

    def __init__(self):
        self.issues = []  # list of {'number', 'html_url', 'body'}
        self.ensure_label_calls = []
        self._next_number = 1

    def ensure_label(self, label, color="0366d6", description=""):
        self.ensure_label_calls.append(label)

    def find_open_issue(self, labels, marker):
        for issue in self.issues:
            if marker in issue["body"]:
                return issue
        return None

    def create_issue(self, title, body, labels):
        issue = {
            "number": self._next_number,
            "html_url": f"https://github.com/owner/repo/issues/{self._next_number}",
            "body": body,
        }
        self.issues.append(issue)
        self._next_number += 1
        return {"number": issue["number"], "html_url": issue["html_url"]}


class TestFileAlert(unittest.TestCase):
    def test_creates_issue_when_none_exists(self):
        client = MarkerFilteringFakeClient()

        result = file_alert(
            client,
            "Possible website issues",
            "something is wrong",
            ["site-scanning-alert"],
        )

        self.assertEqual(result["action"], "created")
        self.assertEqual(len(client.issues), 1)
        self.assertEqual(client.ensure_label_calls, ["site-scanning-alert"])

    def test_noop_when_identical_findings_already_open(self):
        client = MarkerFilteringFakeClient()

        first = file_alert(
            client,
            "Possible website issues",
            "something is wrong",
            ["site-scanning-alert"],
        )
        client.ensure_label_calls.clear()

        second = file_alert(
            client,
            "Possible website issues",
            "something is wrong",
            ["site-scanning-alert"],
        )

        self.assertEqual(second["action"], "no-op")
        self.assertEqual(second["issue_url"], first["issue_url"])
        self.assertEqual(len(client.issues), 1)
        # ensure_label should not run again once the issue already exists.
        self.assertEqual(client.ensure_label_calls, [])

    def test_files_new_issue_when_findings_change(self):
        """
        A changed set of findings (e.g. a new domain fails) has a
        different fingerprint, so it must not match the earlier issue -
        it gets its own issue rather than being folded into the first.
        """
        client = MarkerFilteringFakeClient()

        first = file_alert(
            client,
            "Possible website issues",
            "domain-a is down",
            ["site-scanning-alert"],
        )
        second = file_alert(
            client,
            "Possible website issues",
            "domain-a and domain-b are down",
            ["site-scanning-alert"],
        )

        self.assertEqual(first["action"], "created")
        self.assertEqual(second["action"], "created")
        self.assertNotEqual(first["issue_url"], second["issue_url"])
        self.assertEqual(len(client.issues), 2)

    def test_streams_do_not_collide_on_shared_labels(self):
        """
        'alerts' and 'staleness' streams share the same labels, so the
        marker must scope by stream as well as fingerprint - otherwise
        one stream's finding could be mistaken for the other's.
        """
        client = MarkerFilteringFakeClient()

        alert_result = file_alert(
            client,
            "Possible website issues",
            "something is wrong",
            ["site-scanning-alert"],
            stream="alerts",
        )
        stale_result = file_alert(
            client,
            "Site Scanning data is stale",
            "data is stale",
            ["site-scanning-alert"],
            stream="staleness",
        )

        self.assertEqual(alert_result["action"], "created")
        self.assertEqual(stale_result["action"], "created")
        self.assertEqual(len(client.issues), 2)
        self.assertNotEqual(alert_result["issue_url"], stale_result["issue_url"])

    def test_staleness_rerun_is_noop_and_does_not_touch_alert_issue(self):
        client = MarkerFilteringFakeClient()
        file_alert(
            client,
            "Possible website issues",
            "something is wrong",
            ["site-scanning-alert"],
            stream="alerts",
        )
        file_alert(
            client,
            "Site Scanning data is stale",
            "data is stale",
            ["site-scanning-alert"],
            stream="staleness",
        )

        result = file_alert(
            client,
            "Site Scanning data is stale",
            "data is stale",
            ["site-scanning-alert"],
            stream="staleness",
        )

        self.assertEqual(result["action"], "no-op")
        self.assertEqual(result["issue_url"], client.issues[1]["html_url"])
        self.assertEqual(len(client.issues), 2)

    def test_default_stream_is_alerts(self):
        client = MarkerFilteringFakeClient()

        file_alert(
            client,
            "Possible website issues",
            "something is wrong",
            ["site-scanning-alert"],  # no explicit stream
        )
        result = file_alert(
            client,
            "Possible website issues",
            "something is wrong",
            ["site-scanning-alert"],
            stream="alerts",
        )

        self.assertEqual(result["action"], "no-op")  # same stream, same fingerprint

    def test_empty_labels_raises_value_error(self):
        """
        file_alert must never run with an empty labels list -
        find_open_issue would never find a match, so every run would
        create a brand-new issue.
        """
        client = MarkerFilteringFakeClient()

        with self.assertRaises(ValueError):
            file_alert(
                client,
                "Possible website issues",
                "something is wrong",
                [],
            )


if __name__ == "__main__":
    unittest.main()
