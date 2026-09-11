#!/usr/bin/env python3
"""Tests for issues.py"""
import unittest
import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from issues import (
    compute_fingerprint,
    embed_fingerprint,
    extract_fingerprint,
    has_cleared_marker,
    IssueClient,
    handle_alert_lifecycle,
    MAX_ISSUE_PAGES
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
    
    def test_embed_and_extract(self):
        body = "Alert body content"
        fp = compute_fingerprint(body)
        
        embedded = embed_fingerprint(body, fp)
        extracted = extract_fingerprint(embedded)
        
        self.assertEqual(extracted, fp)
    
    def test_extract_nonexistent(self):
        body = "Plain body with no fingerprint"
        extracted = extract_fingerprint(body)
        
        self.assertIsNone(extracted)


class TestIssueClientMock(unittest.TestCase):
    """
    Test IssueClient with mocked HTTP calls.
    
    Full integration tests would require a real GitHub token and repo;
    these tests verify the client's structure and basic logic.
    """
    
    def test_client_init(self):
        client = IssueClient('owner/repo', 'token')

        self.assertEqual(client.repo, 'owner/repo')
        self.assertEqual(client.token, 'token')
        self.assertEqual(client.base_url, 'https://api.github.com/repos/owner/repo')

    def test_find_open_issue_paginates(self):
        """A matching issue on page 2 must still be found."""
        client = IssueClient('owner/repo', 'token')

        page_1 = [{'number': n, 'html_url': f'u{n}', 'body': 'no marker here'} for n in range(100)]
        page_2 = [{'number': 100, 'html_url': 'u100', 'body': '<!-- alert-fingerprint: abc123 -->\n\nbody'}]

        with patch.object(client, '_request', side_effect=[page_1, page_2]) as mock_request:
            result = client.find_open_issue(['site-scanning-alert'], '<!-- alert-fingerprint:')

        self.assertIsNotNone(result)
        self.assertEqual(result['number'], 100)
        self.assertEqual(mock_request.call_count, 2)
        self.assertIn('page=2', mock_request.call_args_list[1][0][1])

    def test_find_open_issue_stops_when_page_short(self):
        client = IssueClient('owner/repo', 'token')

        page_1 = [{'number': 1, 'html_url': 'u1', 'body': 'no marker'}]

        with patch.object(client, '_request', return_value=page_1) as mock_request:
            result = client.find_open_issue(['site-scanning-alert'], '<!-- alert-fingerprint:')

        self.assertIsNone(result)
        mock_request.assert_called_once()

    def test_find_open_issue_stops_at_page_ceiling(self):
        """A repo with unbounded matching open issues must not be walked forever."""
        client = IssueClient('owner/repo', 'token')

        full_page = [{'number': n, 'html_url': f'u{n}', 'body': 'no marker here'} for n in range(100)]

        with patch.object(client, '_request', return_value=full_page) as mock_request:
            result = client.find_open_issue(['site-scanning-alert'], '<!-- alert-fingerprint:')

        self.assertIsNone(result)
        self.assertEqual(mock_request.call_count, MAX_ISSUE_PAGES)

    def test_find_open_issue_skips_null_body_without_crashing(self):
        """
        Regression for finding #1: GitHub returns body: null for issues
        created without a description. `marker in None` must not raise
        TypeError - it should just be treated as non-matching.
        """
        client = IssueClient('owner/repo', 'token')

        issues = [
            {'number': 1, 'html_url': 'u1', 'body': None},
            {'number': 2, 'html_url': 'u2', 'body': '<!-- alert-fingerprint: abc123 -->\n\nbody'},
        ]

        with patch.object(client, '_request', return_value=issues):
            result = client.find_open_issue(['site-scanning-alert'], '<!-- alert-fingerprint:')

        self.assertIsNotNone(result)
        self.assertEqual(result['number'], 2)

    def test_find_open_issue_all_null_bodies_returns_none(self):
        client = IssueClient('owner/repo', 'token')

        issues = [{'number': 1, 'html_url': 'u1', 'body': None}]

        with patch.object(client, '_request', return_value=issues):
            result = client.find_open_issue(['site-scanning-alert'], '<!-- alert-fingerprint:')

        self.assertIsNone(result)

    def test_find_open_issue_url_encodes_labels(self):
        """Labels with spaces/commas must not produce a malformed query string."""
        client = IssueClient('owner/repo', 'token')

        with patch.object(client, '_request', return_value=[]) as mock_request:
            client.find_open_issue(['needs encoding'], '<!-- alert-fingerprint:')

        path = mock_request.call_args_list[0][0][1]
        self.assertNotIn(' ', path)
        self.assertIn('needs+encoding', path)

    def test_ensure_label_url_encodes_label(self):
        client = IssueClient('owner/repo', 'token')

        with patch.object(client, '_request', return_value={}) as mock_request:
            client.ensure_label('needs encoding')

        method, path = mock_request.call_args_list[0][0][:2]
        self.assertEqual(method, 'GET')
        self.assertNotIn(' ', path)
        self.assertIn('needs%20encoding', path)


class FakeIssueClient:
    """In-memory stand-in for IssueClient, for lifecycle testing without HTTP."""

    def __init__(self, existing_issue=None):
        self.existing_issue = existing_issue
        self.created = []
        self.comments = []
        self.updates = []
        self.ensure_label_calls = []

    def ensure_label(self, label, color='0366d6', description=''):
        self.ensure_label_calls.append(label)

    def find_open_issue(self, labels, marker):
        return self.existing_issue

    def create_issue(self, title, body, labels):
        self.created.append({'title': title, 'body': body, 'labels': labels})
        return {'number': 1, 'html_url': 'https://github.com/owner/repo/issues/1'}

    def comment_on_issue(self, issue_number, comment):
        self.comments.append({'issue_number': issue_number, 'comment': comment})

    def update_issue(self, issue_number, body):
        self.updates.append({'issue_number': issue_number, 'body': body})
        # Write back into the same dict find_open_issue returns, so a
        # subsequent handle_alert_lifecycle call in the same test sees the
        # patched body - without this, findings #1/#2 regress invisibly.
        if self.existing_issue and self.existing_issue['number'] == issue_number:
            self.existing_issue['body'] = body


class TestAlertLifecycle(unittest.TestCase):

    def test_creates_issue_when_none_exists(self):
        client = FakeIssueClient(existing_issue=None)

        result = handle_alert_lifecycle(
            client, 'Possible website issues', 'something is wrong',
            ['site-scanning-alert'], is_clear=False
        )

        self.assertEqual(result['action'], 'created')
        self.assertEqual(len(client.created), 1)

    def test_noop_when_alert_unchanged(self):
        body = 'something is wrong'
        fp = compute_fingerprint(body)
        existing = {
            'number': 1,
            'html_url': 'https://github.com/owner/repo/issues/1',
            'body': embed_fingerprint(body, fp)
        }
        client = FakeIssueClient(existing_issue=existing)

        result = handle_alert_lifecycle(
            client, 'Possible website issues', body,
            ['site-scanning-alert'], is_clear=False
        )

        self.assertEqual(result['action'], 'no-op')
        self.assertEqual(result['issue_url'], existing['html_url'])
        self.assertEqual(len(client.comments), 0)
        self.assertEqual(len(client.created), 0)

    def test_comments_when_alert_changed(self):
        existing = {
            'number': 1,
            'html_url': 'https://github.com/owner/repo/issues/1',
            'body': embed_fingerprint('old alert body', compute_fingerprint('old alert body'))
        }
        client = FakeIssueClient(existing_issue=existing)

        result = handle_alert_lifecycle(
            client, 'Possible website issues', 'new alert body',
            ['site-scanning-alert'], is_clear=False
        )

        self.assertEqual(result['action'], 'commented')
        self.assertEqual(len(client.comments), 1)
        self.assertEqual(len(client.created), 0)

    def test_cleared_comments_on_existing_issue(self):
        existing = {
            'number': 1,
            'html_url': 'https://github.com/owner/repo/issues/1',
            'body': embed_fingerprint('old alert body', compute_fingerprint('old alert body'))
        }
        client = FakeIssueClient(existing_issue=existing)

        result = handle_alert_lifecycle(
            client, 'Possible website issues', 'all clear',
            ['site-scanning-alert'], is_clear=True, comment_on_clear=True
        )

        self.assertEqual(result['action'], 'cleared')
        self.assertEqual(result['issue_url'], existing['html_url'])
        self.assertEqual(len(client.comments), 1)

    def test_clear_without_comment_on_clear_still_returns_issue_url(self):
        existing = {
            'number': 1,
            'html_url': 'https://github.com/owner/repo/issues/1',
            'body': embed_fingerprint('old alert body', compute_fingerprint('old alert body'))
        }
        client = FakeIssueClient(existing_issue=existing)

        result = handle_alert_lifecycle(
            client, 'Possible website issues', 'all clear',
            ['site-scanning-alert'], is_clear=True, comment_on_clear=False
        )

        self.assertEqual(result['action'], 'no-op')
        self.assertEqual(result['issue_url'], existing['html_url'])
        self.assertEqual(len(client.comments), 0)

    def test_clear_without_comment_on_clear_still_marks_body_cleared(self):
        """
        Regression for finding #6: comment_on_clear=False must still
        persist the cleared marker on the issue body. Without it, a later
        re-fire with a matching fingerprint gets silently swallowed as a
        no-op instead of posting a re-fire comment.
        """
        existing = {
            'number': 1,
            'html_url': 'https://github.com/owner/repo/issues/1',
            'body': embed_fingerprint('old alert body', compute_fingerprint('old alert body'))
        }
        client = FakeIssueClient(existing_issue=existing)

        handle_alert_lifecycle(
            client, 'Possible website issues', 'all clear',
            ['site-scanning-alert'], is_clear=True, comment_on_clear=False
        )

        self.assertTrue(has_cleared_marker(client.existing_issue['body']))
        self.assertEqual(len(client.updates), 1)
        self.assertEqual(len(client.comments), 0)

        # A second consecutive silent clear must stay a no-op (idempotent -
        # the has_cleared_marker guard should short-circuit before another
        # update_issue call).
        client.updates.clear()
        second = handle_alert_lifecycle(
            client, 'Possible website issues', 'all clear',
            ['site-scanning-alert'], is_clear=True, comment_on_clear=False
        )
        self.assertEqual(second['action'], 'no-op')
        self.assertEqual(len(client.updates), 0)

    def test_silent_clear_then_refire_posts_refire_comment(self):
        """
        End-to-end regression for finding #6: an alert clears silently
        (comment_on_clear=False), then the exact same failure returns.
        Because the body was still marked cleared, this must be
        recognized as a re-fire and commented on, not swallowed.
        """
        body = 'site is down'
        existing = {
            'number': 1,
            'html_url': 'https://github.com/owner/repo/issues/1',
            'body': embed_fingerprint(body, compute_fingerprint(body))
        }
        client = FakeIssueClient(existing_issue=existing)

        # Silent clear
        handle_alert_lifecycle(
            client, 'Possible website issues', 'all clear',
            ['site-scanning-alert'], is_clear=True, comment_on_clear=False
        )
        self.assertEqual(len(client.comments), 0)

        # Same failure returns with an identical fingerprint to what was
        # open before the clear.
        result = handle_alert_lifecycle(
            client, 'Possible website issues', body,
            ['site-scanning-alert'], is_clear=False, comment_on_clear=False
        )

        self.assertEqual(result['action'], 'commented')
        self.assertEqual(len(client.comments), 1)
        self.assertIn('re-fired', client.comments[0]['comment'])

    def test_clear_with_no_existing_issue_is_noop_with_no_url(self):
        client = FakeIssueClient(existing_issue=None)

        result = handle_alert_lifecycle(
            client, 'Possible website issues', 'all clear',
            ['site-scanning-alert'], is_clear=True, comment_on_clear=True
        )

        self.assertEqual(result['action'], 'no-op')
        self.assertIsNone(result['issue_url'])

    def test_changed_alert_patches_body_so_next_identical_run_is_noop(self):
        """
        Regression for finding #1: a changed alert must update the issue
        body's fingerprint, not just comment - otherwise every subsequent
        run re-compares against the stale Day 1 fingerprint and comments
        again even though nothing new happened.
        """
        existing = {
            'number': 1,
            'html_url': 'https://github.com/owner/repo/issues/1',
            'body': embed_fingerprint('old alert body', compute_fingerprint('old alert body'))
        }
        client = FakeIssueClient(existing_issue=existing)

        first = handle_alert_lifecycle(
            client, 'Possible website issues', 'new alert body',
            ['site-scanning-alert'], is_clear=False
        )
        self.assertEqual(first['action'], 'commented')
        self.assertEqual(len(client.updates), 1)

        # Re-run with the same (now current) alert body - must be a no-op,
        # not another "Alert updated" comment.
        second = handle_alert_lifecycle(
            client, 'Possible website issues', 'new alert body',
            ['site-scanning-alert'], is_clear=False
        )
        self.assertEqual(second['action'], 'no-op')
        self.assertEqual(len(client.comments), 1)  # still just the first run's comment

    def test_cleared_flag_prevents_second_daily_comment(self):
        """
        Regression for finding #2: once a cleared condition is reported,
        it must not be reported again on the next healthy run.
        """
        existing = {
            'number': 1,
            'html_url': 'https://github.com/owner/repo/issues/1',
            'body': embed_fingerprint('old alert body', compute_fingerprint('old alert body'))
        }
        client = FakeIssueClient(existing_issue=existing)

        first = handle_alert_lifecycle(
            client, 'Possible website issues', 'all clear',
            ['site-scanning-alert'], is_clear=True, comment_on_clear=True
        )
        self.assertEqual(first['action'], 'cleared')
        self.assertEqual(len(client.comments), 1)
        self.assertTrue(has_cleared_marker(client.existing_issue['body']))

        second = handle_alert_lifecycle(
            client, 'Possible website issues', 'all clear',
            ['site-scanning-alert'], is_clear=True, comment_on_clear=True
        )
        self.assertEqual(second['action'], 'no-op')
        self.assertEqual(len(client.comments), 1)

    def test_alert_refires_after_clear_even_with_matching_fingerprint(self):
        """
        If an alert clears and then the exact same failure reappears, the
        cleared marker must force a comment rather than a no-op, even
        though the fingerprint matches what was on the issue before it
        cleared.
        """
        body = 'site is down'
        fp = compute_fingerprint(body)
        existing = {
            'number': 1,
            'html_url': 'https://github.com/owner/repo/issues/1',
            'body': embed_fingerprint(body, fp, cleared=True)
        }
        client = FakeIssueClient(existing_issue=existing)

        result = handle_alert_lifecycle(
            client, 'Possible website issues', body,
            ['site-scanning-alert'], is_clear=False
        )

        self.assertEqual(result['action'], 'commented')
        self.assertEqual(len(client.comments), 1)
        self.assertIn('re-fired', client.comments[0]['comment'])
        # The patched body must drop the cleared marker now that the
        # condition is active again.
        self.assertFalse(has_cleared_marker(client.updates[0]['body']))

    def test_ensure_label_only_called_on_creation(self):
        """
        Regression for the API-hygiene finding: ensure_label should not
        run on every no-op/commented/cleared run, only when an issue is
        first created.
        """
        client = FakeIssueClient(existing_issue=None)

        handle_alert_lifecycle(
            client, 'Possible website issues', 'something is wrong',
            ['site-scanning-alert', 'other-label'], is_clear=False
        )
        self.assertEqual(client.ensure_label_calls, ['site-scanning-alert', 'other-label'])

        # Now that the issue exists, subsequent runs must not call
        # ensure_label again.
        client.existing_issue = {
            'number': 1,
            'html_url': 'https://github.com/owner/repo/issues/1',
            'body': client.created[0]['body'],
        }
        client.ensure_label_calls.clear()

        handle_alert_lifecycle(
            client, 'Possible website issues', 'something is wrong',
            ['site-scanning-alert', 'other-label'], is_clear=False
        )
        self.assertEqual(client.ensure_label_calls, [])

    def test_empty_labels_raises_value_error(self):
        """
        Regression for finding #2: handle_alert_lifecycle must never run
        with an empty labels list - find_open_issue would never find a
        match, so every run would create a brand-new issue.
        """
        client = FakeIssueClient(existing_issue=None)

        with self.assertRaises(ValueError):
            handle_alert_lifecycle(
                client, 'Possible website issues', 'something is wrong',
                [], is_clear=False
            )


class MarkerFilteringFakeClient:
    """
    A more faithful in-memory fake than FakeIssueClient: filters
    find_open_issue by marker the way the real client does, so it can
    exercise stream isolation between alert kinds sharing the same labels.
    """

    def __init__(self):
        self.issues = []  # list of {'number', 'html_url', 'body'}
        self.comments = []
        self._next_number = 1

    def ensure_label(self, label, color='0366d6', description=''):
        pass

    def find_open_issue(self, labels, marker):
        for issue in self.issues:
            if marker in issue['body']:
                return issue
        return None

    def create_issue(self, title, body, labels):
        issue = {
            'number': self._next_number,
            'html_url': f'https://github.com/owner/repo/issues/{self._next_number}',
            'body': body,
        }
        self.issues.append(issue)
        self._next_number += 1
        return {'number': issue['number'], 'html_url': issue['html_url']}

    def comment_on_issue(self, issue_number, comment):
        self.comments.append({'issue_number': issue_number, 'comment': comment})

    def update_issue(self, issue_number, body):
        for issue in self.issues:
            if issue['number'] == issue_number:
                issue['body'] = body
                return


class TestStreamIsolation(unittest.TestCase):
    """
    Regression coverage for the alerts/staleness marker collision: both
    streams share the same labels, so without a stream-scoped marker,
    find_open_issue can't tell them apart.
    """

    def test_alerts_and_staleness_create_separate_issues(self):
        client = MarkerFilteringFakeClient()

        alert_result = handle_alert_lifecycle(
            client, 'Possible website issues', 'something is wrong',
            ['site-scanning-alert'], is_clear=False, stream='alerts'
        )
        stale_result = handle_alert_lifecycle(
            client, 'Site Scanning data is stale', 'data is stale',
            ['site-scanning-alert'], is_clear=False, stream='staleness'
        )

        self.assertEqual(alert_result['action'], 'created')
        self.assertEqual(stale_result['action'], 'created')
        self.assertEqual(len(client.issues), 2)
        self.assertNotEqual(alert_result['issue_url'], stale_result['issue_url'])
        self.assertEqual(len(client.comments), 0)

    def test_staleness_rerun_does_not_comment_on_alert_issue(self):
        client = MarkerFilteringFakeClient()
        handle_alert_lifecycle(
            client, 'Possible website issues', 'something is wrong',
            ['site-scanning-alert'], is_clear=False, stream='alerts'
        )
        handle_alert_lifecycle(
            client, 'Site Scanning data is stale', 'data is stale',
            ['site-scanning-alert'], is_clear=False, stream='staleness'
        )

        # Re-run staleness with an unchanged message: must be a no-op on the
        # staleness issue, and must never touch the alert issue or comment
        # at all (this is the bug: without stream scoping, this used to
        # match the alert issue and post a spurious comment onto it).
        result = handle_alert_lifecycle(
            client, 'Site Scanning data is stale', 'data is stale',
            ['site-scanning-alert'], is_clear=False, stream='staleness'
        )

        self.assertEqual(result['action'], 'no-op')
        self.assertEqual(result['issue_url'], client.issues[1]['html_url'])
        self.assertEqual(len(client.comments), 0)

    def test_default_stream_is_alerts(self):
        client = MarkerFilteringFakeClient()

        handle_alert_lifecycle(
            client, 'Possible website issues', 'something is wrong',
            ['site-scanning-alert'], is_clear=False  # no explicit stream
        )
        result = handle_alert_lifecycle(
            client, 'Possible website issues', 'something is wrong',
            ['site-scanning-alert'], is_clear=False, stream='alerts'
        )

        self.assertEqual(result['action'], 'no-op')  # same stream, same fingerprint


if __name__ == '__main__':
    unittest.main()
