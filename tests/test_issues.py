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
    IssueClient,
    handle_alert_lifecycle
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


class FakeIssueClient:
    """In-memory stand-in for IssueClient, for lifecycle testing without HTTP."""

    def __init__(self, existing_issue=None):
        self.existing_issue = existing_issue
        self.created = []
        self.comments = []

    def ensure_label(self, label, color='0366d6', description=''):
        pass

    def find_open_issue(self, labels, marker):
        return self.existing_issue

    def create_issue(self, title, body, labels):
        self.created.append({'title': title, 'body': body, 'labels': labels})
        return {'number': 1, 'html_url': 'https://github.com/owner/repo/issues/1'}

    def comment_on_issue(self, issue_number, comment):
        self.comments.append({'issue_number': issue_number, 'comment': comment})


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

    def test_clear_with_no_existing_issue_is_noop_with_no_url(self):
        client = FakeIssueClient(existing_issue=None)

        result = handle_alert_lifecycle(
            client, 'Possible website issues', 'all clear',
            ['site-scanning-alert'], is_clear=True, comment_on_clear=True
        )

        self.assertEqual(result['action'], 'no-op')
        self.assertIsNone(result['issue_url'])


if __name__ == '__main__':
    unittest.main()
