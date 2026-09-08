#!/usr/bin/env python3
"""Tests for issues.py"""
import unittest
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from issues import (
    compute_fingerprint,
    embed_fingerprint,
    extract_fingerprint,
    IssueClient
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


if __name__ == '__main__':
    unittest.main()
