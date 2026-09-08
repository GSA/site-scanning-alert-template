#!/usr/bin/env python3
"""
GitHub issue lifecycle management for Site Scanning alerts.

Implements fingerprinted rolling issues: search for an open issue with the label,
create if none exists, comment if fingerprint changed, no-op if identical.
"""
import hashlib
import json
import urllib.request
import urllib.error
from typing import List, Optional, Dict


class IssueClient:
    """
    GitHub issue client for alert lifecycle.
    
    Constructor-injectable for testability (no global state).
    """
    
    def __init__(self, repo: str, token: str):
        """
        Args:
            repo: Repository in owner/name format (e.g. "GSA/site-scanning-alert-template")
            token: GitHub token with issues:write permission
        """
        self.repo = repo
        self.token = token
        self.base_url = f"https://api.github.com/repos/{repo}"
    
    def _request(
        self,
        method: str,
        path: str,
        data: Optional[Dict] = None
    ) -> Dict:
        """Make authenticated GitHub API request."""
        url = f"{self.base_url}{path}"
        headers = {
            'Authorization': f'Bearer {self.token}',
            'Accept': 'application/vnd.github+json',
            'Content-Type': 'application/json'
        }
        
        req_data = json.dumps(data).encode() if data else None
        req = urllib.request.Request(url, data=req_data, headers=headers, method=method)
        
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                return json.loads(response.read().decode())
        except urllib.error.HTTPError as e:
            error_body = e.read().decode() if e.fp else ''
            raise RuntimeError(f"GitHub API {method} {path} failed: HTTP {e.code} - {error_body}")
        except urllib.error.URLError as e:
            raise RuntimeError(f"GitHub API {method} {path} failed: {e.reason}")
    
    def ensure_label(self, label: str, color: str = '0366d6', description: str = '') -> None:
        """Create label if it doesn't exist (idempotent)."""
        # Check existence via GET /labels/:name (404 = doesn't exist)
        try:
            self._request('GET', f"/labels/{label}")
            return  # Already exists
        except RuntimeError as e:
            if 'HTTP 404' not in str(e):
                raise  # Unexpected error
        
        # Create it
        self._request('POST', '/labels', {
            'name': label,
            'color': color,
            'description': description or f'Site Scanning alert: {label}'
        })
    
    def find_open_issue(self, labels: List[str], marker: str) -> Optional[Dict]:
        """
        Search for an open issue with given labels and marker comment.
        
        Args:
            labels: List of label names (all must be present)
            marker: HTML comment marker to look for in issue body
        
        Returns:
            Issue dict with keys: number, html_url, body
            None if no matching issue found
        """
        # Use list-by-label endpoint (no search API rate limit)
        # GET /repos/:owner/:repo/issues?labels=label1,label2&state=open
        label_str = ','.join(labels)
        page = 1
        while True:
            path = f"/issues?labels={label_str}&state=open&per_page=100&page={page}"
            issues = self._request('GET', path)

            if not issues:
                return None

            for issue in issues:
                # Skip pull requests (they appear in /issues but have a pull_request key)
                if 'pull_request' in issue:
                    continue

                body = issue.get('body', '')
                if marker in body:
                    return {
                        'number': issue['number'],
                        'html_url': issue['html_url'],
                        'body': body
                    }

            if len(issues) < 100:
                return None

            page += 1
    
    def create_issue(
        self,
        title: str,
        body: str,
        labels: List[str]
    ) -> Dict:
        """
        Create a new issue.
        
        Returns:
            Issue dict with keys: number, html_url
        """
        data = {
            'title': title,
            'body': body,
            'labels': labels
        }
        
        result = self._request('POST', '/issues', data)
        return {
            'number': result['number'],
            'html_url': result['html_url']
        }
    
    def comment_on_issue(self, issue_number: int, comment: str) -> None:
        """Add a comment to an existing issue."""
        self._request('POST', f"/issues/{issue_number}/comments", {'body': comment})


def compute_fingerprint(body: str) -> str:
    """
    Compute stable fingerprint of an alert body.
    
    Strips the marker comment itself and non-semantic whitespace before hashing.
    """
    # Remove any existing fingerprint marker
    lines = [line for line in body.split('\n') if not line.strip().startswith('<!-- alert-fingerprint:')]
    normalized = '\n'.join(lines).strip()
    return hashlib.sha256(normalized.encode()).hexdigest()[:12]


def embed_fingerprint(body: str, fingerprint: str) -> str:
    """Embed fingerprint as HTML comment in body."""
    marker = f"<!-- alert-fingerprint: {fingerprint} -->"
    return f"{marker}\n\n{body}"


def extract_fingerprint(body: str) -> Optional[str]:
    """Extract fingerprint from body if present."""
    for line in body.split('\n'):
        if line.strip().startswith('<!-- alert-fingerprint:'):
            # Extract the hash between : and -->
            try:
                return line.split(':', 1)[1].split('-->')[0].strip()
            except IndexError:
                return None
    return None


def handle_alert_lifecycle(
    client: IssueClient,
    title: str,
    body: str,
    labels: List[str],
    is_clear: bool,
    comment_on_clear: bool = True
) -> Dict[str, any]:
    """
    Manage full alert issue lifecycle with fingerprinting.

    Args:
        client: IssueClient instance
        title: Issue title
        body: Alert body (without fingerprint marker)
        labels: List of label names to apply
        is_clear: True if the caller has determined no alert conditions are
            currently active (e.g. zero alerts found this run)
        comment_on_clear: If True, comment when condition clears

    Returns:
        Dict with keys:
            - action: 'created', 'commented', 'no-op', or 'cleared'
            - issue_url: URL of the issue (if applicable)
            - fingerprint: Computed fingerprint
    """
    # Ensure label exists
    if labels:
        for label in labels:
            client.ensure_label(label)

    # Compute fingerprint of this alert
    fingerprint = compute_fingerprint(body)
    marker = f"<!-- alert-fingerprint:"  # Partial marker for search

    # Search for existing open issue
    existing = client.find_open_issue(labels, marker) if labels else None

    # Case 1: No active alert conditions
    if is_clear:
        if existing and comment_on_clear:
            # Condition cleared - add comment but don't close
            comment = "✅ **Condition cleared**\n\n" + body
            client.comment_on_issue(existing['number'], comment)
            return {
                'action': 'cleared',
                'issue_url': existing['html_url'],
                'fingerprint': fingerprint
            }
        else:
            return {
                'action': 'no-op',
                'issue_url': existing['html_url'] if existing else None,
                'fingerprint': fingerprint
            }
    
    # Case 2: No existing issue - create new
    if not existing:
        body_with_fp = embed_fingerprint(body, fingerprint)
        result = client.create_issue(title, body_with_fp, labels)
        return {
            'action': 'created',
            'issue_url': result['html_url'],
            'fingerprint': fingerprint
        }
    
    # Case 3: Existing issue - compare fingerprints
    existing_fp = extract_fingerprint(existing['body'])
    
    if existing_fp == fingerprint:
        # Identical alert - no-op (idempotent re-runs)
        return {
            'action': 'no-op',
            'issue_url': existing['html_url'],
            'fingerprint': fingerprint
        }
    else:
        # Changed alert - add comment with new findings
        body_with_fp = embed_fingerprint(body, fingerprint)
        comment = f"🔄 **Alert updated**\n\n{body_with_fp}"
        client.comment_on_issue(existing['number'], comment)
        return {
            'action': 'commented',
            'issue_url': existing['html_url'],
            'fingerprint': fingerprint
        }
