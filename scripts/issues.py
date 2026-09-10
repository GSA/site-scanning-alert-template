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
import urllib.parse
from typing import Any, List, Optional, Dict

# Cap on pages walked in find_open_issue - protects against runaway API
# consumption in repos with a very large number of open issues.
MAX_ISSUE_PAGES = 5

CLEARED_MARKER = '<!-- alert-cleared -->'


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
        encoded = urllib.parse.quote(label, safe='')
        try:
            self._request('GET', f"/labels/{encoded}")
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
        # Encode each label individually so the comma separator itself
        # stays a literal comma (GitHub reads it as label1 AND label2).
        label_str = ','.join(urllib.parse.quote_plus(label) for label in labels)
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
            if page > MAX_ISSUE_PAGES:
                print(
                    f"WARNING: find_open_issue hit the {MAX_ISSUE_PAGES}-page cap "
                    f"({MAX_ISSUE_PAGES * 100} issues) without finding a match; "
                    "treating as not found. Consider closing stale open issues."
                )
                return None
    
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

    def update_issue(self, issue_number: int, body: str) -> None:
        """Overwrite an existing issue's body (PATCH /issues/:number)."""
        self._request('PATCH', f"/issues/{issue_number}", {'body': body})


def strip_markers(body: str) -> str:
    """Remove alert-fingerprint, alert-stream, and alert-cleared marker lines."""
    lines = [
        line for line in body.split('\n')
        if not line.strip().startswith('<!-- alert-fingerprint:')
        and not line.strip().startswith('<!-- alert-stream:')
        and not line.strip().startswith(CLEARED_MARKER)
    ]
    return '\n'.join(lines)


def compute_fingerprint(body: str) -> str:
    """
    Compute stable fingerprint of an alert body.

    Strips the marker comments themselves and non-semantic whitespace before hashing.
    """
    normalized = strip_markers(body).strip()
    return hashlib.sha256(normalized.encode()).hexdigest()[:12]


def embed_fingerprint(
    body: str,
    fingerprint: str,
    stream: str = 'alerts',
    cleared: bool = False
) -> str:
    """
    Embed fingerprint and stream markers as HTML comments in body.

    The stream marker (e.g. 'alerts' vs 'staleness') lets find_open_issue
    distinguish issues filed by different alert kinds that share the same
    labels, so one kind never mistakes another's issue for its own.

    When cleared=True, also embeds the alert-cleared marker, which signals
    that the last run already posted a "Condition cleared" comment for the
    current state, so a subsequent healthy run can recognize this as a
    no-op rather than commenting again.
    """
    stream_marker = f"<!-- alert-stream: {stream} -->"
    fp_marker = f"<!-- alert-fingerprint: {fingerprint} -->"
    markers = [stream_marker, fp_marker]
    if cleared:
        markers.append(CLEARED_MARKER)
    return '\n'.join(markers) + f"\n\n{body}"


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


def has_cleared_marker(body: str) -> bool:
    """Check whether the body has already been marked as cleared."""
    return any(line.strip().startswith(CLEARED_MARKER) for line in body.split('\n'))


def handle_alert_lifecycle(
    client: IssueClient,
    title: str,
    body: str,
    labels: List[str],
    is_clear: bool,
    comment_on_clear: bool = True,
    stream: str = 'alerts'
) -> Dict[str, Any]:
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
        stream: Distinguishes alert kinds that share the same labels (e.g.
            'alerts' vs 'staleness'), so find_open_issue only matches an
            issue filed by this same stream and never cross-contaminates
            with another stream's issue.

    Returns:
        Dict with keys:
            - action: 'created', 'commented', 'no-op', or 'cleared'
            - issue_url: URL of the issue (if applicable)
            - fingerprint: Computed fingerprint
    """
    # Compute fingerprint of this alert
    fingerprint = compute_fingerprint(body)
    marker = f"<!-- alert-stream: {stream} -->"

    # Search for existing open issue from this same stream
    existing = client.find_open_issue(labels, marker) if labels else None

    # Case 1: No active alert conditions
    if is_clear:
        if not existing:
            return {'action': 'no-op', 'issue_url': None, 'fingerprint': fingerprint}

        if has_cleared_marker(existing['body']):
            # Already flagged as cleared on a previous run - nothing new to say.
            return {
                'action': 'no-op',
                'issue_url': existing['html_url'],
                'fingerprint': fingerprint
            }

        if comment_on_clear:
            # Condition cleared - comment once, then flag the issue body so
            # subsequent healthy runs recognize it's already been reported
            # and don't repeat the comment. The issue itself stays open.
            comment = "✅ **Condition cleared**\n\n" + body
            client.comment_on_issue(existing['number'], comment)
            updated_body = embed_fingerprint(body, fingerprint, stream, cleared=True)
            client.update_issue(existing['number'], updated_body)
            return {
                'action': 'cleared',
                'issue_url': existing['html_url'],
                'fingerprint': fingerprint
            }
        else:
            return {
                'action': 'no-op',
                'issue_url': existing['html_url'],
                'fingerprint': fingerprint
            }

    # Case 2: No existing issue - create new
    if not existing:
        if labels:
            for label in labels:
                client.ensure_label(label)
        body_with_fp = embed_fingerprint(body, fingerprint, stream)
        result = client.create_issue(title, body_with_fp, labels)
        return {
            'action': 'created',
            'issue_url': result['html_url'],
            'fingerprint': fingerprint
        }

    # Case 3: Existing issue - compare fingerprints. A cleared marker forces
    # an update even when the fingerprint happens to match what was open
    # before the clear - otherwise an identical alert re-firing right after
    # a clear would be silently swallowed as a no-op.
    existing_fp = extract_fingerprint(existing['body'])
    was_cleared = has_cleared_marker(existing['body'])

    if existing_fp == fingerprint and not was_cleared:
        # Identical alert - no-op (idempotent re-runs)
        return {
            'action': 'no-op',
            'issue_url': existing['html_url'],
            'fingerprint': fingerprint
        }
    else:
        # Changed alert (or a re-fire after a clear) - comment with the new
        # findings, then patch the issue body so the next run compares
        # against the current fingerprint instead of the original one.
        header = "❗ **Alert re-fired**" if was_cleared else "🔄 **Alert updated**"
        comment = f"{header}\n\n{body}"
        client.comment_on_issue(existing['number'], comment)
        updated_body = embed_fingerprint(body, fingerprint, stream)
        client.update_issue(existing['number'], updated_body)
        return {
            'action': 'commented',
            'issue_url': existing['html_url'],
            'fingerprint': fingerprint
        }
