#!/usr/bin/env python3
"""
GitHub issue filing for Site Scanning alerts.

MVP approach: file a new issue for each distinct set of findings; skip
filing if an open issue already carries the identical fingerprint. No
rolling comments, no auto-close, no "condition cleared" tracking - a
sustained, unchanged outage produces exactly one open issue, and a
changed or new outage produces another. Triage and closing are manual.
This trades issue-tab tidiness for a much simpler, harder-to-break
lifecycle; revisit if the noise becomes a real problem.
"""
import hashlib
import json
import urllib.request
import urllib.error
import urllib.parse
from typing import List, Optional, Dict

# Cap on pages walked in find_open_issue - protects against runaway API
# consumption in repos with a very large number of open issues.
MAX_ISSUE_PAGES = 5

MARKER_PREFIX = '<!-- site-scanning-alert:'


def _find_issue_with_marker(issues: List[Dict], marker: str) -> Optional[Dict]:
    """Scan a list of issue objects for one containing the specified marker."""
    for issue in issues:
        # Skip pull requests (they appear in /issues but have a pull_request key)
        if 'pull_request' in issue:
            continue

        # GitHub returns body: null for issues created without a
        # description, so `issue.get('body', '')` isn't enough -
        # the key is present with value None.
        body = issue.get('body') or ''
        if marker in body:
            return {
                'number': issue['number'],
                'html_url': issue['html_url'],
                'body': body
            }
    return None


class IssueClient:
    """
    GitHub issue client for alert filing.

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
        for page in range(1, MAX_ISSUE_PAGES + 1):
            path = f"/issues?labels={label_str}&state=open&per_page=100&page={page}"
            issues = self._request('GET', path)

            if not issues:
                return None

            matched = _find_issue_with_marker(issues, marker)
            if matched:
                return matched

            if len(issues) < 100:
                return None

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


def strip_markers(body: str) -> str:
    """Remove alert marker lines."""
    lines = [
        line for line in body.split('\n')
        if not line.strip().startswith(MARKER_PREFIX)
    ]
    return '\n'.join(lines)


def compute_fingerprint(body: str) -> str:
    """
    Compute stable fingerprint of an alert body.

    Strips the marker comment itself and non-semantic whitespace before hashing.
    """
    normalized = strip_markers(body).strip()
    return hashlib.sha256(normalized.encode()).hexdigest()[:12]


def alert_marker(stream: str, fingerprint: str) -> str:
    """
    Build the marker embedded in a filed issue's body.

    Combines the stream (e.g. 'alerts' vs 'staleness') and the findings'
    fingerprint into one marker, so a single substring search on
    find_open_issue answers "is this exact finding, from this stream,
    already open?" - no separate stream/fingerprint bookkeeping needed.
    """
    return f"{MARKER_PREFIX} {stream}:{fingerprint} -->"


def file_alert(
    client: IssueClient,
    title: str,
    body: str,
    labels: List[str],
    stream: str = 'alerts',
    footer: str = ''
) -> Dict[str, Optional[str]]:
    """
    File a new issue for the given findings, unless an open issue already
    carries the identical fingerprint for this stream.

    Args:
        client: IssueClient instance
        title: Issue title
        body: Alert body (without marker). Fingerprinted for dedupe.
        labels: List of label names to apply
        stream: Distinguishes alert kinds that share the same labels (e.g.
            'alerts' vs 'staleness'), so find_open_issue only matches an
            issue filed by this same stream.
        footer: Optional trailing text appended to the created issue body
            (e.g. snapshot date, doc links). Deliberately excluded from
            the fingerprint - it's expected to change from run to run
            (the snapshot date, for one) even when the findings
            themselves are identical, and including it would defeat
            dedupe by forcing a new issue every time.

    Returns:
        Dict with keys:
            - action: 'created' or 'no-op'
            - issue_url: URL of the issue (if applicable)

    Raises:
        ValueError: If labels is empty. An empty label list means
            find_open_issue can never locate an issue this same call
            would create, so every run creates a brand-new issue -
            callers must supply at least one label (or resolve their
            configured fallback) before calling this function.
    """
    if not labels:
        raise ValueError(
            "file_alert requires at least one label; an empty labels "
            "list means an existing issue can never be found, so every "
            "run would create a new one."
        )

    marker = alert_marker(stream, compute_fingerprint(body))
    existing = client.find_open_issue(labels, marker)

    if existing:
        return {'action': 'no-op', 'issue_url': existing['html_url']}

    for label in labels:
        client.ensure_label(label)

    full_body = f"{marker}\n\n{body}"
    if footer:
        full_body += f"\n\n{footer}"

    result = client.create_issue(title, full_body, labels)
    return {'action': 'created', 'issue_url': result['html_url']}
