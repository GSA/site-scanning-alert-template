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
import math
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, List, Optional

# Cap on pages walked in find_open_issue - protects against runaway API
# consumption in repos with a very large number of open issues.
MAX_ISSUE_PAGES = 5

MARKER_PREFIX = "<!-- site-scanning-alert:"

# Retry shape for _request, modeled on snapshot._fetch.
API_TIMEOUT_SECONDS = 30
API_RETRY_COUNT = 3
API_RETRY_DELAY = 2.0
MAX_RETRY_AFTER_SECONDS = 60

SECONDARY_RATE_LIMIT_MARKERS = ("secondary rate limit", "abuse detection")


def _is_rate_limited(code: int, body: str) -> bool:
    """
    A 429, or a 403 from GitHub's secondary rate limit / abuse detection.
    A plain permissions 403 will never succeed on retry.
    """
    if code == 429:
        return True
    lowered = body.lower()
    return code == 403 and any(marker in lowered for marker in SECONDARY_RATE_LIMIT_MARKERS)


def _is_retryable_status(method: str, code: int, body: str) -> bool:
    """
    Rate limits are rejected before GitHub does any work, so they're safe to
    resend for any verb. A 5xx can arrive after a write was already applied,
    so only an idempotent GET retries it.
    """
    if _is_rate_limited(code, body):
        return True
    return method == "GET" and 500 <= code < 600


def _retry_after_seconds(headers, fallback: float) -> float:
    """
    Read a Retry-After header if present, capped so a hostile or
    misconfigured header can't park the job for hours.

    Only the integer-seconds form is honored; the HTTP-date form falls
    back to the caller's own backoff delay rather than parsing a date.
    """
    raw = headers.get("Retry-After") if headers else None
    if raw is None:
        return fallback
    try:
        seconds = float(raw)
    except ValueError:
        return fallback
    # A negative value would make time.sleep raise ValueError.
    if not math.isfinite(seconds) or seconds < 0:
        return fallback
    return min(seconds, MAX_RETRY_AFTER_SECONDS)


def _find_issue_with_marker(issues: List[Dict], marker: str) -> Optional[Dict]:
    """Scan a list of issue objects for one containing the specified marker."""
    for issue in issues:
        # Skip pull requests (they appear in /issues but have a pull_request key)
        if "pull_request" in issue:
            continue

        # GitHub returns body: null for issues created without a
        # description, so `issue.get('body', '')` isn't enough -
        # the key is present with value None.
        body = issue.get("body") or ""
        if marker in body:
            return {
                "number": issue["number"],
                "html_url": issue["html_url"],
                "body": body,
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
        data: Optional[Dict] = None,
    ) -> Dict:
        """
        Make an authenticated GitHub API request, retrying transient
        failures.

        A POST is retried only on a rate limit. A 5xx or network error on a
        POST may mean the write already happened server-side, and retrying
        `POST /issues` would file a duplicate issue.
        """
        url = f"{self.base_url}{path}"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
        }
        req_data = json.dumps(data).encode() if data else None
        idempotent = method == "GET"

        last_error = RuntimeError(f"GitHub API {method} {path} failed: no attempts made")
        for attempt in range(API_RETRY_COUNT):
            req = urllib.request.Request(url, data=req_data, headers=headers, method=method)
            sleep_for = API_RETRY_DELAY * (attempt + 1)

            try:
                with urllib.request.urlopen(req, timeout=API_TIMEOUT_SECONDS) as response:
                    return json.loads(response.read().decode())
            except urllib.error.HTTPError as e:
                # HTTPError subclasses URLError, so this clause must come first.
                error_body = e.read().decode() if e.fp else ""
                last_error = RuntimeError(
                    f"GitHub API {method} {path} failed: HTTP {e.code} - {error_body}"
                )
                if not _is_retryable_status(method, e.code, error_body):
                    raise last_error from e
                sleep_for = _retry_after_seconds(e.headers, sleep_for)
            except (urllib.error.URLError, TimeoutError) as e:
                # A bare TimeoutError (not wrapped in URLError) is what
                # urlopen(timeout=...) raises on a read timeout.
                last_error = RuntimeError(
                    f"GitHub API {method} {path} failed: {getattr(e, 'reason', e)}"
                )
                if not idempotent:
                    raise last_error from e

            if attempt < API_RETRY_COUNT - 1:
                time.sleep(sleep_for)

        raise last_error

    def ensure_label(self, label: str, color: str = "0366d6", description: str = "") -> None:
        """Create label if it doesn't exist (idempotent)."""
        # Check existence via GET /labels/:name (404 = doesn't exist)
        encoded = urllib.parse.quote(label, safe="")
        try:
            self._request("GET", f"/labels/{encoded}")
            return  # Already exists
        except RuntimeError as e:
            if "HTTP 404" not in str(e):
                raise  # Unexpected error

        # Create it
        self._request(
            "POST",
            "/labels",
            {
                "name": label,
                "color": color,
                "description": description or f"Site Scanning alert: {label}",
            },
        )

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
        label_str = ",".join(urllib.parse.quote_plus(label) for label in labels)
        for page in range(1, MAX_ISSUE_PAGES + 1):
            path = f"/issues?labels={label_str}&state=open&per_page=100&page={page}"
            issues = self._request("GET", path)

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
            "treating as not found. Consider closing stale open issues.",
        )
        return None

    def create_issue(
        self,
        title: str,
        body: str,
        labels: List[str],
    ) -> Dict:
        """
        Create a new issue.

        Returns:
            Issue dict with keys: number, html_url
        """
        data = {
            "title": title,
            "body": body,
            "labels": labels,
        }

        result = self._request("POST", "/issues", data)
        return {
            "number": result["number"],
            "html_url": result["html_url"],
        }


def strip_markers(body: str) -> str:
    """Remove alert marker lines."""
    lines = [line for line in body.split("\n") if not line.strip().startswith(MARKER_PREFIX)]
    return "\n".join(lines)


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
    stream: str = "alerts",
) -> Dict[str, Optional[str]]:
    """
    File a new issue for the given findings, unless an open issue already
    carries the identical fingerprint for this stream.

    Args:
        client: IssueClient instance
        title: Issue title
        body: Alert body (without marker)
        labels: List of label names to apply
        stream: Distinguishes alert kinds that share the same labels (e.g.
            'alerts' vs 'staleness'), so find_open_issue only matches an
            issue filed by this same stream.

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
            "run would create a new one.",
        )

    marker = alert_marker(stream, compute_fingerprint(body))
    existing = client.find_open_issue(labels, marker)

    if existing:
        return {"action": "no-op", "issue_url": existing["html_url"]}

    for label in labels:
        client.ensure_label(label)

    result = client.create_issue(title, f"{marker}\n\n{body}", labels)
    return {"action": "created", "issue_url": result["html_url"]}
