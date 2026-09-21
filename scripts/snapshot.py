#!/usr/bin/env python3
"""
Snapshot loading and filtering for Site Scanning data.

Downloads and parses Site Scanning CSV snapshots with filtered column projection
to minimize memory use on large files (~45 MB, ~30k rows).
"""
import csv
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple
import time


# Columns needed for alert evaluation
REQUIRED_COLUMNS = [
    'initial_domain',
    'initial_base_domain',
    'live',
    'status_code',
    'primary_scan_status',
    'scan_date'
]


class SnapshotError(Exception):
    """Raised when snapshot loading or validation fails."""
    pass


def _fetch(url: str, retry_count: int, retry_delay: float) -> bytes:
    """
    Download the raw bytes of a snapshot, retrying on transient network
    failures only. Client errors (403/404/410) fail immediately.

    Raises:
        SnapshotError: If retry_count is exhausted (or zero) without a
            successful fetch.
    """
    last_error = SnapshotError(f"Failed to fetch {url}: no attempts made (retry_count={retry_count})")

    for attempt in range(retry_count):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'GSA-Site-Scanning-Alert-Action'})
            with urllib.request.urlopen(req, timeout=180) as response:
                return response.read()
        except urllib.error.HTTPError as e:
            last_error = SnapshotError(f"HTTP {e.code} from {url}: {e.reason}")
            if e.code in (403, 404, 410):  # Client errors - don't retry
                raise last_error
        except urllib.error.URLError as e:
            last_error = SnapshotError(f"Failed to fetch {url}: {e.reason}")

        if attempt < retry_count - 1:
            time.sleep(retry_delay * (attempt + 1))  # Exponential backoff

    raise last_error


def _parse(
    raw: bytes,
    url: str,
    wanted_columns: Optional[List[str]],
    optional_columns: Optional[List[str]]
) -> List[Dict[str, str]]:
    """
    Parse and project a downloaded snapshot's CSV bytes.

    Not retried by the caller - a malformed or incomplete CSV won't fix
    itself on re-download, so failures here should surface immediately
    with their real message instead of being retried and rewrapped.

    Raises:
        SnapshotError: If the CSV has no header, is missing a required
            (wanted) column, or has zero data rows.
    """
    csv.field_size_limit(10 ** 7)  # Handle Site Scanning's 2000-char truncated fields

    try:
        reader = csv.DictReader(raw.decode('utf-8', errors='replace').splitlines())
    except (csv.Error, UnicodeDecodeError) as e:
        raise SnapshotError(f"Failed to parse CSV from {url}: {e}")

    if reader.fieldnames is None:
        raise SnapshotError(f"Snapshot at {url} has no header row")

    # Determine which columns to keep
    available = set(reader.fieldnames)
    if wanted_columns:
        missing = set(wanted_columns) - available
        if missing:
            raise SnapshotError(
                f"Snapshot missing required columns: {', '.join(sorted(missing))}"
            )
        keep = set(wanted_columns)
    else:
        keep = set(reader.fieldnames)

    if optional_columns:
        keep |= (set(optional_columns) & available)

    try:
        rows = [
            {k: (v or '') for k, v in row.items() if k in keep}
            for row in reader
        ]
    except csv.Error as e:
        raise SnapshotError(f"Failed to parse CSV from {url}: {e}")

    if not rows:
        raise SnapshotError(f"Snapshot at {url} contains zero rows")

    return rows


def download_snapshot(
    url: str,
    wanted_columns: Optional[List[str]] = None,
    retry_count: int = 3,
    retry_delay: float = 2.0,
    optional_columns: Optional[List[str]] = None
) -> List[Dict[str, str]]:
    """
    Download and parse a Site Scanning CSV snapshot.

    Args:
        url: URL of the CSV snapshot
        wanted_columns: List of column names to project (None = all columns).
            Missing columns raise SnapshotError - these are required.
        retry_count: Number of retries on transient failures
        retry_delay: Seconds to wait between retries
        optional_columns: Extra column names to keep if present (e.g. a
            user's custom `fields` input). Unlike wanted_columns, a missing
            optional column is not an error - it's simply absent from the
            returned rows, so the caller can detect and warn about it.

    Returns:
        List of dicts, one per row, with wanted_columns plus any present
        optional_columns

    Raises:
        SnapshotError: On download failure after retries, or if the CSV is
            malformed, missing a required (wanted) column, or has zero rows.
            Parse/validation failures are not retried - retrying won't fix a
            missing column.
    """
    raw = _fetch(url, retry_count, retry_delay)
    return _parse(raw, url, wanted_columns, optional_columns)


def _parse_watchlist_entry(entry: str) -> Tuple[bool, str]:
    """
    Parse one watchlist entry into (is_base_match, value).

    "base:domain.gov" matches all sites under that base domain (is_base_match
    is True, value is the base domain); anything else is an exact match on
    initial_domain. The value is lowercased for case-insensitive comparison.
    """
    entry = entry.strip()
    if entry.startswith('base:'):
        return True, entry[5:].lower()
    return False, entry.lower()


def _split_watchlist(watchlist: List[str]) -> Tuple[Set[str], Set[str]]:
    """
    Split raw watchlist entries into exact-match and base-match sets.

    Returns:
        Tuple of (exact_domains, base_domains), both lowercased.
    """
    exact_domains: Set[str] = set()
    base_domains: Set[str] = set()

    for entry in watchlist:
        is_base, value = _parse_watchlist_entry(entry)
        (base_domains if is_base else exact_domains).add(value)

    return exact_domains, base_domains


def filter_to_watchlist(
    rows: List[Dict[str, str]],
    watchlist: List[str]
) -> List[Dict[str, str]]:
    """
    Filter snapshot rows to only those matching the watchlist.

    Args:
        rows: Snapshot rows (dicts with initial_domain and initial_base_domain keys)
        watchlist: List of entries; "base:domain.gov" matches all under that base,
                   otherwise exact match on initial_domain

    Returns:
        Filtered list of rows
    """
    exact_domains, base_domains = _split_watchlist(watchlist)

    return [
        row for row in rows
        if row.get('initial_domain', '').lower() in exact_domains
        or row.get('initial_base_domain', '').lower() in base_domains
    ]


def find_unmatched_entries(
    rows: List[Dict[str, str]],
    watchlist: List[str]
) -> List[str]:
    """
    Find watchlist entries that match nothing in the (unfiltered) snapshot.

    Uses the same matching rules as filter_to_watchlist (base:/exact,
    case-insensitive) so an entry reported here is genuinely never going to
    trigger an alert - e.g. because of a typo or a domain that's been
    dropped from the Site Scanning index.

    Args:
        rows: Full snapshot rows (not pre-filtered to the watchlist)
        watchlist: Raw watchlist entries, as loaded from the watchlist file

    Returns:
        List of watchlist entries (original casing/prefix) with zero matches
    """
    present_domains = {row.get('initial_domain', '').lower() for row in rows}
    present_bases = {row.get('initial_base_domain', '').lower() for row in rows}

    unmatched = []
    for entry in watchlist:
        is_base, value = _parse_watchlist_entry(entry)
        present = present_bases if is_base else present_domains
        if value not in present:
            unmatched.append(entry)

    return unmatched


def parse_scan_date(scan_date_str: str) -> Optional[datetime]:
    """
    Parse scan_date field to datetime.
    
    Args:
        scan_date_str: ISO8601 datetime string from snapshot
    
    Returns:
        datetime object, or None if parsing fails
    """
    if not scan_date_str:
        return None
    
    try:
        # Handle both "2026-09-02T08:11:41.911Z" and "2026-09-02" formats.
        # Both are normalized to UTC-aware datetimes - a naive datetime
        # from the date-only format would otherwise raise TypeError when
        # compared against the tz-aware datetime parsed from the other
        # format (e.g. in has_snapshot_rotated).
        if 'T' in scan_date_str:
            parsed = datetime.fromisoformat(scan_date_str.replace('Z', '+00:00'))
        else:
            parsed = datetime.fromisoformat(scan_date_str)

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed
    except (ValueError, AttributeError):
        return None


def _max_scan_date(rows: List[Dict[str, str]]) -> Optional[datetime]:
    """Parse each row's scan_date and return the latest, or None if rows is
    empty or none of its scan_date values parse."""
    dates = [parse_scan_date(row.get('scan_date', '')) for row in rows]
    dates = [d for d in dates if d is not None]
    return max(dates) if dates else None


def check_snapshot_freshness(
    rows: List[Dict[str, str]],
    max_age_days: int
) -> tuple[bool, Optional[str]]:
    """
    Check if snapshot is fresh enough to use.

    Args:
        rows: Snapshot rows with scan_date field
        max_age_days: Maximum allowed age in days

    Returns:
        Tuple of (is_fresh, max_date_str)
    """
    max_date = _max_scan_date(rows)

    if max_date is None:
        return False, None

    age = datetime.now(max_date.tzinfo) - max_date

    return age.days <= max_age_days, max_date.strftime('%Y-%m-%d')


def has_snapshot_rotated(
    latest_rows: List[Dict[str, str]],
    previous_rows: List[Dict[str, str]]
) -> bool:
    """
    Check if latest snapshot is newer than previous (i.e., rotation has occurred).

    Safe to call multiple times in a day - returns False if max scan_date is identical,
    making re-runs idempotent.

    Args:
        latest_rows: Rows from site-scanning-latest.csv
        previous_rows: Rows from site-scanning-previous.csv

    Returns:
        True if latest is newer than previous, False otherwise
    """
    max_latest = _max_scan_date(latest_rows)
    max_previous = _max_scan_date(previous_rows)

    if max_latest is None or max_previous is None:
        return True  # Can't determine, proceed

    return max_latest > max_previous
