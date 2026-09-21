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


# One parsed snapshot row: CSV column name -> value (never None; see _parse).
Row = Dict[str, str]


# Columns needed for alert evaluation
REQUIRED_COLUMNS = [
    'initial_domain',
    'initial_base_domain',
    'live',
    'status_code',
    'primary_scan_status',
    'scan_date'
]

# Watchlist entry prefix selecting base-domain (rather than exact) matching,
# and the two snapshot columns those two modes compare against.
BASE_PREFIX = 'base:'
MATCH_COLUMNS = ('initial_domain', 'initial_base_domain')


class SnapshotError(Exception):
    """Raised when snapshot loading or validation fails."""
    pass


def _fetch_attempt(url: str) -> bytes:
    """Execute a single HTTP request for snapshot bytes."""
    req = urllib.request.Request(url, headers={'User-Agent': 'GSA-Site-Scanning-Alert-Action'})
    with urllib.request.urlopen(req, timeout=180) as response:
        return response.read()


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
            return _fetch_attempt(url)
        except urllib.error.HTTPError as e:
            last_error = SnapshotError(f"HTTP {e.code} from {url}: {e.reason}")
            if e.code in (403, 404, 410):  # Client errors - don't retry
                raise last_error
        except urllib.error.URLError as e:
            last_error = SnapshotError(f"Failed to fetch {url}: {e.reason}")

        if attempt < retry_count - 1:
            time.sleep(retry_delay * (attempt + 1))  # Exponential backoff

    raise last_error


def _determine_columns_to_keep(
    fieldnames: List[str],
    wanted_columns: Optional[List[str]],
    optional_columns: Optional[List[str]]
) -> Set[str]:
    """Determine the set of columns to project from available CSV headers."""
    available = set(fieldnames)
    if not wanted_columns:
        keep = set(available)
    else:
        missing = set(wanted_columns) - available
        if missing:
            raise SnapshotError(
                f"Snapshot missing required columns: {', '.join(sorted(missing))}"
            )
        keep = set(wanted_columns)

    if optional_columns:
        keep |= (set(optional_columns) & available)

    return keep


def _parse(
    raw: bytes,
    url: str,
    wanted_columns: Optional[List[str]],
    optional_columns: Optional[List[str]]
) -> List[Row]:
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

    keep = _determine_columns_to_keep(reader.fieldnames, wanted_columns, optional_columns)

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
) -> List[Row]:
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


def _match_column(entry: str) -> Tuple[str, str]:
    """
    Parse one watchlist entry into (snapshot column, lowercased value).

    "base:domain.gov" matches all sites under that base domain, so it is
    compared against `initial_base_domain`; anything else is an exact match
    on `initial_domain`. The value is lowercased for case-insensitive
    comparison.

    This is the single definition of the watchlist matching rule - both
    filter_to_watchlist and find_unmatched_entries go through it, so an
    entry reported as unmatched is genuinely one that can never match.
    """
    entry = entry.strip()
    if entry.startswith(BASE_PREFIX):
        return 'initial_base_domain', entry[len(BASE_PREFIX):].lower()
    return 'initial_domain', entry.lower()


def _column_values(rows: List[Row], column: str) -> Set[str]:
    """Collect the lowercased values of one column across rows."""
    return {row.get(column, '').lower() for row in rows}


def filter_to_watchlist(rows: List[Row], watchlist: List[str]) -> List[Row]:
    """
    Filter snapshot rows to only those matching the watchlist.

    Args:
        rows: Snapshot rows (dicts with initial_domain and initial_base_domain keys)
        watchlist: List of entries; "base:domain.gov" matches all under that base,
                   otherwise exact match on initial_domain

    Returns:
        Filtered list of rows
    """
    wanted: Dict[str, Set[str]] = {}
    for entry in watchlist:
        column, value = _match_column(entry)
        wanted.setdefault(column, set()).add(value)

    return [
        row for row in rows
        if any(row.get(column, '').lower() in values for column, values in wanted.items())
    ]


def find_unmatched_entries(rows: List[Row], watchlist: List[str]) -> List[str]:
    """
    Find watchlist entries that match nothing in the (unfiltered) snapshot.

    An entry reported here is genuinely never going to trigger an alert -
    e.g. because of a typo or a domain that's been dropped from the Site
    Scanning index.

    Args:
        rows: Full snapshot rows (not pre-filtered to the watchlist)
        watchlist: Raw watchlist entries, as loaded from the watchlist file

    Returns:
        List of watchlist entries (original casing/prefix) with zero matches
    """
    present = {column: _column_values(rows, column) for column in MATCH_COLUMNS}

    unmatched = []
    for entry in watchlist:
        column, value = _match_column(entry)
        if value not in present[column]:
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
        normalized = scan_date_str.replace('Z', '+00:00') if 'T' in scan_date_str else scan_date_str
        parsed = datetime.fromisoformat(normalized)

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed
    except (ValueError, AttributeError):
        return None


def _max_scan_date(rows: List[Row]) -> Optional[datetime]:
    """Parse each row's scan_date and return the latest, or None if rows is
    empty or none of its scan_date values parse."""
    dates = [
        d for d in (parse_scan_date(row.get('scan_date', '')) for row in rows)
        if d is not None
    ]
    return max(dates) if dates else None


def check_snapshot_freshness(
    rows: List[Row],
    max_age_days: int
) -> Tuple[bool, Optional[str]]:
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
    latest_rows: List[Row],
    previous_rows: List[Row]
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
