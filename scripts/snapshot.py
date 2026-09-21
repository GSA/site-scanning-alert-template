#!/usr/bin/env python3
"""
Snapshot loading and filtering for Site Scanning data.

Downloads and parses Site Scanning CSV snapshots with filtered column projection
to minimize memory use on large files (~45 MB, ~30k rows).
"""
import csv
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set
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
        SnapshotError: On download or parse failure after retries, or if a
            required (wanted) column is missing
    """
    csv.field_size_limit(10 ** 7)  # Handle Site Scanning's 2000-char truncated fields

    last_error = None
    for attempt in range(retry_count):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'GSA-Site-Scanning-Alert-Action'})
            with urllib.request.urlopen(req, timeout=180) as response:
                raw = response.read()

            # Parse CSV with optional column projection
            rows = []
            reader = csv.DictReader(raw.decode('utf-8', errors='replace').splitlines())

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

            for row in reader:
                # Project to wanted columns only
                filtered = {k: (v or '') for k, v in row.items() if k in keep}
                rows.append(filtered)

            if not rows:
                raise SnapshotError(f"Snapshot at {url} contains zero rows")

            return rows
        
        except urllib.error.HTTPError as e:
            last_error = SnapshotError(f"HTTP {e.code} from {url}: {e.reason}")
            if e.code in (403, 404, 410):  # Client errors - don't retry
                raise last_error
        except urllib.error.URLError as e:
            last_error = SnapshotError(f"Failed to fetch {url}: {e.reason}")
        except (csv.Error, UnicodeDecodeError) as e:
            last_error = SnapshotError(f"Failed to parse CSV from {url}: {e}")
            raise last_error  # Parse errors don't benefit from retry
        except Exception as e:
            last_error = SnapshotError(f"Unexpected error loading {url}: {e}")
        
        if attempt < retry_count - 1:
            time.sleep(retry_delay * (attempt + 1))  # Exponential backoff
    
    raise last_error


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
    exact_domains: Set[str] = set()
    base_domains: Set[str] = set()
    
    for entry in watchlist:
        entry = entry.strip()
        if entry.startswith('base:'):
            base_domains.add(entry[5:].lower())
        else:
            exact_domains.add(entry.lower())
    
    filtered = []
    for row in rows:
        domain = row.get('initial_domain', '').lower()
        base = row.get('initial_base_domain', '').lower()
        
        if domain in exact_domains or base in base_domains:
            filtered.append(row)
    
    return filtered


def find_unmatched_entries(
    rows: List[Dict[str, str]],
    watchlist: List[str]
) -> List[str]:
    """
    Find watchlist entries that match nothing in the (unfiltered) snapshot.

    Mirrors filter_to_watchlist's matching rules exactly (base:/exact,
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
        stripped = entry.strip()
        if stripped.startswith('base:'):
            if stripped[5:].lower() not in present_bases:
                unmatched.append(entry)
        else:
            if stripped.lower() not in present_domains:
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


def check_snapshot_freshness(
    rows: List[Dict[str, str]],
    max_age_days: int
) -> tuple[bool, Optional[str], Optional[datetime]]:
    """
    Check if snapshot is fresh enough to use.
    
    Args:
        rows: Snapshot rows with scan_date field
        max_age_days: Maximum allowed age in days
    
    Returns:
        Tuple of (is_fresh, max_date_str, max_date_obj)
    """
    dates = [parse_scan_date(row.get('scan_date', '')) for row in rows]
    dates = [d for d in dates if d is not None]
    
    if not dates:
        return False, None, None
    
    max_date = max(dates)
    age = datetime.now(max_date.tzinfo) - max_date
    
    return age.days <= max_age_days, max_date.strftime('%Y-%m-%d'), max_date


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
    latest_dates = [parse_scan_date(r.get('scan_date', '')) for r in latest_rows]
    previous_dates = [parse_scan_date(r.get('scan_date', '')) for r in previous_rows]
    
    latest_dates = [d for d in latest_dates if d is not None]
    previous_dates = [d for d in previous_dates if d is not None]
    
    if not latest_dates or not previous_dates:
        return True  # Can't determine, proceed
    
    max_latest = max(latest_dates)
    max_previous = max(previous_dates)
    
    return max_latest > max_previous
