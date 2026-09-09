#!/usr/bin/env python3
"""
Site Scanning Alerts - Entrypoint

Monitors federal websites for status changes and configuration issues using
GSA Site Scanning data.
"""
import os
import sys
from typing import List, Set

# Add scripts directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from snapshot import (
    download_snapshot,
    filter_to_watchlist,
    check_snapshot_freshness,
    has_snapshot_rotated,
    REQUIRED_COLUMNS,
    SnapshotError
)
from rules import (
    evaluate_change_diff,
    evaluate_state_check,
    render_alerts,
    parse_ignore_transitions,
    Alert
)
from issues import IssueClient, handle_alert_lifecycle


def load_watchlist(path: str) -> List[str]:
    """Load and parse watchlist file."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"Watchlist file not found: {path}")
    
    with open(path, 'r') as f:
        lines = f.readlines()
    
    entries = []
    for line in lines:
        line = line.strip()
        # Skip comments and empty lines
        if line and not line.startswith('#'):
            entries.append(line)
    
    return entries


def parse_csv_set(value: str) -> Set[str]:
    """Parse comma-separated string into set."""
    if not value:
        return set()
    return set(item.strip() for item in value.split(',') if item.strip())


def write_step_summary(content: str):
    """Write to GitHub Actions step summary if available."""
    summary_file = os.getenv('GITHUB_STEP_SUMMARY')
    if summary_file:
        with open(summary_file, 'a') as f:
            f.write(content + '\n')


def main():
    """Main entrypoint."""
    # Read inputs from environment (set by action.yml)
    watchlist_path = os.getenv('INPUT_WATCHLIST', 'watchlist.txt')
    mode = os.getenv('INPUT_MODE', 'both')
    fields = [f.strip() for f in os.getenv('INPUT_FIELDS', 'live,status_code,primary_scan_status').split(',')]
    alert_on_status_codes = parse_csv_set(os.getenv('INPUT_ALERT_ON_STATUS_CODES', '500,502,503,504'))
    alert_on_scan_status = parse_csv_set(os.getenv('INPUT_ALERT_ON_SCAN_STATUS', ''))
    alert_on_not_live = os.getenv('INPUT_ALERT_ON_NOT_LIVE', 'false').lower() == 'true'
    ignore_blank_transitions = os.getenv('INPUT_IGNORE_BLANK_TRANSITIONS', 'false').lower() == 'true'
    ignore_transitions_str = os.getenv('INPUT_IGNORE_TRANSITIONS', '')
    max_changes = int(os.getenv('INPUT_MAX_CHANGES', '25'))
    labels = [l.strip() for l in os.getenv('INPUT_LABELS', 'site-scanning-alert').split(',') if l.strip()]
    issue_title = os.getenv('INPUT_ISSUE_TITLE', 'Possible website issues')
    snapshot_url = os.getenv('INPUT_SNAPSHOT_URL', 'https://api.gsa.gov/technology/site-scanning/data/site-scanning-latest.csv')
    previous_snapshot_url = os.getenv('INPUT_PREVIOUS_SNAPSHOT_URL', 'https://api.gsa.gov/technology/site-scanning/data/site-scanning-previous.csv')
    max_snapshot_age_days = int(os.getenv('INPUT_MAX_SNAPSHOT_AGE_DAYS', '3'))
    token = os.getenv('INPUT_TOKEN', '')
    fail_on_alert = os.getenv('INPUT_FAIL_ON_ALERT', 'false').lower() == 'true'
    dry_run = os.getenv('INPUT_DRY_RUN', 'false').lower() == 'true'
    comment_on_clear = os.getenv('INPUT_COMMENT_ON_CLEAR', 'true').lower() == 'true'
    
    repo = os.getenv('GITHUB_REPOSITORY', '')
    
    try:
        # Load watchlist
        print(f"Loading watchlist from {watchlist_path}...")
        watchlist = load_watchlist(watchlist_path)
        
        if not watchlist:
            msg = f"⚠️ **Watchlist is empty**\n\nThe watchlist file `{watchlist_path}` contains no active entries (only comments or blank lines).\n\nAdd domains to monitor, one per line. See the watchlist file for syntax examples."
            print(msg)
            write_step_summary(msg)
            sys.exit(0)
        
        print(f"Loaded {len(watchlist)} watchlist entries")
        
        # Download snapshots
        print(f"Downloading latest snapshot from {snapshot_url}...")
        latest_rows = download_snapshot(snapshot_url, REQUIRED_COLUMNS)
        print(f"Downloaded {len(latest_rows)} rows")
        
        # Check freshness
        is_fresh, max_date_str, _ = check_snapshot_freshness(latest_rows, max_snapshot_age_days)
        if not is_fresh:
            msg = f"⚠️ **Snapshot is stale**\n\nLatest snapshot is dated {max_date_str or 'unknown'}, which is older than {max_snapshot_age_days} days.\n\nThis typically indicates the scanning engine has not run recently. Please investigate the upstream system before acting on any alerts."
            print(msg)
            write_step_summary(msg)
            
            if not dry_run and token and repo:
                # File staleness issue
                client = IssueClient(repo, token)
                result = handle_alert_lifecycle(
                    client,
                    "Site Scanning data is stale",
                    msg,
                    labels,
                    is_clear=False,
                    comment_on_clear=comment_on_clear,
                    stream='staleness'
                )
                print(f"Staleness alert: {result['action']} - {result.get('issue_url', 'N/A')}")
            
            sys.exit(0)
        
        print(f"Snapshot freshness OK (dated {max_date_str})")
        
        # Filter to watchlist
        filtered_latest = filter_to_watchlist(latest_rows, watchlist)
        print(f"Filtered to {len(filtered_latest)} monitored sites")
        
        if not filtered_latest:
            unmatched = '\n'.join(f"  - {entry}" for entry in watchlist[:10])
            if len(watchlist) > 10:
                unmatched += f"\n  ... and {len(watchlist) - 10} more"
            
            msg = f"⚠️ **No sites matched your watchlist**\n\nWatchlist entries:\n{unmatched}\n\nCheck for typos or verify that these domains exist in the Site Scanning index."
            print(msg)
            write_step_summary(msg)
            sys.exit(0)
        
        # Evaluate alerts
        all_alerts: List[Alert] = []
        
        # Change mode
        if mode in ('change', 'both'):
            print(f"Downloading previous snapshot from {previous_snapshot_url}...")
            previous_rows = download_snapshot(previous_snapshot_url, REQUIRED_COLUMNS)
            print(f"Downloaded {len(previous_rows)} rows")
            
            # Check rotation
            if not has_snapshot_rotated(latest_rows, previous_rows):
                msg = f"ℹ️ **Snapshot has not rotated**\n\nLatest and previous snapshots have identical scan dates. This usually means the workflow ran multiple times before the daily rotation at 15:00 UTC.\n\nNo alerts generated (this is expected behavior)."
                print(msg)
                write_step_summary(msg)
                sys.exit(0)
            
            filtered_previous = filter_to_watchlist(previous_rows, watchlist)
            
            ignore_transitions = parse_ignore_transitions(ignore_transitions_str)
            
            change_alerts = evaluate_change_diff(
                filtered_latest,
                filtered_previous,
                fields,
                ignore_blank_transitions,
                ignore_transitions
            )
            print(f"Found {len(change_alerts)} change alerts")
            all_alerts.extend(change_alerts)
        
        # State mode
        if mode in ('state', 'both'):
            state_alerts = evaluate_state_check(
                filtered_latest,
                alert_on_status_codes,
                alert_on_scan_status,
                alert_on_not_live
            )
            print(f"Found {len(state_alerts)} state alerts")
            all_alerts.extend(state_alerts)
        
        # Render
        body = render_alerts(all_alerts, max_changes, issue_title)
        
        # Output
        if dry_run:
            print("\n" + "="*60)
            print("DRY RUN - Issue body preview:")
            print("="*60)
            print(body)
            print("="*60)
            write_step_summary(f"## Dry Run\n\n{body}")
        else:
            if not token or not repo:
                print("ERROR: token and GITHUB_REPOSITORY must be set for non-dry-run mode")
                sys.exit(1)
            
            client = IssueClient(repo, token)
            result = handle_alert_lifecycle(
                client,
                issue_title,
                body,
                labels,
                is_clear=(len(all_alerts) == 0),
                comment_on_clear=comment_on_clear,
                stream='alerts'
            )
            
            action = result['action']
            url = result.get('issue_url', 'N/A')
            
            print(f"\nIssue lifecycle: {action}")
            print(f"Issue URL: {url}")
            
            summary = f"## Site Scanning Alerts\n\n**Action:** {action}\n\n**Issue:** {url}\n\n**Alerts found:** {len(all_alerts)}"
            write_step_summary(summary)
            
            if fail_on_alert and len(all_alerts) > 0 and action in ('created', 'commented'):
                print("\nWorkflow configured to fail on alerts (fail_on_alert=true)")
                sys.exit(1)
        
        print("\nCompleted successfully")
        sys.exit(0)
    
    except SnapshotError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        write_step_summary(f"## Error\n\n{e}")
        sys.exit(1)
    except Exception as e:
        print(f"UNEXPECTED ERROR: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        write_step_summary(f"## Unexpected Error\n\n```\n{traceback.format_exc()}\n```")
        sys.exit(1)


if __name__ == '__main__':
    main()
