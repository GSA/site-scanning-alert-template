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
    find_unmatched_entries,
    check_snapshot_freshness,
    has_snapshot_rotated,
    REQUIRED_COLUMNS,
    SnapshotError
)
from rules import (
    evaluate_change_diff,
    evaluate_state_check,
    dedupe_alerts,
    render_alerts,
    parse_ignore_transitions,
    Alert
)
from issues import IssueClient, file_alert

# Fallback labels used when the `labels` input parses to an empty list
# (e.g. a workflow override of `labels: ''`). file_alert requires at
# least one label - see its docstring - so this must never be passed
# through empty.
DEFAULT_LABELS = ['site-scanning-alert']

# Modes accepted by the `mode` input. Anything else must hard-fail before
# any network I/O, rather than silently skipping both evaluators and
# falling through to a false "condition cleared".
VALID_MODES = ('change', 'state', 'both')


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
    
    repo = os.getenv('GITHUB_REPOSITORY', '')
    
    try:
        # Validate mode before any network I/O. An unrecognized mode would
        # otherwise skip both the change and state evaluators, silently
        # leaving all_alerts empty instead of hard-failing on a
        # misconfigured workflow.
        if mode not in VALID_MODES:
            msg = f"❌ **Invalid `mode`: `{mode}`**\n\nExpected one of: {', '.join(VALID_MODES)}."
            print(msg, file=sys.stderr)
            write_step_summary(msg)
            sys.exit(1)

        # An empty labels input (e.g. a workflow override of `labels: ''`)
        # must not be passed through empty - file_alert can never find an
        # existing issue without a label to search on, so every run would
        # create a new one. Fall back to the default and warn instead of
        # silently flooding the repo.
        if not labels:
            labels = list(DEFAULT_LABELS)
            msg = f"⚠️ **Empty `labels` input - falling back to default labels:** {', '.join(labels)}"
            print(msg)
            write_step_summary(msg)

        # Load watchlist
        print(f"Loading watchlist from {watchlist_path}...")
        watchlist = load_watchlist(watchlist_path)
        
        if not watchlist:
            msg = f"⚠️ **Watchlist is empty**\n\nThe watchlist file `{watchlist_path}` contains no active entries (only comments or blank lines).\n\nAdd domains to monitor, one per line. See the watchlist file for syntax examples."
            print(msg)
            write_step_summary(msg)
            sys.exit(0)
        
        print(f"Loaded {len(watchlist)} watchlist entries")
        
        # Download snapshots. optional_columns keeps any user-configured
        # custom `fields` present in the CSV, without hard-failing when one
        # is missing (that's reported as a warning further down instead).
        print(f"Downloading latest snapshot from {snapshot_url}...")
        latest_rows = download_snapshot(snapshot_url, REQUIRED_COLUMNS, optional_columns=fields)
        print(f"Downloaded {len(latest_rows)} rows")

        # Check freshness
        is_fresh, max_date_str, _ = check_snapshot_freshness(latest_rows, max_snapshot_age_days)

        client = None
        if not dry_run and token and repo:
            client = IssueClient(repo, token)

        if not is_fresh:
            msg = f"⚠️ **Snapshot is stale**\n\nLatest snapshot is dated {max_date_str or 'unknown'}, which is older than {max_snapshot_age_days} days.\n\nThis typically indicates the scanning engine has not run recently. Please investigate the upstream system before acting on any alerts."
            print(msg)
            write_step_summary(msg)

            if client:
                result = file_alert(
                    client,
                    "Site Scanning data is stale",
                    msg,
                    labels,
                    stream='staleness'
                )
                print(f"Staleness alert: {result['action']} - {result.get('issue_url', 'N/A')}")

                if fail_on_alert and result['action'] == 'created':
                    print("\nWorkflow configured to fail on alerts (fail_on_alert=true)")
                    sys.exit(1)

            sys.exit(0)

        print(f"Snapshot freshness OK (dated {max_date_str})")

        # Recovery from staleness is reported in the step summary only -
        # there's no issue to clear or comment on, since staleness alerts
        # are filed (not tracked) per finding.

        # Filter to watchlist
        filtered_latest = filter_to_watchlist(latest_rows, watchlist)
        print(f"Filtered to {len(filtered_latest)} monitored sites")

        unmatched_entries = find_unmatched_entries(latest_rows, watchlist)
        if unmatched_entries:
            unmatched_list = '\n'.join(f"  - {entry}" for entry in unmatched_entries[:10])
            if len(unmatched_entries) > 10:
                unmatched_list += f"\n  ... and {len(unmatched_entries) - 10} more"

            msg = f"⚠️ **{len(unmatched_entries)} watchlist entries matched nothing**\n\n{unmatched_list}\n\nCheck for typos or verify that these domains exist in the Site Scanning index."
            print(msg)
            write_step_summary(msg)

        if not filtered_latest:
            sys.exit(0)

        # Evaluate alerts
        all_alerts: List[Alert] = []
        rotation_stalled = False

        # Change mode
        if mode in ('change', 'both'):
            print(f"Downloading previous snapshot from {previous_snapshot_url}...")
            previous_rows = download_snapshot(previous_snapshot_url, REQUIRED_COLUMNS, optional_columns=fields)
            print(f"Downloaded {len(previous_rows)} rows")

            # Custom fields are only usable for change detection if present
            # on both sides of the diff - a field missing from one side
            # would otherwise appear as a spurious '' -> value change on
            # every row.
            available_fields = set(latest_rows[0].keys()) & set(previous_rows[0].keys())
            effective_fields = [f for f in fields if f in available_fields]
            dropped_fields = [f for f in fields if f not in available_fields]
            if dropped_fields:
                msg = f"⚠️ **Unrecognized monitoring field(s) skipped:** {', '.join(dropped_fields)}\n\nThese are not present in the Site Scanning snapshot and will not be monitored. Check for typos against the Site Scanning Data Dictionary."
                print(msg)
                write_step_summary(msg)

            # Check rotation. A stalled rotation means there's no fresh diff
            # to evaluate, but that's no reason to skip state-mode checks -
            # an active outage doesn't wait for the daily snapshot rotation.
            rotation_stalled = not has_snapshot_rotated(latest_rows, previous_rows)
            if rotation_stalled:
                msg = "ℹ️ **Snapshot has not rotated**\n\nLatest and previous snapshots have identical scan dates. This usually means the workflow ran multiple times before the daily rotation at 15:00 UTC.\n\nChange detection skipped for this run; state checks (if enabled) still ran against the current data."
                print(msg)
                write_step_summary(msg)
            else:
                filtered_previous = filter_to_watchlist(previous_rows, watchlist)

                ignore_transitions = parse_ignore_transitions(ignore_transitions_str)

                change_alerts = evaluate_change_diff(
                    filtered_latest,
                    filtered_previous,
                    effective_fields,
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

        # Both-mode can raise a change alert and a state alert for the same
        # underlying failure (e.g. status_code 200->503 and status_code 503);
        # collapse those before rendering/fingerprinting.
        all_alerts = dedupe_alerts(all_alerts)

        if rotation_stalled and not all_alerts:
            # No fresh diff and no active state findings - there's nothing
            # new to report, and nothing new to file.
            msg = "ℹ️ **No new information this run**\n\nSnapshot has not rotated, so change detection was skipped, and no state-check findings were found. Skipping issue filing."
            print(msg)
            write_step_summary(msg)
            sys.exit(0)

        if not all_alerts:
            # Nothing to report. In change-only mode this just means
            # "nothing changed today" (not "the site recovered" - a
            # sustained outage produces no diff on day 2), but either way
            # there are no findings to file an issue for.
            msg = "✅ **No alerts this run**\n\nAll monitored sites are operating as expected (or, in `mode: change`, nothing changed since the last snapshot)."
            print(msg)
            write_step_summary(msg)
            sys.exit(0)

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
            if not client:
                print("ERROR: token and GITHUB_REPOSITORY must be set for non-dry-run mode")
                sys.exit(1)

            result = file_alert(
                client,
                issue_title,
                body,
                labels,
                stream='alerts'
            )

            action = result['action']
            url = result.get('issue_url', 'N/A')

            print(f"\nIssue filing: {action}")
            print(f"Issue URL: {url}")

            summary = f"## Site Scanning Alerts\n\n**Action:** {action}\n\n**Issue:** {url}\n\n**Alerts found:** {len(all_alerts)}"
            write_step_summary(summary)

            if fail_on_alert and action == 'created':
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
