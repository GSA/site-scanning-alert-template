#!/usr/bin/env python3
"""
Site Scanning Alerts - Entrypoint

Monitors federal websites for status changes and configuration issues using
GSA Site Scanning data.
"""

import os
import sys
import traceback
from typing import List, NamedTuple, NoReturn, Optional, Set, Tuple

# Add scripts directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from issues import IssueClient, file_alert
from rules import (
    Alert,
    dedupe_alerts,
    evaluate_change_diff,
    evaluate_state_check,
    parse_ignore_transitions,
    render_alerts,
)
from snapshot import (
    REQUIRED_COLUMNS,
    Row,
    SnapshotError,
    check_snapshot_freshness,
    download_snapshot,
    filter_to_watchlist,
    find_unmatched_entries,
    has_snapshot_rotated,
)

# Fallback labels used when the `labels` input parses to an empty list
# (e.g. a workflow override of `labels: ''`). file_alert requires at
# least one label - see its docstring - so this must never be passed
# through empty.
DEFAULT_LABELS = ["site-scanning-alert"]

# Modes accepted by the `mode` input. Anything else must hard-fail before
# any network I/O, rather than silently skipping both evaluators and
# falling through to a false "condition cleared".
VALID_MODES = ("change", "state", "both")

# Cap on watchlist entries listed individually in the unmatched-entries
# warning before it collapses into a count.
MAX_UNMATCHED_LISTED = 10


class Config(NamedTuple):
    """Parsed `INPUT_*`/`GITHUB_*` environment variables set by action.yml."""

    watchlist_path: str
    mode: str
    fields: List[str]
    alert_on_status_codes: Set[str]
    alert_on_scan_status: Set[str]
    alert_on_not_live: bool
    ignore_blank_transitions: bool
    ignore_transitions_str: str
    report_recoveries: bool
    max_changes: int
    labels: List[str]
    issue_title: str
    snapshot_url: str
    previous_snapshot_url: str
    max_snapshot_age_days: int
    token: str
    fail_on_alert: bool
    dry_run: bool
    repo: str


def load_watchlist(path: str) -> List[str]:
    """Load a watchlist file, dropping blank lines and `#` comments."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"Watchlist file not found: {path}")

    with open(path, "r") as f:
        lines = (line.strip() for line in f)
        return [line for line in lines if line and not line.startswith("#")]


def parse_csv_list(value: str) -> List[str]:
    """Parse a comma-separated input into a list, preserving order and dropping blanks."""
    return [item.strip() for item in value.split(",") if item.strip()]


def write_step_summary(content: str) -> None:
    """Write to GitHub Actions step summary if available."""
    summary_file = os.getenv("GITHUB_STEP_SUMMARY")
    if summary_file:
        with open(summary_file, "a") as f:
            f.write(content + "\n")


def report(msg: str) -> None:
    """Print msg to stdout and mirror it to the GitHub Actions step summary."""
    print(msg)
    write_step_summary(msg)


def _env(name: str, default: str = "") -> str:
    """Read an `INPUT_*` action input."""
    return os.getenv(f"INPUT_{name.upper()}", default)


def _env_flag(name: str, default: str = "false") -> bool:
    """Read a boolean `INPUT_*` action input."""
    return _env(name, default).lower() == "true"


def _env_int(name: str, default: str, minimum: int = 0) -> int:
    """
    Read an integer `INPUT_*` action input, hard-failing on a bad value.

    main() calls read_config() outside its try block, so a bare int() would
    escape as a raw traceback with nothing in the step summary. Failing here
    also runs before any network I/O.
    """
    raw = _env(name, default).strip()
    try:
        value: Optional[int] = int(raw)
    except ValueError:
        value = None
    if value is None or value < minimum:
        shown = f"`{raw}`" if raw else "(empty)"
        _fail(f"❌ **Invalid `{name}`: {shown}**\n\nExpected a whole number ≥ {minimum}.")
    return value


def read_config() -> Config:
    """Read inputs from environment (set by action.yml)."""
    return Config(
        watchlist_path=_env("watchlist", "watchlist.txt"),
        mode=_env("mode", "both"),
        fields=parse_csv_list(_env("fields", "live,status_code,primary_scan_status")),
        alert_on_status_codes=set(parse_csv_list(_env("alert_on_status_codes", "500,502,503,504"))),
        alert_on_scan_status=set(parse_csv_list(_env("alert_on_scan_status"))),
        # Defaults true: a fully unreachable site has live=false, a blank
        # status_code, and a primary_scan_status outside the empty-by-default
        # alert_on_scan_status set - with this off, mode: both produces zero
        # state alerts for the worst possible failure. Must agree with
        # action.yml's `alert_on_not_live` default (_env_flag has no implicit
        # default), since the local dry-run recipe in AGENTS.md invokes this
        # script directly, bypassing action.yml entirely.
        alert_on_not_live=_env_flag("alert_on_not_live", "true"),
        ignore_blank_transitions=_env_flag("ignore_blank_transitions"),
        ignore_transitions_str=_env("ignore_transitions"),
        report_recoveries=_env_flag("report_recoveries", "false"),
        max_changes=_env_int("max_changes", "25", minimum=1),
        labels=parse_csv_list(_env("labels", "site-scanning-alert")),
        issue_title=_env("issue_title", "Possible website issues"),
        snapshot_url=_env(
            "snapshot_url",
            "https://api.gsa.gov/technology/site-scanning/data/site-scanning-latest.csv",
        ),
        previous_snapshot_url=_env(
            "previous_snapshot_url",
            "https://api.gsa.gov/technology/site-scanning/data/site-scanning-previous.csv",
        ),
        max_snapshot_age_days=_env_int("max_snapshot_age_days", "3"),
        token=_env("token"),
        fail_on_alert=_env_flag("fail_on_alert"),
        dry_run=_env_flag("dry_run"),
        repo=os.getenv("GITHUB_REPOSITORY", ""),
    )


def _fail(msg: str) -> NoReturn:
    """Report a fatal message to stderr and the step summary, then exit 1."""
    print(msg, file=sys.stderr)
    write_step_summary(msg)
    sys.exit(1)


def _exit_on_alert(config: Config, success_msg: str = "") -> NoReturn:
    """
    Exit 1 if the workflow is configured to fail on alerts, else exit 0
    after printing success_msg (if given).
    """
    if config.fail_on_alert:
        print("\nWorkflow configured to fail on alerts (fail_on_alert=true)")
        sys.exit(1)
    if success_msg:
        print(success_msg)
    sys.exit(0)


def _validate_mode(mode: str) -> None:
    """Validate mode before any network I/O."""
    if mode not in VALID_MODES:
        _fail(f"❌ **Invalid `mode`: `{mode}`**\n\nExpected one of: {', '.join(VALID_MODES)}.")


def _resolve_labels(labels: List[str]) -> List[str]:
    """Ensure at least one label is provided, falling back to default if empty."""
    if labels:
        return labels
    report(
        f"⚠️ **Empty `labels` input - falling back to default labels:** {', '.join(DEFAULT_LABELS)}"
    )
    return list(DEFAULT_LABELS)


def _init_client(config: Config) -> Optional[IssueClient]:
    """Initialize GitHub issue client for non-dry runs."""
    if config.dry_run:
        return None
    if not (config.token and config.repo):
        _fail("ERROR: token and GITHUB_REPOSITORY must be set for non-dry-run mode")
    return IssueClient(config.repo, config.token)


def _check_freshness_or_exit(
    config: Config,
    latest_rows: List[Row],
    labels: List[str],
    client: Optional[IssueClient],
) -> None:
    """Validate snapshot freshness and exit if stale (filing staleness issue if configured)."""
    is_fresh, max_date_str = check_snapshot_freshness(latest_rows, config.max_snapshot_age_days)
    if is_fresh:
        print(f"Snapshot freshness OK (dated {max_date_str})")
        return

    msg = (
        f"⚠️ **Snapshot is stale**\n\nLatest snapshot is dated {max_date_str or 'unknown'}, "
        f"which is older than {config.max_snapshot_age_days} days.\n\n"
        "This typically indicates the scanning engine has not run recently. "
        "Please investigate the upstream system before acting on any alerts."
    )
    report(msg)

    if config.dry_run:
        sys.exit(0)

    result = file_alert(client, "Site Scanning data is stale", msg, labels, stream="staleness")
    print(f"Staleness alert: {result['action']} - {result.get('issue_url', 'N/A')}")

    _exit_on_alert(config)


def _warn_unmatched_entries(latest_rows: List[Row], watchlist: List[str]) -> None:
    """Report watchlist entries that matched no domains in snapshot."""
    unmatched = find_unmatched_entries(latest_rows, watchlist)
    if not unmatched:
        return

    listed = "\n".join(f"  - {entry}" for entry in unmatched[:MAX_UNMATCHED_LISTED])
    if len(unmatched) > MAX_UNMATCHED_LISTED:
        listed += f"\n  ... and {len(unmatched) - MAX_UNMATCHED_LISTED} more"

    report(
        f"⚠️ **{len(unmatched)} watchlist entries matched nothing**\n\n{listed}\n\n"
        "Check for typos or verify that these domains exist in the Site Scanning index.",
    )


def _resolve_fields(config: Config, latest_rows: List[Row], previous_rows: List[Row]) -> List[str]:
    """
    Narrow the configured `fields` to those usable for change detection,
    warning about any that were dropped.

    A custom field is only usable if present on both sides of the diff - a
    field missing from one side would otherwise appear as a spurious
    '' -> value change on every row.
    """
    available = set(latest_rows[0]) & set(previous_rows[0])
    dropped = [f for f in config.fields if f not in available]
    if dropped:
        report(
            f"⚠️ **Unrecognized monitoring field(s) skipped:** {', '.join(dropped)}\n\n"
            "These are not present in the Site Scanning snapshot and will not be monitored. "
            "Check for typos against the Site Scanning Data Dictionary.",
        )

    return [f for f in config.fields if f in available]


def _evaluate_changes(
    config: Config,
    latest_rows: List[Row],
    filtered_latest: List[Row],
    watchlist: List[str],
) -> Tuple[List[Alert], bool]:
    """Download previous snapshot and evaluate change diff.

    Returns:
        (change_alerts, rotation_stalled)
    """
    print(f"Downloading previous snapshot from {config.previous_snapshot_url}...")
    previous_rows = download_snapshot(
        config.previous_snapshot_url,
        REQUIRED_COLUMNS,
        optional_columns=config.fields,
    )
    print(f"Downloaded {len(previous_rows)} rows")

    effective_fields = _resolve_fields(config, latest_rows, previous_rows)

    # Check rotation. A stalled rotation means there's no fresh diff
    # to evaluate, but that's no reason to skip state-mode checks -
    # an active outage doesn't wait for the daily snapshot rotation.
    if not has_snapshot_rotated(latest_rows, previous_rows):
        report(
            "ℹ️ **Snapshot has not rotated**\n\nLatest and previous snapshots have identical scan "
            "dates. This usually means the workflow ran multiple times before the daily rotation "
            "at 15:00 UTC.\n\nChange detection skipped for this run; state checks (if enabled) "
            "still ran against the current data.",
        )
        return [], True

    change_alerts = evaluate_change_diff(
        filtered_latest,
        filter_to_watchlist(previous_rows, watchlist),
        effective_fields,
        config.ignore_blank_transitions,
        parse_ignore_transitions(config.ignore_transitions_str),
        config.report_recoveries,
    )
    print(f"Found {len(change_alerts)} change alerts")
    return change_alerts, False


def _publish_alerts(
    config: Config,
    client: Optional[IssueClient],
    body: str,
    labels: List[str],
    alert_count: int,
) -> NoReturn:
    """Output alert preview in dry run, or file a GitHub issue. Always exits."""
    if config.dry_run:
        print("\n" + "=" * 60)
        print("DRY RUN - Issue body preview:")
        print("=" * 60)
        print(body)
        print("=" * 60)
        write_step_summary(f"## Dry Run\n\n{body}")
        print("\nCompleted successfully")
        sys.exit(0)

    result = file_alert(client, config.issue_title, body, labels, stream="alerts")
    action = result["action"]
    url = result.get("issue_url", "N/A")

    print(f"\nIssue filing: {action}")
    print(f"Issue URL: {url}")
    write_step_summary(
        f"## Site Scanning Alerts\n\n**Action:** {action}\n\n"
        f"**Issue:** {url}\n\n**Alerts found:** {alert_count}",
    )

    _exit_on_alert(config, "\nCompleted successfully")


def _collect_alerts(
    config: Config,
    latest_rows: List[Row],
    filtered_latest: List[Row],
    watchlist: List[str],
) -> Tuple[List[Alert], bool]:
    """
    Run the evaluators enabled by `mode` and return their deduped findings.

    Returns:
        (alerts, rotation_stalled)
    """
    alerts: List[Alert] = []
    rotation_stalled = False

    if config.mode in ("change", "both"):
        change_alerts, rotation_stalled = _evaluate_changes(
            config,
            latest_rows,
            filtered_latest,
            watchlist,
        )
        alerts.extend(change_alerts)

    if config.mode in ("state", "both"):
        state_alerts = evaluate_state_check(
            filtered_latest,
            config.alert_on_status_codes,
            config.alert_on_scan_status,
            config.alert_on_not_live,
        )
        print(f"Found {len(state_alerts)} state alerts")
        alerts.extend(state_alerts)

    # Both-mode can raise a change alert and a state alert for the same
    # underlying failure (e.g. status_code 200->503 and status_code 503);
    # collapse those before rendering/fingerprinting.
    return dedupe_alerts(alerts), rotation_stalled


def _load_watchlist_or_exit(path: str) -> List[str]:
    """Load the watchlist, exiting 0 with an explanation if it has no entries."""
    print(f"Loading watchlist from {path}...")
    watchlist = load_watchlist(path)

    if not watchlist:
        report(
            f"⚠️ **Watchlist is empty**\n\n"
            f"The watchlist file `{path}` contains no active entries "
            "(only comments or blank lines).\n\nAdd domains to monitor, one per line. "
            "See the watchlist file for syntax examples.",
        )
        sys.exit(0)

    print(f"Loaded {len(watchlist)} watchlist entries")
    return watchlist


def _exit_no_alerts(rotation_stalled: bool) -> NoReturn:
    """Explain why there's nothing to file, then exit 0."""
    if rotation_stalled:
        # No fresh diff and no active state findings - there's nothing new
        # to report, and nothing new to file.
        report(
            "ℹ️ **No new information this run**\n\nSnapshot has not rotated, so change detection "
            "was skipped, and no state-check findings were found. Skipping issue filing.",
        )
    else:
        # In change-only mode this just means "nothing changed today" (not
        # "the site recovered" - a sustained outage produces no diff on day
        # 2), but either way there are no findings to file an issue for.
        report(
            "✅ **No alerts this run**\n\nAll monitored sites are operating as expected (or, in "
            "`mode: change`, nothing changed since the last snapshot).",
        )
    sys.exit(0)


def run(config: Config) -> NoReturn:
    """
    Run one evaluation cycle. Exits the process directly (via sys.exit) at
    every terminal point, same as the guard clauses this replaces - a
    SnapshotError or unexpected exception raised from here is caught by
    main().
    """
    _validate_mode(config.mode)
    labels = _resolve_labels(config.labels)
    client = _init_client(config)
    watchlist = _load_watchlist_or_exit(config.watchlist_path)

    # Download snapshots. optional_columns keeps any user-configured
    # custom `fields` present in the CSV, without hard-failing when one
    # is missing (that's reported as a warning further down instead).
    print(f"Downloading latest snapshot from {config.snapshot_url}...")
    latest_rows = download_snapshot(
        config.snapshot_url, REQUIRED_COLUMNS, optional_columns=config.fields
    )
    print(f"Downloaded {len(latest_rows)} rows")

    _check_freshness_or_exit(config, latest_rows, labels, client)

    filtered_latest = filter_to_watchlist(latest_rows, watchlist)
    print(f"Filtered to {len(filtered_latest)} monitored sites")

    _warn_unmatched_entries(latest_rows, watchlist)

    if not filtered_latest:
        sys.exit(0)

    all_alerts, rotation_stalled = _collect_alerts(
        config,
        latest_rows,
        filtered_latest,
        watchlist,
    )

    if not all_alerts:
        _exit_no_alerts(rotation_stalled)

    _publish_alerts(
        config,
        client,
        render_alerts(all_alerts, config.max_changes),
        labels,
        len(all_alerts),
    )


def main():
    """Main entrypoint."""
    config = read_config()

    try:
        run(config)
    except SnapshotError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        write_step_summary(f"## Error\n\n{e}")
        sys.exit(1)
    except Exception as e:
        print(f"UNEXPECTED ERROR: {e}", file=sys.stderr)
        traceback.print_exc()
        write_step_summary(f"## Unexpected Error\n\n```\n{traceback.format_exc()}\n```")
        sys.exit(1)


if __name__ == "__main__":
    main()
