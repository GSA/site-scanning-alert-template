#!/usr/bin/env python3
"""
Alert rule evaluation for Site Scanning data.

Implements change-detection (latest vs previous) and state-check (bad current values)
with configurable noise suppression.
"""

from collections import Counter
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

# One snapshot row: CSV column name -> value. Deliberately re-declared here
# rather than imported from snapshot.py - this module is pure logic with no
# I/O dependencies, and importing the producer just to borrow a type name
# would drag urllib into every consumer of the rules.
Row = Dict[str, str]

# A suppressed (field, old, new) value transition, as parsed from the
# `ignore_transitions` input.
Transition = Tuple[str, str, str]


@dataclass
class Alert:
    """Represents a single alert finding."""

    domain: str
    field: str
    old_value: str
    new_value: str
    alert_type: str = "change"  # 'change', 'state', 'corpus'

    def to_bullet(self) -> str:
        """
        Format as a nested bullet, without the domain - render_alerts nests
        these under a per-domain bullet, so repeating it here would be noise.

        Indented two spaces to sit inside the parent list item.
        """
        if self.alert_type == "state":
            # State alerts have no old_value (see evaluate_state_check), so
            # the suffix keeps this from reading as a change missing its half.
            return f"  - `{self.field}`: {self.new_value} (current value)"
        if self.alert_type == "corpus":
            # Message is in new_value, lowercase; capitalize it as a sentence.
            message = self.new_value
            return f"  - {message[:1].upper()}{message[1:]}"

        old = self.old_value or "(no data)"
        new = self.new_value or "(no data)"
        return f"  - `{self.field}`: {old} → {new}"

    def dedupe_key(self) -> Tuple[str, str]:
        """
        Key identifying the underlying condition this alert describes.

        Change and state alerts for the same domain/field describe the same
        condition and so share a key (see dedupe_alerts). Corpus alerts have
        no field, so they key on their message instead and never collide
        with change/state alerts.
        """
        if self.alert_type == "corpus":
            return (self.domain, self.new_value)
        return (self.domain, self.field)


def _is_healthy_status_code(value: str) -> bool:
    """
    A 2xx status_code value. 3xx is excluded: an outage often redirects to a
    maintenance page, so a redirect can't confirm the site recovered.
    """
    value = value.strip()
    return len(value) == 3 and value.isdigit() and value[0] == "2"


def _is_recovery(field: str, old: str, new: str) -> bool:
    """
    Determine whether a field transition is a good-direction ("recovery")
    change.

    This is an allowlist, not a heuristic: only the three fields the action
    has real direction knowledge for can ever be a recovery. Any other
    field - including a user-configured custom `fields` entry like
    `https_enforced` or `hsts` - always returns False, since the action has
    no basis for judging which direction is "good" for an arbitrary column.
    """
    if field == "live":
        return new.strip().lower() == "true" and old.strip().lower() != "true"
    if field == "status_code":
        return _is_healthy_status_code(new) and not _is_healthy_status_code(old)
    if field == "primary_scan_status":
        return new.strip() == "completed" and old.strip() != "completed"
    return False


def _should_ignore_change(
    field: str,
    old: str,
    new: str,
    ignore_blank_transitions: bool,
    ignore_transitions: Set[Transition],
    report_recoveries: bool,
) -> bool:
    """Determine whether a field value transition should be ignored."""
    if old == new:
        return True
    if not report_recoveries and _is_recovery(field, old, new):
        return True
    if ignore_blank_transitions and (not old or not new):
        return True
    return (field, old, new) in ignore_transitions


def _diff_domain_fields(
    domain: str,
    prev_row: Row,
    latest_row: Row,
    fields: List[str],
    ignore_blank_transitions: bool,
    ignore_transitions: Set[Transition],
    report_recoveries: bool,
) -> List[Alert]:
    """Find changed fields between previous and latest snapshots for a single domain."""
    alerts = []
    for field in fields:
        old = prev_row.get(field, "")
        new = latest_row.get(field, "")
        if _should_ignore_change(
            field, old, new, ignore_blank_transitions, ignore_transitions, report_recoveries
        ):
            continue
        alerts.append(Alert(domain, field, old, new, "change"))
    return alerts


def evaluate_change_diff(
    latest_rows: List[Row],
    previous_rows: List[Row],
    fields: List[str],
    ignore_blank_transitions: bool = False,
    ignore_transitions: Optional[Set[Transition]] = None,
    report_recoveries: bool = True,
) -> List[Alert]:
    """
    Detect changes between latest and previous snapshots.

    Args:
        latest_rows: Filtered rows from latest snapshot
        previous_rows: Filtered rows from previous snapshot
        fields: List of field names to compare (e.g. ['live', 'status_code', 'primary_scan_status'])
        ignore_blank_transitions: If True, suppress value <-> '' transitions
        ignore_transitions: Set of (field, old, new) tuples to suppress
        report_recoveries: If False, suppress good-direction transitions
            (see _is_recovery). Defaults True here so this pure-logic
            function suppresses nothing on its own; the action's own
            default of False is applied by its caller.

    Returns:
        List of Alert objects
    """
    ignore_transitions = ignore_transitions or set()

    # Build lookup: initial_domain -> row dict
    prev_map = {row["initial_domain"]: row for row in previous_rows}
    latest_map = {row["initial_domain"]: row for row in latest_rows}

    alerts = []

    # Check for changes in common domains or new domains
    for domain, latest_row in latest_map.items():
        prev_row = prev_map.get(domain)
        if prev_row is None:
            alerts.append(Alert(domain, "", "", "newly in snapshot", "corpus"))
            continue

        alerts.extend(
            _diff_domain_fields(
                domain,
                prev_row,
                latest_row,
                fields,
                ignore_blank_transitions,
                ignore_transitions,
                report_recoveries,
            )
        )

    # Check for domains that disappeared
    alerts.extend(
        Alert(domain, "", "", "no longer in snapshot", "corpus")
        for domain in prev_map
        if domain not in latest_map
    )

    return alerts


def evaluate_state_check(
    latest_rows: List[Row],
    alert_on_status_codes: Set[str],
    alert_on_scan_status: Set[str],
    alert_on_not_live: bool,
) -> List[Alert]:
    """
    Check current state for bad values.

    Args:
        latest_rows: Filtered rows from latest snapshot
        alert_on_status_codes: Set of status_code values to alert on (e.g. {'500', '503'})
        alert_on_scan_status: Set of primary_scan_status values to alert on
        alert_on_not_live: If True, alert when live=false

    Returns:
        List of Alert objects
    """
    alerts = []

    for row in latest_rows:
        domain = row["initial_domain"]

        status_code = row.get("status_code", "")
        if status_code in alert_on_status_codes:
            alerts.append(Alert(domain, "status_code", "", status_code, "state"))

        scan_status = row.get("primary_scan_status", "")
        if scan_status in alert_on_scan_status:
            alerts.append(Alert(domain, "primary_scan_status", "", scan_status, "state"))

        # `live` is compared case-insensitively; the snapshot is not
        # consistent about 'false' vs 'False'.
        if alert_on_not_live and row.get("live", "").lower() == "false":
            alerts.append(Alert(domain, "live", "", "false", "state"))

    return alerts


def dedupe_alerts(alerts: List[Alert]) -> List[Alert]:
    """
    Collapse duplicate alerts for the same (domain, field) in `both` mode.

    A failing site typically triggers both a change alert (e.g.
    "status_code: 200 -> 503") and a state alert (e.g. "status_code: 503")
    for the same underlying condition. Reporting both doubles the noise and
    double-counts against max_changes, so when a change and a state alert
    share a domain/field, the change alert wins - it carries the old value
    too, which is strictly more diagnostic context than the state value
    alone. See Alert.dedupe_key for how corpus alerts are keyed.

    Order-preserving and independent of whether change or state alerts were
    appended first.
    """
    change_keys = {a.dedupe_key() for a in alerts if a.alert_type == "change"}

    deduped = []
    seen = set()
    for alert in alerts:
        key = alert.dedupe_key()

        # A change alert for this domain/field already covers this state alert.
        if key in seen or (alert.alert_type == "state" and key in change_keys):
            continue

        seen.add(key)
        deduped.append(alert)

    return deduped


def summarize_alerts(alerts: List[Alert]) -> str:
    """
    Produce a summary when max_changes is exceeded.

    Returns multi-line summary with counts by field and top affected domains.
    """
    if not alerts:
        return "No changes detected."

    # Corpus alerts have no field, so they're grouped under their type.
    by_field = Counter(a.field or a.alert_type for a in alerts)
    by_domain = Counter(a.domain for a in alerts)

    lines = [
        f"**{len(alerts)} total changes detected** (exceeds max_changes threshold)",
        "",
        "Changes by field:",
        *(f"  - {field}: {count}" for field, count in by_field.most_common()),
        "",
        "Top 10 affected domains:",
        *(f"  - {domain}: {count} changes" for domain, count in by_domain.most_common(10)),
    ]

    return "\n".join(lines)


def _group_by_domain(alerts: List[Alert]) -> List[Tuple[str, List[Alert]]]:
    """
    Group alerts by domain, domains ordered alphabetically.

    sorted() is stable, so alerts for the same domain keep their original
    relative order within that domain's group.
    """
    grouped: Dict[str, List[Alert]] = {}
    for alert in sorted(alerts, key=lambda a: a.domain):
        grouped.setdefault(alert.domain, []).append(alert)
    return list(grouped.items())


def render_alerts(alerts: List[Alert], max_changes: int) -> str:
    """
    Render alerts as issue body text.

    Args:
        alerts: List of Alert objects to render
        max_changes: Maximum number to enumerate; beyond this, show summary

    Returns:
        Markdown-formatted issue body
    """
    if not alerts:
        return "Site Scanning results have returned to normal. All monitored websites are operating as expected."

    if len(alerts) > max_changes:
        detail = summarize_alerts(alerts)
    else:
        # One bullet per affected site, its findings nested underneath, so a
        # reader scans sites first and only drills into the ones they own.
        # Deliberately a nested list rather than per-site headings: an issue
        # body starts below the title, so injecting headings here lands them
        # at the wrong level in the document outline. No blank lines between
        # sites - that keeps it one tight list instead of many loose ones.
        detail = "\n".join(
            f"- **{domain}**\n" + "\n".join(alert.to_bullet() for alert in domain_alerts)
            for domain, domain_alerts in _group_by_domain(alerts)
        )

    return (
        "❗ Site Scanning results have changed for websites that you are monitoring:\n\n"
        f"{detail}\n\nPlease investigate as appropriate."
    )


def _parse_transition(entry: str) -> Optional[Transition]:
    """Parse one 'field:old->new' entry into a (field, old, new) tuple, or
    None if it's blank or malformed."""
    try:
        field, old_to_new = entry.split(":", 1)
        old, new = old_to_new.split("->", 1)
    except ValueError:
        return None
    return (field.strip(), old.strip(), new.strip())


def parse_ignore_transitions(ignore_str: str) -> Set[Transition]:
    """
    Parse comma-separated ignore_transitions input.

    Format: "field:old->new,field:old->new,..."

    Malformed entries are skipped rather than raising - a typo in one
    suppression rule shouldn't take down the whole run.

    Returns:
        Set of (field, old, new) tuples
    """
    parsed = (_parse_transition(entry) for entry in ignore_str.split(","))
    return {transition for transition in parsed if transition is not None}
