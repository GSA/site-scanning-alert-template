#!/usr/bin/env python3
"""
Alert rule evaluation for Site Scanning data.

Implements change-detection (latest vs previous) and state-check (bad current values)
with configurable noise suppression.
"""
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple
from collections import Counter


@dataclass
class Alert:
    """Represents a single alert finding."""

    domain: str
    field: str
    old_value: str
    new_value: str
    alert_type: str = 'change'  # 'change', 'state', 'corpus'

    def to_line(self) -> str:
        """Format as issue body line."""
        if self.alert_type == 'state':
            return f"initial_domain: {self.domain}\n{self.field}: {self.new_value}"
        elif self.alert_type == 'corpus':
            return f"initial_domain: {self.domain}\n{self.new_value}"  # message in new_value
        else:  # 'change'
            old = '(no data)' if self.old_value == '' else self.old_value
            new = '(no data)' if self.new_value == '' else self.new_value
            return f"initial_domain: {self.domain}\n{self.field}: {old} -> {new}"


def evaluate_change_diff(
    latest_rows: List[Dict[str, str]],
    previous_rows: List[Dict[str, str]],
    fields: List[str],
    ignore_blank_transitions: bool = False,
    ignore_transitions: Set[Tuple[str, str, str]] = None
) -> List[Alert]:
    """
    Detect changes between latest and previous snapshots.
    
    Args:
        latest_rows: Filtered rows from latest snapshot
        previous_rows: Filtered rows from previous snapshot
        fields: List of field names to compare (e.g. ['live', 'status_code', 'primary_scan_status'])
        ignore_blank_transitions: If True, suppress value <-> '' transitions
        ignore_transitions: Set of (field, old, new) tuples to suppress
    
    Returns:
        List of Alert objects
    """
    if ignore_transitions is None:
        ignore_transitions = set()
    
    # Build lookup: initial_domain -> row dict
    prev_map = {row['initial_domain']: row for row in previous_rows}
    latest_map = {row['initial_domain']: row for row in latest_rows}
    
    alerts = []
    
    # Check for changes in common domains
    for domain in latest_map:
        if domain not in prev_map:
            # New domain in corpus
            alerts.append(Alert(domain, '', '', 'newly in snapshot', 'corpus'))
            continue
        
        prev_row = prev_map[domain]
        latest_row = latest_map[domain]
        
        for field in fields:
            old = prev_row.get(field, '')
            new = latest_row.get(field, '')
            
            if old == new:
                continue
            
            # Noise suppression
            if ignore_blank_transitions:
                if old == '' or new == '':
                    continue
            
            if (field, old, new) in ignore_transitions:
                continue
            
            alerts.append(Alert(domain, field, old, new, 'change'))
    
    # Check for domains that disappeared
    for domain in prev_map:
        if domain not in latest_map:
            alerts.append(Alert(domain, '', '', 'no longer in snapshot', 'corpus'))
    
    return alerts


def evaluate_state_check(
    latest_rows: List[Dict[str, str]],
    alert_on_status_codes: Set[str],
    alert_on_scan_status: Set[str],
    alert_on_not_live: bool
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
        domain = row['initial_domain']
        
        # Check status_code
        status_code = row.get('status_code', '')
        if status_code in alert_on_status_codes:
            alerts.append(Alert(domain, 'status_code', '', status_code, 'state'))
        
        # Check primary_scan_status
        scan_status = row.get('primary_scan_status', '')
        if scan_status in alert_on_scan_status:
            alerts.append(Alert(domain, 'primary_scan_status', '', scan_status, 'state'))
        
        # Check live
        if alert_on_not_live:
            live = row.get('live', '').lower()
            if live == 'false':
                alerts.append(Alert(domain, 'live', '', 'false', 'state'))
    
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
    alone. Corpus alerts ("newly/no longer in snapshot") have no field, so
    they're keyed on domain + message instead and never collide with
    change/state alerts.

    Order-preserving and independent of whether change or state alerts were
    appended first.
    """
    change_keys = {
        (a.domain, a.field) for a in alerts if a.alert_type == 'change'
    }

    deduped = []
    seen = set()
    for alert in alerts:
        if alert.alert_type == 'corpus':
            key = (alert.domain, 'corpus', alert.new_value)
        else:
            key = (alert.domain, alert.field)

        if alert.alert_type == 'state' and key in change_keys:
            # A change alert for this domain/field already covers this.
            continue

        if key in seen:
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
    
    by_field = Counter(a.field if a.field else a.alert_type for a in alerts)
    by_domain = Counter(a.domain for a in alerts)
    
    lines = [
        f"**{len(alerts)} total changes detected** (exceeds max_changes threshold)",
        "",
        "Changes by field:",
    ]
    
    for field, count in sorted(by_field.items(), key=lambda x: -x[1]):
        lines.append(f"  - {field}: {count}")
    
    lines.append("")
    lines.append("Top 10 affected domains:")
    for domain, count in by_domain.most_common(10):
        lines.append(f"  - {domain}: {count} changes")
    
    return '\n'.join(lines)


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

    header = "❗ Site Scanning results have changed for websites that you are monitoring:\n\n"

    if len(alerts) > max_changes:
        return header + summarize_alerts(alerts) + "\n\nPlease investigate as appropriate."

    # Enumerate all, grouped by domain. sorted() is stable, so alerts for
    # the same domain keep their original relative order.
    lines = [alert.to_line() for alert in sorted(alerts, key=lambda a: a.domain)]
    return header + "\n\n".join(lines) + "\n\nPlease investigate as appropriate."


def parse_ignore_transitions(ignore_str: str) -> Set[Tuple[str, str, str]]:
    """
    Parse comma-separated ignore_transitions input.
    
    Format: "field:old->new,field:old->new,..."
    
    Returns:
        Set of (field, old, new) tuples
    """
    if not ignore_str:
        return set()
    
    result = set()
    for entry in ignore_str.split(','):
        entry = entry.strip()
        if not entry:
            continue
        
        try:
            field_part, transition = entry.split(':', 1)
            old, new = transition.split('->', 1)
            result.add((field_part.strip(), old.strip(), new.strip()))
        except ValueError:
            # Malformed entry, skip
            continue
    
    return result
