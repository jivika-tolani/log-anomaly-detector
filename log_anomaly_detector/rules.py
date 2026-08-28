"""
Detector rules. Each rule is a plain function: (entries, config) -> list[Finding].
Kept as functions rather than a class hierarchy — there's no shared state
or inheritance need yet, and three independent functions are easier to
read and test than an abstract base class built for rules that don't
exist yet.
"""
from dataclasses import dataclass
from datetime import timedelta
from collections import defaultdict


@dataclass
class Finding:
    rule: str
    severity: str  # "HIGH" | "MEDIUM" | "LOW"
    message: str
    timestamp: str
    line_numbers: list


DEFAULT_LOGIN_THRESHOLD = 5
DEFAULT_LOGIN_WINDOW_MINUTES = 10
DEFAULT_BUSINESS_HOURS = (9, 18)  # 9am-6pm, inclusive start, exclusive end
PRIVILEGE_ESCALATION_ACTIONS = {"SUDO", "PRIVILEGE_ESCALATION", "SU"}
PRIVILEGE_ESCALATION_KEYWORDS = ("sudo", "root login", "priv_esc", "privilege escalation")


def failed_login_burst(entries, threshold=DEFAULT_LOGIN_THRESHOLD, window_minutes=DEFAULT_LOGIN_WINDOW_MINUTES):
    """
    Flags a burst of LOGIN_FAILED events from the same source IP within a
    sliding time window — a basic brute-force / credential-stuffing signal.
    Grouped by src_ip (falls back to 'unknown' if the field is missing,
    rather than dropping those events silently).
    """
    failed = [e for e in entries if e.get("action") == "LOGIN_FAILED"]
    by_source = defaultdict(list)
    for e in failed:
        by_source[e.get("src_ip", "unknown")].append(e)

    findings = []
    window = timedelta(minutes=window_minutes)
    for src_ip, group in by_source.items():
        group.sort(key=lambda e: e.timestamp)
        start = 0
        for end in range(len(group)):
            while group[end].timestamp - group[start].timestamp > window:
                start += 1
            count = end - start + 1
            if count >= threshold:
                window_entries = group[start:end + 1]
                findings.append(Finding(
                    rule="failed_login_burst",
                    severity="HIGH",
                    message=(
                        f"{count} failed logins from {src_ip} within "
                        f"{window_minutes} minutes (threshold: {threshold})"
                    ),
                    timestamp=window_entries[-1].timestamp.isoformat(sep=" "),
                    line_numbers=[e.line_number for e in window_entries],
                ))
                break  # one finding per source is enough; don't re-flag every subsequent line in the same burst
    return findings


def off_hours_activity(entries, business_hours=DEFAULT_BUSINESS_HOURS):
    """
    Flags successful logins (action == LOGIN_SUCCESS) outside the
    configured business hours. Timezone-naive by design: this operates on
    whatever local time the log timestamps are already in — it does not
    attempt timezone conversion.
    """
    start_hour, end_hour = business_hours
    findings = []
    for e in entries:
        if e.get("action") != "LOGIN_SUCCESS":
            continue
        hour = e.timestamp.hour
        if hour < start_hour or hour >= end_hour:
            findings.append(Finding(
                rule="off_hours_activity",
                severity="MEDIUM",
                message=(
                    f"Login by user={e.get('user', 'unknown')} at "
                    f"{e.timestamp.strftime('%H:%M')}, outside business hours "
                    f"({start_hour}:00-{end_hour}:00)"
                ),
                timestamp=e.timestamp.isoformat(sep=" "),
                line_numbers=[e.line_number],
            ))
    return findings


def privilege_escalation(entries):
    """
    Flags entries whose action or message indicates a privilege escalation
    attempt (sudo, su, explicit PRIVILEGE_ESCALATION action). Keyword
    matching on `msg` is case-insensitive and intentionally narrow — it
    trades recall for not drowning real signal in false positives.
    """
    findings = []
    for e in entries:
        action = e.get("action", "")
        msg = e.get("msg", "").lower()
        matched_keyword = next((kw for kw in PRIVILEGE_ESCALATION_KEYWORDS if kw in msg), None)
        if action in PRIVILEGE_ESCALATION_ACTIONS or matched_keyword:
            reason = f"action={action}" if action in PRIVILEGE_ESCALATION_ACTIONS else f"message contains {matched_keyword!r}"
            findings.append(Finding(
                rule="privilege_escalation",
                severity="HIGH",
                message=f"Privilege escalation indicator for user={e.get('user', 'unknown')} ({reason})",
                timestamp=e.timestamp.isoformat(sep=" "),
                line_numbers=[e.line_number],
            ))
    return findings


ALL_RULES = {
    "failed_login_burst": failed_login_burst,
    "off_hours_activity": off_hours_activity,
    "privilege_escalation": privilege_escalation,
}


def run_rules(entries, rule_names=None, login_threshold=DEFAULT_LOGIN_THRESHOLD,
              login_window_minutes=DEFAULT_LOGIN_WINDOW_MINUTES, business_hours=DEFAULT_BUSINESS_HOURS):
    """Runs the requested rules (default: all) and returns a flat, timestamp-sorted list of Findings."""
    names = rule_names or list(ALL_RULES.keys())
    findings = []
    for name in names:
        if name == "failed_login_burst":
            findings.extend(failed_login_burst(entries, threshold=login_threshold, window_minutes=login_window_minutes))
        elif name == "off_hours_activity":
            findings.extend(off_hours_activity(entries, business_hours=business_hours))
        elif name == "privilege_escalation":
            findings.extend(privilege_escalation(entries))
        else:
            raise ValueError(f"Unknown rule: {name!r}. Available: {list(ALL_RULES.keys())}")
    findings.sort(key=lambda f: f.timestamp)
    return findings
