from datetime import datetime

from log_anomaly_detector.parser import LogEntry
from log_anomaly_detector.rules import failed_login_burst, off_hours_activity, privilege_escalation, run_rules


def entry(ts, line_number=1, **fields):
    return LogEntry(timestamp=datetime.fromisoformat(ts), fields=fields, raw_line="", line_number=line_number)


# --- failed_login_burst ---

def test_failed_login_burst_triggers_at_threshold():
    entries = [
        entry(f"2026-08-15 02:14:{i:02d}", line_number=i, action="LOGIN_FAILED", src_ip="1.2.3.4")
        for i in range(5)  # 5 attempts, 1 second apart, well within any reasonable window
    ]
    findings = failed_login_burst(entries, threshold=5, window_minutes=10)
    assert len(findings) == 1
    assert findings[0].rule == "failed_login_burst"
    assert "1.2.3.4" in findings[0].message


def test_failed_login_burst_does_not_trigger_below_threshold():
    entries = [
        entry(f"2026-08-15 02:14:{i:02d}", line_number=i, action="LOGIN_FAILED", src_ip="1.2.3.4")
        for i in range(4)  # one short of the threshold of 5
    ]
    findings = failed_login_burst(entries, threshold=5, window_minutes=10)
    assert findings == []


def test_failed_login_burst_ignores_attempts_spread_beyond_window():
    # 5 attempts, but 20 minutes apart each — never 5 within any 10-minute window
    entries = [
        entry(f"2026-08-15 0{2 + i}:00:00", line_number=i, action="LOGIN_FAILED", src_ip="1.2.3.4")
        for i in range(5)
    ]
    findings = failed_login_burst(entries, threshold=5, window_minutes=10)
    assert findings == []


def test_failed_login_burst_ignores_successful_logins():
    entries = [
        entry(f"2026-08-15 02:14:{i:02d}", line_number=i, action="LOGIN_SUCCESS", src_ip="1.2.3.4")
        for i in range(10)
    ]
    findings = failed_login_burst(entries, threshold=5, window_minutes=10)
    assert findings == []


def test_failed_login_burst_tracks_sources_independently():
    # 3 failed attempts each from two different sources — neither alone hits threshold=5
    entries = [
        entry(f"2026-08-15 02:14:{i:02d}", line_number=i, action="LOGIN_FAILED", src_ip="1.1.1.1")
        for i in range(3)
    ] + [
        entry(f"2026-08-15 02:14:{i:02d}", line_number=i + 10, action="LOGIN_FAILED", src_ip="2.2.2.2")
        for i in range(3)
    ]
    findings = failed_login_burst(entries, threshold=5, window_minutes=10)
    assert findings == []


# --- off_hours_activity ---

def test_off_hours_login_is_flagged():
    entries = [entry("2026-08-15 03:00:00", action="LOGIN_SUCCESS", user="admin")]
    findings = off_hours_activity(entries, business_hours=(9, 18))
    assert len(findings) == 1
    assert "admin" in findings[0].message


def test_business_hours_login_is_not_flagged():
    entries = [entry("2026-08-15 14:00:00", action="LOGIN_SUCCESS", user="admin")]
    findings = off_hours_activity(entries, business_hours=(9, 18))
    assert findings == []


def test_off_hours_boundary_start_hour_is_inside_business_hours():
    entries = [entry("2026-08-15 09:00:00", action="LOGIN_SUCCESS", user="admin")]
    findings = off_hours_activity(entries, business_hours=(9, 18))
    assert findings == []  # 9:00 is the start of business hours, inclusive


def test_off_hours_boundary_end_hour_is_outside_business_hours():
    entries = [entry("2026-08-15 18:00:00", action="LOGIN_SUCCESS", user="admin")]
    findings = off_hours_activity(entries, business_hours=(9, 18))
    assert len(findings) == 1  # 18:00 is the end of business hours, exclusive


def test_off_hours_only_checks_login_success_not_other_actions():
    entries = [entry("2026-08-15 03:00:00", action="FILE_ACCESS", user="admin")]
    findings = off_hours_activity(entries, business_hours=(9, 18))
    assert findings == []


# --- privilege_escalation ---

def test_sudo_action_is_flagged():
    entries = [entry("2026-08-15 10:00:00", action="SUDO", user="rahul", msg="sudo systemctl restart nginx")]
    findings = privilege_escalation(entries)
    assert len(findings) == 1


def test_keyword_in_message_is_flagged_case_insensitively():
    entries = [entry("2026-08-15 10:00:00", action="FILE_ACCESS", user="admin", msg="attempted ROOT LOGIN for restore")]
    findings = privilege_escalation(entries)
    assert len(findings) == 1


def test_ordinary_entry_is_not_flagged():
    entries = [entry("2026-08-15 10:00:00", action="FILE_ACCESS", user="priya", msg="opened report.csv")]
    findings = privilege_escalation(entries)
    assert findings == []


# --- run_rules ---

def test_run_rules_rejects_unknown_rule_name():
    import pytest
    with pytest.raises(ValueError):
        run_rules([], rule_names=["not_a_real_rule"])


def test_run_rules_returns_sorted_by_timestamp():
    entries = [
        entry("2026-08-15 18:00:00", action="LOGIN_SUCCESS", user="late"),
        entry("2026-08-15 03:00:00", action="LOGIN_SUCCESS", user="early"),
    ]
    findings = run_rules(entries, rule_names=["off_hours_activity"])
    assert [f.timestamp for f in findings] == sorted(f.timestamp for f in findings)
