import json

from log_anomaly_detector.cli import main


def write_log(tmp_path, content):
    path = tmp_path / "test.log"
    path.write_text(content)
    return str(path)


def test_cli_no_anomalies_returns_exit_code_0(tmp_path, capsys):
    path = write_log(tmp_path, "2026-08-15 10:00:00 user=priya action=LOGIN_SUCCESS\n")
    code = main([path])
    assert code == 0
    assert "No anomalies found" in capsys.readouterr().out


def test_cli_with_anomalies_returns_exit_code_1(tmp_path, capsys):
    lines = [
        f"2026-08-15 02:14:{i:02d} user=admin src_ip=1.2.3.4 action=LOGIN_FAILED"
        for i in range(5)
    ]
    path = write_log(tmp_path, "\n".join(lines) + "\n")
    code = main([path])
    assert code == 1
    out = capsys.readouterr().out
    assert "anomal" in out.lower()


def test_cli_missing_file_returns_exit_code_2(capsys):
    code = main(["/tmp/definitely-does-not-exist-12345.log"])
    assert code == 2
    assert "not found" in capsys.readouterr().err.lower()


def test_cli_unknown_rule_returns_exit_code_2(tmp_path, capsys):
    path = write_log(tmp_path, "2026-08-15 10:00:00 user=priya action=LOGIN_SUCCESS\n")
    code = main([path, "--rules", "not_a_real_rule"])
    assert code == 2
    assert "Unknown rule" in capsys.readouterr().err


def test_cli_json_output_is_valid_json(tmp_path, capsys):
    path = write_log(tmp_path, "2026-08-15 10:00:00 user=priya action=LOGIN_SUCCESS\n")
    code = main([path, "--format", "json"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["entries_parsed"] == 1
    assert payload["findings_count"] == 0


def test_cli_custom_login_threshold_is_respected(tmp_path, capsys):
    # only 2 failed attempts — would not trigger the default threshold of 5,
    # but should trigger with --login-threshold 2
    lines = [
        "2026-08-15 02:14:00 user=admin src_ip=1.2.3.4 action=LOGIN_FAILED",
        "2026-08-15 02:14:05 user=admin src_ip=1.2.3.4 action=LOGIN_FAILED",
    ]
    path = write_log(tmp_path, "\n".join(lines) + "\n")

    code_default = main([path])
    assert code_default == 0

    code_custom = main([path, "--login-threshold", "2"])
    assert code_custom == 1


def test_cli_custom_business_hours_is_respected(tmp_path, capsys):
    path = write_log(tmp_path, "2026-08-15 20:00:00 user=priya action=LOGIN_SUCCESS\n")

    # default business hours (9-18): 20:00 is off-hours -> anomaly
    assert main([path]) == 1

    # widened business hours covering 20:00 -> no anomaly
    assert main([path, "--business-hours", "0-24"]) == 0


def test_cli_malformed_business_hours_exits_cleanly(tmp_path):
    path = write_log(tmp_path, "2026-08-15 10:00:00 user=priya action=LOGIN_SUCCESS\n")
    try:
        main([path, "--business-hours", "not-a-range"])
        assert False, "expected SystemExit"
    except SystemExit:
        pass


def test_cli_selecting_specific_rule_only_runs_that_rule(tmp_path, capsys):
    # off-hours login that would also NOT trigger failed_login_burst (no failed logins present)
    path = write_log(tmp_path, "2026-08-15 20:00:00 user=priya action=LOGIN_SUCCESS\n")
    code = main([path, "--rules", "off_hours_activity", "--format", "json"])
    assert code == 1
    payload = json.loads(capsys.readouterr().out)
    assert all(f["rule"] == "off_hours_activity" for f in payload["findings"])
