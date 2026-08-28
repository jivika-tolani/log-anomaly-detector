from datetime import datetime

from log_anomaly_detector.parser import parse_line, parse_log_text, parse_log_file


def test_parses_valid_line():
    entry, error = parse_line(
        '2026-08-15 03:22:11 host=web01 user=admin src_ip=192.168.1.45 action=LOGIN_FAILED msg="invalid password"',
        line_number=1,
    )
    assert error is None
    assert entry.timestamp == datetime(2026, 8, 15, 3, 22, 11)
    assert entry.get("host") == "web01"
    assert entry.get("user") == "admin"
    assert entry.get("src_ip") == "192.168.1.45"
    assert entry.get("action") == "LOGIN_FAILED"
    assert entry.get("msg") == "invalid password"


def test_quoted_value_with_spaces_and_equals_sign():
    entry, error = parse_line(
        '2026-08-15 03:22:11 user=admin msg="failed: reason=bad password"',
        line_number=1,
    )
    assert error is None
    assert entry.get("msg") == "failed: reason=bad password"


def test_blank_line_is_skipped_not_an_error():
    entry, error = parse_line("   \n", line_number=1)
    assert entry is None
    assert error is None


def test_unparseable_timestamp_reports_error_not_crash():
    entry, error = parse_line("NOT A TIMESTAMP user=admin", line_number=5)
    assert entry is None
    assert error is not None
    assert error.line_number == 5


def test_line_with_no_kv_fields_reports_error():
    entry, error = parse_line("2026-08-15 03:22:11 just some prose with no equals signs", line_number=2)
    assert entry is None
    assert error is not None


def test_too_short_line_reports_error_not_crash():
    entry, error = parse_line("short", line_number=3)
    assert entry is None
    assert error is not None


def test_unterminated_quote_does_not_crash():
    entry, error = parse_line('2026-08-15 03:22:11 user=admin msg="never closed', line_number=1)
    assert error is None
    assert entry.get("msg") == "never closed"


def test_parse_log_text_mixes_good_and_bad_lines():
    text = "\n".join([
        '2026-08-15 03:22:11 user=admin action=LOGIN_SUCCESS',
        'this line is garbage',
        '2026-08-15 03:23:00 user=priya action=LOGIN_SUCCESS',
    ])
    result = parse_log_text(text)
    assert len(result.entries) == 2
    assert len(result.errors) == 1
    assert result.errors[0].line_number == 2


def test_windows_crlf_line_endings_do_not_leak_into_field_values(tmp_path):
    # Regression test: a naive line.rstrip("\n") alone would leave a
    # trailing \r stuck to the last field's value on Windows-authored logs,
    # silently breaking equality checks like action == "LOGIN_SUCCESS".
    # Python's text-mode universal newline handling strips \r\n -> \n before
    # our code ever sees it — this test locks that behavior in.
    path = tmp_path / "crlf.log"
    path.write_bytes(b"2026-08-15 10:00:00 user=priya action=LOGIN_SUCCESS\r\n")
    result = parse_log_file(str(path))
    assert len(result.entries) == 1
    assert result.entries[0].get("action") == "LOGIN_SUCCESS"  # no trailing \r
