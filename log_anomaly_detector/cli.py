import argparse
import sys

from log_anomaly_detector.parser import parse_log_file
from log_anomaly_detector.rules import run_rules, ALL_RULES, DEFAULT_LOGIN_THRESHOLD, DEFAULT_LOGIN_WINDOW_MINUTES, DEFAULT_BUSINESS_HOURS
from log_anomaly_detector.report import format_text, format_json


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="log-anomaly-detector",
        description="Scan a log file for suspicious patterns: failed-login bursts, off-hours access, and privilege escalation indicators.",
    )
    p.add_argument("log_file", help="Path to the log file to scan")
    p.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="Output format (default: text)",
    )
    p.add_argument(
        "--rules", default=None,
        help=f"Comma-separated list of rules to run (default: all). Available: {', '.join(ALL_RULES.keys())}",
    )
    p.add_argument(
        "--login-threshold", type=int, default=DEFAULT_LOGIN_THRESHOLD,
        help=f"Failed logins from one source within the window to trigger a finding (default: {DEFAULT_LOGIN_THRESHOLD})",
    )
    p.add_argument(
        "--login-window-minutes", type=int, default=DEFAULT_LOGIN_WINDOW_MINUTES,
        help=f"Sliding window size in minutes for the failed-login rule (default: {DEFAULT_LOGIN_WINDOW_MINUTES})",
    )
    p.add_argument(
        "--business-hours", default=None, metavar="START-END",
        help=f"Business hours as START-END in 24h clock, e.g. 9-18 (default: {DEFAULT_BUSINESS_HOURS[0]}-{DEFAULT_BUSINESS_HOURS[1]})",
    )
    return p


def _parse_business_hours(value):
    if value is None:
        return DEFAULT_BUSINESS_HOURS
    try:
        start_s, end_s = value.split("-")
        start, end = int(start_s), int(end_s)
    except ValueError:
        raise SystemExit(f"--business-hours must look like START-END (e.g. 9-18), got {value!r}")
    if not (0 <= start <= 24 and 0 <= end <= 24):
        raise SystemExit(f"--business-hours values must be between 0 and 24, got {value!r}")
    return (start, end)


def main(argv=None) -> int:
    """
    Returns an exit code: 0 if the file parsed and no anomalies were found,
    1 if anomalies were found (useful for wiring into cron/CI as a pass/fail
    check), 2 if the log file itself couldn't be read at all.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    rule_names = [r.strip() for r in args.rules.split(",")] if args.rules else None
    if rule_names:
        unknown = [r for r in rule_names if r not in ALL_RULES]
        if unknown:
            print(f"Unknown rule(s): {', '.join(unknown)}. Available: {', '.join(ALL_RULES.keys())}", file=sys.stderr)
            return 2

    business_hours = _parse_business_hours(args.business_hours)

    try:
        result = parse_log_file(args.log_file)
    except FileNotFoundError:
        print(f"Log file not found: {args.log_file}", file=sys.stderr)
        return 2
    except IsADirectoryError:
        print(f"{args.log_file} is a directory, not a file", file=sys.stderr)
        return 2

    findings = run_rules(
        result.entries,
        rule_names=rule_names,
        login_threshold=args.login_threshold,
        login_window_minutes=args.login_window_minutes,
        business_hours=business_hours,
    )

    if args.format == "json":
        print(format_json(findings, result.errors, len(result.entries)))
    else:
        print(format_text(findings, result.errors, len(result.entries)))

    return 1 if findings else 0


def run():
    sys.exit(main(sys.argv[1:]))


if __name__ == "__main__":
    run()
