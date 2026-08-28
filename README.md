# Log Anomaly Detector

![Tests](https://github.com/jivika-tolani/log-anomaly-detector/actions/workflows/tests.yml/badge.svg)

A command-line tool that scans a log file and flags patterns that usually indicate something worth investigating: repeated failed logins, logins outside normal working hours, and signs of privilege escalation.

## The Problem

Security teams generate huge volumes of log data, and most of it is routine. Manually scanning logs for the handful of entries that actually matter does not scale, and simple keyword searches miss patterns that only become suspicious in combination — five failed logins in ten minutes matters; five failed logins spread across a month usually does not.

## How It Solves the Problem

The tool reads a log file, breaks each line into structured fields, and checks the result against three independent rules:

| Rule | What it looks for |
|---|---|
| Failed login burst | A cluster of failed login attempts from the same source within a short time window — a common sign of a brute-force or credential-stuffing attempt |
| Off-hours activity | A successful login outside configured business hours |
| Privilege escalation | An action or message indicating an attempt to gain elevated access (for example, `sudo`) |

Each finding is reported with a severity level, a timestamp, and the exact line number(s) in the original file, so a human reviewer can go straight to the source.

## Log Format

The tool expects a specific, simple format rather than attempting to parse every possible log style:

```
2026-08-15 03:22:11 host=web01 user=admin src_ip=192.168.1.45 action=LOGIN_FAILED msg="invalid password"
```

A timestamp, followed by `key=value` fields (quoted if the value contains spaces). This keeps the parser small and predictable rather than pretending to support arbitrary log formats it hasn't actually been tested against.

## How to Use the Code

**What you need first:** Python 3.9 or later.

**Step 1 — Install it**

```bash
pip install -e .
```

This makes the `log-anomaly-detector` command available in your terminal.

**Step 2 — Run it against a log file**

```bash
log-anomaly-detector sample_logs/demo.log
```

**Step 3 — Try the other options**

```bash
log-anomaly-detector sample_logs/demo.log --format json
log-anomaly-detector sample_logs/demo.log --login-threshold 3 --login-window-minutes 5
log-anomaly-detector sample_logs/demo.log --business-hours 8-20
log-anomaly-detector sample_logs/demo.log --rules failed_login_burst,privilege_escalation
```

The tool exits with status code `0` if no anomalies were found, `1` if anomalies were found, and `2` if the log file couldn't be read at all — so it can be wired into a scheduled job or CI pipeline as a pass/fail check, not just run by hand.

**Step 4 — Run the automated checks**

```bash
pip install -r requirements-dev.txt
pytest -v
```

This runs 33 automated tests covering the parser (valid input, malformed lines, unusual formatting, Windows line endings) and every rule (correct positive cases, correct negative cases, and the exact boundary where a rule should or shouldn't trigger).

## Known Limitations

This is a deliberately scoped first version, not a claim to cover everything a production log-monitoring system would need:

- Only the specific `key=value` log format described above is supported — real-world logs from different systems (syslog, Windows Event Log, cloud provider logs) would need a separate parser.
- The three rules here are pattern-based, not statistical. There's no baseline learning, no source-IP reputation lookup, and no geographic anomaly detection.
- Timestamps are treated as-is, with no timezone conversion — the tool assumes all entries in a given file share the same clock.
