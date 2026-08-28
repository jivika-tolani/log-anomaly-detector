import json


def format_text(findings, parse_errors, entry_count) -> str:
    lines = []
    lines.append(f"Parsed {entry_count} log entries.")
    if parse_errors:
        lines.append(f"{len(parse_errors)} line(s) could not be parsed and were skipped:")
        for err in parse_errors[:10]:
            lines.append(f"  line {err.line_number}: {err.reason}")
        if len(parse_errors) > 10:
            lines.append(f"  ... and {len(parse_errors) - 10} more")
    lines.append("")

    if not findings:
        lines.append("No anomalies found.")
        return "\n".join(lines)

    lines.append(f"{len(findings)} anomal{'y' if len(findings) == 1 else 'ies'} found:")
    lines.append("")
    for f in findings:
        line_ref = f"line {f.line_numbers[0]}" if len(f.line_numbers) == 1 else f"lines {f.line_numbers[0]}-{f.line_numbers[-1]}"
        lines.append(f"[{f.severity:6s}] {f.timestamp}  {f.rule:22s} {f.message} ({line_ref})")
    return "\n".join(lines)


def format_json(findings, parse_errors, entry_count) -> str:
    payload = {
        "entries_parsed": entry_count,
        "parse_errors": [
            {"line_number": e.line_number, "reason": e.reason} for e in parse_errors
        ],
        "findings_count": len(findings),
        "findings": [
            {
                "rule": f.rule,
                "severity": f.severity,
                "message": f.message,
                "timestamp": f.timestamp,
                "line_numbers": f.line_numbers,
            }
            for f in findings
        ],
    }
    return json.dumps(payload, indent=2)
