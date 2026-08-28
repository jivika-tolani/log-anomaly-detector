"""
Parses log lines in a common key=value format:

    2026-08-15 03:22:11 host=web01 user=admin src_ip=192.168.1.45 action=LOGIN_FAILED msg="invalid password"

This is not an attempt to support every real-world log format — that's a
much bigger project. It's a deliberately simple, well-defined format that
covers what the rule engine actually needs (timestamp, actor, source,
action, message), documented honestly rather than pretending to be a
universal log parser.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"

_LINE_RE_TIMESTAMP_LEN = len("2026-08-15 03:22:11")


@dataclass
class LogEntry:
    timestamp: datetime
    fields: dict
    raw_line: str
    line_number: int

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        return self.fields.get(key, default)


@dataclass
class ParseError:
    line_number: int
    raw_line: str
    reason: str


@dataclass
class ParseResult:
    entries: list = field(default_factory=list)
    errors: list = field(default_factory=list)


def _parse_kv_pairs(text: str) -> dict:
    """
    Parses `key=value` and `key="quoted value with spaces"` pairs from the
    remainder of a log line. Malformed tokens (no '=') are skipped rather
    than raising — one bad token shouldn't discard the rest of the line's
    fields.
    """
    fields = {}
    i = 0
    n = len(text)
    while i < n:
        while i < n and text[i].isspace():
            i += 1
        if i >= n:
            break
        eq = text.find("=", i)
        if eq == -1:
            break  # no more key=value tokens
        key = text[i:eq].strip()
        i = eq + 1
        if i < n and text[i] == '"':
            end = text.find('"', i + 1)
            if end == -1:
                # unterminated quote — take the rest of the line as the value
                value = text[i + 1:]
                i = n
            else:
                value = text[i + 1:end]
                i = end + 1
        else:
            sp = text.find(" ", i)
            if sp == -1:
                value = text[i:]
                i = n
            else:
                value = text[i:sp]
                i = sp
        if key:
            fields[key] = value
    return fields


def parse_line(raw_line: str, line_number: int) -> tuple:
    """
    Returns (LogEntry, None) on success or (None, ParseError) on failure.
    Never raises — malformed lines are reported, not fatal.
    """
    line = raw_line.rstrip("\n")
    if not line.strip():
        return None, None  # blank lines are silently skipped, not errors

    if len(line) < _LINE_RE_TIMESTAMP_LEN:
        return None, ParseError(line_number, raw_line, "line shorter than expected timestamp")

    ts_text = line[:_LINE_RE_TIMESTAMP_LEN]
    try:
        timestamp = datetime.strptime(ts_text, TIMESTAMP_FORMAT)
    except ValueError:
        return None, ParseError(line_number, raw_line, f"could not parse timestamp {ts_text!r}")

    rest = line[_LINE_RE_TIMESTAMP_LEN:].strip()
    fields = _parse_kv_pairs(rest)
    if not fields:
        return None, ParseError(line_number, raw_line, "no key=value fields found after timestamp")

    return LogEntry(timestamp=timestamp, fields=fields, raw_line=line, line_number=line_number), None


def parse_log_file(path: str) -> ParseResult:
    result = ParseResult()
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for i, raw_line in enumerate(f, start=1):
            entry, error = parse_line(raw_line, i)
            if entry is not None:
                result.entries.append(entry)
            elif error is not None:
                result.errors.append(error)
    return result


def parse_log_text(text: str) -> ParseResult:
    result = ParseResult()
    for i, raw_line in enumerate(text.splitlines(), start=1):
        entry, error = parse_line(raw_line, i)
        if entry is not None:
            result.entries.append(entry)
        elif error is not None:
            result.errors.append(error)
    return result
