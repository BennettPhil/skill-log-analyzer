#!/usr/bin/env python3
"""Log file analyzer - parses structured and unstructured logs.

Supports: JSON lines, Apache/nginx common log, syslog, generic.
Produces: summary with level counts, top error patterns, time range.
"""

import argparse
import collections
import json
import re
import sys
from datetime import datetime

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Apache / nginx common log format
# 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.1" 200 2326
APACHE_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
)

# Syslog RFC 3164
# Jan  5 14:32:01 myhost myapp[1234]: some message
SYSLOG_RE = re.compile(
    r'^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<program>[^\[:]+)(?:\[(?P<pid>\d+)\])?:\s*'
    r'(?P<message>.*)'
)

# ISO 8601 timestamp
ISO_TS_RE = re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}')

# Apache date format
APACHE_TS_RE = re.compile(r'\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}')

# Syslog date format
SYSLOG_TS_RE = re.compile(r'[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}')

# Generic log level keyword
LEVEL_RE = re.compile(r'\b(ERROR|WARN(?:ING)?|INFO|DEBUG|FATAL|CRITICAL|TRACE)\b', re.IGNORECASE)

# Pattern normalization: strip numbers, UUIDs, hex strings, IPs
NORMALIZE_PATTERNS = [
    (re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I), '<UUID>'),
    (re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'), '<IP>'),
    (re.compile(r'\b0x[0-9a-fA-F]+\b'), '<HEX>'),
    (re.compile(r'\b\d+\b'), '<N>'),
]


# ---------------------------------------------------------------------------
# Timestamp parsing
# ---------------------------------------------------------------------------

def parse_iso_ts(s):
    """Parse ISO 8601 timestamp string to datetime."""
    m = ISO_TS_RE.search(s)
    if not m:
        return None
    ts_str = m.group(0)
    for fmt in ('%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S'):
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    return None


def parse_apache_ts(s):
    """Parse Apache common log timestamp."""
    m = APACHE_TS_RE.search(s)
    if not m:
        return None
    try:
        return datetime.strptime(m.group(0), '%d/%b/%Y:%H:%M:%S')
    except ValueError:
        return None


def parse_syslog_ts(s):
    """Parse syslog-style timestamp (no year)."""
    m = SYSLOG_TS_RE.search(s)
    if not m:
        return None
    try:
        dt = datetime.strptime(m.group(0), '%b %d %H:%M:%S')
        return dt.replace(year=datetime.now().year)
    except ValueError:
        return None


def extract_timestamp(line):
    """Try all timestamp parsers, return first match or None."""
    for parser in (parse_iso_ts, parse_apache_ts, parse_syslog_ts):
        ts = parser(line)
        if ts is not None:
            return ts
    return None


# ---------------------------------------------------------------------------
# Log level mapping
# ---------------------------------------------------------------------------

LEVEL_MAP = {
    'error': 'ERROR',
    'fatal': 'ERROR',
    'critical': 'ERROR',
    'warn': 'WARN',
    'warning': 'WARN',
    'info': 'INFO',
    'debug': 'DEBUG',
    'trace': 'DEBUG',
}


def normalize_level(raw):
    """Map a raw level string to one of ERROR, WARN, INFO, DEBUG."""
    if raw is None:
        return None
    return LEVEL_MAP.get(raw.lower())


# ---------------------------------------------------------------------------
# Message normalization for pattern grouping
# ---------------------------------------------------------------------------

def normalize_message(msg):
    """Strip variable parts from a message to group similar errors."""
    result = msg.strip()
    for pattern, replacement in NORMALIZE_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


# ---------------------------------------------------------------------------
# Format detection and line parsing
# ---------------------------------------------------------------------------

def detect_and_parse(line):
    """Return (format_name, level, message, timestamp) for a log line."""

    stripped = line.strip()
    if not stripped:
        return None

    # Try JSON lines first
    if stripped.startswith('{'):
        try:
            obj = json.loads(stripped)
            if isinstance(obj, dict):
                raw_level = obj.get('level') or obj.get('severity') or obj.get('loglevel')
                message = obj.get('message') or obj.get('msg') or obj.get('text') or ''
                ts_raw = obj.get('timestamp') or obj.get('time') or obj.get('@timestamp') or ''
                ts = parse_iso_ts(str(ts_raw)) if ts_raw else None
                level = normalize_level(str(raw_level)) if raw_level else None
                return ('jsonl', level, str(message), ts)
        except (json.JSONDecodeError, ValueError):
            pass

    # Try Apache/nginx common log
    m = APACHE_RE.match(stripped)
    if m:
        status = int(m.group('status'))
        if status >= 500:
            level = 'ERROR'
        elif status >= 400:
            level = 'WARN'
        else:
            level = 'INFO'
        message = f"{m.group('method')} {m.group('path')} {status}"
        ts = parse_apache_ts(stripped)
        return ('apache', level, message, ts)

    # Try syslog
    m = SYSLOG_RE.match(stripped)
    if m:
        message = m.group('message')
        ts = parse_syslog_ts(stripped)
        # Try to find level in message
        lm = LEVEL_RE.search(message)
        level = normalize_level(lm.group(1)) if lm else 'INFO'
        return ('syslog', level, message, ts)

    # Generic: scan for level keyword
    lm = LEVEL_RE.search(stripped)
    if lm:
        level = normalize_level(lm.group(1))
        # Message is everything after the level keyword
        idx = lm.end()
        message = stripped[idx:].lstrip(' :-]')
        if not message:
            message = stripped
    else:
        level = None
        message = stripped

    ts = extract_timestamp(stripped)
    return ('generic', level, message, ts)


# ---------------------------------------------------------------------------
# HTTP status helpers for Apache format
# ---------------------------------------------------------------------------

def apache_status_level(status):
    if status >= 500:
        return 'ERROR'
    if status >= 400:
        return 'WARN'
    return 'INFO'


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def analyze(lines, level_filter=None, top_n=10):
    """Analyze an iterable of log lines. Return summary dict."""

    total = 0
    level_counts = collections.Counter()
    pattern_counts = collections.Counter()
    formats_seen = collections.Counter()
    timestamps = []

    for line in lines:
        result = detect_and_parse(line)
        if result is None:
            continue

        fmt, level, message, ts = result
        total += 1
        formats_seen[fmt] += 1

        if level:
            level_counts[level] += 1

        if ts is not None:
            timestamps.append(ts)

        # Apply level filter
        if level_filter:
            if level != level_filter:
                continue

        # Group patterns for ERROR and WARN (or all if filter set)
        if level in ('ERROR', 'WARN') or level_filter:
            norm = normalize_message(message)
            if norm:
                pattern_counts[norm] += 1

    # Build time range
    time_range = None
    if timestamps:
        timestamps.sort()
        time_range = {
            'first': timestamps[0].isoformat(),
            'last': timestamps[-1].isoformat(),
        }

    # Top patterns
    top_patterns = pattern_counts.most_common(top_n)

    return {
        'total_lines': total,
        'levels': {
            'ERROR': level_counts.get('ERROR', 0),
            'WARN': level_counts.get('WARN', 0),
            'INFO': level_counts.get('INFO', 0),
            'DEBUG': level_counts.get('DEBUG', 0),
        },
        'top_patterns': [{'pattern': p, 'count': c} for p, c in top_patterns],
        'time_range': time_range,
        'formats_detected': dict(formats_seen),
    }


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def format_text(summary):
    """Format summary as human-readable text."""
    lines = []
    lines.append('=== Log Analysis Summary ===')
    lines.append(f"Total lines parsed: {summary['total_lines']}")
    lines.append('')
    lines.append('Lines by level:')
    for lvl in ('ERROR', 'WARN', 'INFO', 'DEBUG'):
        count = summary['levels'][lvl]
        lines.append(f"  {lvl:6s}: {count:>5d}")
    lines.append('')

    if summary['time_range']:
        tr = summary['time_range']
        lines.append(f"Time range: {tr['first']}  to  {tr['last']}")
        lines.append('')

    if summary['top_patterns']:
        lines.append(f"Top {len(summary['top_patterns'])} patterns:")
        for i, entry in enumerate(summary['top_patterns'], 1):
            lines.append(f"  {i:3d}. [{entry['count']:>5d}x] {entry['pattern']}")
        lines.append('')

    fmts = summary.get('formats_detected', {})
    if fmts:
        lines.append('Formats detected: ' + ', '.join(
            f"{k}({v})" for k, v in sorted(fmts.items(), key=lambda x: -x[1])
        ))

    return '\n'.join(lines)


def format_json(summary):
    """Format summary as JSON."""
    return json.dumps(summary, indent=2)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='Analyze log files for error patterns and summaries.'
    )
    parser.add_argument(
        'logfile', nargs='?', default=None,
        help='Path to log file (reads stdin if omitted)'
    )
    parser.add_argument(
        '--format', dest='output_format', choices=('text', 'json'),
        default='text', help='Output format (default: text)'
    )
    parser.add_argument(
        '--top', type=int, default=10,
        help='Show top N patterns (default: 10)'
    )
    parser.add_argument(
        '--level', default=None,
        help='Filter by log level (error, warn, info, debug)'
    )

    args = parser.parse_args()

    # Resolve level filter
    level_filter = None
    if args.level:
        level_filter = normalize_level(args.level)
        if level_filter is None:
            print(f"Unknown level: {args.level}", file=sys.stderr)
            sys.exit(1)

    # Get input
    if args.logfile:
        try:
            with open(args.logfile, 'r', errors='replace') as f:
                content = f.readlines()
        except FileNotFoundError:
            print(f"File not found: {args.logfile}", file=sys.stderr)
            sys.exit(2)
        except PermissionError:
            print(f"Permission denied: {args.logfile}", file=sys.stderr)
            sys.exit(2)
        except OSError as e:
            print(f"File error: {e}", file=sys.stderr)
            sys.exit(2)
    else:
        if sys.stdin.isatty():
            print("No input: provide a file path or pipe data to stdin.", file=sys.stderr)
            sys.exit(1)
        content = sys.stdin.readlines()

    if not content or all(line.strip() == '' for line in content):
        print("No input: log file is empty.", file=sys.stderr)
        sys.exit(1)

    # Analyze
    summary = analyze(content, level_filter=level_filter, top_n=args.top)

    # Output
    if args.output_format == 'json':
        print(format_json(summary))
    else:
        print(format_text(summary))

    sys.exit(0)


if __name__ == '__main__':
    main()
