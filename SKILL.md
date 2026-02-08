---
name: log-analyzer
description: >
  A log file analyzer that parses structured and unstructured log files to extract
  error patterns, frequency distributions, and timeline summaries. Supports common
  log formats including Apache, nginx, syslog, and JSON lines.
version: 0.1.0
license: Apache-2.0
entry: scripts/run.sh
builder: smoke-first-structured-builder
gates:
  - smoke
  - contract
  - integration
---

# log-analyzer

Parse log files to extract error patterns, frequency distributions, and summaries.

## Supported Formats

| Format       | Detection                              |
|--------------|----------------------------------------|
| JSON lines   | Each line is valid JSON with common fields |
| Apache/nginx | Common Log Format regex match          |
| Syslog       | RFC 3164 style with priority/facility  |
| Generic      | Line-by-line keyword scanning          |

## Usage

```bash
# Analyze a log file (auto-detect format)
./scripts/run.sh /var/log/syslog

# Pipe from stdin
cat app.log | ./scripts/run.sh

# JSON output with top 5 patterns
./scripts/run.sh --format=json --top=5 /var/log/app.log

# Filter to errors only
./scripts/run.sh --level=error access.log
```

## Output

- Total lines parsed
- Lines by log level (ERROR, WARN, INFO, DEBUG)
- Top error/warn patterns (grouped by similarity)
- Time range (first and last timestamp)

## Exit Codes

| Code | Meaning          |
|------|------------------|
| 0    | Success          |
| 1    | No input provided|
| 2    | File error       |
