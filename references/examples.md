# log-analyzer: Usage Examples

## Basic Usage

### Analyze a log file with auto-detection

```bash
./scripts/run.sh /var/log/app.log
```

Output:
```
=== Log Analysis Summary ===
Total lines parsed: 1523

Lines by level:
  ERROR :    47
  WARN  :   132
  INFO  :  1298
  DEBUG :    46

Time range: 2025-01-15T00:00:01  to  2025-01-15T23:59:58

Top 10 patterns:
    1. [   23x] Connection refused to database at <IP>:<N>
    2. [   12x] Timeout waiting for response from <UUID>
    3. [    8x] Rate limit exceeded for user <N>
    4. [    4x] Disk usage at <N>% on /dev/sda<N>

Formats detected: jsonl(1523)
```

### Pipe from another command

```bash
docker logs mycontainer 2>&1 | ./scripts/run.sh
```

### JSON output

```bash
./scripts/run.sh --format=json /var/log/nginx/access.log
```

Output:
```json
{
  "total_lines": 5420,
  "levels": {
    "ERROR": 15,
    "WARN": 203,
    "INFO": 5202,
    "DEBUG": 0
  },
  "top_patterns": [
    {"pattern": "GET /api/health <N>", "count": 2100},
    {"pattern": "POST /api/login <N>", "count": 340}
  ],
  "time_range": {
    "first": "2025-01-15T00:00:00",
    "last": "2025-01-15T23:59:59"
  },
  "formats_detected": {"apache": 5420}
}
```

## Filtering

### Show only errors

```bash
./scripts/run.sh --level=error /var/log/syslog
```

### Top 3 patterns only

```bash
./scripts/run.sh --top=3 application.log
```

### Combine filters with JSON output

```bash
./scripts/run.sh --level=warn --top=5 --format=json /var/log/app.log
```

## Supported Log Formats

### JSON Lines

```json
{"timestamp": "2025-01-15T10:00:00Z", "level": "error", "message": "Connection failed"}
{"timestamp": "2025-01-15T10:00:01Z", "level": "info", "message": "Retrying..."}
```

Recognized fields: `level`/`severity`/`loglevel`, `message`/`msg`/`text`, `timestamp`/`time`/`@timestamp`.

### Apache / nginx Common Log Format

```
192.168.1.1 - frank [10/Oct/2025:13:55:36 -0700] "GET /page.html HTTP/1.1" 200 2326
```

Status codes are mapped: 5xx = ERROR, 4xx = WARN, 2xx/3xx = INFO.

### Syslog (RFC 3164)

```
Jan 15 14:32:01 myhost myapp[1234]: ERROR: something went wrong
```

Level is extracted from the message body if present, otherwise defaults to INFO.

### Generic

```
2025-01-15 10:00:00 ERROR Failed to connect to service
2025-01-15 10:00:01 WARN Disk usage at 85%
```

Scans for level keywords (ERROR, WARN, WARNING, INFO, DEBUG, FATAL, CRITICAL, TRACE) anywhere in the line.

## Pattern Grouping

Similar messages are grouped by normalizing variable parts:

| Original | Normalized |
|----------|-----------|
| `Connection to 192.168.1.5:3306 failed` | `Connection to <IP>:<N> failed` |
| `Request abc123-def4-5678-ghij-klmnopqrstuv timed out` | `Request <UUID> timed out` |
| `Processed 1523 records in 45ms` | `Processed <N> records in <N>ms` |

This lets you see that 50 "Connection to ... failed" errors are really the same issue.
