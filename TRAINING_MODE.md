# Training Mode

Training Mode records structured WAF decisions and converts them into a self-contained HTML security-event timeline. It is designed for rule tuning, incident review, and learning how an encoded input was interpreted by the inspection engine.

It is disabled by default because captured payloads can contain sensitive application data. When it is needed, retain the default redaction control and protect both the JSON Lines log and generated report as security-sensitive records.

## Operational guarantee

Training Mode observes a decision that the WAF has already made. It never changes block, monitor, or allow behavior. If a directory cannot be created or a record cannot be written, only the logger enters a degraded state; request processing continues.

## Event schema

Each event is one JSON object per line:

| Field | Meaning |
|---|---|
| `timestamp` | UTC RFC3339 event time. |
| `request_id` | Correlation identifier shared with access logs. |
| `ip` | Derived client IP. |
| `method` | HTTP method for request-phase events. |
| `path` | Target path. |
| `phase` | `request`, `response`, `websocket-client`, or `websocket-server`. |
| `action` | `blocked` or `detected`. |
| `category` | Threat or protocol category. |
| `location` | Matching input location. |
| `rule` | Matched expression or stable rule identifier. |
| `payload` | Bounded original matching value. |
| `variants` | Bounded normalized variants used during inspection. |

Example:

```json
{"timestamp":"2026-07-31T14:02:11Z","request_id":"7dd0...","ip":"203.0.113.10","method":"GET","path":"/search","phase":"request","action":"blocked","category":"XSS","location":"Query","rule":"(?i)<\\s*script","payload":"q=%3Cscript%3Ealert(1)%3C%2Fscript%3E","variants":["q=<script>alert(1)</script>"]}
```

Payloads, rules, and variant lists have fixed size limits. Invalid JSON Lines are skipped by the report loader so a partial write cannot invalidate an entire report.

## Configuration

| Variable | Default | Purpose |
|---|---:|---|
| `TRAINING_MODE` | `false` | Enable structured event persistence. |
| `TRAINING_LOG_FILE` | `logs/training.jsonl` | Destination file. An empty value disables logging. |
| `TRAINING_REDACT_SENSITIVE` | `true` | Redact common password, token, secret, session, cookie, API-key, and authorization values. |

Directories are created with owner-only permissions and the log file is restricted to its owner where the operating system supports those permissions. Redaction reduces exposure but cannot identify every application-specific secret. Avoid collecting unnecessary traffic, restrict file access, define retention, and remove reports when they are no longer needed.

## Recommended rollout

1. Enable Training Mode in a controlled environment.
2. Run `WAF_MODE=monitor` with representative legitimate and adversarial traffic.
3. Review categories, rules, routes, decoded variants, and backend response findings.
4. Fix the application when possible; otherwise add the narrowest category/path allowlist entry.
5. Repeat the traffic set and confirm the exception does not create a bypass on sibling paths.
6. Change to `WAF_MODE=block`, monitor alerts, and periodically reevaluate rules and exceptions.

Response XSS matching is disabled by default, and response database/stack diagnostics are limited to error responses by default. These settings reduce common false positives on documentation and security-training pages while retaining high-signal file-disclosure inspection. WebSocket text-message detections use the two direction-specific phases; binary messages are recorded only when binary inspection has been explicitly enabled.

## Generate the report

```bash
go run ./cmd/report -in logs/training.jsonl -out training-report.html
go run ./cmd/report -in logs/training.jsonl -out training-report.html -open
```

On Windows:

```bat
generate_report.bat
generate_report.bat -in logs\training.jsonl -out training-report.html
```

The report includes aggregate counts, category and source distributions, filters, a chronological timeline, decoded variants, and category explanations. It uses Go's `html/template`; captured values are contextually escaped and displayed as inert text. The stylesheet is embedded so the output has no runtime dependency on repository files.

## Data flow

```text
HTTP or WebSocket WAF decision
  -> waf.DescribeBlock locates the matching bounded value
  -> optional sensitive-value redaction
  -> traininglog.Record appends one JSON object
  -> cmd/report loads valid records
  -> html/template generates a self-contained report
```

Generate reports and validation artifacts outside the project directory when possible. Neither the JSON Lines log nor the generated HTML report should be committed.
