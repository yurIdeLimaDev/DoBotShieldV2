# Operator-defined rules

DoBot Shield can add application-specific regular expressions to its built-in defensive rules. Set `CUSTOM_RULES_FILE` to a local JSON file. The file is loaded once at startup; an unreadable file, invalid expression, unknown field, duplicate identifier, or unsupported phase/target stops startup instead of silently weakening policy.

Custom expressions use Go's RE2-compatible regular-expression syntax. RE2 does not implement backreferences or lookaround and avoids catastrophic backtracking. DoBot Shield also limits the file to 1 MiB, the rule count to 256, and each expression to 4096 bytes.

## File format

```json
{
  "version": 1,
  "rules": [
    {
      "id": "tenant-admin-command",
      "phase": "request",
      "target": "body",
      "pattern": "(?i)tenant-admin\\s*:\\s*[0-9]{4}",
      "description": "Reject a private control token outside the application protocol"
    },
    {
      "id": "internal-response-marker",
      "phase": "response",
      "target": "body",
      "pattern": "INTERNAL_[A-Z0-9]{8}"
    },
    {
      "id": "websocket-privileged-command",
      "phase": "websocket-client",
      "target": "message",
      "pattern": "(?i)admin\\s*:\\s*shutdown"
    }
  ]
}
```

JSON requires each backslash in an expression to be escaped as `\\`. Rule identifiers are case-insensitively unique and may contain only letters, digits, dots, underscores, and hyphens, with a maximum of 64 characters.

## Phases and targets

| Phase | Targets | Inspected data |
|---|---|---|
| `request` | `any`, `path`, `query`, `host`, `headers`, `body` | HTTP request fields after the normal bounded body-decoding step. |
| `response` | `any`, `headers`, `body` | Supported backend response headers and the bounded response prefix. |
| `websocket-client` | `any`, `message` | One complete client-to-backend WebSocket message. |
| `websocket-server` | `any`, `message` | One complete backend-to-client WebSocket message. |

Each expression is evaluated against the same bounded normalization variants used by the built-in WAF. A match is reported as `CUSTOM_RULE_<id>` with the stable rule reference `custom:<id>`; the expression itself is not copied into operational logs.

Custom rules follow `ENABLE_WAF`, `WAF_MODE`, response-inspection settings, and `WAF_ALLOWLIST`. In monitor mode they are logged and forwarded. In block mode a request is rejected, a matching response is replaced, or a matching WebSocket connection is closed with status 1008 before the offending message is forwarded.

## Deployment workflow

1. Store the JSON file outside the repository and restrict write access to the WAF operator.
2. Start with `WAF_MODE=monitor` and representative legitimate traffic.
3. Test raw and encoded matches, false positives, the exact phase, and the intended target.
4. Change to `WAF_MODE=block` only after review.
5. Restart DoBot Shield after changing the file. Startup recompiles and revalidates the complete policy atomically.

For containers, mount the policy read-only and point the environment variable at the mounted path:

```bash
docker run --rm -p 8080:8080 \
  -e TARGET_URL=http://host.docker.internal:4280 \
  -e CUSTOM_RULES_FILE=/policy/custom-rules.json \
  -v "$PWD/policy:/policy:ro" \
  dobotshield
```

Custom regular expressions are a narrow extension mechanism, not a replacement for authorization or application validation. Prefer semantic application controls for values whose meaning depends on user identity, state, or business workflow.
