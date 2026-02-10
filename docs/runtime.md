# Runtime Files

Default config path: `~/.csbridge/config.toml` (auto-created on first run).

All runtime artifacts are auto-created — no manual setup needed.

| File | Path | Purpose |
|------|------|---------|
| Config | `~/.csbridge/config.toml` | Global settings (approval TTL, security defaults) |
| Profiles | `~/.csbridge/profiles.json` | Saved SSH profile definitions |
| Approvals | `~/.csbridge/runtime/approvals.jsonl` | Pending/resolved approval requests |
| Grants | `~/.csbridge/runtime/grants.json` | Active reusable privilege grants |
| Audit logs | `~/.csbridge/logs/audit-YYYYMMDD.jsonl` | Per-day audit trail of all operations |

## Config (`config.toml`)

Auto-generated with sensible defaults on first run. Key fields:

```toml
[security]
default_security_profile = "easy_safe"
easy_safe_approval_ttl_sec = 900

[connect]
allow_public_host = false
```

## Audit Logs

Every SSH operation (connect, exec, file read/write, transfer, disconnect) is logged to the daily audit file in JSONL format. Each entry includes timestamp, connection ID, operation type, and result.
