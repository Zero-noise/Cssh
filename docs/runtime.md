# Runtime Files

Default config path: `~/.csbridge/config.toml` (auto-created on first run).

All runtime artifacts are auto-created — no manual setup needed.

| File | Path | Purpose |
|------|------|---------|
| Config | `~/.csbridge/config.toml` | Global settings (approval TTL, security defaults) |
| Profiles | `~/.csbridge/profiles.json` | Saved SSH profile definitions |
| Cnotes | `~/.csbridge/runtime/profiles/<id>-<hash>/cnote.md` | Per-profile AI instructions and operating notes |
| Approvals | `~/.csbridge/runtime/approvals.jsonl` | Pending/resolved approval requests |
| Grants | `~/.csbridge/runtime/grants.json` | Active reusable privilege grants |
| Audit logs | `~/.csbridge/logs/audit-YYYYMMDD.jsonl` | Per-day audit trail of all operations |

## Config (`config.toml`)

Auto-generated with sensible defaults on first run. Key fields:

```toml
security_profile_default = "easy_safe"
allow_public_host = true    # global-only switch; cannot be overridden per-profile
sudo_enabled = true
allow_root_login = false    # permit root user login (global override; per-profile: allow_root_user)
```

## Audit Logs

Every SSH operation (connect, exec, file read/write, transfer, disconnect) is logged to the daily audit file in JSONL format. Each entry includes timestamp, connection ID, operation type, and result.
