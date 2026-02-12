# Security Model

## Security Profiles

Two built-in security profiles control command approval behavior:

### `easy_safe` (default)

Only critical destructive commands (L2) require approval. Examples:
- `rm -rf /`
- `reboot`, `shutdown`
- `mkfs`

Approved commands generate a **reusable privilege grant** scoped by command template. The grant remains valid for `easy_safe_approval_ttl_sec` seconds (default `900`). Set to `0` to disable reuse.

All other commands execute immediately without approval.

### `ops_strict`

Every command requires explicit approval. No reusable grants by default.

## Approval Flow

Approval is MCP-first via `ssh_approve_request` tool call. This avoids `/dev/tty` prompt deadlocks in Claude Code / Codex sessions.

Fallback: `csshctl approve <approval_id> --by <name>` from a local terminal.

## Access Controls

- **Profile-only connect**: remote connections are restricted to pre-configured profiles. Direct host/username connect is blocked unless a matching profile exists.
- **Public host policy**: public internet hosts are allowed by default (`allow_public_host=true`). Effective rule is OR (global OR profile): if global is `true`, profile cannot further restrict; if global is `false`, only profiles with `allow_public_host=true` can connect public hosts.
- **Write scope**: remote file writes (`ssh_write_file`, `ssh_apply_patch`) are restricted to directories listed in `workspace_roots`.
- **Runtime narrowing**: `ssh_connect(limit_dir=...)` can further narrow effective runtime scope to a subdirectory (must be inside configured `workspace_roots`).
- **Root user**: root login is denied by default. A profile can allow it with `allow_root_user: true`; global `allow_root_login: true` also permits root and has higher priority.

## Credential Storage

Credentials are stored in the OS keychain and never written to config files or passed through AI:

| Platform | Backend | CLI |
|----------|---------|-----|
| macOS | Keychain | `security` command |
| Linux | Secret Service (D-Bus) | `secret-tool` |

Stored credential types:
- `password` — SSH password for password/hybrid auth
- `key_passphrase` — passphrase for encrypted SSH private keys
- `sudo_password` — password for `sudo` command execution on remote host

The `ssh_credentials_prompt` tool opens a **local web form** where the user enters credentials directly into the OS keychain. Credentials never pass through the AI model.

If the web form is unavailable, the tool returns manual CLI commands:
```bash
csshctl secret set-password --profile <profile_id>
csshctl secret set-key-passphrase --profile <profile_id>
csshctl secret set-sudo-password --profile <profile_id>
```
If `csshctl` is not in `PATH`, use an absolute path.
