# Security Model

## Security Profiles

Two built-in security profiles control command approval behavior:

### `easy_safe` (default) — Development Environment

Trusts the AI. Maximizes convenience. Only irreversible operations gate execution.

**DenyAlways** (hard deny, no override):
- `rm -rf /`, fork bombs, `find -delete` on critical system paths

**DenyNeedApprove**:
- Shutdown/reboot: `shutdown`, `reboot`, `poweroff`, `halt`, `init 0/6`
  (override: `AllowReboot=true` → auto-execute)
- Disk formatting: `mkfs`, `dd of=/dev/`, `wipefs`, `fdisk`, `sfdisk`, `parted`
  (override: `AllowDiskOps=true` → auto-execute)
  (disk ops grants are reusable — approve once, valid for the connection session; configurable via `grant_ttl_sec`)

**Everything else auto-executes**:
- `workspace_roots` enforcement is **skipped on command execution**
  (file tools like `ssh_write_file` still enforce it)
- User deny patterns are still honored

### `ops_strict` — Production Environment

Strict security. Every high-risk action requires individual human approval.

- All high-risk (L2) commands require explicit approval (MaxAutoRisk=L1)
- L2 coverage includes: user management, `systemctl stop/disable/mask`, `chmod 777`,
  `chown -R root`, `pkill`/`killall`, `crontab -r/-e`, firewall write ops
  (`iptables -A/-D/-F/...`, `ufw`, `firewall-cmd`), `docker/podman rm/stop/kill`
- `AllowReboot`/`AllowDiskOps` overrides are ignored
- All `sudo` commands require approval
- `workspace_roots` violations require approval (including `..` traversal)
- No reusable grants — every execution requires fresh approval

## Approval Flow

Approval is MCP-first via `ssh_approve_request` tool call. This avoids `/dev/tty` prompt deadlocks in Claude Code / Codex sessions.

Fallback: `csshctl approve <approval_id> --by <name>` from a local terminal.

## Grant Caching

Reusable grants (policy-driven approvals like workspace_roots violations or easy_safe disk ops) are cached per-connection. Once approved, similar commands (same template hash) auto-execute without re-approval.

| Setting | Behavior |
|---------|----------|
| `grant_ttl_sec=0` (default) | Session-scoped: grant valid until connection disconnects |
| `grant_ttl_sec=N` (N>0) | TTL: grant expires after N seconds |

Grants are always revoked on disconnect via `RevokeByConnection`. In `ops_strict` mode, grants are never reusable regardless of TTL setting.

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
