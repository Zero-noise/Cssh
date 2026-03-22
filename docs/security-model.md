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
  (file tools like `ssh_write_file` still enforce it; session cwd is always validated)
- User deny patterns are still honored

### `ops_strict` — Production Environment

Strict security. Every high-risk action requires individual human approval.

- All high-risk (L2) commands require explicit approval (MaxAutoRisk=L1)
- L2 coverage includes: user management, `systemctl stop/disable/mask`, `chmod 777`,
  `chown -R root`, `pkill`/`killall`, `crontab -r/-e`, firewall write ops
  (`iptables -A/-D/-F/...`, `ufw`, `firewall-cmd`), `docker/podman rm/stop/kill`
- `AllowReboot`/`AllowDiskOps` overrides are ignored
- All `sudo` commands require approval
- `workspace_roots` violations require approval (including `..` traversal and `cwd` outside roots)
- `cwd` violations use directory-isolated grants: the grant hash includes the literal resolved cwd path, so approving `/etc` does not auto-approve `/var` (relative `..` traversal stays one-shot)
- Sessions (`ssh_open_session`) cannot be created with `cwd` outside `workspace_roots` (applies to all profiles, including `easy_safe`)
- No reusable grants — every execution requires fresh approval

## Approval Flow

Approval is done via `csshctl approve <approval_id>` from a local terminal. The original tool call is then retried with `approval_token=<approval_id>`. This avoids `/dev/tty` prompt deadlocks in Claude Code / Codex sessions.

## Grant Caching

Reusable grants (policy-driven approvals like workspace_roots violations or easy_safe disk ops) are cached per-connection. Once approved, similar commands (same template hash) auto-execute without re-approval.

| Setting | Behavior |
|---------|----------|
| `grant_ttl_sec=0` (default) | Session-scoped: grant valid until connection disconnects |
| `grant_ttl_sec=N` (N>0) | TTL: grant expires after N seconds |

Grants are always revoked on disconnect via `RevokeByConnection`. In `ops_strict` mode, grants are never reusable regardless of TTL setting.

## Access Controls

- **Profile-only connect**: remote connections require a pre-configured profile (`profile_id` or `profile_name`). Direct host/username connect is not supported.
- **Public host policy**: public internet hosts are allowed by default (`allow_public_host=true` in global config). This is a global-only switch — it cannot be overridden per-profile or at connect time. When set to `false`, all connections to auto-detected public hosts are blocked.
- **Write scope**: remote file writes (`ssh_write_file`, `ssh_apply_patch`) are restricted to directories listed in `workspace_roots`.
- **CWD enforcement**: The `cwd` parameter in `ssh_exec` is validated against `workspace_roots` for write commands (L1/L2). Grants are directory-isolated: the hash includes the literal cwd, so approving one directory does not auto-approve others. Relative `..` traversal in cwd is always one-shot (non-reusable). Sessions cannot be created with `cwd` outside `workspace_roots` (all profiles, including `easy_safe`).
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

The `ssh_credentials_prompt` tool opens a **local web form** where the user enters credentials directly into the OS keychain. The `ssh_key_setup` tool opens a similar form for selecting an SSH key and entering its passphrase. Credentials never pass through the AI model.

If the web form is unavailable, each tool returns manual CLI commands with the auto-resolved `csshctl` path:
```bash
# ssh_credentials_prompt fallback
csshctl secret set-password --profile <profile_id>
csshctl secret set-key-passphrase --profile <profile_id>
csshctl secret set-sudo-password --profile <profile_id>

# ssh_key_setup fallback
csshctl key scan --dir ~/.ssh/
csshctl profile edit --id <profile_id> --key-path <path>
csshctl secret set-key-passphrase --profile <profile_id>
```
