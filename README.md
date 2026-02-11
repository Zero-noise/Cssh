# Cssh

Cssh is an SSH bridge for MCP-compatible coding agents (Claude Code / Codex).
It lets AI agents securely connect, execute commands, transfer files, and manage remote servers over SSH — all through MCP tool calls.

## Prerequisites

- Go 1.22+ (for building from source)
- macOS or Linux
- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) CLI installed

## Quick Start

```bash
# 1. Clone and build
git clone https://github.com/yourname/cssh.git
cd cssh
go build -o cssh-mcp ./cmd/cssh-mcp

# 2. Register as MCP server in Claude Code
claude mcp add --transport stdio --scope user cssh -- $(pwd)/cssh-mcp

# 3. Verify
claude mcp list
# Expected: cssh: /path/to/cssh-mcp - ✓ Connected
```

That's it. Open Claude Code and tell the AI: "Help me connect to my SSH server", and it will guide you through profile setup and connection.

## Uninstall

```bash
claude mcp remove cssh
```

## Security Model

- **Profile-based access**: connections are restricted to pre-configured profiles. Public hosts are denied by default.
- **Command approval**: in `easy_safe` mode (default), only critical destructive commands (e.g. `rm -rf /`, `reboot`, `mkfs`) require approval. In `ops_strict` mode, every command requires explicit approval.
- **Write protection**: remote file writes are restricted to directories listed in `workspace_roots`.
- **Credential storage**: passwords and key passphrases are stored in the OS keychain (macOS Keychain / Linux Secret Service), never in config files.

## Tools

| Tool | Description |
|------|-------------|
| `ssh_connect` | Create an SSH connection, returns `connection_id` |
| `ssh_open_session` | Create a reusable shell session |
| `ssh_exec` | Run a command on remote host |
| `ssh_connection_status` | Check connection health |
| `ssh_disconnect` | Close a connection |
| `ssh_read_file` | Read remote file |
| `ssh_write_file` | Write remote file |
| `ssh_apply_patch` | Apply unified diff patch on remote host |
| `ssh_list_dir` | List remote directory entries |
| `ssh_search_text` | Search text in remote files |
| `ssh_tail_log` | Tail remote log file |
| `ssh_transfer` | Transfer files using `scp` client (SFTP by default, legacy SCP fallback) with optional SHA-256 verification |
| `ssh_profile` | List or delete saved profiles |
| `ssh_profile_setup` | Create profiles via guided setup flow |
| `ssh_credentials_prompt` | Securely store credentials via local web form |
| `ssh_privilege_status` | List active privilege grants |
| `ssh_privilege_revoke` | Revoke a privilege grant |
| `ssh_approve_request` | Approve or reject a pending command |

## Build

```bash
# Both binaries
go build -o cssh-mcp ./cmd/cssh-mcp && go build -o csshctl ./cmd/csshctl
```

> **Note**: After modifying `.go` source files, re-run `go build` to regenerate the binary.

## CLI Reference

```bash
# Add a profile
csshctl profile add \
  --id devbox \
  --name rayna-dev \
  --host 100.88.0.10 \
  --user ubuntu \
  --workspace-roots /home/ubuntu/project \
  --auth-priority key,password \
  --key-path ~/.ssh/id_ed25519 \
  --security-profile easy_safe

# Store credentials
csshctl secret set-password --profile devbox
csshctl secret set-key-passphrase --profile devbox
csshctl secret set-sudo-password --profile devbox

# Manage approvals
csshctl approvals list --status pending
csshctl approve apr_xxx --by yourname
```

## File Transfer

`ssh_transfer` supports `direction=upload` (local → remote) and `direction=download` (remote → local).

- `scp` is the transport client. On modern OpenSSH it uses SFTP mode by default; if SFTP subsystem is unavailable, Cssh retries with legacy SCP (`-O`).
- Default mode is `create` (fails if target exists). Use `mode=overwrite` to replace.
- SHA-256 checksum verification is enabled by default.
- Local paths are restricted to the current working directory unless `allow_local_anywhere=true`.
- Response includes `transfer_protocol` (`sftp` or `scp_legacy`) and `fallback_used` (`true/false`). When fallback happens, `fallback_reason` is also returned.

## Recommended AI Workflow

Use canonical tools only (legacy aliases remain compatible but deprecated):

1. `ssh_profile_setup(step=template|save)`
2. `ssh_credentials_prompt(profile_id=...)` (if auth requires credentials)
3. `ssh_connect(profile_id=...)`
4. `ssh_exec` / `ssh_read_file` / `ssh_write_file` / `ssh_transfer`
5. `ssh_approve_request` only when a call returns `approval_required`

```json
{
  "direction": "upload",
  "connection_id": "conn_xxx",
  "local_path": "./model.bin",
  "remote_path": "/home/ubuntu/project/model.bin"
}
```

## Notes

- Password auth uses `SSH_ASKPASS` flow.
- `ssh_apply_patch` requires `patch` and `base64` on the remote host.
- `ssh_search_text` uses `grep`/`find` on the remote host.
- Default config path: `~/.csbridge/config.toml` (auto-created on first run).
