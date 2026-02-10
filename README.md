# Cssh

Cssh is an SSH bridge for MCP-compatible coding agents (Claude Code / Codex).
It provides tool calls for SSH connect/exec, file read/write, patch apply, search, log tail, approval workflow, and audit logging.

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

# 2. Register as MCP server in Claude Code (globally available)
claude mcp add --transport stdio --scope user cssh -- $(pwd)/cssh-mcp

# 3. Verify
claude mcp list
# Expected: cssh: /path/to/cssh-mcp - ✓ Connected
```

That's it. Open Claude Code and tell the AI: "Help me connect to my SSH server", and it will guide you through setup.

## Uninstall

```bash
claude mcp remove cssh
```

## Components

- `cmd/cssh-mcp`: MCP server over stdio (NDJSON framing, protocol version `2025-11-25`).
- `cmd/csshctl`: CLI for profile/secrets/approval management.

## Security Model (v2)

- Default mode: `easy_safe`.
- `easy_safe`: only critical destructive commands require approval (for example `rm -rf /`, `reboot`, `shutdown`, `mkfs`). Approvals are reusable by command template for `easy_safe_approval_ttl_sec` seconds (default `900`, set to `0` to disable reuse).
- Non-`easy_safe` (for example `ops_strict`): every command requires explicit approval (no reusable grant by default).
- Approval flow is MCP-first (`ssh_approve_request`) to avoid `/dev/tty` prompt deadlocks in Claude Code/Codex sessions.
- Remote connect defaults to profile-only (whitelisted profiles).
- Write scope: only inside `workspace_roots`.
- Credentials are stored in OS key store:
  - macOS: Keychain (`security` command)
  - Linux: Secret Service (`secret-tool`)
- `sudo` password is stored as `sudo_password` secret in keychain/secret-service.
- Public host is denied by default unless profile/config explicitly enables it.

## Runtime Files

Default config path: `~/.csbridge/config.toml` (auto-created on first run).

Runtime artifacts (all auto-created, no manual setup needed):
- config: `~/.csbridge/config.toml`
- profiles store: `~/.csbridge/profiles.json`
- approvals queue: `~/.csbridge/runtime/approvals.jsonl`
- privilege grants: `~/.csbridge/runtime/grants.json`
- audit logs: `~/.csbridge/logs/audit-YYYYMMDD.jsonl`

## Build

```bash
# One-command build (both binaries)
go build -o cssh-mcp ./cmd/cssh-mcp && go build -o csshctl ./cmd/csshctl

# Or build separately
go build -o cssh-mcp ./cmd/cssh-mcp
go build -o csshctl ./cmd/csshctl
```

> **Note**: After modifying `.go` source files, you must re-run `go build` to regenerate the binary. Claude Code runs the compiled binary, not the source code.

## CLI Usage

```bash
# Add a profile
csshctl profile add \
  --id devbox \
  --name rayna-dev \
  --host 100.88.0.10 \
  --port 22 \
  --user ubuntu \
  --workspace-roots /home/ubuntu/project \
  --auth-priority key,password \
  --key-path ~/.ssh/id_ed25519 \
  --security-profile easy_safe

# Store password for fallback auth
csshctl secret set-password --profile devbox

# Store private key passphrase (optional)
csshctl secret set-key-passphrase --profile devbox

# Store sudo password (optional, for sudo command execution)
csshctl secret set-sudo-password --profile devbox

# List pending approvals
csshctl approvals list --status pending

# Approve a high-risk command
csshctl approve apr_xxx --by yourname

# Migrate old profiles to v2 security fields
csshctl migrate security
```

## Tool List

| Tool | Description |
|------|-------------|
| `ssh_connect` | Create an SSH connection, returns `connection_id` |
| `ssh_open_session` | Create a reusable shell session |
| `ssh_exec` | Run a command on remote host (easy_safe: critical L2 approval; non-easy_safe: any command may require approval) |
| `ssh_connection_status` | Check one/all active SSH connection health and session summary |
| `ssh_privilege_status` | List privilege grants (active/all) |
| `ssh_privilege_revoke` | Revoke one privilege grant immediately |
| `ssh_transfer` | Unified file transfer via scp. `direction=upload` (local->remote) or `direction=download` (remote->local), with optional SHA-256 verify |
| `ssh_read_file` | Read remote file (workspace_roots guarded) |
| `ssh_write_file` | Write remote file (workspace_roots guarded) |
| `ssh_apply_patch` | Apply unified diff patch on remote host |
| `ssh_list_dir` | List remote directory entries |
| `ssh_search_text` | Search text in remote files |
| `ssh_tail_log` | Tail remote log file |
| `ssh_disconnect` | Close an SSH connection |
| `ssh_profile` | Unified profile operations. `action=list` lists profiles; `action=delete` deletes one profile via two-step confirm token flow |
| `ssh_profile_setup` | Unified setup flow. `step=template` returns onboarding form; `step=save` stores profile metadata |
| `ssh_credentials_prompt` | Default secure web credential prompt; if web unavailable returns manual `./csshctl secret set-* --profile <id>` commands |
| `ssh_approve_request` | Approve/reject one pending `ssh_exec` approval request |

## Credential Fallback (No Web)

Default credential flow is `ssh_credentials_prompt` with web form.
If web is unavailable in current MCP session, tool response includes:

- `profile_id`
- `manual_commands` (for example `./csshctl secret set-key-passphrase --profile <profile_id>`)

Run the returned command(s) in your local terminal.
If you run them in another terminal tab/window, continue without restarting.
If you run them after this session is closed, restart Claude Code/Codex and resume this conversation.

Common commands:

```bash
./csshctl secret set-password --profile <profile_id>
./csshctl secret set-key-passphrase --profile <profile_id>
./csshctl secret set-sudo-password --profile <profile_id>
```

## Fast Setup Flow (AI-Guided)

When a user says "I want to connect to this SSH host to do X", AI can run:

1. `ssh_profile_setup` with `step=template` to get a compact fill-in form.
2. Ask the user to provide the form values.
3. `ssh_profile_setup` with `step=save` to persist profile metadata (credentials are not stored here).
4. Call `ssh_credentials_prompt` (web by default). If web fails, run returned `manual_commands`.
5. Call `ssh_connect` with returned `profile_id`.

Example `ssh_profile_setup` save arguments:

```json
{
  "step": "save",
  "purpose": "debug jsonl worker",
  "profile_name": "rayna-dev",
  "host": "100.88.0.10",
  "username": "ubuntu",
  "auth_mode": "hybrid",
  "workspace_roots": ["/home/ubuntu/project"],
  "key_path": "~/.ssh/id_ed25519"
}
```

For multiple servers, keep unique names (for AI readability) and unique profile IDs (for exact targeting).
`ssh_connect` supports both `profile_name` and `profile_id`.

## Notes

- Password SSH auth is implemented through `SSH_ASKPASS` flow.
- `ssh_apply_patch` requires `patch` and `base64` on remote host.
- `ssh_search_text` uses `grep/find` on remote host.

## File Transfer (SCP)

`ssh_transfer` reuses the active SSH control socket from `connection_id`.
This usually avoids re-entering password after `ssh_connect`.

- Default `mode` is `create` (fails if target exists).
- Set `mode=overwrite` to replace existing target file.
- Default `verify_checksum=true` returns `local_sha256` and `remote_sha256`.
- Local path is restricted to current working directory by default.
  Set `allow_local_anywhere=true` explicitly if you need paths outside current working directory.

Example upload:

```json
{
  "direction": "upload",
  "connection_id": "conn_xxx",
  "local_path": "/Users/me/workspace/model.bin",
  "remote_path": "/home/ubuntu/project/model.bin",
  "mode": "create",
  "create_parents": true,
  "verify_checksum": true,
  "allow_local_anywhere": true,
  "approval_token": "",
  "timeout_sec": 300
}
```

Example download:

```json
{
  "direction": "download",
  "connection_id": "conn_xxx",
  "remote_path": "/home/ubuntu/project/logs/latest.log",
  "local_path": "/Users/me/workspace/latest.log",
  "mode": "create",
  "create_parents": true,
  "verify_checksum": true,
  "approval_token": "",
  "timeout_sec": 300
}
```
