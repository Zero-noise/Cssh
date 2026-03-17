# Cssh

Cssh is an SSH bridge for MCP-compatible coding agents (Claude Code, Codex, Cursor, VS Code, Windsurf, and more).
It lets AI agents securely connect, execute commands, transfer files, and manage remote servers over SSH — all through MCP tool calls.

## Installation

### One-line install (recommended)

```bash
curl -sSL https://raw.githubusercontent.com/Zero-noise/Cssh/main/scripts/install.sh | bash
```

### Developer install

```bash
git clone https://github.com/Zero-noise/Cssh.git && cd Cssh && ./scripts/install.sh
```

The installer builds binaries to `~/.csbridge/bin/`, adds them to your PATH, registers the MCP server with Claude Code, and auto-approves tool permissions.

Open Claude Code and tell the AI: "Help me connect to my SSH server", and it will guide you through profile setup and connection.

### Uninstall

```bash
curl -sSL https://raw.githubusercontent.com/Zero-noise/Cssh/main/scripts/uninstall.sh | bash
# or, from repo checkout:
./scripts/uninstall.sh
```

### Verify installation

```bash
csshctl --help          # CLI tool works
claude mcp list         # cssh is registered (Claude Code)
```

If `claude mcp list` does not show cssh, register manually:

```bash
claude mcp add --transport stdio --scope user cssh -- ~/.csbridge/bin/cssh-mcp
```

## Other MCP Clients

The install script registers cssh with **Claude Code** automatically. For other clients, add the config manually.

Binary path: `~/.csbridge/bin/cssh-mcp` — if your client does not expand `~`, use the full absolute path.

<details>
<summary><b>Cursor</b></summary>

`~/.cursor/mcp.json` (global) or `.cursor/mcp.json` (project):

```json
{
  "mcpServers": {
    "cssh": { "command": "~/.csbridge/bin/cssh-mcp" }
  }
}
```
</details>

<details>
<summary><b>VS Code / GitHub Copilot</b></summary>

`.vscode/mcp.json` (workspace) or command palette → **MCP: Open User Configuration**:

```json
{
  "servers": {
    "cssh": { "command": "~/.csbridge/bin/cssh-mcp" }
  }
}
```

> VS Code uses `"servers"` as the root key, not `"mcpServers"`.
</details>

<details>
<summary><b>Windsurf</b></summary>

`~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "cssh": { "command": "~/.csbridge/bin/cssh-mcp" }
  }
}
```
</details>

<details>
<summary><b>Codex CLI</b></summary>

`~/.codex/config.toml` (global) or `.codex/config.toml` (project):

```toml
[mcp_servers.cssh]
command = "~/.csbridge/bin/cssh-mcp"
```

Or: `codex mcp add cssh -- ~/.csbridge/bin/cssh-mcp`
</details>

<details>
<summary><b>JetBrains IDEs</b></summary>

**Settings** → **Tools** → **AI Assistant** → **Model Context Protocol (MCP)** → **+** → add stdio server with command `~/.csbridge/bin/cssh-mcp`.
</details>

## Features

- **Managed SSH master lifecycle** — master processes run with `-MN`; Cssh tracks process health and detects death automatically
- **Auto-reconnect** — if an SSH master dies unexpectedly, Cssh reconnects transparently and notifies the AI agent
- **Exec progress streaming** — real-time output via MCP progress notifications during long-running commands
- **Per-profile Cnote** — persistent AI-facing notes per profile (e.g. "download to /mnt/ssd", "don't restart during business hours"); returned automatically on `ssh_connect`
- **File transfer with verification** — `scp` transport with automatic SFTP/legacy-SCP fallback and SHA-256 checksums
- **Credential storage** — passwords and key passphrases stored in OS keychain (macOS Keychain / Linux Secret Service), never in config files
- **Tool annotations** — all tools annotated with MCP spec hints (`readOnlyHint`, `destructiveHint`, etc.)

## Security Model

Two built-in security profiles control command approval:

| | `easy_safe` (default) | `ops_strict` |
|---|---|---|
| **Intent** | Development — trust the AI | Production — verify everything |
| **Hard deny** | `rm -rf /`, fork bombs, destructive finds | Same |
| **Approval** | Only irreversible ops (reboot, mkfs) | All high-risk + all sudo |
| **Grant caching** | Configurable TTL | Disabled (fresh approval every time) |
| **Overrides** | `AllowReboot`, `AllowDiskOps` | Ignored |

Additional controls: profile-only connections, `workspace_roots` write restrictions, `limit_dir` runtime narrowing, `allow_root_user` policy, public-host OR-precedence.

> Full details: [docs/security-model.md](docs/security-model.md)

## Tools

| Tool | Description |
|------|-------------|
| `ssh_connect` | Profile-based SSH connection, returns `connection_id` |
| `ssh_open_session` | Create a reusable shell session |
| `ssh_exec` | Run a command with real-time progress streaming |
| `ssh_connection_status` | Inspect connection health |
| `ssh_disconnect` | Close a connection |
| `ssh_read_file` | Read remote file |
| `ssh_write_file` | Write remote file (workspace_roots guarded) |
| `ssh_apply_patch` | Apply unified diff patch on remote host |
| `ssh_transfer` | Transfer files via scp (SFTP default, legacy SCP fallback) with SHA-256 verification |
| `ssh_profile` | List or delete saved profiles |
| `ssh_cnote` | Read or update per-profile Cnote instructions |
| `ssh_profile_setup` | Create or edit profiles via guided setup flow |
| `ssh_credentials_prompt` | Securely store credentials via local web form |
| `ssh_key_setup` | Select SSH key and store passphrase via local web form |
| `ssh_privilege` | Inspect or revoke privilege grants |

## Build

```bash
go build -o cssh-mcp ./cmd/cssh-mcp && go build -o csshctl ./cmd/csshctl
```

> After modifying `.go` source files, re-run `go build` to regenerate the binary.

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

# Edit a profile
csshctl profile edit --id devbox --host 10.0.0.5 --workspace-roots /home/ubuntu/app

# Scan for SSH keys
csshctl key scan --dir ~/.ssh/

# Store credentials
csshctl secret set-password --profile devbox
csshctl secret set-key-passphrase --profile devbox
csshctl secret set-sudo-password --profile devbox

# Manage approvals
csshctl approvals list --status pending
csshctl approve apr_xxx --by yourname
```

## AI Workflow

> Full setup flow: [docs/setup-flow.md](docs/setup-flow.md) · Runtime paths: [docs/runtime.md](docs/runtime.md)

1. `ssh_profile_setup(step=template|save)` — create a profile
2. `ssh_key_setup(profile_id=...)` — select SSH key and store passphrase (if key auth)
3. `ssh_credentials_prompt(profile_id=...)` — store password/sudo credentials if needed
4. `ssh_connect(profile_id=...)` — connect (Cnote is returned automatically)
5. `ssh_exec` / `ssh_read_file` / `ssh_write_file` / `ssh_transfer` — work on the remote host
6. When a call returns `approval_required`, run `csshctl approve <id>` in a separate terminal, then retry with `approval_token`

## Notes

- Tell the AI to "record this in the Cnote" to persist profile-level rules.
- Password auth uses `SSH_ASKPASS` flow.
- `ssh_apply_patch` requires `patch` and `base64` on the remote host.
- Default config path: `~/.csbridge/config.toml` (auto-created on first run).
