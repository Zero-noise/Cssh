# AI-Guided Setup Flow

When a user says "I want to connect to this SSH host to do X", the AI agent should use canonical tools in this order:

1. `ssh_profile_setup(step=template)` — returns a compact fill-in form with defaults.
2. Ask the user to provide host, username, auth method, workspace roots.
3. `ssh_profile_setup(step=save)` — persists profile metadata (credentials are NOT stored here).
4. `ssh_key_setup(profile_id=...)` — if key auth, opens a local web form to select a key and enter passphrase. If web fails, returns manual `csshctl key scan` / `csshctl profile edit` commands.
5. `ssh_credentials_prompt(profile_id=...)` — opens a local web form for password/sudo credential entry. If web fails, returns manual `csshctl secret set-*` commands.
6. `ssh_cnote(action=get|set|append, profile_id=...)` — read or update the profile's Cnote when the user wants persistent AI instructions.
7. `ssh_connect(profile_id=...)` — establishes the SSH connection and returns the current `cnote`. Pre-validates key existence and passphrase availability; returns `KEY_NOT_FOUND` or `KEY_PASSPHRASE_REQUIRED` errors with hints if issues are detected.
8. Use operational tools (`ssh_exec`, `ssh_transfer`, `ssh_read_file`, `ssh_write_file`, `ssh_apply_patch`) as needed.

## Approval Token Rule

If an operation returns `status=approval_required` (for example from `ssh_exec` or `ssh_transfer` with privileged options):

1. Run `csshctl approve <approval_id>` from a separate terminal.
2. Retry the original tool call with `approval_token=<approval_id>`.

## Example `ssh_profile_setup` Save Payload

```json
{
  "step": "save",
  "purpose": "debug jsonl worker",
  "profile_name": "rayna-dev",
  "host": "100.88.0.10",
  "username": "ubuntu",
  "auth_mode": "hybrid",
  "workspace_roots": ["/"],
  "key_path": "~/.ssh/id_ed25519"
}
```

## Editing Profiles

Use `ssh_profile_setup(step=edit, profile_id=...)` to modify existing profile fields. Only provided fields are updated; omitted fields remain unchanged. `auth_priority` overrides `auth_mode` if both are given.

## Shell Detection

Cssh auto-detects how to wrap commands on the remote host. This matters because `ssh_exec` needs a shell prefix (e.g. `bash -lc "cmd"`) to get a proper login environment — but not every host has bash, and some setups break with a wrapper entirely.

### How it works

On `ssh_connect`, if no shell is stored for the profile, Cssh probes the remote host through the ControlMaster socket (5 s timeout per probe). It tries candidates in order:

| Priority | Probe command | Stored value | Meaning |
|----------|---------------|--------------|---------|
| 1 | `bash -lc 'echo __cssh_ok'` | `bash -lc` | Full login-shell environment (PATH, aliases, etc.) |
| 2 | `sh -c 'echo __cssh_ok'` | `sh -c` | POSIX shell fallback |
| 3 | `cd / && echo __cssh_ok` | `__raw__` | No wrapper — commands sent directly to SSH |

The first probe that returns exit 0 **and** prints `__cssh_ok` wins. The result is persisted to the profile so subsequent connects skip detection.

If **all probes fail**, the shell field stays empty and exec falls back to the manager's default shell at runtime. Next connect will retry detection.

### Shell values

| Value | Meaning |
|-------|---------|
| `""` (empty) | Not yet detected — triggers auto-detection on next connect |
| `auto` | Explicitly request re-detection on next connect |
| `bash -lc` | Wrap commands as `bash -lc "<cmd>"` |
| `sh -c` | Wrap commands as `sh -c "<cmd>"` |
| `__raw__` | No wrapper — command string passed directly to SSH |

### Shell priority in exec / session

When executing a command, the shell is resolved in this order:

1. **Session-level** — if `ssh_open_session` was called with a `shell` parameter
2. **Connection-level** — the auto-detected (or manually set) value
3. **Manager default** — built-in fallback (`bash -lc`)

### Changing the shell

Use `ssh_profile_setup(step=edit, profile_id=..., shell=<value>)` to override detection:

- Set to `"auto"` to force re-detection on next connect.
- Set to a specific value (`bash -lc`, `sh -c`, `__raw__`) to pin it.
- Set to `""` (empty string) to clear and let detection run again.

## Multiple Servers

Keep unique names (for AI readability) and unique profile IDs (for exact targeting).
`ssh_connect` supports both `profile_name` and `profile_id`.
