# AI-Guided Setup Flow

When a user says "I want to connect to this SSH host to do X", the AI agent should use canonical tools in this order:

1. `ssh_profile_setup(step=template)` — returns a compact fill-in form with defaults.
2. Ask the user to provide host, username, auth method, workspace roots.
3. `ssh_profile_setup(step=save)` — persists profile metadata (credentials are NOT stored here).
4. `ssh_credentials_prompt(profile_id=...)` — opens a local web form for credential entry. If web fails, returns manual `csshctl secret set-*` commands.
5. `ssh_connect(profile_id=...)` — establishes the SSH connection.
6. Use operational tools (`ssh_exec`, `ssh_transfer`, `ssh_read_file`, `ssh_write_file`, `ssh_apply_patch`) as needed.

## Approval Token Rule

If an operation returns `status=approval_required` (for example from `ssh_exec` or `ssh_transfer` with privileged options):

1. Call `ssh_approve_request(approval_id=..., decision=approve|reject)`.
2. Retry the original tool call with `approval_token=<approval_id>`.

Do not switch to legacy alias tools (`ssh_upload_file`, `ssh_profile_delete`, etc.); they remain backward-compatible but are deprecated.

## Example `ssh_profile_setup` Save Payload

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

## Multiple Servers

Keep unique names (for AI readability) and unique profile IDs (for exact targeting).
`ssh_connect` supports both `profile_name` and `profile_id`.
