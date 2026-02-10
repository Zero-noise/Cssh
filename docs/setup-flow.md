# AI-Guided Setup Flow

When a user says "I want to connect to this SSH host to do X", the AI agent runs:

1. `ssh_profile_setup(step=template)` — returns a compact fill-in form with defaults.
2. Ask the user to provide host, username, auth method, workspace roots.
3. `ssh_profile_setup(step=save)` — persists profile metadata (credentials are NOT stored here).
4. `ssh_credentials_prompt(profile_id=...)` — opens a local web form for credential entry. If web fails, returns manual `csshctl secret set-*` commands.
5. `ssh_connect(profile_id=...)` — establishes the SSH connection.

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
