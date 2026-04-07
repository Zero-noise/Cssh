#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="$HOME/.csbridge/bin"
MARKER="# cssh-path-inject"

# ── Output ────────────────────────────────────────────

if [ -t 1 ] && [ "${NO_COLOR:-}" = "" ]; then
  CYAN='\033[1;36m'
  GREEN='\033[0;32m'
  YELLOW='\033[0;33m'
  DIM='\033[0;90m'
  RESET='\033[0m'
else
  CYAN='' GREEN='' YELLOW='' DIM='' RESET=''
fi

header()    { printf '\n  %b◆ cssh · uninstall%b\n\n' "$CYAN" "$RESET"; }
ok()        { printf '    %b✓%b  %s\n' "$GREEN" "$RESET" "$*"; }
skip()      { printf '    %b·%b  %s\n' "$DIM" "$RESET" "$*"; }
warn_step() { printf '    %b⚠%b  %s\n' "$YELLOW" "$RESET" "$*"; }

# ── Helpers ───────────────────────────────────────────

set_cleanup_trap() {
  local target="$1"
  local cleanup_cmd
  printf -v cleanup_cmd 'rm -rf -- %q' "$target"
  trap "$cleanup_cmd" EXIT
}

clear_cleanup_trap() { trap - EXIT; }

cleanup_path() {
  rm -rf -- "$1"
  clear_cleanup_trap
}

# ── Steps ─────────────────────────────────────────────

remove_binaries() {
  if [ -d "$INSTALL_DIR" ]; then
    rm -rf "$INSTALL_DIR"
    ok "Removed ~/.csbridge/bin/"
  else
    skip "No binaries at ~/.csbridge/bin/"
  fi
}

remove_path_injection() {
  local removed=false
  local rc_file
  for rc_file in \
    "$HOME/.zshrc" \
    "$HOME/.bash_profile" \
    "$HOME/.bash_login" \
    "$HOME/.profile" \
    "$HOME/.bashrc"; do
    if [ -f "$rc_file" ] && grep -qF "$MARKER" "$rc_file" 2>/dev/null; then
      local tmp status
      tmp="$(mktemp)"
      set_cleanup_trap "$tmp"
      status=0
      grep -vF "$MARKER" "$rc_file" > "$tmp" || status=$?
      if [ "$status" -gt 1 ]; then
        cleanup_path "$tmp"
        warn_step "Failed to update $rc_file"
        continue
      fi
      mv "$tmp" "$rc_file"
      clear_cleanup_trap
      ok "Removed PATH from ${rc_file/#$HOME/~}"
      removed=true
    fi
  done
  if [ "$removed" = false ]; then
    skip "No PATH injection found"
  fi
}

unregister_mcp() {
  if command -v claude &>/dev/null; then
    if claude mcp list 2>/dev/null | grep -q cssh; then
      claude mcp remove cssh || true
      ok "Unregistered MCP server"
    else
      skip "MCP server not registered"
    fi
  else
    skip "Claude CLI not found"
  fi
}

remove_permissions() {
  local settings_file="$HOME/.claude/settings.json"
  if [ ! -f "$settings_file" ]; then
    skip "No settings file found"
    return
  fi
  if ! command -v jq &>/dev/null; then
    warn_step "jq not found — clean permissions manually in ~/.claude/settings.json"
    return
  fi
  if ! jq empty "$settings_file" 2>/dev/null; then
    warn_step "settings.json is not valid JSON — skipping"
    return
  fi
  if ! jq -e '
    if .permissions? == null then true
    elif (.permissions | type) != "object" then false
    elif .permissions.allow? == null then true
    else (.permissions.allow | type) == "array"
    end
  ' "$settings_file" >/dev/null; then
    warn_step "Unexpected settings format — skipping"
    return
  fi
  local tmp
  tmp="$(mktemp)"
  set_cleanup_trap "$tmp"
  if jq '
    if .permissions?.allow then
      .permissions.allow = [.permissions.allow[] | select(startswith("mcp__cssh__") | not)]
    else . end |
    if .permissions?.allow == [] then del(.permissions.allow) else . end |
    if .permissions == {} then del(.permissions) else . end
  ' "$settings_file" > "$tmp"; then
    mv "$tmp" "$settings_file"
    clear_cleanup_trap
    ok "Removed permissions from settings.json"
  else
    cleanup_path "$tmp"
    warn_step "Failed to update settings.json"
  fi
}

# ── Main ─────────────────────────────────────────────

main() {
  header
  remove_binaries
  remove_path_injection
  unregister_mcp
  remove_permissions
  printf '\n  Uninstalled.\n\n'
}

main "$@"
