#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="$HOME/.csbridge/bin"
MARKER="# cssh-path-inject"

info()  { printf '\033[1;34m[cssh]\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[cssh]\033[0m %s\n' "$*"; }

clear_cleanup_trap() {
  trap - EXIT
}

set_cleanup_trap() {
  local target="$1"
  local cleanup_cmd
  printf -v cleanup_cmd 'rm -rf -- %q' "$target"
  trap "$cleanup_cmd" EXIT
}

cleanup_path() {
  local target="$1"
  rm -rf -- "$target"
  clear_cleanup_trap
}

remove_binaries() {
  if [ -d "$INSTALL_DIR" ]; then
    rm -rf "$INSTALL_DIR"
    info "Removed $INSTALL_DIR"
  else
    info "No binaries found at $INSTALL_DIR"
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
      # Remove lines containing the marker
      local tmp
      local status
      tmp="$(mktemp)"
      set_cleanup_trap "$tmp"
      status=0
      grep -vF "$MARKER" "$rc_file" > "$tmp" || status=$?
      if [ "$status" -gt 1 ]; then
        cleanup_path "$tmp"
        warn "Failed to update $rc_file while removing PATH entry"
        continue
      fi
      mv "$tmp" "$rc_file"
      clear_cleanup_trap
      info "Removed PATH entry from $rc_file"
      removed=true
    fi
  done
  if [ "$removed" = false ]; then
    info "No PATH injection found in shell RC files"
  fi
}

unregister_mcp() {
  if command -v claude &>/dev/null; then
    if claude mcp list 2>/dev/null | grep -q cssh; then
      claude mcp remove cssh || true
      info "Removed cssh from MCP servers"
    else
      info "cssh not registered as MCP server"
    fi
  else
    info "Claude Code CLI not found — skip MCP unregister"
  fi
}

remove_permissions() {
  local settings_file="$HOME/.claude/settings.json"
  [ -f "$settings_file" ] || return
  command -v jq &>/dev/null || { warn "jq not found — cannot clean permissions"; return; }
  if ! jq empty "$settings_file" 2>/dev/null; then
    warn "$settings_file is not valid JSON — skipping permission cleanup"
    return
  fi
  if ! jq -e '
    if .permissions? == null then true
    elif (.permissions | type) != "object" then false
    elif .permissions.allow? == null then true
    else (.permissions.allow | type) == "array"
    end
  ' "$settings_file" >/dev/null; then
    warn "$settings_file has unexpected permissions.allow format — skipping permission cleanup"
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
    info "Removed cssh permissions from Claude Code settings"
  else
    cleanup_path "$tmp"
    warn "Failed to update $settings_file — skipping permission cleanup"
  fi
}

main() {
  info "Uninstalling cssh..."
  remove_binaries
  remove_path_injection
  unregister_mcp
  remove_permissions
  echo ""
  info "Uninstall complete!"
}

main "$@"
