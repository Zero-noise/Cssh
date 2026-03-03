#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="$HOME/.csbridge/bin"
MARKER="# cssh-path-inject"

info()  { printf '\033[1;34m[cssh]\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[cssh]\033[0m %s\n' "$*"; }

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
  for rc_file in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.profile"; do
    if [ -f "$rc_file" ] && grep -qF "$MARKER" "$rc_file" 2>/dev/null; then
      # Remove lines containing the marker
      local tmp
      tmp="$(mktemp)"
      grep -vF "$MARKER" "$rc_file" > "$tmp"
      mv "$tmp" "$rc_file"
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

main() {
  info "Uninstalling cssh..."
  remove_binaries
  remove_path_injection
  unregister_mcp
  echo ""
  info "Uninstall complete!"
}

main "$@"
