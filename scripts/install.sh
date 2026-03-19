#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="$HOME/.csbridge/bin"
REPO="Zero-noise/Cssh"
MARKER="# cssh-path-inject"

info()  { printf '\033[1;34m[cssh]\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[cssh]\033[0m %s\n' "$*"; }
error() { printf '\033[1;31m[cssh]\033[0m %s\n' "$*" >&2; exit 1; }

detect_mode() {
  if [ -f go.mod ] && grep -q '^module cssh$' go.mod 2>/dev/null; then
    echo "dev"
  else
    echo "user"
  fi
}

detect_platform() {
  OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    arm64|aarch64) ARCH="arm64" ;;
    *) error "Unsupported architecture: $ARCH" ;;
  esac
  case "$OS" in
    darwin|linux) ;;
    *) error "Unsupported OS: $OS" ;;
  esac
}

build_local() {
  if ! command -v go &>/dev/null; then
    error "Go is required for developer install. Install from https://go.dev/dl/"
  fi
  info "Building cssh-mcp and csshctl..."
  mkdir -p "$INSTALL_DIR"
  go build -o "$INSTALL_DIR/cssh-mcp" ./cmd/cssh-mcp
  go build -o "$INSTALL_DIR/csshctl" ./cmd/csshctl
  info "Built binaries in $INSTALL_DIR"
}

sha256_verify() {
  local file="$1" expected="$2"
  local actual
  if command -v sha256sum &>/dev/null; then
    actual="$(sha256sum "$file" | awk '{print $1}')"
  elif command -v shasum &>/dev/null; then
    actual="$(shasum -a 256 "$file" | awk '{print $1}')"
  else
    error "sha256sum or shasum is required for checksum verification"
  fi
  if [ "$actual" != "$expected" ]; then
    error "Checksum verification failed for $(basename "$file")\n  expected: $expected\n  actual:   $actual"
  fi
}

install_from_release() {
  detect_platform
  local base_url="https://github.com/$REPO/releases/latest/download"
  local archive="cssh-${OS}-${ARCH}.tar.gz"
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  info "Downloading cssh for ${OS}/${ARCH}..."
  if command -v curl &>/dev/null; then
    curl -fsSL "$base_url/$archive" -o "$tmp/$archive"
    curl -fsSL "$base_url/checksums.txt" -o "$tmp/checksums.txt"
  elif command -v wget &>/dev/null; then
    wget -qO "$tmp/$archive" "$base_url/$archive"
    wget -qO "$tmp/checksums.txt" "$base_url/checksums.txt"
  else
    error "curl or wget is required"
  fi

  info "Verifying checksum..."
  local expected
  expected="$(grep "$archive" "$tmp/checksums.txt" | awk '{print $1}')"
  if [ -z "$expected" ]; then
    error "No checksum found for $archive in checksums.txt"
  fi
  sha256_verify "$tmp/$archive" "$expected"
  info "Checksum OK"

  mkdir -p "$INSTALL_DIR"
  tar xzf "$tmp/$archive" -C "$tmp"
  cp "$tmp"/cssh-mcp-* "$INSTALL_DIR/cssh-mcp"
  cp "$tmp"/csshctl-* "$INSTALL_DIR/csshctl"
  chmod +x "$INSTALL_DIR/cssh-mcp" "$INSTALL_DIR/csshctl"
  info "Installed binaries to $INSTALL_DIR"
}

install_user_mode() {
  if command -v go &>/dev/null; then
    info "Go detected — cloning and building from source..."
    local tmp
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    git clone --depth 1 "https://github.com/$REPO.git" "$tmp/cssh"
    mkdir -p "$INSTALL_DIR"
    (cd "$tmp/cssh" && go build -o "$INSTALL_DIR/cssh-mcp" ./cmd/cssh-mcp)
    (cd "$tmp/cssh" && go build -o "$INSTALL_DIR/csshctl" ./cmd/csshctl)
    info "Built binaries in $INSTALL_DIR"
  else
    install_from_release
  fi
}

inject_path() {
  local rc_file=""
  case "${SHELL:-}" in
    */zsh)  rc_file="$HOME/.zshrc" ;;
    */bash) rc_file="$HOME/.bashrc" ;;
    *)
      if [ -f "$HOME/.zshrc" ]; then
        rc_file="$HOME/.zshrc"
      elif [ -f "$HOME/.bashrc" ]; then
        rc_file="$HOME/.bashrc"
      fi
      ;;
  esac

  if [ -z "$rc_file" ]; then
    warn "Could not detect shell RC file. Add this to your shell profile manually:"
    warn "  export PATH=\"$INSTALL_DIR:\$PATH\" $MARKER"
    return
  fi

  if grep -qF "$MARKER" "$rc_file" 2>/dev/null; then
    info "PATH already configured in $rc_file"
  else
    printf '\nexport PATH="%s:$PATH" %s\n' "$INSTALL_DIR" "$MARKER" >> "$rc_file"
    info "Added PATH entry to $rc_file"
  fi

  # Refresh current session
  export PATH="$INSTALL_DIR:$PATH"
}

register_mcp() {
  if ! command -v claude &>/dev/null; then
    warn "Claude Code CLI not found. Register MCP manually:"
    warn "  claude mcp add --transport stdio --scope user cssh -- $INSTALL_DIR/cssh-mcp"
    return
  fi

  info "Registering cssh as MCP server..."
  claude mcp add --transport stdio --scope user cssh -- "$INSTALL_DIR/cssh-mcp" || true

  if claude mcp list 2>/dev/null | grep -q cssh; then
    info "MCP registration verified"
  else
    warn "MCP registration may need manual verification: claude mcp list"
  fi
}

SETTINGS_FILE="$HOME/.claude/settings.json"
CSSH_TOOLS=(
  "mcp__cssh__ssh_connect"
  "mcp__cssh__ssh_open_session"
  "mcp__cssh__ssh_exec"
  "mcp__cssh__ssh_connection_status"
  "mcp__cssh__ssh_privilege"
  "mcp__cssh__ssh_read_file"
  "mcp__cssh__ssh_disconnect"
  "mcp__cssh__ssh_profile"
  "mcp__cssh__ssh_cnote"
  "mcp__cssh__ssh_profile_setup"
  "mcp__cssh__ssh_credentials_prompt"
)

inject_permissions() {
  if ! command -v jq &>/dev/null; then
    warn "jq not found — skipping permission setup"
    warn "You can manually allow cssh tools in ~/.claude/settings.json"
    return
  fi
  mkdir -p "$(dirname "$SETTINGS_FILE")"
  [ -f "$SETTINGS_FILE" ] || echo '{}' > "$SETTINGS_FILE"
  if ! jq empty "$SETTINGS_FILE" 2>/dev/null; then
    warn "$SETTINGS_FILE is not valid JSON — skipping permission injection"
    return
  fi
  local tools_json
  tools_json=$(printf '%s\n' "${CSSH_TOOLS[@]}" | jq -R . | jq -s .)
  local tmp; tmp="$(mktemp)"
  jq --argjson t "$tools_json" '
    .permissions //= {} |
    .permissions.allow //= [] |
    .permissions.allow = (.permissions.allow + ($t - .permissions.allow))
  ' "$SETTINGS_FILE" > "$tmp" && mv "$tmp" "$SETTINGS_FILE"
  info "Auto-approved ${#CSSH_TOOLS[@]} cssh tools in Claude Code settings"
}

verify() {
  if "$INSTALL_DIR/csshctl" --help &>/dev/null; then
    info "csshctl is working"
  else
    warn "csshctl verification failed — check $INSTALL_DIR/csshctl"
  fi
}

main() {
  info "Installing cssh..."
  local mode
  mode="$(detect_mode)"

  if [ "$mode" = "dev" ]; then
    info "Developer mode (building from local source)"
    build_local
  else
    info "User mode"
    install_user_mode
  fi

  inject_path
  register_mcp
  inject_permissions
  verify

  echo ""
  info "Installation complete!"
  info "Binaries: $INSTALL_DIR/cssh-mcp, $INSTALL_DIR/csshctl"
  info "Open Claude Code and say: \"Help me connect to my SSH server\""
}

main "$@"
