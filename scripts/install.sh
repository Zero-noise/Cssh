#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="$HOME/.csbridge/bin"
REPO="Zero-noise/Cssh"
MARKER="# cssh-path-inject"

info()  { printf '\033[1;34m[cssh]\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[cssh]\033[0m %s\n' "$*"; }
error() { printf '\033[1;31m[cssh]\033[0m %b\n' "$*" >&2; exit 1; }

set_cleanup_trap() {
  local target="$1"
  local cleanup_cmd
  printf -v cleanup_cmd 'rm -rf -- %q' "$target"
  trap "$cleanup_cmd" EXIT
}

clear_cleanup_trap() {
  trap - EXIT
}

cleanup_path() {
  local target="$1"
  rm -rf -- "$target"
  clear_cleanup_trap
}

release_error() {
  error "$1\nManual fallback:\n  Download the matching archive from https://github.com/$REPO/releases/latest\n  or clone the repo and run ./scripts/install.sh from the checkout."
}

first_existing_file() {
  local candidate
  for candidate in "$@"; do
    if [ -f "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

detect_rc_file() {
  local rc_file
  case "${SHELL:-}" in
    */zsh)
      printf '%s\n' "$HOME/.zshrc"
      ;;
    */bash)
      if [ "$(uname -s)" = "Darwin" ]; then
        # macOS: terminals open login shells → prioritize login rc files
        if rc_file="$(first_existing_file \
          "$HOME/.bash_profile" \
          "$HOME/.bash_login" \
          "$HOME/.profile" \
          "$HOME/.bashrc")"; then
          printf '%s\n' "$rc_file"
        else
          printf '%s\n' "$HOME/.bash_profile"
        fi
      else
        # Linux: terminals open non-login shells → prioritize .bashrc
        if rc_file="$(first_existing_file \
          "$HOME/.bashrc" \
          "$HOME/.bash_profile" \
          "$HOME/.bash_login" \
          "$HOME/.profile")"; then
          printf '%s\n' "$rc_file"
        else
          printf '%s\n' "$HOME/.bashrc"
        fi
      fi
      ;;
    *)
      if rc_file="$(first_existing_file \
        "$HOME/.zshrc" \
        "$HOME/.bash_profile" \
        "$HOME/.bash_login" \
        "$HOME/.profile" \
        "$HOME/.bashrc")"; then
        printf '%s\n' "$rc_file"
      else
        printf '%s\n' "$HOME/.profile"
      fi
      ;;
  esac
}

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
  set_cleanup_trap "$tmp"

  info "Downloading cssh for ${OS}/${ARCH}..."
  if command -v curl &>/dev/null; then
    if ! curl -fsSL "$base_url/$archive" -o "$tmp/$archive"; then
      release_error "Failed to download $archive from GitHub Releases"
    fi
    if ! curl -fsSL "$base_url/checksums.txt" -o "$tmp/checksums.txt"; then
      release_error "Failed to download checksums.txt from GitHub Releases"
    fi
  elif command -v wget &>/dev/null; then
    if ! wget -qO "$tmp/$archive" "$base_url/$archive"; then
      release_error "Failed to download $archive from GitHub Releases"
    fi
    if ! wget -qO "$tmp/checksums.txt" "$base_url/checksums.txt"; then
      release_error "Failed to download checksums.txt from GitHub Releases"
    fi
  else
    release_error "curl or wget is required to download release binaries"
  fi

  info "Verifying checksum..."
  local expected
  expected="$(awk -v name="$archive" '$2 == name { print $1 }' "$tmp/checksums.txt")"
  if [ -z "$expected" ]; then
    release_error "No checksum found for $archive in checksums.txt"
  fi
  sha256_verify "$tmp/$archive" "$expected"
  info "Checksum OK"

  mkdir -p "$INSTALL_DIR"
  if ! tar xzf "$tmp/$archive" -C "$tmp"; then
    release_error "Failed to extract $archive"
  fi
  cp "$tmp"/cssh-mcp-* "$INSTALL_DIR/cssh-mcp"
  cp "$tmp"/csshctl-* "$INSTALL_DIR/csshctl"
  chmod +x "$INSTALL_DIR/cssh-mcp" "$INSTALL_DIR/csshctl"
  cleanup_path "$tmp"
  info "Installed binaries to $INSTALL_DIR"
}

install_user_mode() {
  install_from_release
}

inject_path() {
  local rc_file
  rc_file="$(detect_rc_file)"

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
  "mcp__cssh__ssh_write_file"
  "mcp__cssh__ssh_apply_patch"
  "mcp__cssh__ssh_transfer"
  "mcp__cssh__ssh_disconnect"
  "mcp__cssh__ssh_profile"
  "mcp__cssh__ssh_cnote"
  "mcp__cssh__ssh_profile_setup"
  "mcp__cssh__ssh_credentials_prompt"
  "mcp__cssh__ssh_key_setup"
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
  if ! jq -e '
    if .permissions? == null then true
    elif (.permissions | type) != "object" then false
    elif .permissions.allow? == null then true
    else (.permissions.allow | type) == "array"
    end
  ' "$SETTINGS_FILE" >/dev/null; then
    warn "$SETTINGS_FILE has unexpected permissions.allow format — skipping permission injection"
    return
  fi
  local tools_json
  tools_json=$(printf '%s\n' "${CSSH_TOOLS[@]}" | jq -R . | jq -s .)
  local tmp
  tmp="$(mktemp)"
  set_cleanup_trap "$tmp"
  if jq --argjson t "$tools_json" '
    .permissions //= {} |
    .permissions.allow //= [] |
    .permissions.allow = (.permissions.allow + ($t - .permissions.allow))
  ' "$SETTINGS_FILE" > "$tmp"; then
    mv "$tmp" "$SETTINGS_FILE"
    clear_cleanup_trap
    info "Auto-approved ${#CSSH_TOOLS[@]} cssh tools in Claude Code settings"
  else
    cleanup_path "$tmp"
    warn "Failed to update $SETTINGS_FILE — skipping permission injection"
  fi
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
    info "User mode (installing latest release binary)"
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
