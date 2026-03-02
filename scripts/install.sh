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

install_from_release() {
  detect_platform
  local url="https://github.com/$REPO/releases/latest/download/cssh-${OS}-${ARCH}.tar.gz"
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  info "Downloading cssh for ${OS}/${ARCH}..."
  if command -v curl &>/dev/null; then
    curl -fsSL "$url" -o "$tmp/cssh.tar.gz"
  elif command -v wget &>/dev/null; then
    wget -qO "$tmp/cssh.tar.gz" "$url"
  else
    error "curl or wget is required"
  fi

  mkdir -p "$INSTALL_DIR"
  tar xzf "$tmp/cssh.tar.gz" -C "$tmp"
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
  verify

  echo ""
  info "Installation complete!"
  info "Binaries: $INSTALL_DIR/cssh-mcp, $INSTALL_DIR/csshctl"
  info "Open Claude Code and say: \"Help me connect to my SSH server\""
}

main "$@"
