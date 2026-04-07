#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="$HOME/.csbridge/bin"
REPO="Zero-noise/Cssh"
MARKER="# cssh-path-inject"

# ── Output ────────────────────────────────────────────

if [ -t 1 ] && [ "${NO_COLOR:-}" = "" ]; then
  BOLD='\033[1m'
  CYAN='\033[1;36m'
  GREEN='\033[0;32m'
  YELLOW='\033[0;33m'
  RED='\033[0;31m'
  DIM='\033[0;90m'
  RESET='\033[0m'
else
  BOLD='' CYAN='' GREEN='' YELLOW='' RED='' DIM='' RESET=''
fi

header()    { printf '\n  %b◆ cssh%b\n\n' "$CYAN" "$RESET"; }
meta()      { printf '    %-14s %b%s%b\n' "$1" "$DIM" "$2" "$RESET"; }
ok()        { printf '    %b✓%b  %s\n' "$GREEN" "$RESET" "$*"; }
skip()      { printf '    %b·%b  %s\n' "$DIM" "$RESET" "$*"; }
warn_step() { printf '    %b⚠%b  %s\n' "$YELLOW" "$RESET" "$*"; }
tildify()   { printf '%s' "${1/#$HOME/~}"; }

strip_ansi() { sed $'s/\033\\[[0-9;]*m//g'; }

hint() {
  local text="$*"
  while IFS= read -r line; do
    printf '       %b%s%b\n' "$DIM" "$line" "$RESET"
  done <<< "$text"
}

die() {
  local msg="$1"; shift
  printf '    %b✗%b  %s\n' "$RED" "$RESET" "$msg"
  for arg in "$@"; do [ -n "$arg" ] && hint "$arg"; done
  printf '\n'
  exit 1
}

footer() {
  printf '\n  %bReady — open Claude Code and say:%b\n' "$BOLD" "$RESET"
  printf '  "Help me connect to my SSH server"\n\n'
}

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

first_existing_file() {
  local f
  for f in "$@"; do
    if [ -f "$f" ]; then
      printf '%s\n' "$f"
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

# ── Build / Download ─────────────────────────────────

build_local() {
  command -v go &>/dev/null \
    || die "Go toolchain not found" "Install from https://go.dev/dl/"
  mkdir -p "$INSTALL_DIR"
  local err
  err="$(go build -o "$INSTALL_DIR/cssh-mcp" ./cmd/cssh-mcp 2>&1)" \
    || die "Build failed: cssh-mcp" "$err"
  ok "Built cssh-mcp"
  err="$(go build -o "$INSTALL_DIR/csshctl" ./cmd/csshctl 2>&1)" \
    || die "Build failed: csshctl" "$err"
  ok "Built csshctl"
  ok "Installed to $(tildify "$INSTALL_DIR")/"
}

sha256_verify() {
  local file="$1" expected="$2" actual
  if command -v sha256sum &>/dev/null; then
    actual="$(sha256sum "$file" | awk '{print $1}')"
  elif command -v shasum &>/dev/null; then
    actual="$(shasum -a 256 "$file" | awk '{print $1}')"
  else
    die "Checksum tool not found" "sha256sum or shasum is required"
  fi
  [ "$actual" = "$expected" ] || die "Checksum mismatch" \
    "expected  $expected" \
    "got       $actual"
}

install_from_release() {
  local base_url="https://github.com/$REPO/releases/latest/download"
  local archive="cssh-${OS}-${ARCH}.tar.gz"
  local tmp
  tmp="$(mktemp -d)"
  set_cleanup_trap "$tmp"

  local err
  if command -v curl &>/dev/null; then
    err="$(curl -fsSL "$base_url/$archive" -o "$tmp/$archive" 2>&1)" \
      || die "Download failed: $archive" "$err" \
           "https://github.com/$REPO/releases/latest" \
           "Or clone the repo and run ./scripts/install.sh"
    err="$(curl -fsSL "$base_url/checksums.txt" -o "$tmp/checksums.txt" 2>&1)" \
      || die "Download failed: checksums.txt" "$err" \
           "https://github.com/$REPO/releases/latest" \
           "Or clone the repo and run ./scripts/install.sh"
  elif command -v wget &>/dev/null; then
    err="$(wget -qO "$tmp/$archive" "$base_url/$archive" 2>&1)" \
      || die "Download failed: $archive" "$err" \
           "https://github.com/$REPO/releases/latest" \
           "Or clone the repo and run ./scripts/install.sh"
    err="$(wget -qO "$tmp/checksums.txt" "$base_url/checksums.txt" 2>&1)" \
      || die "Download failed: checksums.txt" "$err" \
           "https://github.com/$REPO/releases/latest" \
           "Or clone the repo and run ./scripts/install.sh"
  else
    die "No download tool found" "curl or wget is required"
  fi
  ok "Downloaded $archive"

  local expected
  expected="$(awk -v name="$archive" '$2 == name { print $1 }' "$tmp/checksums.txt")"
  [ -n "$expected" ] || die "No checksum found for $archive"
  sha256_verify "$tmp/$archive" "$expected"
  ok "Checksum verified (sha256)"

  mkdir -p "$INSTALL_DIR"
  err="$(tar xzf "$tmp/$archive" -C "$tmp" 2>&1)" \
    || die "Extraction failed: $archive" "$err"
  cp "$tmp"/cssh-mcp-* "$INSTALL_DIR/cssh-mcp"
  cp "$tmp"/csshctl-* "$INSTALL_DIR/csshctl"
  chmod +x "$INSTALL_DIR/cssh-mcp" "$INSTALL_DIR/csshctl"
  cleanup_path "$tmp"
  ok "Installed to $(tildify "$INSTALL_DIR")/"
}

# ── Post-install ─────────────────────────────────────

inject_path() {
  local rc_file
  rc_file="$(detect_rc_file)"
  if grep -qF "$MARKER" "$rc_file" 2>/dev/null; then
    skip "PATH already in $(tildify "$rc_file")"
  else
    printf '\nexport PATH="%s:$PATH" %s\n' "$INSTALL_DIR" "$MARKER" >> "$rc_file"
    ok "PATH added to $(tildify "$rc_file")"
  fi
  export PATH="$INSTALL_DIR:$PATH"
}

register_mcp() {
  if ! command -v claude &>/dev/null; then
    warn_step "Claude CLI not found — register manually:"
    hint "claude mcp add --transport stdio --scope user cssh -- $INSTALL_DIR/cssh-mcp"
    return
  fi
  local mcp_out
  mcp_out="$(claude mcp add --transport stdio --scope user cssh -- "$INSTALL_DIR/cssh-mcp" 2>&1 | strip_ansi)" || true
  if [ -n "$mcp_out" ]; then
    hint "$mcp_out"
  fi
  if claude mcp list 2>/dev/null | grep -q cssh; then
    ok "MCP server registered"
  else
    warn_step "MCP registration may need verification: claude mcp list"
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
    warn_step "jq not found — approve tools manually in ~/.claude/settings.json"
    return
  fi
  mkdir -p "$(dirname "$SETTINGS_FILE")"
  [ -f "$SETTINGS_FILE" ] || echo '{}' > "$SETTINGS_FILE"
  if ! jq empty "$SETTINGS_FILE" 2>/dev/null; then
    warn_step "settings.json is not valid JSON — skipping permission setup"
    return
  fi
  if ! jq -e '
    if .permissions? == null then true
    elif (.permissions | type) != "object" then false
    elif .permissions.allow? == null then true
    else (.permissions.allow | type) == "array"
    end
  ' "$SETTINGS_FILE" >/dev/null 2>&1; then
    warn_step "Unexpected settings format — skipping permission setup"
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
    ok "${#CSSH_TOOLS[@]} tools auto-approved"
  else
    cleanup_path "$tmp"
    warn_step "Failed to update settings — approve tools manually"
  fi
}

verify() {
  if "$INSTALL_DIR/csshctl" --help &>/dev/null; then
    ok "csshctl verified"
  else
    warn_step "csshctl verification failed — check $INSTALL_DIR/csshctl"
  fi
}

# ── Main ─────────────────────────────────────────────

main() {
  header

  local mode
  mode="$(detect_mode)"

  local plat_os plat_arch
  plat_os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  plat_arch="$(uname -m)"
  case "$plat_arch" in
    x86_64|amd64) plat_arch="amd64" ;;
    arm64|aarch64) plat_arch="arm64" ;;
  esac

  if [ "$mode" = "dev" ]; then
    meta "Platform" "$plat_os · $plat_arch"
    meta "Source" "local build"
    printf '\n'
    build_local
  else
    meta "Platform" "$plat_os · $plat_arch"
    meta "Source" "release binary"
    printf '\n'
    case "$plat_arch" in
      amd64|arm64) ;;
      *) die "Unsupported architecture: $plat_arch" ;;
    esac
    case "$plat_os" in
      darwin|linux) ;;
      *) die "Unsupported OS: $plat_os" ;;
    esac
    OS="$plat_os"
    ARCH="$plat_arch"
    install_from_release
  fi

  inject_path
  register_mcp
  inject_permissions
  verify
  footer
}

main "$@"
