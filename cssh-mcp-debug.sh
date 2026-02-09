#!/bin/bash
# Debug wrapper: log all stdin/stdout to files
exec 2>/tmp/cssh-debug-stderr.log
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
tee /tmp/cssh-debug-stdin.log | "$SCRIPT_DIR/cssh-mcp" | tee /tmp/cssh-debug-stdout.log
