#!/bin/bash
# Debug wrapper: log all stdin/stdout to files
exec 2>/tmp/cssh-debug-stderr.log
tee /tmp/cssh-debug-stdin.log | /path/to/cssh/cssh-mcp | tee /tmp/cssh-debug-stdout.log
