package sshbridge

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"cssh/internal/model"
)

// ShellRaw is the sentinel value stored in Profile.Shell / Connection.Shell
// when shell detection determined that no wrapper is needed — commands are
// sent directly to the remote login shell via SSH.
const ShellRaw = "__raw__"

// ValidShellValues lists all accepted values for Profile.Shell (manual edit).
var ValidShellValues = map[string]bool{
	"":         true, // undetected / cleared
	"auto":     true, // triggers re-detection on next connect
	"bash -lc": true,
	"sh -c":    true,
	ShellRaw:   true,
}

// shellCandidate describes one probe attempt.
type shellCandidate struct {
	// remoteCmd is the exact string sent as the SSH command argument.
	remoteCmd string
	// result is the value persisted to Profile.Shell on success.
	result string
}

// probeShell detects the best available shell on the remote host by trying
// candidates in priority order through the already-established ControlMaster.
// It returns the shell prefix string to store (e.g. "bash -lc", "sh -c", or
// ShellRaw). Returns an error only when ALL probes fail, meaning even the
// raw echo probe could not execute.
func (m *Manager) probeShell(conn *model.Connection) (string, error) {
	candidates := []shellCandidate{
		{remoteCmd: "bash -lc 'echo __cssh_ok'", result: "bash -lc"},
		{remoteCmd: "sh -c 'echo __cssh_ok'", result: "sh -c"},
		// Raw probe uses the same compound command pattern (cd + &&) that
		// ExecWithProgressCtx produces, so we verify the login shell can
		// handle it — not just a bare echo.
		{remoteCmd: "cd / && echo __cssh_ok", result: ShellRaw},
	}

	target := fmt.Sprintf("%s@%s", conn.Username, conn.Host)

	for _, c := range candidates {
		if ok := m.runShellProbe(conn.ControlPath, conn.Port, target, c.remoteCmd); ok {
			return c.result, nil
		}
	}
	return "", errors.New("shell detection failed: none of bash, sh, or raw echo succeeded on remote host")
}

// runShellProbe sends a single probe command through the SSH control socket.
func (m *Manager) runShellProbe(controlPath string, port int, target, remoteCmd string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var stdout bytes.Buffer
	cmd := exec.CommandContext(ctx, "ssh",
		"-S", controlPath,
		"-o", "ControlMaster=no",
		"-p", strconv.Itoa(port),
		target, remoteCmd,
	)
	cmd.Stdout = &stdout
	err := cmd.Run()
	return err == nil && strings.Contains(stdout.String(), "__cssh_ok")
}

// NeedsShellProbe returns true when the shell value indicates that automatic
// detection should run (empty string or "auto").
func NeedsShellProbe(shell string) bool {
	s := strings.TrimSpace(shell)
	return s == "" || strings.EqualFold(s, "auto")
}

// ResolveShellForExec converts the stored shell value into the actual prefix
// used for command wrapping. ShellRaw maps to "" (no wrapper); everything else
// passes through unchanged.
func ResolveShellForExec(shell string) string {
	if shell == ShellRaw {
		return ""
	}
	return shell
}

// DisplayShell returns a human-friendly representation of the shell value.
// ShellRaw → "(raw / no wrapper)", empty → "(not detected)".
func DisplayShell(shell string) string {
	switch shell {
	case ShellRaw:
		return "(raw / no wrapper)"
	case "":
		return "(not detected)"
	default:
		return shell
	}
}
