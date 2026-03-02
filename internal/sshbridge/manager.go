package sshbridge

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"cssh/internal/errorsx"
	"cssh/internal/model"
	"cssh/internal/util"
)

type ExecResult struct {
	ExitCode   int
	Stdout     string
	Stderr     string
	DurationMS int64
}

type TransferResult struct {
	DurationMS     int64
	Protocol       string
	FallbackUsed   bool
	FallbackReason string
}

const (
	transferProtocolSFTP      = "sftp"
	transferProtocolSCPLegacy = "scp_legacy"
)

type Manager struct {
	runtimeDir      string
	defaultShell    string
	defaultTimeoutS int

	mu          sync.RWMutex
	connections map[string]*model.Connection
	sessions    map[string]*model.Session
}

func NewManager(runtimeDir, defaultShell string, defaultTimeout int) *Manager {
	cleanupLegacyAskPassScripts(runtimeDir)
	cleanupOrphanedMasters(runtimeDir)
	return &Manager{
		runtimeDir:      runtimeDir,
		defaultShell:    defaultShell,
		defaultTimeoutS: defaultTimeout,
		connections:     map[string]*model.Connection{},
		sessions:        map[string]*model.Session{},
	}
}

// cleanupLegacyAskPassScripts removes leftover askpass-*.sh files from older
// versions that embedded plaintext passwords. These may linger on disk if the
// process was killed before the defer cleanup ran.
func cleanupLegacyAskPassScripts(runtimeDir string) {
	matches, err := filepath.Glob(filepath.Join(runtimeDir, "askpass-*.sh"))
	if err != nil {
		return
	}
	for _, f := range matches {
		_ = os.Remove(f)
	}
}

// cleanupOrphanedMasters terminates SSH master processes left behind by a
// previous crash. It finds ctrl-*.sock files in the runtime directory and
// sends "exit" via the control socket. This prevents resource leaks when
// ControlPersist keeps masters alive after the managing process is gone.
func cleanupOrphanedMasters(runtimeDir string) {
	matches, err := filepath.Glob(filepath.Join(runtimeDir, "ctrl-*.sock"))
	if err != nil {
		return
	}
	for _, sock := range matches {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cmd := exec.CommandContext(ctx, "ssh", "-S", sock, "-O", "exit", "dummy")
		_ = cmd.Run()
		cancel()
		_ = os.Remove(sock)
	}
}

func (m *Manager) Connect(input model.Connection) (*model.Connection, error) {
	if input.Host == "" || input.Username == "" {
		return nil, errorsx.New(errorsx.CodeInvalidParams, "host and username are required")
	}
	if input.Port == 0 {
		input.Port = 22
	}
	if len(input.AuthPriority) == 0 {
		input.AuthPriority = []string{"key", "password"}
	}
	if len(input.WorkspaceRoots) == 0 {
		input.WorkspaceRoots = []string{"/"}
	}

	conn := input
	conn.ID = util.NewID("conn")
	conn.CreatedAt = time.Now().UTC()
	conn.ControlPath = filepath.Join(m.runtimeDir, "ctrl-"+conn.ID+".sock")

	var lastErr error
	for _, method := range conn.AuthPriority {
		if method != "key" && method != "password" {
			continue
		}
		if err := m.startMaster(conn, method); err != nil {
			lastErr = err
			continue
		}
		m.mu.Lock()
		m.connections[conn.ID] = &conn
		m.mu.Unlock()
		return &conn, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no usable auth method")
	}
	return nil, errorsx.New(errorsx.CodeAuthFailed, lastErr.Error())
}

func (m *Manager) startMaster(conn model.Connection, method string) error {
	if err := os.MkdirAll(m.runtimeDir, 0o700); err != nil {
		return err
	}
	target := fmt.Sprintf("%s@%s", conn.Username, conn.Host)
	args := []string{
		"-MNf",
		"-o", "ControlMaster=yes",
		"-o", "ControlPersist=3600",
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "ServerAliveInterval=15",
		"-o", "ServerAliveCountMax=4",
		"-o", "TCPKeepAlive=yes",
		"-o", "ConnectTimeout=15",
		"-S", conn.ControlPath,
		"-p", strconv.Itoa(conn.Port),
	}
	if method == "key" {
		if conn.KeyPath != "" {
			args = append(args, "-i", conn.KeyPath)
		}
		args = append(args, "-o", "PreferredAuthentications=publickey")
	}
	if method == "password" {
		args = append(args, "-o", "PubkeyAuthentication=no")
		args = append(args, "-o", "PreferredAuthentications=password")
		args = append(args, "-o", "NumberOfPasswordPrompts=1")
	}
	args = append(args, target)
	cmd := exec.Command("ssh", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if method == "password" || (method == "key" && conn.KeyPassphrase != "") {
		secret := conn.Password
		if method == "key" {
			secret = conn.KeyPassphrase
		}
		if secret == "" {
			return errors.New("ssh askpass secret is empty")
		}
		scriptPath, err := m.ensureAskPassScript()
		if err != nil {
			return err
		}
		cmd.Env = append(os.Environ(),
			"CSSH_SECRET="+secret,
			"SSH_ASKPASS="+scriptPath,
			"SSH_ASKPASS_REQUIRE=force",
			"DISPLAY=cssh:0",
		)
	}

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("open ssh control socket failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	vCtx, vCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer vCancel()
	verify := exec.CommandContext(vCtx, "ssh",
		"-S", conn.ControlPath,
		"-p", strconv.Itoa(conn.Port),
		target,
		"true",
	)
	var vStderr bytes.Buffer
	verify.Stderr = &vStderr
	if err := verify.Run(); err != nil {
		_ = m.closeMaster(conn)
		return fmt.Errorf("verify ssh connection failed: %w: %s", err, strings.TrimSpace(vStderr.String()))
	}
	return nil
}

const askPassBody = "#!/bin/sh\nprintf '%s\\n' \"$CSSH_SECRET\"\n"

// ensureAskPassScript creates a static askpass script (containing no secrets)
// in the runtime directory. The script reads the password from the CSSH_SECRET
// environment variable, which is set per-connection and never touches disk.
// On reuse it validates the file is a regular file with correct permissions
// and expected content, rewriting it if anything looks wrong.
func (m *Manager) ensureAskPassScript() (string, error) {
	scriptPath := filepath.Join(m.runtimeDir, "askpass.sh")
	if m.isValidAskPassScript(scriptPath) {
		return scriptPath, nil
	}
	// Remove first so WriteFile creates with the exact permissions we want,
	// rather than inheriting the mode of an existing corrupted/tampered file.
	_ = os.Remove(scriptPath)
	if err := os.WriteFile(scriptPath, []byte(askPassBody), 0o700); err != nil {
		return "", err
	}
	return scriptPath, nil
}

func (m *Manager) isValidAskPassScript(path string) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	if !info.Mode().IsRegular() {
		return false
	}
	if info.Mode().Perm() != 0o700 {
		return false
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return string(content) == askPassBody
}

func (m *Manager) closeMaster(conn model.Connection) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	target := fmt.Sprintf("%s@%s", conn.Username, conn.Host)
	cmd := exec.CommandContext(ctx, "ssh",
		"-S", conn.ControlPath,
		"-p", strconv.Itoa(conn.Port),
		"-O", "exit",
		target,
	)
	err := cmd.Run()
	// Always try to remove the socket file regardless of ssh exit result.
	_ = os.Remove(conn.ControlPath)
	return err
}

func (m *Manager) GetConnection(id string) (*model.Connection, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	conn := m.connections[id]
	if conn == nil {
		return nil, errorsx.New(errorsx.CodeConnectionMissing, "connection_id not found")
	}
	cp := *conn
	return &cp, nil
}

func (m *Manager) ListConnections() []model.Connection {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]model.Connection, 0, len(m.connections))
	for _, conn := range m.connections {
		cp := *conn
		out = append(out, cp)
	}
	return out
}

func (m *Manager) OpenSession(connectionID, cwd, shell string) (*model.Session, error) {
	if shell == "" {
		shell = m.defaultShell
	}
	if _, err := m.GetConnection(connectionID); err != nil {
		return nil, err
	}
	s := &model.Session{
		ID:           util.NewID("sess"),
		ConnectionID: connectionID,
		CWD:          cwd,
		Shell:        shell,
		CreatedAt:    time.Now().UTC(),
	}
	m.mu.Lock()
	m.sessions[s.ID] = s
	m.mu.Unlock()
	cp := *s
	return &cp, nil
}

func (m *Manager) ListSessionsByConnection(connectionID string) []model.Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]model.Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		if s.ConnectionID != connectionID {
			continue
		}
		cp := *s
		out = append(out, cp)
	}
	return out
}

func (m *Manager) GetSession(id string) (*model.Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := m.sessions[id]
	if s == nil {
		return nil, errorsx.New(errorsx.CodeSessionMissing, "session_id not found")
	}
	cp := *s
	return &cp, nil
}

// PreFlightCheck performs a fast ssh -O check before command execution,
// returning a CONNECTION_DEAD error immediately if the connection is no longer
// alive. The check uses the SSH control socket and completes in <10ms for
// healthy connections, so the overhead is negligible compared to the benefit
// of avoiding a full timeout wait on dead connections.
func (m *Manager) PreFlightCheck(connectionID string) error {
	alive, _, msg, err := m.CheckConnection(connectionID, 3)
	if err != nil {
		return err
	}
	if !alive {
		if strings.TrimSpace(msg) == "" {
			msg = "ssh control connection is not alive"
		}
		return errorsx.New(errorsx.CodeConnectionDead,
			msg+"; please use ssh_disconnect and ssh_connect to re-establish the connection")
	}
	return nil
}

func (m *Manager) Exec(connectionID, sessionID, command, cwd string, timeoutSec int) (ExecResult, error) {
	return m.ExecWithInput(connectionID, sessionID, command, cwd, timeoutSec, "")
}

func (m *Manager) ExecWithInput(connectionID, sessionID, command, cwd string, timeoutSec int, stdin string) (ExecResult, error) {
	if command == "" {
		return ExecResult{}, errorsx.New(errorsx.CodeInvalidParams, "command is required")
	}
	conn, err := m.GetConnection(connectionID)
	if err != nil {
		return ExecResult{}, err
	}
	shell := m.defaultShell
	if sessionID != "" {
		s, err := m.GetSession(sessionID)
		if err != nil {
			return ExecResult{}, err
		}
		if s.ConnectionID != connectionID {
			return ExecResult{}, errorsx.New(errorsx.CodeInvalidParams, "session_id does not belong to connection_id")
		}
		shell = s.Shell
		if cwd == "" {
			cwd = s.CWD
		}
	}
	if timeoutSec <= 0 {
		timeoutSec = m.defaultTimeoutS
	}

	// Fast-fail: verify the SSH control connection is still alive before
	// spending time on the actual command. ssh -O check is <10ms for
	// healthy connections and returns immediately for dead ones.
	if err := m.PreFlightCheck(connectionID); err != nil {
		return ExecResult{}, err
	}

	remoteCmd := command
	if cwd != "" {
		remoteCmd = "cd " + util.ShellQuote(cwd) + " && " + remoteCmd
	}
	if shell != "" {
		remoteCmd = shell + " " + util.ShellQuote(remoteCmd)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	target := fmt.Sprintf("%s@%s", conn.Username, conn.Host)
	args := []string{
		"-S", conn.ControlPath,
		"-p", strconv.Itoa(conn.Port),
		target,
		remoteCmd,
	}
	cmd := exec.CommandContext(ctx, "ssh", args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	start := time.Now()
	err = cmd.Run()
	d := time.Since(start)

	res := ExecResult{
		Stdout:     stdout.String(),
		Stderr:     stderr.String(),
		DurationMS: d.Milliseconds(),
	}
	if ctx.Err() == context.DeadlineExceeded {
		return res, errorsx.New(errorsx.CodeExecTimeout, "command execution timed out")
	}
	if err == nil {
		res.ExitCode = 0
		return res, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		res.ExitCode = exitErr.ExitCode()
		return res, nil
	}
	return res, errorsx.New(errorsx.CodeInternal, err.Error())
}

func (m *Manager) UploadFile(connectionID, localPath, remotePath string, timeoutSec int) (TransferResult, error) {
	if strings.TrimSpace(localPath) == "" || strings.TrimSpace(remotePath) == "" {
		return TransferResult{}, errorsx.New(errorsx.CodeInvalidParams, "local_path and remote_path are required")
	}
	conn, err := m.GetConnection(connectionID)
	if err != nil {
		return TransferResult{}, err
	}
	if err := m.PreFlightCheck(connectionID); err != nil {
		return TransferResult{}, err
	}
	target := scpRemoteSpec(conn.Username, conn.Host, remotePath)
	return m.runSCP(conn, timeoutSec, localPath, target)
}

func (m *Manager) DownloadFile(connectionID, remotePath, localPath string, timeoutSec int) (TransferResult, error) {
	if strings.TrimSpace(remotePath) == "" || strings.TrimSpace(localPath) == "" {
		return TransferResult{}, errorsx.New(errorsx.CodeInvalidParams, "remote_path and local_path are required")
	}
	conn, err := m.GetConnection(connectionID)
	if err != nil {
		return TransferResult{}, err
	}
	if err := m.PreFlightCheck(connectionID); err != nil {
		return TransferResult{}, err
	}
	source := scpRemoteSpec(conn.Username, conn.Host, remotePath)
	return m.runSCP(conn, timeoutSec, source, localPath)
}

func (m *Manager) CheckConnection(connectionID string, timeoutSec int) (bool, bool, string, error) {
	conn, err := m.GetConnection(connectionID)
	if err != nil {
		return false, false, "", err
	}
	if timeoutSec <= 0 {
		timeoutSec = 5
	}
	_, statErr := os.Stat(conn.ControlPath)
	socketExists := statErr == nil

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	target := fmt.Sprintf("%s@%s", conn.Username, conn.Host)
	cmd := exec.CommandContext(ctx, "ssh",
		"-S", conn.ControlPath,
		"-p", strconv.Itoa(conn.Port),
		"-O", "check",
		target,
	)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	msg := strings.TrimSpace(stdout.String())
	if msg == "" {
		msg = strings.TrimSpace(stderr.String())
	}
	if ctx.Err() == context.DeadlineExceeded {
		return false, socketExists, "connection status check timed out", nil
	}
	if err == nil {
		return true, socketExists, msg, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if msg == "" {
			msg = err.Error()
		}
		return false, socketExists, msg, nil
	}
	if msg == "" {
		msg = err.Error()
	}
	return false, socketExists, msg, nil
}

func (m *Manager) runSCP(conn *model.Connection, timeoutSec int, source, target string) (TransferResult, error) {
	if timeoutSec <= 0 {
		timeoutSec = m.defaultTimeoutS
	}
	totalTimeout := time.Duration(timeoutSec) * time.Second
	start := time.Now()
	firstStderr, firstErr := m.runSCPOnce(conn, totalTimeout, false, source, target)
	if firstErr == nil {
		return TransferResult{
			DurationMS: time.Since(start).Milliseconds(),
			Protocol:   transferProtocolSFTP,
		}, nil
	}
	if isExecTimeoutError(firstErr) {
		return TransferResult{
			DurationMS: time.Since(start).Milliseconds(),
			Protocol:   transferProtocolSFTP,
		}, firstErr
	}
	if !shouldRetryLegacySCP(firstStderr) {
		return TransferResult{
			DurationMS: time.Since(start).Milliseconds(),
			Protocol:   transferProtocolSFTP,
		}, errorsx.New(errorsx.CodeInternal, formatSCPAttemptError(firstStderr, firstErr))
	}
	fallbackReason := formatSCPAttemptError(firstStderr, firstErr)
	remaining := totalTimeout - time.Since(start)
	if remaining <= 0 {
		return TransferResult{
			DurationMS:     time.Since(start).Milliseconds(),
			Protocol:       transferProtocolSCPLegacy,
			FallbackUsed:   true,
			FallbackReason: fallbackReason,
		}, errorsx.New(errorsx.CodeExecTimeout, "command execution timed out")
	}
	secondStderr, secondErr := m.runSCPOnce(conn, remaining, true, source, target)
	if secondErr == nil {
		return TransferResult{
			DurationMS:     time.Since(start).Milliseconds(),
			Protocol:       transferProtocolSCPLegacy,
			FallbackUsed:   true,
			FallbackReason: fallbackReason,
		}, nil
	}
	if isExecTimeoutError(secondErr) {
		return TransferResult{
			DurationMS:     time.Since(start).Milliseconds(),
			Protocol:       transferProtocolSCPLegacy,
			FallbackUsed:   true,
			FallbackReason: fallbackReason,
		}, secondErr
	}
	msg := "scp sftp attempt failed: " + formatSCPAttemptError(firstStderr, firstErr) +
		"; scp legacy retry failed: " + formatSCPAttemptError(secondStderr, secondErr)
	return TransferResult{
		DurationMS:     time.Since(start).Milliseconds(),
		Protocol:       transferProtocolSCPLegacy,
		FallbackUsed:   true,
		FallbackReason: fallbackReason,
	}, errorsx.New(errorsx.CodeInternal, msg)
}

func (m *Manager) runSCPOnce(conn *model.Connection, timeout time.Duration, legacy bool, source, target string) (string, error) {
	if timeout <= 0 {
		return "", errorsx.New(errorsx.CodeExecTimeout, "command execution timed out")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	args := []string{
		"-P", strconv.Itoa(conn.Port),
		"-o", "ControlPath=" + conn.ControlPath,
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=10",
	}
	if legacy {
		args = append(args, "-O")
	}
	args = append(args, "--", source, target)

	cmd := exec.CommandContext(ctx, "scp", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return stderr.String(), errorsx.New(errorsx.CodeExecTimeout, "command execution timed out")
	}
	if err == nil {
		return stderr.String(), nil
	}
	return stderr.String(), err
}

func isExecTimeoutError(err error) bool {
	ce, ok := err.(*errorsx.CsshError)
	return ok && ce.Code == errorsx.CodeExecTimeout
}

func formatSCPAttemptError(stderr string, err error) string {
	msg := strings.TrimSpace(stderr)
	if msg != "" {
		return msg
	}
	if err != nil {
		return err.Error()
	}
	return "unknown scp error"
}

func scpRemoteSpec(username, host, remotePath string) string {
	// Do NOT shell-quote the remote path: exec.Command passes argv directly (no shell),
	// and OpenSSH 10+ defaults to SFTP mode where the path is used literally —
	// single quotes would become part of the filename causing "No such file or directory".
	return fmt.Sprintf("%s@%s:%s", username, normalizeSCPHost(host), remotePath)
}

func normalizeSCPHost(host string) string {
	h := strings.TrimSpace(host)
	if strings.Contains(h, ":") && !(strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]")) {
		return "[" + h + "]"
	}
	return h
}

func shouldRetryLegacySCP(stderr string) bool {
	s := strings.ToLower(strings.TrimSpace(stderr))
	if s == "" {
		return false
	}
	if strings.Contains(s, "subsystem request failed") || strings.Contains(s, "unknown subsystem") {
		return true
	}
	if !strings.Contains(s, "sftp") {
		return false
	}
	for _, hint := range []string{
		"failed",
		"failure",
		"unavailable",
		"not found",
		"unknown",
		"disabled",
		"closed",
		"reset",
		"refused",
	} {
		if strings.Contains(s, hint) {
			return true
		}
	}
	return false
}

// Shutdown closes all active SSH master connections. It should be called
// when the process is exiting to prevent orphaned ssh master processes.
func (m *Manager) Shutdown() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, conn := range m.connections {
		if err := m.closeMaster(*conn); err != nil {
			fmt.Fprintf(os.Stderr, "cssh: shutdown: failed to close connection %s (%s@%s): %v\n",
				id, conn.Username, conn.Host, err)
		}
		delete(m.connections, id)
	}
	for id := range m.sessions {
		delete(m.sessions, id)
	}
}

func (m *Manager) Disconnect(connectionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	conn := m.connections[connectionID]
	if conn == nil {
		return errorsx.New(errorsx.CodeConnectionMissing, "connection_id not found")
	}
	closeErr := m.closeMaster(*conn) // best-effort; connection may already be dead
	delete(m.connections, connectionID)
	for id, s := range m.sessions {
		if s.ConnectionID == connectionID {
			delete(m.sessions, id)
		}
	}
	if closeErr != nil {
		fmt.Fprintf(os.Stderr, "cssh: disconnect: closeMaster %s (%s@%s): %v\n",
			connectionID, conn.Username, conn.Host, closeErr)
	}
	return nil
}
