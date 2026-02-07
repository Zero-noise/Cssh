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

type Manager struct {
	runtimeDir      string
	defaultShell    string
	defaultTimeoutS int

	mu          sync.RWMutex
	connections map[string]*model.Connection
	sessions    map[string]*model.Session
}

func NewManager(runtimeDir, defaultShell string, defaultTimeout int) *Manager {
	return &Manager{
		runtimeDir:      runtimeDir,
		defaultShell:    defaultShell,
		defaultTimeoutS: defaultTimeout,
		connections:     map[string]*model.Connection{},
		sessions:        map[string]*model.Session{},
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
		"-o", "ControlPersist=600",
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "ServerAliveInterval=30",
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

	cleanupAskPass := func() {}
	if method == "password" || (method == "key" && conn.KeyPassphrase != "") {
		secret := conn.Password
		if method == "key" {
			secret = conn.KeyPassphrase
		}
		if secret == "" {
			return errors.New("ssh askpass secret is empty")
		}
		scriptPath := filepath.Join(m.runtimeDir, "askpass-"+conn.ID+".sh")
		body := "#!/bin/sh\nprintf '%s\\n' " + util.ShellQuote(secret) + "\n"
		if err := os.WriteFile(scriptPath, []byte(body), 0o700); err != nil {
			return err
		}
		cleanupAskPass = func() { _ = os.Remove(scriptPath) }
		cmd.Env = append(os.Environ(),
			"SSH_ASKPASS="+scriptPath,
			"SSH_ASKPASS_REQUIRE=force",
			"DISPLAY=cssh:0",
		)
	}
	defer cleanupAskPass()

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("open ssh control socket failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	verify := exec.Command("ssh",
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

func (m *Manager) closeMaster(conn model.Connection) error {
	target := fmt.Sprintf("%s@%s", conn.Username, conn.Host)
	cmd := exec.Command("ssh",
		"-S", conn.ControlPath,
		"-p", strconv.Itoa(conn.Port),
		"-O", "exit",
		target,
	)
	_ = cmd.Run()
	_ = os.Remove(conn.ControlPath)
	return nil
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

func (m *Manager) Exec(connectionID, sessionID, command, cwd string, timeoutSec int) (ExecResult, error) {
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
		shell = s.Shell
		if cwd == "" {
			cwd = s.CWD
		}
	}
	if timeoutSec <= 0 {
		timeoutSec = m.defaultTimeoutS
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

func (m *Manager) UploadFile(connectionID, localPath, remotePath string, timeoutSec int) (int64, error) {
	if strings.TrimSpace(localPath) == "" || strings.TrimSpace(remotePath) == "" {
		return 0, errorsx.New(errorsx.CodeInvalidParams, "local_path and remote_path are required")
	}
	conn, err := m.GetConnection(connectionID)
	if err != nil {
		return 0, err
	}
	target := scpRemoteSpec(conn.Username, conn.Host, remotePath)
	return m.runSCP(conn, timeoutSec, localPath, target)
}

func (m *Manager) DownloadFile(connectionID, remotePath, localPath string, timeoutSec int) (int64, error) {
	if strings.TrimSpace(remotePath) == "" || strings.TrimSpace(localPath) == "" {
		return 0, errorsx.New(errorsx.CodeInvalidParams, "remote_path and local_path are required")
	}
	conn, err := m.GetConnection(connectionID)
	if err != nil {
		return 0, err
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

func (m *Manager) runSCP(conn *model.Connection, timeoutSec int, source, target string) (int64, error) {
	if timeoutSec <= 0 {
		timeoutSec = m.defaultTimeoutS
	}
	totalTimeout := time.Duration(timeoutSec) * time.Second
	start := time.Now()
	firstStderr, firstErr := m.runSCPOnce(conn, totalTimeout, false, source, target)
	if firstErr == nil {
		return time.Since(start).Milliseconds(), nil
	}
	if isExecTimeoutError(firstErr) {
		return time.Since(start).Milliseconds(), firstErr
	}
	if !shouldRetryLegacySCP(firstStderr) {
		return time.Since(start).Milliseconds(), errorsx.New(errorsx.CodeInternal, formatSCPAttemptError(firstStderr, firstErr))
	}
	remaining := totalTimeout - time.Since(start)
	if remaining <= 0 {
		return time.Since(start).Milliseconds(), errorsx.New(errorsx.CodeExecTimeout, "command execution timed out")
	}
	secondStderr, secondErr := m.runSCPOnce(conn, remaining, true, source, target)
	if secondErr == nil {
		return time.Since(start).Milliseconds(), nil
	}
	if isExecTimeoutError(secondErr) {
		return time.Since(start).Milliseconds(), secondErr
	}
	msg := "scp sftp attempt failed: " + formatSCPAttemptError(firstStderr, firstErr) +
		"; scp legacy retry failed: " + formatSCPAttemptError(secondStderr, secondErr)
	return time.Since(start).Milliseconds(), errorsx.New(errorsx.CodeInternal, msg)
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

func (m *Manager) Disconnect(connectionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	conn := m.connections[connectionID]
	if conn == nil {
		return errorsx.New(errorsx.CodeConnectionMissing, "connection_id not found")
	}
	if err := m.closeMaster(*conn); err != nil {
		return err
	}
	delete(m.connections, connectionID)
	for id, s := range m.sessions {
		if s.ConnectionID == connectionID {
			delete(m.sessions, id)
		}
	}
	return nil
}
