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
	"sync/atomic"
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

type ExecProgress struct {
	Stream string
	Chunk  string
}

type ExecProgressFn func(ExecProgress)

type execStreamWriter struct {
	mu         sync.Mutex
	buf        bytes.Buffer
	stream     string
	onProgress ExecProgressFn
}

type TransferResult struct {
	DurationMS     int64
	Protocol       string
	FallbackUsed   bool
	FallbackReason string
	FileCount      int   // directory transfers: number of files transferred
	TotalBytes     int64 // directory transfers: total size in bytes
}

const (
	transferProtocolSFTP      = "sftp"
	transferProtocolSCPLegacy = "scp_legacy"
	execWaitDelay             = 5 * time.Second
)

// masterHandle holds a reference to a managed SSH master process.
type masterHandle struct {
	cmd         *exec.Cmd
	stderr      bytes.Buffer
	done        chan struct{} // closed when cmd.Wait() returns
	exitErr     error
	intentional atomic.Bool // true = disconnect/shutdown, don't reconnect
}

type reconnectPhase int

const (
	reconnectIdle reconnectPhase = iota
	reconnectInProgress
	reconnectSucceeded
	reconnectFailed
)

type reconnectState struct {
	mu          sync.Mutex // always acquired AFTER m.mu if both needed
	phase       reconnectPhase
	attempts    int
	maxAttempts int
	lastAttempt time.Time
	cooldown    time.Duration
	failReason  string
	succeeded   bool   // consumed once by ReconnectInfo
	reason      string // human-readable death reason
}

type Manager struct {
	runtimeDir      string
	defaultShell    string
	defaultTimeoutS int

	mu          sync.RWMutex
	connections map[string]*model.Connection
	sessions    map[string]*model.Session
	masters     map[string]*masterHandle
	reconState  map[string]*reconnectState
	rsyncAvail  map[string]bool // cached rsync availability per connection
	onReconnect func(connectionID, reason string)
	wg          sync.WaitGroup
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
		masters:         map[string]*masterHandle{},
		reconState:      map[string]*reconnectState{},
	}
}

// SetOnReconnect registers a callback invoked after a successful auto-reconnect.
// Called by the service layer to wire grant revocation and audit logging.
func (m *Manager) SetOnReconnect(fn func(connectionID, reason string)) {
	m.onReconnect = fn
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
// the managing process is gone.
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
		mh, err := m.startMaster(conn, method)
		if err != nil {
			lastErr = err
			continue
		}
		conn.AuthMethod = method
		conn.Generation = 0
		rs := &reconnectState{
			maxAttempts: 1,
			cooldown:    30 * time.Second,
		}
		m.mu.Lock()
		m.connections[conn.ID] = &conn
		m.masters[conn.ID] = mh
		m.reconState[conn.ID] = rs
		m.wg.Add(1) // must be inside lock so Shutdown's wg.Wait() can't race
		m.mu.Unlock()
		go m.watchMaster(conn.ID)
		return &conn, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no usable auth method")
	}
	return nil, errorsx.New(errorsx.CodeAuthFailed, lastErr.Error())
}

func (m *Manager) startMaster(conn model.Connection, method string) (*masterHandle, error) {
	if err := os.MkdirAll(m.runtimeDir, 0o700); err != nil {
		return nil, err
	}
	target := fmt.Sprintf("%s@%s", conn.Username, conn.Host)
	args := []string{
		"-MN",
		"-o", "ControlMaster=yes",
		"-o", "ControlPersist=no",
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
	mh := &masterHandle{
		cmd:  cmd,
		done: make(chan struct{}),
	}
	cmd.Stderr = &mh.stderr

	if method == "password" || (method == "key" && conn.KeyPassphrase != "") {
		secret := conn.Password
		if method == "key" {
			secret = conn.KeyPassphrase
		}
		if secret == "" {
			return nil, errors.New("ssh askpass secret is empty")
		}
		scriptPath, err := m.ensureAskPassScript()
		if err != nil {
			return nil, err
		}
		cmd.Env = append(os.Environ(),
			"CSSH_SECRET="+secret,
			"SSH_ASKPASS="+scriptPath,
			"SSH_ASKPASS_REQUIRE=force",
			"DISPLAY=cssh:0",
		)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("ssh master start failed: %w", err)
	}

	// Goroutine to capture process exit.
	go func() {
		mh.exitErr = cmd.Wait()
		close(mh.done)
	}()

	// Poll for socket file OR early process exit OR timeout.
	deadline := time.After(20 * time.Second)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()

	for {
		select {
		case <-mh.done:
			// Process exited before socket appeared (auth failure, etc.)
			_ = os.Remove(conn.ControlPath) // clean up partial socket if any
			errMsg := strings.TrimSpace(mh.stderr.String())
			if mh.exitErr != nil {
				return nil, fmt.Errorf("open ssh control socket failed: %w: %s", mh.exitErr, errMsg)
			}
			return nil, fmt.Errorf("ssh master exited unexpectedly: %s", errMsg)
		case <-deadline:
			// Timeout — kill the process and clean up.
			_ = cmd.Process.Kill()
			<-mh.done
			_ = os.Remove(conn.ControlPath)
			return nil, fmt.Errorf("ssh master did not create control socket within 20s: %s",
				strings.TrimSpace(mh.stderr.String()))
		case <-tick.C:
			if _, err := os.Stat(conn.ControlPath); err == nil {
				// Socket appeared — verify the connection works.
				vCtx, vCancel := context.WithTimeout(context.Background(), 15*time.Second)
				verify := exec.CommandContext(vCtx, "ssh",
					"-S", conn.ControlPath,
					"-p", strconv.Itoa(conn.Port),
					target,
					"true",
				)
				var vStderr bytes.Buffer
				verify.Stderr = &vStderr
				if err := verify.Run(); err != nil {
					vCancel()
					mh.intentional.Store(true)
					_ = cmd.Process.Kill()
					<-mh.done
					_ = os.Remove(conn.ControlPath)
					return nil, fmt.Errorf("verify ssh connection failed: %w: %s", err, strings.TrimSpace(vStderr.String()))
				}
				vCancel()
				return mh, nil
			}
		}
	}
}

// watchMaster blocks until the master process dies, then triggers auto-reconnect
// if the death was unexpected.
func (m *Manager) watchMaster(connectionID string) {
	defer m.wg.Done()
	m.mu.RLock()
	mh := m.masters[connectionID]
	m.mu.RUnlock()
	if mh == nil {
		return
	}

	<-mh.done // block until master dies
	if mh.intentional.Load() {
		return // disconnect/shutdown, don't reconnect
	}
	reason := "master process exited"
	if mh.exitErr != nil {
		reason = mh.exitErr.Error()
	}
	if errText := strings.TrimSpace(mh.stderr.String()); errText != "" {
		reason += ": " + errText
	}
	fmt.Fprintf(os.Stderr, "cssh: connection %s master died: %s\n", connectionID, reason)
	m.handleMasterDeath(connectionID, reason)
}

// handleMasterDeath attempts a single auto-reconnect after the master dies.
// Lock ordering: always m.mu first, then rs.mu.
func (m *Manager) handleMasterDeath(connectionID, reason string) {
	// Phase 1: check eligibility (brief lock)
	m.mu.RLock()
	rs := m.reconState[connectionID]
	conn := m.connections[connectionID]
	m.mu.RUnlock()
	if conn == nil || rs == nil {
		return
	}

	rs.mu.Lock()
	if rs.attempts >= rs.maxAttempts {
		rs.phase = reconnectFailed
		rs.failReason = "auto-reconnect exhausted; please use ssh_disconnect and ssh_connect to re-establish the connection"
		rs.reason = reason
		rs.mu.Unlock()
		return
	}
	if rs.cooldown > 0 && !rs.lastAttempt.IsZero() && time.Since(rs.lastAttempt) < rs.cooldown {
		rs.phase = reconnectFailed
		rs.failReason = "cooldown period not elapsed"
		rs.reason = reason
		rs.mu.Unlock()
		return
	}
	rs.phase = reconnectInProgress
	rs.attempts++
	rs.lastAttempt = time.Now()
	rs.reason = reason
	rs.mu.Unlock() // RELEASE before startMaster

	// Phase 2: reconnect attempt (no lock held)
	_ = os.Remove(conn.ControlPath) // clean old socket
	connCopy := *conn
	mh, err := m.startMaster(connCopy, connCopy.AuthMethod)

	// Phase 3: write result
	rs.mu.Lock()
	if err != nil {
		rs.phase = reconnectFailed
		rs.failReason = "reconnect failed: " + err.Error() +
			"; please use ssh_disconnect and ssh_connect to re-establish the connection"
		rs.mu.Unlock()
		return
	}

	// Success
	rs.phase = reconnectSucceeded
	rs.succeeded = true
	rs.attempts = 0 // RESET: allow future auto-reconnects
	rs.mu.Unlock()

	m.mu.Lock()
	if m.connections[connectionID] == nil {
		// Disconnected while reconnecting — kill new master
		m.mu.Unlock()
		mh.intentional.Store(true)
		_ = mh.cmd.Process.Kill()
		<-mh.done
		return
	}
	m.masters[connectionID] = mh
	conn.Generation++                  // invalidates pending approval tokens
	delete(m.rsyncAvail, connectionID) // clear cached rsync availability
	m.wg.Add(1)                        // must be inside lock so Shutdown's wg.Wait() can't race
	m.mu.Unlock()

	if m.onReconnect != nil {
		m.onReconnect(connectionID, reason)
	}

	go m.watchMaster(connectionID) // watch the new master
}

// ReconnectInfo returns whether an auto-reconnect succeeded (consume-once).
func (m *Manager) ReconnectInfo(connectionID string) (reconnected bool, reason string) {
	m.mu.RLock()
	rs := m.reconState[connectionID]
	m.mu.RUnlock()
	if rs == nil {
		return false, ""
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.succeeded {
		rs.succeeded = false
		return true, rs.reason
	}
	return false, ""
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

// PreFlightCheck performs a fast check before command execution.
// It first consults reconnect state, then falls back to ssh -O check.
func (m *Manager) PreFlightCheck(connectionID string) error {
	// Check reconnect state first.
	m.mu.RLock()
	rs := m.reconState[connectionID]
	m.mu.RUnlock()

	if rs != nil {
		rs.mu.Lock()
		phase := rs.phase
		failReason := rs.failReason
		rs.mu.Unlock()

		switch phase {
		case reconnectFailed:
			return errorsx.New(errorsx.CodeReconnectFailed, failReason)
		case reconnectInProgress:
			// Poll up to 3s waiting for phase change.
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				time.Sleep(200 * time.Millisecond)
				rs.mu.Lock()
				p := rs.phase
				fr := rs.failReason
				rs.mu.Unlock()
				if p == reconnectFailed {
					return errorsx.New(errorsx.CodeReconnectFailed, fr)
				}
				if p == reconnectSucceeded || p == reconnectIdle {
					break
				}
			}
		}
	}

	// Proceed to existing ssh -O check.
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
	return m.ExecWithInputCtx(context.Background(), connectionID, sessionID, command, cwd, timeoutSec, stdin)
}

func (m *Manager) ExecWithInputCtx(parent context.Context, connectionID, sessionID, command, cwd string, timeoutSec int, stdin string) (ExecResult, error) {
	return m.ExecWithProgressCtx(parent, connectionID, sessionID, command, cwd, timeoutSec, stdin, nil)
}

func (m *Manager) ExecWithProgressCtx(parent context.Context, connectionID, sessionID, command, cwd string, timeoutSec int, stdin string, onProgress ExecProgressFn) (ExecResult, error) {
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

	ctx, cancel := context.WithTimeout(parent, time.Duration(timeoutSec)*time.Second)
	defer cancel()

	target := fmt.Sprintf("%s@%s", conn.Username, conn.Host)

	// Parallel connection probe: run "true" over the multiplexed connection
	// with a short timeout. On a healthy connection this completes in <200ms
	// (just a network round-trip) and adds zero blocking latency because it
	// runs concurrently with the real command. If the network path is broken
	// the probe fails in ≤5s and cancels the main command immediately,
	// avoiding the full timeout wait.
	var probeDead atomic.Bool
	probeCtx, probeCancel := context.WithTimeout(parent, 5*time.Second)
	defer probeCancel()
	go func() {
		probeCmd := exec.CommandContext(probeCtx, "ssh",
			"-S", conn.ControlPath,
			"-p", strconv.Itoa(conn.Port),
			target, "true",
		)
		if err := probeCmd.Run(); err != nil {
			if probeCtx.Err() == context.Canceled {
				return // probe cancelled because main command finished; ignore
			}
			probeDead.Store(true)
			cancel() // cancel the main command immediately
		}
	}()

	args := []string{
		"-S", conn.ControlPath,
		"-p", strconv.Itoa(conn.Port),
		target,
		remoteCmd,
	}
	cmd := exec.CommandContext(ctx, "ssh", args...)
	stdoutWriter := &execStreamWriter{stream: "stdout", onProgress: onProgress}
	stderrWriter := &execStreamWriter{stream: "stderr", onProgress: onProgress}
	cmd.Stdout = stdoutWriter
	cmd.Stderr = stderrWriter
	cmd.WaitDelay = execWaitDelay
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	start := time.Now()
	err = cmd.Run()
	d := time.Since(start)

	res := ExecResult{
		Stdout:     stdoutWriter.String(),
		Stderr:     stderrWriter.String(),
		DurationMS: d.Milliseconds(),
	}
	if ctx.Err() != nil {
		// Parent context cancelled (MCP request cancellation) — return fast
		if parent.Err() != nil && !probeDead.Load() {
			return res, errorsx.New(errorsx.CodeCancelled, "request cancelled")
		}
		if probeDead.Load() {
			return res, errorsx.New(errorsx.CodeConnectionDead,
				"connection probe failed; please use ssh_disconnect and ssh_connect to re-establish the connection")
		}
		// Probe didn't fire, but command timed out. Double-check connection.
		alive, _, _, _ := m.CheckConnection(connectionID, 3)
		if !alive {
			return res, errorsx.New(errorsx.CodeConnectionDead,
				"command timed out and connection is no longer alive; please use ssh_disconnect and ssh_connect to re-establish the connection")
		}
		return res, errorsx.New(errorsx.CodeExecTimeout, "command execution timed out")
	}
	if err == nil {
		res.ExitCode = 0
		return res, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		res.ExitCode = exitErr.ExitCode()
		// SSH returns 255 for its own errors (connection lost, auth failure, etc.)
		if exitErr.ExitCode() == 255 {
			alive, _, _, _ := m.CheckConnection(connectionID, 3)
			if !alive {
				return res, errorsx.New(errorsx.CodeConnectionDead,
					"ssh exited with code 255 and connection is dead; please use ssh_disconnect and ssh_connect to re-establish the connection")
			}
		}
		return res, nil
	}
	if errors.Is(err, exec.ErrWaitDelay) {
		return res, errorsx.New(errorsx.CodeExecTimeout, "command execution finished but output pipes did not close before wait delay elapsed")
	}
	return res, errorsx.New(errorsx.CodeInternal, err.Error())
}

func (w *execStreamWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	w.mu.Lock()
	_, _ = w.buf.Write(p)
	w.mu.Unlock()
	if w.onProgress != nil {
		w.onProgress(ExecProgress{
			Stream: w.stream,
			Chunk:  string(p),
		})
	}
	return len(p), nil
}

func (w *execStreamWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

func (m *Manager) UploadFile(connectionID, localPath, remotePath string, timeoutSec int, recursive bool, onProgress ExecProgressFn) (TransferResult, error) {
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
	return m.runSCP(conn, connectionID, timeoutSec, recursive, onProgress, localPath, target)
}

func (m *Manager) DownloadFile(connectionID, remotePath, localPath string, timeoutSec int, recursive bool, onProgress ExecProgressFn) (TransferResult, error) {
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
	return m.runSCP(conn, connectionID, timeoutSec, recursive, onProgress, source, localPath)
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

func (m *Manager) runSCP(conn *model.Connection, connectionID string, timeoutSec int, recursive bool, onProgress ExecProgressFn, source, target string) (TransferResult, error) {
	if timeoutSec <= 0 {
		timeoutSec = m.defaultTimeoutS
	}
	totalTimeout := time.Duration(timeoutSec) * time.Second
	start := time.Now()
	firstStderr, firstErr := m.runSCPOnce(conn, totalTimeout, false, recursive, onProgress, source, target)
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
		}, m.timeoutOrDeadError(connectionID)
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
		}, m.timeoutOrDeadError(connectionID)
	}
	secondStderr, secondErr := m.runSCPOnce(conn, remaining, true, recursive, onProgress, source, target)
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
		}, m.timeoutOrDeadError(connectionID)
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

func (m *Manager) runSCPOnce(conn *model.Connection, timeout time.Duration, legacy, recursive bool, onProgress ExecProgressFn, source, target string) (string, error) {
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
	if recursive {
		args = append(args, "-r")
	}
	args = append(args, "--", source, target)

	cmd := exec.CommandContext(ctx, "scp", args...)
	sw := &execStreamWriter{stream: "stderr", onProgress: onProgress}
	cmd.Stderr = sw
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return sw.String(), errorsx.New(errorsx.CodeExecTimeout, "command execution timed out")
	}
	if err == nil {
		return sw.String(), nil
	}
	return sw.String(), err
}

// HasRsync checks whether rsync is available on the remote host.
// The result is cached per connection (cleared on reconnect).
func (m *Manager) HasRsync(connectionID string) bool {
	m.mu.RLock()
	if avail, ok := m.rsyncAvail[connectionID]; ok {
		m.mu.RUnlock()
		return avail
	}
	m.mu.RUnlock()
	res, err := m.Exec(connectionID, "", "command -v rsync", "", 5)
	avail := err == nil && res.ExitCode == 0
	m.mu.Lock()
	if m.rsyncAvail == nil {
		m.rsyncAvail = map[string]bool{}
	}
	m.rsyncAvail[connectionID] = avail
	m.mu.Unlock()
	return avail
}

// RunRsync performs a file transfer using rsync --partial for resume support.
func (m *Manager) RunRsync(connectionID string, timeoutSec int, source, target string, isUpload bool, onProgress ExecProgressFn) (TransferResult, error) {
	conn, err := m.GetConnection(connectionID)
	if err != nil {
		return TransferResult{}, err
	}
	if err := m.PreFlightCheck(connectionID); err != nil {
		return TransferResult{}, err
	}
	if timeoutSec <= 0 {
		timeoutSec = m.defaultTimeoutS
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	rshFlag := fmt.Sprintf("ssh -o ControlPath=%s -o BatchMode=yes -p %d",
		conn.ControlPath, conn.Port)
	remote := fmt.Sprintf("%s@%s", conn.Username, normalizeSCPHost(conn.Host))

	var rsyncSource, rsyncTarget string
	if isUpload {
		rsyncSource = source
		rsyncTarget = remote + ":" + target
	} else {
		rsyncSource = remote + ":" + source
		rsyncTarget = target
	}

	args := buildRsyncArgs(rshFlag, rsyncSource, rsyncTarget)
	start := time.Now()
	cmd := exec.CommandContext(ctx, "rsync", args...)
	sw := &execStreamWriter{stream: "stderr", onProgress: onProgress}
	cmd.Stderr = sw
	err = cmd.Run()
	d := time.Since(start)

	if ctx.Err() == context.DeadlineExceeded {
		return TransferResult{
			DurationMS: d.Milliseconds(),
			Protocol:   "rsync",
		}, m.timeoutOrDeadError(connectionID)
	}
	if err != nil {
		return TransferResult{
			DurationMS: d.Milliseconds(),
			Protocol:   "rsync",
		}, errorsx.New(errorsx.CodeInternal, "rsync failed: "+formatSCPAttemptError(sw.String(), err))
	}

	return TransferResult{
		DurationMS: d.Milliseconds(),
		Protocol:   "rsync",
	}, nil
}

func buildRsyncArgs(rshFlag, source, target string) []string {
	return []string{"--partial", "-e", rshFlag, "--", source, target}
}

// timeoutOrDeadError is called after a transfer times out. It performs a fast
// ssh -O check to determine whether the timeout was caused by a dead
// connection, returning CONNECTION_DEAD instead of EXEC_TIMEOUT when
// appropriate so the AI can reconnect immediately.
func (m *Manager) timeoutOrDeadError(connectionID string) error {
	alive, _, _, _ := m.CheckConnection(connectionID, 3)
	if !alive {
		return errorsx.New(errorsx.CodeConnectionDead,
			"transfer timed out and connection is no longer alive; please use ssh_disconnect and ssh_connect to re-establish the connection")
	}
	return errorsx.New(errorsx.CodeExecTimeout, "command execution timed out")
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
	for id, mh := range m.masters {
		mh.intentional.Store(true)
		conn := m.connections[id]
		if conn != nil {
			_ = m.closeMaster(*conn)
		}
		// If process is still running, kill it.
		if mh.cmd != nil && mh.cmd.Process != nil {
			_ = mh.cmd.Process.Kill()
		}
	}
	for id := range m.connections {
		delete(m.connections, id)
	}
	for id := range m.sessions {
		delete(m.sessions, id)
	}
	for id := range m.masters {
		delete(m.masters, id)
	}
	for id := range m.reconState {
		delete(m.reconState, id)
	}
	for id := range m.rsyncAvail {
		delete(m.rsyncAvail, id)
	}
	m.mu.Unlock()
	m.wg.Wait()
}

func (m *Manager) Disconnect(connectionID string) error {
	m.mu.Lock()
	conn := m.connections[connectionID]
	if conn == nil {
		m.mu.Unlock()
		return errorsx.New(errorsx.CodeConnectionMissing, "connection_id not found")
	}
	mh := m.masters[connectionID]
	if mh != nil {
		mh.intentional.Store(true) // set before unlock so watchMaster sees it
	}
	delete(m.connections, connectionID)
	delete(m.masters, connectionID)
	delete(m.reconState, connectionID)
	delete(m.rsyncAvail, connectionID)
	for id, s := range m.sessions {
		if s.ConnectionID == connectionID {
			delete(m.sessions, id)
		}
	}
	m.mu.Unlock()

	closeErr := m.closeMaster(*conn) // best-effort; connection may already be dead

	// If process is still running, kill it and wait.
	if mh != nil && mh.cmd != nil && mh.cmd.Process != nil {
		_ = mh.cmd.Process.Kill()
		select {
		case <-mh.done:
		case <-time.After(5 * time.Second):
		}
	}

	if closeErr != nil {
		fmt.Fprintf(os.Stderr, "cssh: disconnect: closeMaster %s (%s@%s): %v\n",
			connectionID, conn.Username, conn.Host, closeErr)
	}
	return nil
}
