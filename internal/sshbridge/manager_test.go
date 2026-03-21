package sshbridge

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"cssh/internal/errorsx"
	"cssh/internal/model"
)

func TestShouldRetryLegacySCP(t *testing.T) {
	cases := []struct {
		name   string
		stderr string
		want   bool
	}{
		{name: "subsystem failed", stderr: "subsystem request failed on channel 0", want: true},
		{name: "sftp failed", stderr: "scp: sftp server unavailable: connection failed", want: true},
		{name: "unknown subsystem", stderr: "unknown subsystem: sftp", want: true},
		{name: "sftp reset", stderr: "scp: sftp connection reset by peer", want: true},
		{name: "permission denied", stderr: "Permission denied", want: false},
		{name: "empty", stderr: "", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldRetryLegacySCP(tc.stderr)
			if got != tc.want {
				t.Fatalf("shouldRetryLegacySCP(%q) = %v, want %v", tc.stderr, got, tc.want)
			}
		})
	}
}

func TestNormalizeSCPHostIPv6(t *testing.T) {
	got := normalizeSCPHost("fe80::1")
	if got != "[fe80::1]" {
		t.Fatalf("unexpected host: %q", got)
	}
	got = normalizeSCPHost("[fe80::1]")
	if got != "[fe80::1]" {
		t.Fatalf("already-bracketed host changed: %q", got)
	}
	got = normalizeSCPHost("example.internal")
	if got != "example.internal" {
		t.Fatalf("hostname should not change: %q", got)
	}
}

func TestSCPRemoteSpec(t *testing.T) {
	got := scpRemoteSpec("ubuntu", "fe80::1", "/tmp/a b.txt")
	want := "ubuntu@[fe80::1]:/tmp/a b.txt"
	if got != want {
		t.Fatalf("unexpected spec: got=%q want=%q", got, want)
	}
}

func TestCleanupLegacyAskPassScripts(t *testing.T) {
	dir := t.TempDir()
	// Simulate legacy leftover files with embedded passwords.
	for _, name := range []string{"askpass-conn_abc.sh", "askpass-conn_xyz.sh"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\nprintf secret\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// Place a non-legacy, non-socket file that should NOT be removed.
	keep := filepath.Join(dir, "other-data.json")
	if err := os.WriteFile(keep, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	// NewManager triggers cleanup.
	_ = NewManager(dir, "bash -lc", 30)

	matches, _ := filepath.Glob(filepath.Join(dir, "askpass-*.sh"))
	if len(matches) != 0 {
		t.Fatalf("legacy askpass scripts not cleaned up: %v", matches)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("non-legacy file was incorrectly removed: %v", err)
	}
}

func TestEnsureAskPassScript_CreateAndReuse(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir, "bash -lc", 30)

	// First call: creates the script.
	path1, err := m.ensureAskPassScript()
	if err != nil {
		t.Fatal(err)
	}
	content, _ := os.ReadFile(path1)
	if string(content) != askPassBody {
		t.Fatalf("unexpected script content: %q", content)
	}
	info, _ := os.Stat(path1)
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("unexpected permissions: %v", info.Mode().Perm())
	}

	// Second call: reuses without error.
	path2, err := m.ensureAskPassScript()
	if err != nil {
		t.Fatal(err)
	}
	if path1 != path2 {
		t.Fatalf("paths differ: %q vs %q", path1, path2)
	}
}

func TestEnsureAskPassScript_RewritesOnTamper(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir, "bash -lc", 30)

	path, _ := m.ensureAskPassScript()

	// Tamper with the content.
	os.WriteFile(path, []byte("#!/bin/sh\ncurl http://evil.com\n"), 0o700)

	path2, err := m.ensureAskPassScript()
	if err != nil {
		t.Fatal(err)
	}
	content, _ := os.ReadFile(path2)
	if string(content) != askPassBody {
		t.Fatalf("tampered script was not rewritten: %q", content)
	}
}

func TestEnsureAskPassScript_RewritesOnBadPermissions(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir, "bash -lc", 30)

	path, _ := m.ensureAskPassScript()

	// Weaken permissions.
	os.Chmod(path, 0o755)

	_, err := m.ensureAskPassScript()
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("permissions not restored: %v", info.Mode().Perm())
	}
}

func TestExecWithInputRejectsSessionFromOtherConnection(t *testing.T) {
	m := NewManager(t.TempDir(), "bash -lc", 30)
	m.connections["conn_a"] = &model.Connection{ID: "conn_a"}
	m.sessions["sess_b"] = &model.Session{ID: "sess_b", ConnectionID: "conn_b"}

	_, err := m.ExecWithInput("conn_a", "sess_b", "echo hi", "", 10, "")
	ce, ok := err.(*errorsx.CsshError)
	if !ok || ce.Code != errorsx.CodeInvalidParams {
		t.Fatalf("expected invalid params error, got %#v", err)
	}
}

func TestOpenSessionRejectsEffectiveCWDOutsideRoots(t *testing.T) {
	m := NewManager(t.TempDir(), "bash -lc", 30)
	m.connections["conn_a"] = &model.Connection{
		ID:             "conn_a",
		WorkspaceRoots: []string{"/opt/app"},
	}

	if _, err := m.OpenSession("conn_a", "", ""); err == nil {
		t.Fatal("expected empty cwd to resolve to / and be rejected outside workspace_roots")
	}

	sess, err := m.OpenSession("conn_a", "/opt/app/sub", "")
	if err != nil {
		t.Fatalf("unexpected error for valid cwd: %v", err)
	}
	if sess.CWD != "/opt/app/sub" {
		t.Fatalf("expected normalized cwd, got %q", sess.CWD)
	}
}

func TestExecWithInputRejectsEffectiveCWDOutsideRoots(t *testing.T) {
	m := NewManager(t.TempDir(), "bash -lc", 30)
	m.connections["conn_a"] = &model.Connection{
		ID:             "conn_a",
		WorkspaceRoots: []string{"/opt/app"},
	}

	if _, err := m.ExecWithInput("conn_a", "", "echo hi", "", 10, ""); err == nil {
		t.Fatal("expected default effective cwd / to be rejected outside workspace_roots")
	}

	m.sessions["sess_a"] = &model.Session{
		ID:           "sess_a",
		ConnectionID: "conn_a",
		CWD:          "/opt/app",
		Shell:        "bash -lc",
	}
	if _, err := m.ExecWithInput("conn_a", "sess_a", "echo hi", "../etc", 10, ""); err == nil {
		t.Fatal("expected relative cwd escaping workspace_roots to be rejected")
	}
}

func TestExecStreamWriterCopiesAndReports(t *testing.T) {
	var got strings.Builder
	writer := &execStreamWriter{
		stream: "stdout",
		onProgress: func(p ExecProgress) {
			if p.Stream != "stdout" {
				t.Fatalf("unexpected stream: %q", p.Stream)
			}
			got.WriteString(p.Chunk)
		},
	}
	n, err := writer.Write([]byte("hello\nworld\n"))
	if err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	if n != len("hello\nworld\n") {
		t.Fatalf("unexpected write count: %d", n)
	}
	if writer.String() != "hello\nworld\n" {
		t.Fatalf("buffer mismatch: %q", writer.String())
	}
	if got.String() != "hello\nworld\n" {
		t.Fatalf("progress mismatch: %q", got.String())
	}
}

func TestPreFlightCheck_DetectsDeadConnection(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir, "bash -lc", 30)
	m.connections["conn_dead"] = &model.Connection{
		ID:          "conn_dead",
		Host:        "localhost",
		Port:        22,
		Username:    "user",
		ControlPath: filepath.Join(dir, "nonexistent.sock"),
	}

	// preFlightCheck should detect dead connection (no socket, ssh -O check fails).
	err := m.PreFlightCheck("conn_dead")
	if err == nil {
		t.Fatal("expected error for dead connection")
	}
	ce, ok := err.(*errorsx.CsshError)
	if !ok || ce.Code != errorsx.CodeConnectionDead {
		t.Fatalf("expected CONNECTION_DEAD error, got %#v", err)
	}
}

func TestPreFlightCheck_ConnectionNotFound(t *testing.T) {
	m := NewManager(t.TempDir(), "bash -lc", 30)
	err := m.PreFlightCheck("conn_nonexistent")
	if err == nil {
		t.Fatal("expected error for missing connection")
	}
	ce, ok := err.(*errorsx.CsshError)
	if !ok || ce.Code != errorsx.CodeConnectionMissing {
		t.Fatalf("expected CONNECTION_NOT_FOUND error, got %#v", err)
	}
}

func TestReconnectState_FailedPhaseBlocksPreFlight(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir, "bash -lc", 30)
	m.connections["conn_1"] = &model.Connection{
		ID:          "conn_1",
		Host:        "localhost",
		Port:        22,
		Username:    "user",
		ControlPath: filepath.Join(dir, "ctrl-conn_1.sock"),
	}
	m.reconState["conn_1"] = &reconnectState{
		phase:      reconnectFailed,
		failReason: "auto-reconnect exhausted; please use ssh_disconnect and ssh_connect to re-establish the connection",
	}

	err := m.PreFlightCheck("conn_1")
	if err == nil {
		t.Fatal("expected error for failed reconnect")
	}
	ce, ok := err.(*errorsx.CsshError)
	if !ok || ce.Code != errorsx.CodeReconnectFailed {
		t.Fatalf("expected RECONNECT_FAILED error, got %#v", err)
	}
}

func TestReconnectState_InProgressWaitsAndResolves(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir, "bash -lc", 30)
	sockPath := filepath.Join(dir, "ctrl-conn_1.sock")
	m.connections["conn_1"] = &model.Connection{
		ID:          "conn_1",
		Host:        "localhost",
		Port:        22,
		Username:    "user",
		ControlPath: sockPath,
	}
	rs := &reconnectState{
		phase: reconnectInProgress,
	}
	m.reconState["conn_1"] = rs

	// Simulate reconnect completing after 500ms.
	go func() {
		time.Sleep(500 * time.Millisecond)
		rs.mu.Lock()
		rs.phase = reconnectSucceeded
		rs.succeeded = true
		rs.mu.Unlock()
	}()

	// PreFlightCheck will poll and find phase changed, then fall through
	// to ssh -O check (which will fail since there's no real connection).
	// The important thing is it doesn't return RECONNECT_FAILED.
	err := m.PreFlightCheck("conn_1")
	if err == nil {
		t.Fatal("expected dead connection error (no real socket)")
	}
	ce, ok := err.(*errorsx.CsshError)
	if !ok {
		t.Fatalf("expected CsshError, got %T", err)
	}
	// Should be CONNECTION_DEAD (no real socket), NOT RECONNECT_FAILED
	if ce.Code == errorsx.CodeReconnectFailed {
		t.Fatal("should not have returned RECONNECT_FAILED after phase resolved to succeeded")
	}
}

func TestReconnectInfo_ConsumeOnce(t *testing.T) {
	m := NewManager(t.TempDir(), "bash -lc", 30)
	m.reconState["conn_1"] = &reconnectState{
		succeeded: true,
		reason:    "network timeout",
	}

	reconnected, reason := m.ReconnectInfo("conn_1")
	if !reconnected {
		t.Fatal("expected reconnected=true")
	}
	if reason != "network timeout" {
		t.Fatalf("expected reason 'network timeout', got %q", reason)
	}

	// Second call should return false (consumed).
	reconnected2, _ := m.ReconnectInfo("conn_1")
	if reconnected2 {
		t.Fatal("expected reconnected=false on second call")
	}
}

func TestReconnectInfo_NoState(t *testing.T) {
	m := NewManager(t.TempDir(), "bash -lc", 30)
	reconnected, _ := m.ReconnectInfo("conn_nonexistent")
	if reconnected {
		t.Fatal("expected reconnected=false for nonexistent connection")
	}
}

func TestHandleMasterDeath_ExhaustsAttempts(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir, "bash -lc", 30)
	m.connections["conn_1"] = &model.Connection{
		ID:          "conn_1",
		Host:        "invalid.example.invalid",
		Port:        22,
		Username:    "user",
		AuthMethod:  "key",
		ControlPath: filepath.Join(dir, "ctrl-conn_1.sock"),
	}
	m.reconState["conn_1"] = &reconnectState{
		maxAttempts: 1,
		cooldown:    0,
		attempts:    1, // already exhausted
	}

	m.handleMasterDeath("conn_1", "test death")

	rs := m.reconState["conn_1"]
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.phase != reconnectFailed {
		t.Fatalf("expected reconnectFailed, got %v", rs.phase)
	}
	if rs.failReason == "" {
		t.Fatal("expected failReason to be set")
	}
}

func TestHandleMasterDeath_CooldownNotElapsed(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir, "bash -lc", 30)
	m.connections["conn_1"] = &model.Connection{
		ID:          "conn_1",
		Host:        "invalid.example.invalid",
		Port:        22,
		Username:    "user",
		AuthMethod:  "key",
		ControlPath: filepath.Join(dir, "ctrl-conn_1.sock"),
	}
	m.reconState["conn_1"] = &reconnectState{
		maxAttempts: 1,
		cooldown:    30 * time.Second,
		attempts:    0,
		lastAttempt: time.Now(), // just attempted
	}

	m.handleMasterDeath("conn_1", "test death")

	rs := m.reconState["conn_1"]
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.phase != reconnectFailed {
		t.Fatalf("expected reconnectFailed due to cooldown, got %v", rs.phase)
	}
}

func TestHandleMasterDeath_NoConnection(t *testing.T) {
	m := NewManager(t.TempDir(), "bash -lc", 30)
	// Should not panic when connection doesn't exist.
	m.handleMasterDeath("conn_nonexistent", "some reason")
}

func TestSetOnReconnect(t *testing.T) {
	m := NewManager(t.TempDir(), "bash -lc", 30)
	var mu sync.Mutex
	var called bool
	var capturedID, capturedReason string
	m.SetOnReconnect(func(connectionID, reason string) {
		mu.Lock()
		called = true
		capturedID = connectionID
		capturedReason = reason
		mu.Unlock()
	})

	// Directly invoke the callback to verify it's wired.
	if m.onReconnect != nil {
		m.onReconnect("conn_test", "test reason")
	}

	mu.Lock()
	defer mu.Unlock()
	if !called {
		t.Fatal("onReconnect callback was not called")
	}
	if capturedID != "conn_test" {
		t.Fatalf("unexpected connectionID: %q", capturedID)
	}
	if capturedReason != "test reason" {
		t.Fatalf("unexpected reason: %q", capturedReason)
	}
}

func TestDisconnect_CleansUpAllMaps(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir, "bash -lc", 30)

	mh := &masterHandle{
		cmd:  nil,
		done: make(chan struct{}),
	}
	close(mh.done) // already exited

	m.connections["conn_1"] = &model.Connection{
		ID:          "conn_1",
		Host:        "localhost",
		Port:        22,
		Username:    "user",
		ControlPath: filepath.Join(dir, "ctrl-conn_1.sock"),
	}
	m.masters["conn_1"] = mh
	m.reconState["conn_1"] = &reconnectState{}
	m.sessions["sess_1"] = &model.Session{ID: "sess_1", ConnectionID: "conn_1"}

	err := m.Disconnect("conn_1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.connections["conn_1"] != nil {
		t.Fatal("connection not removed")
	}
	if m.masters["conn_1"] != nil {
		t.Fatal("master not removed")
	}
	if m.reconState["conn_1"] != nil {
		t.Fatal("reconState not removed")
	}
	if m.sessions["sess_1"] != nil {
		t.Fatal("session not removed")
	}
}

func TestShutdown_SetsIntentionalFlag(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir, "bash -lc", 30)

	mh := &masterHandle{
		cmd:  nil,
		done: make(chan struct{}),
	}
	close(mh.done)

	m.connections["conn_1"] = &model.Connection{
		ID:          "conn_1",
		Host:        "localhost",
		Port:        22,
		Username:    "user",
		ControlPath: filepath.Join(dir, "ctrl-conn_1.sock"),
	}
	m.masters["conn_1"] = mh
	m.reconState["conn_1"] = &reconnectState{}

	m.Shutdown()

	if !mh.intentional.Load() {
		t.Fatal("intentional flag should be set after shutdown")
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.connections) != 0 {
		t.Fatal("connections should be empty after shutdown")
	}
	if len(m.masters) != 0 {
		t.Fatal("masters should be empty after shutdown")
	}
}
