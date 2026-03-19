package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"cssh/internal/app"
	"cssh/internal/errorsx"
	"cssh/internal/model"
	"cssh/internal/sshbridge"
)

func findToolDef(t *testing.T, name string) map[string]any {
	t.Helper()
	for _, td := range toolDefs("csshctl") {
		n, _ := td["name"].(string)
		if n == name {
			return td
		}
	}
	t.Fatalf("tool %s not found", name)
	return nil
}

func containsString(items []any, want string) bool {
	for _, it := range items {
		s, ok := it.(string)
		if ok && s == want {
			return true
		}
	}
	return false
}

func requiredAsAny(t *testing.T, schema map[string]any) []any {
	t.Helper()
	if reqAny, ok := schema["required"].([]any); ok {
		return reqAny
	}
	reqStr, ok := schema["required"].([]string)
	if !ok {
		t.Fatalf("required missing")
	}
	out := make([]any, 0, len(reqStr))
	for _, it := range reqStr {
		out = append(out, it)
	}
	return out
}

func toAnySlice(items any) []any {
	if a, ok := items.([]any); ok {
		return a
	}
	if a, ok := items.([]string); ok {
		out := make([]any, 0, len(a))
		for _, it := range a {
			out = append(out, it)
		}
		return out
	}
	return nil
}

func TestSSHExecSchemaRequiredAndDescriptions(t *testing.T) {
	tool := findToolDef(t, "ssh_exec")
	schema, ok := tool["inputSchema"].(map[string]any)
	if !ok {
		t.Fatalf("inputSchema missing")
	}

	required, ok := schema["required"].([]string)
	if !ok {
		// JSON-y map literals decode as []any when asserted from interface.
		requiredAny, ok2 := schema["required"].([]any)
		if !ok2 {
			t.Fatalf("required missing")
		}
		if !containsString(requiredAny, "connection_id") || !containsString(requiredAny, "command") {
			t.Fatalf("required should contain connection_id and command: %#v", requiredAny)
		}
	} else {
		seenConn, seenCmd := false, false
		for _, r := range required {
			if r == "connection_id" {
				seenConn = true
			}
			if r == "command" {
				seenCmd = true
			}
		}
		if !seenConn || !seenCmd {
			t.Fatalf("required should contain connection_id and command: %#v", required)
		}
	}

	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("properties missing")
	}
	cmdProp, ok := props["command"].(map[string]any)
	if !ok {
		t.Fatalf("command property missing")
	}
	desc, _ := cmdProp["description"].(string)
	if desc == "" {
		t.Fatalf("command description missing")
	}
}

func TestSSHConnectionStatusSchema(t *testing.T) {
	tool := findToolDef(t, "ssh_connection_status")
	schema, ok := tool["inputSchema"].(map[string]any)
	if !ok {
		t.Fatalf("inputSchema missing")
	}

	if _, exists := schema["required"]; exists {
		t.Fatalf("ssh_connection_status should not require parameters")
	}

	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("properties missing")
	}
	if _, exists := props["connection_id"]; !exists {
		t.Fatalf("connection_id property missing")
	}
	if _, exists := props["timeout_sec"]; !exists {
		t.Fatalf("timeout_sec property missing")
	}
}

func TestSSHTransferSchema(t *testing.T) {
	tool := findToolDef(t, "ssh_transfer")
	schema, ok := tool["inputSchema"].(map[string]any)
	if !ok {
		t.Fatalf("inputSchema missing")
	}
	requiredAny := requiredAsAny(t, schema)
	for _, k := range []string{"direction", "connection_id", "local_path", "remote_path"} {
		if !containsString(requiredAny, k) {
			t.Fatalf("required should contain %s: %#v", k, requiredAny)
		}
	}
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("properties missing")
	}
	for _, k := range []string{"mode", "create_parents", "verify_checksum", "allow_local_anywhere", "timeout_sec", "approval_token"} {
		if _, exists := props[k]; !exists {
			t.Fatalf("properties should include %s", k)
		}
	}
	modeProp, ok := props["mode"].(map[string]any)
	if !ok {
		t.Fatalf("mode property missing")
	}
	enumAny := toAnySlice(modeProp["enum"])
	if enumAny == nil {
		t.Fatalf("mode enum missing")
	}
	if !containsString(enumAny, "create") || !containsString(enumAny, "overwrite") || containsString(enumAny, "append") {
		t.Fatalf("unexpected mode enum: %#v", enumAny)
	}
	directionProp, ok := props["direction"].(map[string]any)
	if !ok {
		t.Fatalf("direction property missing")
	}
	directionEnum := toAnySlice(directionProp["enum"])
	if !containsString(directionEnum, "upload") || !containsString(directionEnum, "download") {
		t.Fatalf("direction enum should include upload/download: %#v", directionEnum)
	}
}

func TestPrivilegeToolsSchema(t *testing.T) {
	tool := findToolDef(t, "ssh_privilege")
	schema, ok := tool["inputSchema"].(map[string]any)
	if !ok {
		t.Fatalf("inputSchema missing")
	}
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("properties missing")
	}
	actionProp, ok := props["action"].(map[string]any)
	if !ok {
		t.Fatalf("ssh_privilege should include action")
	}
	actionEnum := toAnySlice(actionProp["enum"])
	if !containsString(actionEnum, "status") || !containsString(actionEnum, "revoke") {
		t.Fatalf("ssh_privilege action enum should include status/revoke: %#v", actionEnum)
	}
	for _, k := range []string{"connection_id", "active_only", "grant_id"} {
		if _, exists := props[k]; !exists {
			t.Fatalf("ssh_privilege should include %s", k)
		}
	}
}

func TestProfileToolsSchema(t *testing.T) {
	profileTool := findToolDef(t, "ssh_profile")
	profileSchema, ok := profileTool["inputSchema"].(map[string]any)
	if !ok {
		t.Fatalf("inputSchema missing")
	}
	profileProps, ok := profileSchema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("properties missing")
	}
	actionProp, ok := profileProps["action"].(map[string]any)
	if !ok {
		t.Fatalf("ssh_profile should include action")
	}
	actionEnum := toAnySlice(actionProp["enum"])
	if !containsString(actionEnum, "list") || !containsString(actionEnum, "delete") {
		t.Fatalf("ssh_profile action enum should include list/delete: %#v", actionEnum)
	}
	for _, k := range []string{"profile_id", "delete_secrets", "confirm_token"} {
		if _, exists := profileProps[k]; !exists {
			t.Fatalf("ssh_profile should include %s", k)
		}
	}
}

func TestCnoteToolSchema(t *testing.T) {
	tool := findToolDef(t, "ssh_cnote")
	schema, ok := tool["inputSchema"].(map[string]any)
	if !ok {
		t.Fatalf("inputSchema missing")
	}
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("properties missing")
	}
	actionProp, ok := props["action"].(map[string]any)
	if !ok {
		t.Fatalf("ssh_cnote should include action")
	}
	actionEnum := toAnySlice(actionProp["enum"])
	for _, want := range []string{"get", "set", "append", "clear"} {
		if !containsString(actionEnum, want) {
			t.Fatalf("ssh_cnote action enum should include %s: %#v", want, actionEnum)
		}
	}
	for _, k := range []string{"profile_id", "profile_name", "content"} {
		if _, exists := props[k]; !exists {
			t.Fatalf("ssh_cnote should include %s", k)
		}
	}
}

func TestApproveRequestToolRemoved(t *testing.T) {
	tools := toolDefs("csshctl")
	for _, td := range tools {
		name, _ := td["name"].(string)
		if name == "ssh_approve_request" {
			t.Fatalf("ssh_approve_request should not be in toolDefs")
		}
	}
}

func TestToRPCErrorAdditionalMappings(t *testing.T) {
	cases := []struct {
		err  error
		code int
	}{
		{errorsx.New(errorsx.CodeFileExists, "exists"), -32007},
		{errorsx.New(errorsx.CodeChecksumMismatch, "mismatch"), -32008},
		{errorsx.New(errorsx.CodeChecksumUnavailable, "missing"), -32009},
		{errorsx.New(errorsx.CodeResumeUnavailable, "resume unavailable"), -32015},
		{errorsx.New(errorsx.CodeContentTooLarge, "too large"), -32012},
	}
	for _, tc := range cases {
		res := toRPCError(1, tc.err)
		if res.Error == nil || res.Error.Code != tc.code {
			t.Fatalf("unexpected code for %v: %#v", tc.err, res.Error)
		}
	}
}

func TestConnectSchemaNoTopLevelCombinators(t *testing.T) {
	tool := findToolDef(t, "ssh_connect")
	schema, ok := tool["inputSchema"].(map[string]any)
	if !ok {
		t.Fatalf("inputSchema missing")
	}

	for _, key := range []string{"oneOf", "allOf", "anyOf"} {
		if _, exists := schema[key]; exists {
			t.Fatalf("%s should not exist at top level: %#v", key, schema[key])
		}
	}

	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("properties missing")
	}
	for _, key := range []string{"profile_id", "profile_name", "limit_dir", "allow_public_host"} {
		if _, exists := props[key]; !exists {
			t.Fatalf("properties should include %s", key)
		}
	}
}

func TestInitializedNotificationGate(t *testing.T) {
	s := NewServer(nil)

	req := request{Method: "tools/call", Params: []byte(`{"name":"ssh_profile","arguments":{"action":"list"}}`)}
	res := s.handleToolCall(context.Background(), req, 1)
	if res.Error == nil || res.Error.Code != -32002 {
		t.Fatalf("expected not-initialized error, got: %#v", res)
	}

	_ = s.handle(request{Method: "initialize"}, 1)
	s.handleNotification(request{Method: "notifications/initialized"})
	if !s.clientInitialized.Load() {
		t.Fatalf("client should be initialized after notification")
	}

	initRes := s.handle(request{Method: "initialize"}, 2)
	result, ok := initRes.Result.(map[string]any)
	if !ok {
		t.Fatalf("initialize result missing: %#v", initRes)
	}
	caps, ok := result["capabilities"].(map[string]any)
	if !ok {
		t.Fatalf("capabilities missing: %#v", result)
	}
	if _, ok := caps["logging"]; !ok {
		t.Fatalf("initialize should advertise logging capability: %#v", caps)
	}
}

func TestCredentialPromptSchemaSupportsSudoPassword(t *testing.T) {
	tool := findToolDef(t, "ssh_credentials_prompt")
	schema, ok := tool["inputSchema"].(map[string]any)
	if !ok {
		t.Fatalf("inputSchema missing")
	}
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("properties missing")
	}
	fieldsProp, ok := props["fields"].(map[string]any)
	if !ok {
		t.Fatalf("fields property missing")
	}
	items, ok := fieldsProp["items"].(map[string]any)
	if !ok {
		t.Fatalf("fields items missing")
	}
	enumAny := toAnySlice(items["enum"])
	if enumAny == nil {
		t.Fatalf("fields enum missing")
	}
	if !containsString(enumAny, "sudo_password") {
		t.Fatalf("fields enum should include sudo_password: %#v", enumAny)
	}
	if !containsString(enumAny, "password") {
		t.Fatalf("fields enum should include password: %#v", enumAny)
	}
	if !containsString(enumAny, "key_passphrase") {
		t.Fatalf("fields enum should include key_passphrase: %#v", enumAny)
	}
	if _, ok := props["prompt_mode"]; !ok {
		t.Fatalf("credential prompt schema should include prompt_mode")
	}
}

func TestProfileSetupSchemaDoesNotAcceptCredentialValues(t *testing.T) {
	tool := findToolDef(t, "ssh_profile_setup")
	schema, ok := tool["inputSchema"].(map[string]any)
	if !ok {
		t.Fatalf("inputSchema missing")
	}
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("properties missing")
	}
	if _, ok := props["password"]; ok {
		t.Fatalf("password should not be exposed in quick setup schema")
	}
	if _, ok := props["key_passphrase"]; ok {
		t.Fatalf("key_passphrase should not be exposed in profile setup schema")
	}
	if _, ok := props["allow_public_host"]; !ok {
		t.Fatalf("allow_public_host should stay available in profile setup schema")
	}
	stepProp, ok := props["step"].(map[string]any)
	if !ok {
		t.Fatalf("step should be exposed in profile setup schema")
	}
	stepEnum := toAnySlice(stepProp["enum"])
	if !containsString(stepEnum, "template") || !containsString(stepEnum, "save") {
		t.Fatalf("step enum should include template/save: %#v", stepEnum)
	}
}

func TestUnknownToolReturnsError(t *testing.T) {
	s := NewServer(nil)
	_, err := s.callTool("ssh_nonexistent", nil)
	if err == nil {
		t.Fatal("expected error for unknown tool")
	}
	if !strings.Contains(err.Error(), "unknown tool") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCnoteToolCall(t *testing.T) {
	tmp := t.TempDir()
	svc := app.NewService(model.Config{
		DefaultShell:           "bash -lc",
		DefaultTimeoutSec:      120,
		RuntimeDir:             filepath.Join(tmp, "runtime"),
		LogsDir:                filepath.Join(tmp, "logs"),
		ProfilesFile:           filepath.Join(tmp, "profiles.json"),
		SecurityProfileDefault: "easy_safe",
	})
	if _, err := svc.QuickSetupSave(app.QuickSetupInput{
		Purpose:  "debug worker",
		Host:     "100.100.1.9",
		Username: "ubuntu",
		AuthMode: "password",
	}); err != nil {
		t.Fatalf("quick save err: %v", err)
	}

	s := NewServer(svc)
	out, err := s.callTool("ssh_cnote", map[string]any{
		"action":     "set",
		"profile_id": "debug-worker-100-100-1-9",
		"content":    "下载大文件时统一落到 /mnt/ssd",
	})
	if err != nil {
		t.Fatalf("ssh_cnote call failed: %v", err)
	}
	if out["cnote_present"] != true {
		t.Fatalf("expected cnote_present=true, got %#v", out["cnote_present"])
	}
	if out["recorded"] != "下载大文件时统一落到 /mnt/ssd" {
		t.Fatalf("unexpected recorded content: %#v", out["recorded"])
	}
}

func TestCancelledNotification(t *testing.T) {
	s := NewServer(nil)
	_ = s.handle(request{Method: "initialize"}, 1)
	s.handleNotification(request{Method: "notifications/initialized"})

	// Simulate an inflight request
	ctx, cancel := context.WithCancel(context.Background())
	reqID := json.RawMessage(`42`)
	idKey := string(reqID)
	s.inflightMu.Lock()
	s.inflight[idKey] = cancel
	s.inflightMu.Unlock()

	// Send notifications/cancelled
	params, _ := json.Marshal(map[string]any{"requestId": 42})
	s.handleNotification(request{
		Method: "notifications/cancelled",
		Params: params,
	})

	// Verify the context was cancelled
	select {
	case <-ctx.Done():
		// expected
	default:
		t.Fatal("expected context to be cancelled")
	}
}

func TestCancelledUnknownId(t *testing.T) {
	s := NewServer(nil)
	// Should not panic on unknown request ID
	params, _ := json.Marshal(map[string]any{"requestId": 999})
	s.handleNotification(request{
		Method: "notifications/cancelled",
		Params: params,
	})
}

func TestConcurrentToolCalls(t *testing.T) {
	tmp := t.TempDir()
	svc := app.NewService(model.Config{
		DefaultShell:      "bash -lc",
		DefaultTimeoutSec: 120,
		RuntimeDir:        filepath.Join(tmp, "runtime"),
		LogsDir:           filepath.Join(tmp, "logs"),
		ProfilesFile:      filepath.Join(tmp, "profiles.json"),
	})
	s := NewServer(svc)
	_ = s.handle(request{Method: "initialize"}, 1)
	s.handleNotification(request{Method: "notifications/initialized"})

	var wg sync.WaitGroup
	results := make([]response, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req := request{
				Method: "tools/call",
				Params: []byte(`{"name":"ssh_profile","arguments":{"action":"list"}}`),
			}
			results[idx] = s.handleToolCall(context.Background(), req, idx+1)
		}(i)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent tool calls did not complete in time")
	}

	for i, res := range results {
		if res.Error != nil {
			t.Fatalf("tool call %d returned error: %#v", i, res.Error)
		}
	}
}

func TestToRPCErrorCancelledMapping(t *testing.T) {
	res := toRPCError(1, errorsx.New(errorsx.CodeCancelled, "cancelled"))
	if res.Error == nil || res.Error.Code != -32800 {
		t.Fatalf("expected -32800, got: %#v", res.Error)
	}
}

func TestProgressTokenFromMeta(t *testing.T) {
	if got, ok := progressTokenFromMeta(map[string]any{"progressToken": "tok-1"}); !ok || got != "tok-1" {
		t.Fatalf("unexpected token: %#v", got)
	}
	if got, ok := progressTokenFromMeta(map[string]any{"progressToken": map[string]any{"bad": true}}); ok || got != nil {
		t.Fatalf("invalid token should be ignored, got %#v", got)
	}
}

func TestProgressTokenFromParamsFallsBackToArgumentsMeta(t *testing.T) {
	got := progressTokenFromParams(nil, map[string]any{
		"_meta": map[string]any{"progressToken": "tok-2"},
	})
	if got != "tok-2" {
		t.Fatalf("unexpected fallback token: %#v", got)
	}
}

func TestProgressReporterEmitsOutputAndHeartbeat(t *testing.T) {
	var out bytes.Buffer
	s := NewServer(nil)
	s.out = &out

	reporter := newProgressReporter(s, "ssh_exec", "tok-1")
	if reporter == nil {
		t.Fatal("expected reporter")
	}
	reporter.flushInterval = 10 * time.Millisecond
	reporter.heartbeatInterval = 20 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reporter.Start(ctx)
	reporter.OnProgress(sshbridge.ExecProgress{Stream: "stderr", Chunk: "Cloning into 'ghostty'...\r"})

	waitForCondition(t, time.Second, func() bool {
		return strings.Contains(out.String(), "Cloning into 'ghostty'...")
	})
	waitForCondition(t, time.Second, func() bool {
		return strings.Contains(out.String(), "Command still running")
	})

	cancel()
	reporter.Close()

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected at least two progress notifications, got %d: %q", len(lines), out.String())
	}

	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("failed to decode first progress notification: %v", err)
	}
	if first["method"] != "notifications/progress" {
		t.Fatalf("unexpected method: %#v", first["method"])
	}
	params, ok := first["params"].(map[string]any)
	if !ok {
		t.Fatalf("params missing: %#v", first)
	}
	if params["progressToken"] != "tok-1" {
		t.Fatalf("unexpected progress token: %#v", params["progressToken"])
	}
	if _, ok := params["message"].(string); !ok {
		t.Fatalf("expected message in progress notification: %#v", params["message"])
	}
}

func TestProgressReporterFallsBackToMessageWithoutToken(t *testing.T) {
	var out bytes.Buffer
	s := NewServer(nil)
	s.out = &out

	reporter := newProgressReporter(s, "ssh_exec", nil)
	if reporter == nil {
		t.Fatal("expected reporter without token")
	}
	reporter.flushInterval = 10 * time.Millisecond
	reporter.heartbeatInterval = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reporter.Start(ctx)
	reporter.OnProgress(sshbridge.ExecProgress{Stream: "stdout", Chunk: "clone started"})

	waitForCondition(t, time.Second, func() bool {
		return strings.Contains(out.String(), "notifications/message")
	})
	cancel()
	reporter.Close()

	var msg map[string]any
	line := strings.TrimSpace(strings.Split(out.String(), "\n")[0])
	if err := json.Unmarshal([]byte(line), &msg); err != nil {
		t.Fatalf("failed to decode message notification: %v", err)
	}
	if msg["method"] != "notifications/message" {
		t.Fatalf("unexpected method: %#v", msg["method"])
	}
	params, ok := msg["params"].(map[string]any)
	if !ok {
		t.Fatalf("params missing: %#v", msg)
	}
	if params["level"] != "info" {
		t.Fatalf("unexpected level: %#v", params["level"])
	}
	if params["logger"] != "ssh_exec" {
		t.Fatalf("unexpected logger: %#v", params["logger"])
	}
	if params["data"] != "clone started" {
		t.Fatalf("unexpected data: %#v", params["data"])
	}
}

func TestNewProgressReporterRequiresSSHExecOnly(t *testing.T) {
	s := NewServer(nil)
	if reporter := newProgressReporter(s, "ssh_exec", nil); reporter == nil {
		t.Fatalf("expected reporter for ssh_exec without token")
	}
	if reporter := newProgressReporter(s, "ssh_profile", "tok-1"); reporter != nil {
		t.Fatalf("expected nil reporter for non-ssh_exec tool")
	}
}

func TestProgressReporterDiscardDropsPendingOutput(t *testing.T) {
	var out bytes.Buffer
	s := NewServer(nil)
	s.out = &out

	reporter := newProgressReporter(s, "ssh_exec", "tok-3")
	reporter.OnProgress(sshbridge.ExecProgress{Stream: "stdout", Chunk: "partial output"})
	reporter.Discard()
	reporter.Close()

	if out.Len() != 0 {
		t.Fatalf("discard should suppress progress notifications, got %q", out.String())
	}
}

func TestProgressReporterRespectsLoggingSetLevel(t *testing.T) {
	var out bytes.Buffer
	s := NewServer(nil)
	s.out = &out

	params, _ := json.Marshal(map[string]any{"level": "warning"})
	res := s.handle(request{Method: "logging/setLevel", Params: params}, 1)
	if res.Error != nil {
		t.Fatalf("logging/setLevel returned error: %#v", res.Error)
	}

	reporter := newProgressReporter(s, "ssh_exec", nil)
	reporter.OnProgress(sshbridge.ExecProgress{Stream: "stdout", Chunk: "info output"})
	reporter.Close()
	if out.Len() != 0 {
		t.Fatalf("warning log level should suppress info messages, got %q", out.String())
	}
}

func TestLoggingSetLevelRejectsInvalidLevel(t *testing.T) {
	s := NewServer(nil)
	params, _ := json.Marshal(map[string]any{"level": "verbose"})
	res := s.handle(request{Method: "logging/setLevel", Params: params}, 1)
	if res.Error == nil || res.Error.Code != -32602 {
		t.Fatalf("expected invalid params error, got %#v", res)
	}
}

func TestToolAnnotations(t *testing.T) {
	tools := toolDefs("csshctl")
	for _, td := range tools {
		name := td["name"].(string)
		ann, ok := td["annotations"].(map[string]any)
		if !ok {
			t.Fatalf("tool %s missing annotations", name)
		}
		if _, ok := ann["title"].(string); !ok {
			t.Fatalf("tool %s missing annotations.title", name)
		}
	}
}

func TestReadOnlyToolAnnotations(t *testing.T) {
	for _, name := range []string{"ssh_connection_status", "ssh_read_file"} {
		td := findToolDef(t, name)
		ann := td["annotations"].(map[string]any)
		if ann["readOnlyHint"] != true {
			t.Errorf("%s: readOnlyHint should be true", name)
		}
		if ann["destructiveHint"] != false {
			t.Errorf("%s: destructiveHint should be false", name)
		}
	}
}

func TestReadFileSchemaParameters(t *testing.T) {
	tool := findToolDef(t, "ssh_read_file")
	schema, ok := tool["inputSchema"].(map[string]any)
	if !ok {
		t.Fatalf("inputSchema missing")
	}
	requiredAny := requiredAsAny(t, schema)
	for _, k := range []string{"connection_id", "path"} {
		if !containsString(requiredAny, k) {
			t.Fatalf("required should contain %s: %#v", k, requiredAny)
		}
	}
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("properties missing")
	}
	for _, k := range []string{"connection_id", "path", "cwd", "offset", "limit", "max_bytes"} {
		prop, exists := props[k]
		if !exists {
			t.Fatalf("properties should include %s", k)
		}
		pm, ok := prop.(map[string]any)
		if !ok {
			t.Fatalf("property %s should be a map", k)
		}
		if pm["type"] == nil {
			t.Fatalf("property %s should have type", k)
		}
	}
	// offset, limit, max_bytes should be integer
	for _, k := range []string{"offset", "limit", "max_bytes"} {
		pm := props[k].(map[string]any)
		if pm["type"] != "integer" {
			t.Errorf("property %s type should be integer, got %v", k, pm["type"])
		}
	}
}

func TestReadFileSchemaDescription(t *testing.T) {
	tool := findToolDef(t, "ssh_read_file")
	desc, ok := tool["description"].(string)
	if !ok || desc == "" {
		t.Fatalf("description missing")
	}
	for _, keyword := range []string{"line number", "binary", "ssh_transfer", "ymlink"} {
		if !strings.Contains(strings.ToLower(desc), strings.ToLower(keyword)) {
			t.Errorf("description should mention %q: %s", keyword, desc)
		}
	}
}

func TestApplyPatchSchemaIncludesDryRun(t *testing.T) {
	tool := findToolDef(t, "ssh_apply_patch")
	schema, ok := tool["inputSchema"].(map[string]any)
	if !ok {
		t.Fatalf("inputSchema missing")
	}
	requiredAny := requiredAsAny(t, schema)
	for _, k := range []string{"connection_id", "patch_unified"} {
		if !containsString(requiredAny, k) {
			t.Fatalf("required should contain %s: %#v", k, requiredAny)
		}
	}
	if containsString(requiredAny, "dry_run") {
		t.Fatalf("dry_run should NOT be required")
	}
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("properties missing")
	}
	drProp, ok := props["dry_run"].(map[string]any)
	if !ok {
		t.Fatalf("dry_run property missing from ssh_apply_patch schema")
	}
	if drProp["type"] != "boolean" {
		t.Fatalf("dry_run should be boolean, got %v", drProp["type"])
	}
	if _, ok := props["base_dir"]; !ok {
		t.Fatalf("base_dir property missing")
	}
}

func TestDestructiveToolAnnotations(t *testing.T) {
	for _, name := range []string{"ssh_write_file", "ssh_apply_patch", "ssh_transfer"} {
		td := findToolDef(t, name)
		ann := td["annotations"].(map[string]any)
		if ann["destructiveHint"] != true {
			t.Errorf("%s: destructiveHint should be true", name)
		}
	}
}

func waitForCondition(t *testing.T, timeout time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met before timeout")
}
