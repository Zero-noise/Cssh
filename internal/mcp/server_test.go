package mcp

import (
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
	statusTool := findToolDef(t, "ssh_privilege_status")
	statusSchema, ok := statusTool["inputSchema"].(map[string]any)
	if !ok {
		t.Fatalf("inputSchema missing")
	}
	statusProps, ok := statusSchema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("properties missing")
	}
	for _, k := range []string{"connection_id", "active_only"} {
		if _, exists := statusProps[k]; !exists {
			t.Fatalf("ssh_privilege_status missing %s", k)
		}
	}

	revokeTool := findToolDef(t, "ssh_privilege_revoke")
	revokeSchema, ok := revokeTool["inputSchema"].(map[string]any)
	if !ok {
		t.Fatalf("inputSchema missing")
	}
	req := requiredAsAny(t, revokeSchema)
	if !containsString(req, "grant_id") {
		t.Fatalf("ssh_privilege_revoke should require grant_id")
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
	for _, key := range []string{"profile_id", "profile_name", "host", "username"} {
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

func TestToolDefsDoNotExposeLegacyAliases(t *testing.T) {
	legacy := []string{
		"ssh_upload_file",
		"ssh_download_file",
		"ssh_profiles_list",
		"ssh_profile_delete",
		"ssh_quick_setup_template",
		"ssh_quick_setup_save",
		"ssh_sudo_password_prompt",
	}
	tools := toolDefs("csshctl")
	for _, alias := range legacy {
		for _, td := range tools {
			name, _ := td["name"].(string)
			if name == alias {
				t.Fatalf("legacy alias should not be exposed in tools/list: %s", alias)
			}
		}
	}
}

func TestAliasCallReturnsCanonicalWarning(t *testing.T) {
	tmp := t.TempDir()
	svc := app.NewService(model.Config{
		DefaultShell:      "bash -lc",
		DefaultTimeoutSec: 120,
		RuntimeDir:        filepath.Join(tmp, "runtime"),
		LogsDir:           filepath.Join(tmp, "logs"),
		ProfilesFile:      filepath.Join(tmp, "profiles.json"),
	})
	s := NewServer(svc)

	out, err := s.callTool("ssh_profiles_list", nil)
	if err != nil {
		t.Fatalf("ssh_profiles_list alias call failed: %v", err)
	}
	if out["canonical_tool"] != "ssh_profile" {
		t.Fatalf("canonical_tool mismatch: %#v", out["canonical_tool"])
	}
	rawWarnings, ok := out["warnings"].([]string)
	if !ok || len(rawWarnings) == 0 {
		t.Fatalf("warnings should include deprecation hint: %#v", out["warnings"])
	}
	if !strings.Contains(rawWarnings[0], "deprecated") {
		t.Fatalf("warning should mention deprecation: %#v", rawWarnings)
	}
}

func TestApplyToolAliasDefaultsForSudoPrompt(t *testing.T) {
	in := map[string]any{"profile_id": "p1"}
	out := applyToolAliasDefaults(in, "ssh_sudo_password_prompt")
	fields, ok := out["fields"].([]string)
	if !ok || len(fields) != 1 || fields[0] != "sudo_password" {
		t.Fatalf("unexpected fields defaults: %#v", out["fields"])
	}
	if out["prompt_mode"] != "web" {
		t.Fatalf("prompt_mode should default to web, got: %#v", out["prompt_mode"])
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
