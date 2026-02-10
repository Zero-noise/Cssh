package mcp

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"strings"

	"cssh/internal/app"
	"cssh/internal/errorsx"
	"cssh/internal/model"
)

type Server struct {
	svc *app.Service

	seenInitialize    bool
	clientInitialized bool
}

func NewServer(svc *app.Service) *Server {
	return &Server{svc: svc}
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id,omitempty"`
	Result  interface{} `json:"result,omitempty"`
	Error   *respError  `json:"error,omitempty"`
}

type respError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func (s *Server) Run() error {
	in := bufio.NewReader(os.Stdin)
	for {
		msg, err := readMessage(in)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			_ = writeMessage(os.Stdout, response{JSONRPC: "2.0", Error: &respError{Code: -32700, Message: err.Error()}})
			continue
		}
		var req request
		if err := json.Unmarshal(msg, &req); err != nil {
			_ = writeMessage(os.Stdout, response{JSONRPC: "2.0", Error: &respError{Code: -32700, Message: "invalid json"}})
			continue
		}
		if len(req.ID) == 0 {
			s.handleNotification(req)
			continue
		}
		id := decodeID(req.ID)
		res := s.handle(req, id)
		if err := writeMessage(os.Stdout, res); err != nil {
			return err
		}
	}
}

func (s *Server) handleNotification(req request) {
	switch req.Method {
	case "notifications/initialized":
		if s.seenInitialize {
			s.clientInitialized = true
		}
	}
}

func (s *Server) handle(req request, id any) response {
	switch req.Method {
	case "initialize":
		s.seenInitialize = true
		s.clientInitialized = false
		return response{JSONRPC: "2.0", ID: id, Result: map[string]any{
			"protocolVersion": "2025-11-25",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "cssh-mcp", "version": "0.1.0"},
		}}
	case "ping":
		return response{JSONRPC: "2.0", ID: id, Result: map[string]any{}}
	case "tools/list":
		return response{JSONRPC: "2.0", ID: id, Result: map[string]any{"tools": toolDefs()}}
	case "tools/call":
		if !s.clientInitialized {
			return rpcError(id, -32002, "client not initialized; send notifications/initialized after initialize", nil)
		}
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return rpcError(id, -32602, "invalid tools/call params", nil)
		}
		result, err := s.callTool(p.Name, p.Arguments)
		if err != nil {
			return toRPCError(id, err)
		}
		text := app.PrettyJSON(result)
		return response{JSONRPC: "2.0", ID: id, Result: map[string]any{
			"content": []map[string]any{{"type": "text", "text": text}},
			"isError": false,
		}}
	default:
		return rpcError(id, -32601, "method not found", map[string]any{"method": req.Method})
	}
}

func (s *Server) callTool(name string, args map[string]any) (map[string]any, error) {
	if args == nil {
		args = map[string]any{}
	}
	switch name {
	case "ssh_connect":
		in := model.ConnectionInput{
			ProfileID:      stringArg(args, "profile_id"),
			ProfileName:    stringArg(args, "profile_name"),
			Host:           stringArg(args, "host"),
			Port:           app.ParseIntAny(args["port"], 22),
			Username:       stringArg(args, "username"),
			AuthMode:       stringArg(args, "auth_mode"),
			KeyRef:         stringArg(args, "key_ref"),
			PasswordRef:    stringArg(args, "password_ref"),
			WorkspaceRoots: app.ParseStringSliceAny(args["workspace_roots"]),
		}
		if v, ok := args["allow_public_host"]; ok {
			b := app.ParseBoolAny(v, false)
			in.AllowPublicHost = &b
		}
		return s.svc.Connect(in)
	case "ssh_open_session":
		connID, err := app.RequireString(args, "connection_id")
		if err != nil {
			return nil, err
		}
		return s.svc.OpenSession(connID, stringArg(args, "cwd"), stringArg(args, "shell"))
	case "ssh_exec":
		connID, err := app.RequireString(args, "connection_id")
		if err != nil {
			return nil, err
		}
		cmd, err := app.RequireString(args, "command")
		if err != nil {
			return nil, err
		}
		return s.svc.Exec(connID, stringArg(args, "session_id"), cmd, stringArg(args, "cwd"), app.ParseIntAny(args["timeout_sec"], 0), stringArg(args, "approval_token"))
	case "ssh_connection_status":
		return s.svc.ConnectionStatus(stringArg(args, "connection_id"), app.ParseIntAny(args["timeout_sec"], 5))
	case "ssh_privilege_status":
		return s.svc.PrivilegeStatus(stringArg(args, "connection_id"), app.ParseBoolAny(args["active_only"], true))
	case "ssh_privilege_revoke":
		grantID, err := app.RequireString(args, "grant_id")
		if err != nil {
			return nil, err
		}
		return s.svc.RevokePrivilege(grantID)
	case "ssh_upload_file":
		connID, err := app.RequireString(args, "connection_id")
		if err != nil {
			return nil, err
		}
		localPath, err := app.RequireString(args, "local_path")
		if err != nil {
			return nil, err
		}
		remotePath, err := app.RequireString(args, "remote_path")
		if err != nil {
			return nil, err
		}
		return s.svc.UploadFile(
			connID,
			localPath,
			remotePath,
			stringArg(args, "mode"),
			stringArg(args, "cwd"),
			app.ParseIntAny(args["timeout_sec"], 300),
			app.ParseBoolAny(args["create_parents"], true),
			app.ParseBoolAny(args["verify_checksum"], true),
			app.ParseBoolAny(args["allow_local_anywhere"], false),
			stringArg(args, "approval_token"),
		)
	case "ssh_download_file":
		connID, err := app.RequireString(args, "connection_id")
		if err != nil {
			return nil, err
		}
		remotePath, err := app.RequireString(args, "remote_path")
		if err != nil {
			return nil, err
		}
		localPath, err := app.RequireString(args, "local_path")
		if err != nil {
			return nil, err
		}
		return s.svc.DownloadFile(
			connID,
			remotePath,
			localPath,
			stringArg(args, "mode"),
			stringArg(args, "cwd"),
			app.ParseIntAny(args["timeout_sec"], 300),
			app.ParseBoolAny(args["create_parents"], true),
			app.ParseBoolAny(args["verify_checksum"], true),
			app.ParseBoolAny(args["allow_local_anywhere"], false),
			stringArg(args, "approval_token"),
		)
	case "ssh_read_file":
		connID, err := app.RequireString(args, "connection_id")
		if err != nil {
			return nil, err
		}
		p, err := app.RequireString(args, "path")
		if err != nil {
			return nil, err
		}
		return s.svc.ReadFile(connID, p, app.ParseIntAny(args["max_bytes"], 65536), stringArg(args, "cwd"))
	case "ssh_write_file":
		connID, err := app.RequireString(args, "connection_id")
		if err != nil {
			return nil, err
		}
		p, err := app.RequireString(args, "path")
		if err != nil {
			return nil, err
		}
		content, err := app.RequireString(args, "content")
		if err != nil {
			return nil, err
		}
		return s.svc.WriteFile(connID, p, content, stringArg(args, "mode"), stringArg(args, "cwd"))
	case "ssh_apply_patch":
		connID, err := app.RequireString(args, "connection_id")
		if err != nil {
			return nil, err
		}
		patch, err := app.RequireString(args, "patch_unified")
		if err != nil {
			return nil, err
		}
		baseDir := stringArg(args, "base_dir")
		if baseDir == "" {
			baseDir = "/"
		}
		return s.svc.ApplyPatch(connID, patch, baseDir)
	case "ssh_list_dir":
		connID, err := app.RequireString(args, "connection_id")
		if err != nil {
			return nil, err
		}
		p, err := app.RequireString(args, "path")
		if err != nil {
			return nil, err
		}
		return s.svc.ListDir(connID, p, app.ParseIntAny(args["depth"], 1), stringArg(args, "cwd"))
	case "ssh_search_text":
		connID, err := app.RequireString(args, "connection_id")
		if err != nil {
			return nil, err
		}
		p, err := app.RequireString(args, "path")
		if err != nil {
			return nil, err
		}
		pattern, err := app.RequireString(args, "pattern")
		if err != nil {
			return nil, err
		}
		return s.svc.SearchText(connID, p, pattern, stringArg(args, "glob"), app.ParseIntAny(args["limit"], 50), stringArg(args, "cwd"))
	case "ssh_tail_log":
		connID, err := app.RequireString(args, "connection_id")
		if err != nil {
			return nil, err
		}
		p, err := app.RequireString(args, "path")
		if err != nil {
			return nil, err
		}
		return s.svc.TailLog(connID, p, app.ParseIntAny(args["lines"], 200), stringArg(args, "cwd"))
	case "ssh_disconnect":
		connID, err := app.RequireString(args, "connection_id")
		if err != nil {
			return nil, err
		}
		return s.svc.Disconnect(connID)
	case "ssh_profiles_list":
		return s.svc.ProfilesList()
	case "ssh_profile_delete":
		profileID, err := app.RequireString(args, "profile_id")
		if err != nil {
			return nil, err
		}
		return s.svc.ProfileDelete(profileID, app.ParseBoolAny(args["delete_secrets"], true), stringArg(args, "confirm_token"))
	case "ssh_quick_setup_template":
		return s.svc.QuickSetupTemplate(stringArg(args, "purpose"), stringArg(args, "auth_mode"), stringArg(args, "username"))
	case "ssh_quick_setup_save":
		purpose, err := app.RequireString(args, "purpose")
		if err != nil {
			return nil, err
		}
		host, err := app.RequireString(args, "host")
		if err != nil {
			return nil, err
		}
		username, err := app.RequireString(args, "username")
		if err != nil {
			return nil, err
		}
		roots := app.ParseStringSliceAny(args["workspace_roots"])
		if len(roots) == 0 {
			single := stringArg(args, "workspace_root")
			if single != "" {
				roots = []string{single}
			}
		}
		in := app.QuickSetupInput{
			Purpose:         purpose,
			ProfileID:       stringArg(args, "profile_id"),
			ProfileName:     stringArg(args, "profile_name"),
			Host:            host,
			Port:            app.ParseIntAny(args["port"], 22),
			Username:        username,
			AuthMode:        stringArg(args, "auth_mode"),
			WorkspaceRoots:  roots,
			KeyPath:         stringArg(args, "key_path"),
			AllowPublicHost: app.ParseBoolAny(args["allow_public_host"], false),
			SecurityProfile: stringArg(args, "security_profile"),
			AllowRootUser:   app.ParseBoolAny(args["allow_root_user"], false),
		}
		return s.svc.QuickSetupSave(in)
	case "ssh_credentials_prompt":
		profileID, err := app.RequireString(args, "profile_id")
		if err != nil {
			return nil, err
		}
		in := app.CredentialPromptInput{
			ProfileID: profileID,
			Fields:    app.ParseStringSliceAny(args["fields"]),
			Mode:      stringArg(args, "prompt_mode"),
		}
		return s.svc.CredentialPrompt(in)
	case "ssh_sudo_password_prompt":
		profileID, err := app.RequireString(args, "profile_id")
		if err != nil {
			return nil, err
		}
		mode := stringArg(args, "prompt_mode")
		if mode == "" {
			mode = "web"
		}
		return s.svc.CredentialPrompt(app.CredentialPromptInput{
			ProfileID: profileID,
			Fields:    []string{"sudo_password"},
			Mode:      mode,
		})
	case "ssh_approve_request":
		approvalID, err := app.RequireString(args, "approval_id")
		if err != nil {
			return nil, err
		}
		return s.svc.ApproveRequest(
			approvalID,
			stringArg(args, "decision"),
			stringArg(args, "approved_by"),
			stringArg(args, "reason"),
		)
	default:
		return nil, errorsx.New(errorsx.CodeInvalidParams, "unknown tool: "+name)
	}
}

func stringArg(args map[string]any, key string) string {
	v, ok := args[key]
	if !ok || v == nil {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

func toRPCError(id any, err error) response {
	if ce, ok := err.(*errorsx.CsshError); ok {
		code := -32000
		switch ce.Code {
		case errorsx.CodeInvalidParams:
			code = -32602
		case errorsx.CodeConnectionMissing, errorsx.CodeSessionMissing:
			code = -32004
		case errorsx.CodeApprovalRequired:
			code = -32003
		case errorsx.CodePathForbidden:
			code = -32005
		case errorsx.CodeExecTimeout:
			code = -32006
		case errorsx.CodeFileExists:
			code = -32007
		case errorsx.CodeChecksumMismatch:
			code = -32008
		case errorsx.CodeChecksumUnavailable:
			code = -32009
		}
		return rpcError(id, code, ce.Message, map[string]any{"code": ce.Code})
	}
	return rpcError(id, -32000, err.Error(), nil)
}

func rpcError(id any, code int, message string, data any) response {
	return response{JSONRPC: "2.0", ID: id, Error: &respError{Code: code, Message: message, Data: data}}
}

func decodeID(raw json.RawMessage) any {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil
	}
	return v
}

func readMessage(r *bufio.Reader) ([]byte, error) {
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		return []byte(line), nil
	}
}

func writeMessage(w io.Writer, payload response) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	body = append(body, '\n')
	_, err = w.Write(body)
	return err
}

func toolDefs() []map[string]any {
	return []map[string]any{
		tool(
			"ssh_connect",
			"Create an SSH connection and return connection_id. Workflow: quick_setup/profile -> ssh_connect -> optional ssh_open_session -> ssh_exec. Profile-based connect is the default policy.",
			connectSchema(),
		),
		tool(
			"ssh_open_session",
			"Create a reusable shell session bound to an existing connection_id. Optional cwd/shell let later ssh_exec calls reuse context.",
			reqSchema([]string{"connection_id"}, "connection_id", "cwd", "shell"),
		),
		tool(
			"ssh_exec",
			"Run a command on remote host. Requires connection_id and command. Optional session_id/cwd/timeout_sec. In easy_safe, critical L2 commands may return approval_required. In non-easy_safe profiles, any command may require approval. Retry with approval_token after ssh_approve_request.",
			reqSchema([]string{"connection_id", "command"}, "connection_id", "command", "session_id", "cwd", "timeout_sec", "approval_token"),
		),
		tool(
			"ssh_connection_status",
			"Inspect SSH connection health. Optional connection_id targets one connection; without it returns all active in-memory connections. Optional timeout_sec controls health-check timeout.",
			reqSchema(nil, "connection_id", "timeout_sec"),
		),
		tool(
			"ssh_privilege_status",
			"Inspect privilege grants. Optional connection_id narrows to one connection. active_only defaults true.",
			reqSchema(nil, "connection_id", "active_only"),
		),
		tool(
			"ssh_privilege_revoke",
			"Revoke an active privilege grant immediately. Requires grant_id.",
			reqSchema([]string{"grant_id"}, "grant_id"),
		),
		tool(
			"ssh_upload_file",
			"Upload a local file to remote host via scp using existing connection_id control socket. Requires connection_id/local_path/remote_path. Optional mode(create|overwrite), create_parents, verify_checksum, timeout_sec, allow_local_anywhere, approval_token.",
			uploadFileSchema(),
		),
		tool(
			"ssh_download_file",
			"Download a remote file to local machine via scp using existing connection_id control socket. Requires connection_id/remote_path/local_path. Optional mode(create|overwrite), create_parents, verify_checksum, timeout_sec, allow_local_anywhere, approval_token.",
			downloadFileSchema(),
		),
		tool(
			"ssh_read_file",
			"Read remote file content (workspace_roots guarded). Requires connection_id + path; supports max_bytes truncation.",
			reqSchema([]string{"connection_id", "path"}, "connection_id", "path", "max_bytes", "cwd"),
		),
		tool(
			"ssh_write_file",
			"Write remote file content inside workspace_roots. Requires connection_id/path/content; mode supports create|overwrite|append.",
			reqSchema([]string{"connection_id", "path", "content"}, "connection_id", "path", "content", "mode", "cwd"),
		),
		tool(
			"ssh_apply_patch",
			"Apply unified patch via patch(1) on remote host. Requires connection_id + patch_unified; base_dir defaults to '/'.",
			reqSchema([]string{"connection_id", "patch_unified"}, "connection_id", "patch_unified", "base_dir"),
		),
		tool(
			"ssh_list_dir",
			"List remote directory entries (workspace_roots guarded). Requires connection_id + path; optional depth controls recursion.",
			reqSchema([]string{"connection_id", "path"}, "connection_id", "path", "depth", "cwd"),
		),
		tool(
			"ssh_search_text",
			"Search text in remote files. Requires connection_id/path/pattern. Optional glob and limit narrow results.",
			reqSchema([]string{"connection_id", "path", "pattern"}, "connection_id", "path", "pattern", "glob", "limit", "cwd"),
		),
		tool(
			"ssh_tail_log",
			"Tail remote log file content. Requires connection_id + path; optional lines defaults to 200.",
			reqSchema([]string{"connection_id", "path"}, "connection_id", "path", "lines", "cwd"),
		),
		tool(
			"ssh_disconnect",
			"Close an SSH connection and attached sessions. Requires connection_id.",
			reqSchema([]string{"connection_id"}, "connection_id"),
		),
		tool(
			"ssh_profiles_list",
			"List saved SSH profiles. Useful before deciding whether to reuse existing profile_id or run quick setup.",
			map[string]any{"type": "object", "properties": map[string]any{}},
		),
		tool(
			"ssh_profile_delete",
			"Delete one saved SSH profile by profile_id using a confirmation token flow. First call returns confirm_required + confirm_token; second call must include confirm_token. Optional delete_secrets (default true) also removes password/key_passphrase/sudo_password from system keychain.",
			reqSchema([]string{"profile_id"}, "profile_id", "delete_secrets", "confirm_token"),
		),
		tool(
			"ssh_quick_setup_template",
			"Return a compact user-facing form template for SSH onboarding. AI should present this form, collect answers, then call ssh_quick_setup_save.",
			reqSchema(nil, "purpose", "auth_mode", "username"),
		),
		tool(
			"ssh_quick_setup_save",
			"Persist SSH profile into MCP storage. This tool only stores profile metadata. After saving, use ssh_credentials_prompt to let the user securely enter credentials via local form.",
			reqSchema([]string{"purpose", "host", "username"}, "purpose", "profile_id", "profile_name", "host", "port", "username", "auth_mode", "workspace_roots", "workspace_root", "key_path", "allow_public_host", "security_profile", "allow_root_user"),
		),
		tool(
			"ssh_credentials_prompt",
			"Open a secure local web form for the user to enter SSH credentials directly into the OS keychain. Credentials NEVER pass through AI. Default path is web prompt. If web is unavailable, tool returns manual ./csshctl secret set-* commands with profile_id. Call this AFTER ssh_quick_setup_save when auth requires password or key passphrase. Also use this when sudo commands fail due to missing sudo_password.",
			credentialPromptSchema(),
		),
		tool(
			"ssh_sudo_password_prompt",
			"Prompt only for sudo_password. Default is secure web flow; if web is unavailable this returns manual ./csshctl command(s) with profile_id.",
			reqSchema([]string{"profile_id"}, "profile_id", "prompt_mode"),
		),
		tool(
			"ssh_approve_request",
			"Approve or reject one pending privilege approval request from ssh_exec approval_required flow. Requires approval_id; decision defaults to approve.",
			reqSchema([]string{"approval_id"}, "approval_id", "decision", "approved_by", "reason"),
		),
	}
}

func credentialPromptSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"profile_id": paramSchema("profile_id"),
			"fields": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string", "enum": []string{"password", "key_passphrase", "sudo_password"}},
				"description": "Credential fields to prompt. Defaults to auto-detect from profile auth_priority. Use sudo_password when the user needs to run sudo commands on the remote host.",
			},
			"prompt_mode": paramSchema("prompt_mode"),
		},
		"required": []string{"profile_id"},
	}
}

func connectSchema() map[string]any {
	props := map[string]any{}
	for _, key := range []string{"profile_id", "profile_name", "host", "port", "username", "auth_mode", "key_ref", "password_ref", "workspace_roots", "allow_public_host"} {
		props[key] = paramSchema(key)
	}
	return map[string]any{
		"type":        "object",
		"properties":  props,
		"description": "Provide one of: profile_id, profile_name, or host+username.",
	}
}

func reqSchema(required []string, keys ...string) map[string]any {
	props := map[string]any{}
	for _, k := range keys {
		props[k] = paramSchema(k)
	}
	out := map[string]any{
		"type":       "object",
		"properties": props,
	}
	if len(required) > 0 {
		out["required"] = required
	}
	return out
}

func uploadFileSchema() map[string]any {
	return transferFileSchema([]string{"connection_id", "local_path", "remote_path"})
}

func downloadFileSchema() map[string]any {
	return transferFileSchema([]string{"connection_id", "remote_path", "local_path"})
}

func transferFileSchema(required []string) map[string]any {
	props := map[string]any{}
	for _, k := range []string{"connection_id", "local_path", "remote_path", "cwd", "timeout_sec", "create_parents", "verify_checksum", "allow_local_anywhere", "approval_token"} {
		props[k] = paramSchema(k)
	}
	props["mode"] = map[string]any{
		"type":        "string",
		"enum":        []string{"create", "overwrite"},
		"description": "Transfer mode. create fails if target exists; overwrite replaces target.",
	}
	return map[string]any{
		"type":       "object",
		"properties": props,
		"required":   required,
	}
}

func paramSchema(key string) map[string]any {
	switch key {
	case "profile_id":
		return map[string]any{"type": "string", "description": "Saved SSH profile identifier."}
	case "profile_name":
		return map[string]any{"type": "string", "description": "Human-readable profile name. If multiple profiles share this name, use profile_id."}
	case "host":
		return map[string]any{"type": "string", "description": "SSH host, usually VPN/private IP or internal DNS."}
	case "port":
		return map[string]any{"type": "integer", "description": "SSH port. Defaults to 22."}
	case "username":
		return map[string]any{"type": "string", "description": "SSH login username."}
	case "auth_mode":
		return map[string]any{"type": "string", "enum": []string{"hybrid", "key", "password"}, "description": "Authentication strategy: key, password, or hybrid fallback."}
	case "key_ref":
		return map[string]any{"type": "string", "description": "Path to SSH private key for direct connect mode."}
	case "password_ref":
		return map[string]any{"type": "string", "description": "Secret reference used to resolve password for direct connect mode."}
	case "workspace_roots":
		return map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Allowed remote root paths for read/write operations."}
	case "workspace_root":
		return map[string]any{"type": "string", "description": "Single workspace root (shortcut if not using workspace_roots array)."}
	case "allow_public_host":
		return map[string]any{"type": "boolean", "description": "Allow public internet host. Default false for safety."}
	case "security_profile":
		return map[string]any{"type": "string", "enum": []string{"easy_safe", "ops_strict"}, "description": "Security profile for privilege approval behavior."}
	case "allow_root_user":
		return map[string]any{"type": "boolean", "description": "Allow root SSH user for this profile."}
	case "delete_secrets":
		return map[string]any{"type": "boolean", "description": "When deleting profile, also delete password/key passphrase/sudo password from keychain. Default true."}
	case "confirm_token":
		return map[string]any{"type": "string", "description": "Confirmation token returned by ssh_profile_delete first call."}
	case "approval_id":
		return map[string]any{"type": "string", "description": "Approval request ID returned by ssh_exec when status=approval_required."}
	case "decision":
		return map[string]any{"type": "string", "enum": []string{"approve", "reject"}, "description": "Approval decision. Defaults to approve."}
	case "approved_by":
		return map[string]any{"type": "string", "description": "Human approver label recorded in audit trail."}
	case "reason":
		return map[string]any{"type": "string", "description": "Optional reject reason (used when decision=reject)."}
	case "prompt_mode":
		return map[string]any{"type": "string", "enum": []string{"auto", "terminal", "web"}, "description": "Credential prompt mode. auto/web prefer local web form then fallback to manual commands; terminal requires interactive TTY."}
	case "connection_id":
		return map[string]any{"type": "string", "description": "Connection ID returned by ssh_connect."}
	case "grant_id":
		return map[string]any{"type": "string", "description": "Privilege grant ID returned by previous approval flow."}
	case "session_id":
		return map[string]any{"type": "string", "description": "Session ID returned by ssh_open_session for context reuse."}
	case "command":
		return map[string]any{"type": "string", "description": "Shell command to execute on remote host."}
	case "cwd":
		return map[string]any{"type": "string", "description": "Working directory for this tool call."}
	case "shell":
		return map[string]any{"type": "string", "description": "Shell wrapper, e.g. 'bash -lc'."}
	case "timeout_sec":
		return map[string]any{"type": "integer", "description": "Execution timeout in seconds."}
	case "approval_token":
		return map[string]any{"type": "string", "description": "Approval ID/token required to execute an operation that returned approval_required."}
	case "path":
		return map[string]any{"type": "string", "description": "Remote filesystem path."}
	case "local_path":
		return map[string]any{"type": "string", "description": "Local filesystem path."}
	case "remote_path":
		return map[string]any{"type": "string", "description": "Remote filesystem path for transfer."}
	case "max_bytes":
		return map[string]any{"type": "integer", "description": "Maximum bytes to read from file."}
	case "content":
		return map[string]any{"type": "string", "description": "File content payload for write operation."}
	case "mode":
		return map[string]any{"type": "string", "enum": []string{"create", "overwrite", "append"}, "description": "Write mode."}
	case "create_parents":
		return map[string]any{"type": "boolean", "description": "Create destination parent directories if missing. Default true."}
	case "verify_checksum":
		return map[string]any{"type": "boolean", "description": "Verify SHA-256 between local and remote after transfer. Default true."}
	case "allow_local_anywhere":
		return map[string]any{"type": "boolean", "description": "Allow local path outside current working directory. Default false."}
	case "patch_unified":
		return map[string]any{"type": "string", "description": "Unified diff patch text."}
	case "base_dir":
		return map[string]any{"type": "string", "description": "Base directory to apply patch in."}
	case "depth":
		return map[string]any{"type": "integer", "description": "Directory listing recursion depth."}
	case "pattern":
		return map[string]any{"type": "string", "description": "Search regex/pattern for text search."}
	case "glob":
		return map[string]any{"type": "string", "description": "Filename glob filter, e.g. '*.go'."}
	case "limit":
		return map[string]any{"type": "integer", "description": "Maximum number of matches to return."}
	case "lines":
		return map[string]any{"type": "integer", "description": "Number of lines for tail output."}
	case "active_only":
		return map[string]any{"type": "boolean", "description": "When true, return only active non-expired grants."}
	case "purpose":
		return map[string]any{"type": "string", "description": "Human-readable purpose, used to generate a profile and defaults."}
	case "key_path":
		return map[string]any{"type": "string", "description": "Path to SSH private key saved in profile."}
	case "password":
		return map[string]any{"type": "string", "description": "SSH password to save into system keychain/secret store."}
	case "key_passphrase":
		return map[string]any{"type": "string", "description": "Private key passphrase to save into system keychain/secret store."}
	default:
		return map[string]any{"type": "string", "description": "Tool parameter."}
	}
}

func tool(name, desc string, input map[string]any) map[string]any {
	return map[string]any{"name": name, "description": desc, "inputSchema": input}
}
