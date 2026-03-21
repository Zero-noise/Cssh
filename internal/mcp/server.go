package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cssh/internal/app"
	"cssh/internal/errorsx"
	"cssh/internal/model"
	"cssh/internal/resolve"
	"cssh/internal/sshbridge"
)

const mcpInstructions = `Cssh provides secure SSH access to remote hosts via saved profiles.

## Cnote — per-profile memory
Each profile has a persistent Cnote (connection note). When you connect to a profile, the current Cnote content is returned automatically in the ssh_connect response (cnote / cnote_present fields).

**When to read Cnote:** You do NOT need to call ssh_cnote(action=get) after connecting — the content is already in the connect response. Only call get if you want to re-check mid-session.

**When to write Cnote:** Use ssh_cnote(action=append) to record useful information discovered during the session, such as:
- User preferences or recurring instructions for this host (e.g. "user prefers apt over snap", "always check systemd logs first")
- Environment quirks or notable configuration (e.g. "runs PostgreSQL 15 on non-standard port 5433", "custom deploy script at /opt/deploy/run.sh")
- Operational context that future sessions should know (e.g. "last migration was v42, next is v43")

Keep notes concise and factual. Do not duplicate information already in the profile metadata. Use append for incremental additions; use set only when a full rewrite is warranted.

**When to follow Cnote:** If the Cnote contains instructions or preferences, treat them as standing guidance for the current session unless the user overrides them.

## Filesystem operations
Use ssh_exec with standard shell commands for filesystem exploration:
- List directories: ls -la, find, tree
- Search text: grep -rn, find ... -exec grep
- Tail logs: tail -n, tail -f (with timeout_sec)
- Check disk usage: df -h, du -sh

When working with tool results, write down any important information you might need later in your response, as the original tool result may be cleared later.

## ssh_read_file usage
ssh_read_file returns line-numbered content with metadata. Key response fields:
- content: numbered lines ("   NR\tline"), size, total_lines, line_start, line_end
- Use offset + limit for partial reads of large files (default: line 1, 2000 lines)
- Binary files: returns binary=true + mime_encoding, no content — use ssh_transfer to download`

type Server struct {
	svc     *app.Service
	ctlPath string
	out     io.Writer

	seenInitialize    atomic.Bool
	clientInitialized atomic.Bool
	minLogLevel       atomic.Int32

	writeMu    sync.Mutex
	inflightMu sync.Mutex
	inflight   map[string]context.CancelFunc
	wg         sync.WaitGroup
}

func NewServer(svc *app.Service) *Server {
	s := &Server{
		svc:      svc,
		ctlPath:  resolve.QuotedPath(),
		out:      os.Stdout,
		inflight: map[string]context.CancelFunc{},
	}
	s.minLogLevel.Store(int32(loggingLevelInfo))
	return s
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

type progressReporter struct {
	server            *Server
	token             any
	flushInterval     time.Duration
	heartbeatInterval time.Duration
	started           time.Time

	mu       sync.Mutex
	pending  strings.Builder
	lastSent time.Time
	seq      int64
	closed   bool
}

const (
	progressFlushInterval     = 400 * time.Millisecond
	progressHeartbeatInterval = 5 * time.Second
	progressMaxMessageRunes   = 1600
	progressTickInterval      = 250 * time.Millisecond
)

type loggingLevel int

const (
	loggingLevelDebug loggingLevel = iota
	loggingLevelInfo
	loggingLevelNotice
	loggingLevelWarning
	loggingLevelError
	loggingLevelCritical
	loggingLevelAlert
	loggingLevelEmergency
)

func (s *Server) Run() error {
	in := bufio.NewReader(os.Stdin)
	for {
		msg, err := readMessage(in)
		if err == io.EOF {
			s.cancelAllInflight()
			s.waitInflight(5 * time.Second)
			return nil
		}
		if err != nil {
			_ = s.writeResponse(response{JSONRPC: "2.0", Error: &respError{Code: -32700, Message: err.Error()}})
			continue
		}
		var req request
		if err := json.Unmarshal(msg, &req); err != nil {
			_ = s.writeResponse(response{JSONRPC: "2.0", Error: &respError{Code: -32700, Message: "invalid json"}})
			continue
		}
		// Notifications (no ID): handle synchronously
		if len(req.ID) == 0 {
			s.handleNotification(req)
			continue
		}
		id := decodeID(req.ID)
		// tools/call: dispatch to goroutine for concurrent execution
		if req.Method == "tools/call" {
			s.dispatchToolCall(req, id)
			continue
		}
		// Other requests (initialize, ping, tools/list): handle synchronously (always fast)
		res := s.handle(req, id)
		if err := s.writeResponse(res); err != nil {
			return err
		}
	}
}

func (s *Server) handleNotification(req request) {
	switch req.Method {
	case "notifications/initialized":
		if s.seenInitialize.Load() {
			s.clientInitialized.Store(true)
		}
	case "notifications/cancelled":
		var p struct {
			RequestID json.RawMessage `json:"requestId"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return
		}
		idKey := string(p.RequestID)
		s.inflightMu.Lock()
		cancel, ok := s.inflight[idKey]
		s.inflightMu.Unlock()
		if ok {
			cancel()
		}
	}
}

func (s *Server) dispatchToolCall(req request, id any) {
	ctx, cancel := context.WithCancel(context.Background())
	idKey := string(req.ID)

	s.inflightMu.Lock()
	s.inflight[idKey] = cancel
	s.inflightMu.Unlock()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() {
			s.inflightMu.Lock()
			delete(s.inflight, idKey)
			s.inflightMu.Unlock()
			cancel()
		}()
		res := s.handleToolCall(ctx, req, id)
		_ = s.writeResponse(res)
	}()
}

func (s *Server) handleToolCall(ctx context.Context, req request, id any) response {
	if !s.clientInitialized.Load() {
		return rpcError(id, -32002, "client not initialized; send notifications/initialized after initialize", nil)
	}
	var p struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
		Meta      map[string]any `json:"_meta"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return rpcError(id, -32602, "invalid tools/call params", nil)
	}
	reporter := newProgressReporter(s, p.Name, progressTokenFromParams(p.Meta, p.Arguments))
	if reporter != nil {
		reporter.Start(ctx)
		defer reporter.Close()
	}
	var onProgress sshbridge.ExecProgressFn
	if reporter != nil {
		onProgress = reporter.OnProgress
	}
	var emitFn func(string)
	if reporter != nil {
		emitFn = reporter.emit
	}
	result, err := s.callToolWithContext(ctx, p.Name, p.Arguments, onProgress, emitFn)
	if ctx.Err() != nil {
		if reporter != nil {
			reporter.Discard()
		}
		return rpcError(id, -32800, "request cancelled", map[string]any{"code": errorsx.CodeCancelled})
	}
	if err != nil {
		if s.svc != nil {
			s.svc.AuditToolCall(p.Name, "error", err.Error())
		}
		return toRPCError(id, err)
	}
	if s.svc != nil {
		s.svc.AuditToolCall(p.Name, "ok", "")
	}
	text := app.PrettyJSON(result)
	return response{JSONRPC: "2.0", ID: id, Result: map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": false,
	}}
}

func (s *Server) handle(req request, id any) response {
	switch req.Method {
	case "initialize":
		s.seenInitialize.Store(true)
		s.clientInitialized.Store(false)
		return response{JSONRPC: "2.0", ID: id, Result: map[string]any{
			"protocolVersion": "2025-11-25",
			"capabilities":    map[string]any{"tools": map[string]any{}, "logging": map[string]any{}},
			"serverInfo":      map[string]any{"name": "cssh-mcp", "version": "0.1.0"},
			"instructions":    mcpInstructions,
		}}
	case "logging/setLevel":
		var p struct {
			Level string `json:"level"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return rpcError(id, -32602, "invalid logging/setLevel params", nil)
		}
		level, ok := parseLoggingLevel(p.Level)
		if !ok {
			return rpcError(id, -32602, "invalid logging/setLevel params", map[string]any{"level": p.Level})
		}
		s.minLogLevel.Store(int32(level))
		return response{JSONRPC: "2.0", ID: id, Result: map[string]any{}}
	case "ping":
		return response{JSONRPC: "2.0", ID: id, Result: map[string]any{}}
	case "tools/list":
		return response{JSONRPC: "2.0", ID: id, Result: map[string]any{"tools": toolDefs(s.ctlPath)}}
	default:
		return rpcError(id, -32601, "method not found", map[string]any{"method": req.Method})
	}
}

func (s *Server) writeResponse(res response) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return writeMessage(s.out, res)
}

func (s *Server) cancelAllInflight() {
	s.inflightMu.Lock()
	defer s.inflightMu.Unlock()
	for _, cancel := range s.inflight {
		cancel()
	}
}

func (s *Server) waitInflight(timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
	}
}

// callToolWithContext is the context-aware entry point for tool calls.
func (s *Server) callToolWithContext(ctx context.Context, name string, args map[string]any, onProgress sshbridge.ExecProgressFn, notify func(string)) (map[string]any, error) {
	if args == nil {
		args = map[string]any{}
	}
	if _, ok := canonicalToolNames[name]; !ok {
		return nil, errorsx.New(errorsx.CodeInvalidParams, "unknown tool: "+name)
	}
	return s.callCanonicalToolWithContext(ctx, name, args, onProgress, notify)
}

// callCanonicalToolWithContext dispatches to the appropriate service method.
// For ssh_exec, ctx is propagated for cancellation support.
// For other tools, ctx.Err() is checked at entry as a fast-fail.
func (s *Server) callCanonicalToolWithContext(ctx context.Context, name string, args map[string]any, onProgress sshbridge.ExecProgressFn, notify func(string)) (map[string]any, error) {
	// Fast-fail if already cancelled (covers all tools)
	if ctx.Err() != nil {
		return nil, errorsx.New(errorsx.CodeCancelled, "request cancelled")
	}

	switch name {
	case "ssh_exec":
		connID, err := app.RequireString(args, "connection_id")
		if err != nil {
			return nil, err
		}
		cmd, err := app.RequireString(args, "command")
		if err != nil {
			return nil, err
		}
		return s.svc.ExecWithProgress(ctx, connID, stringArg(args, "session_id"), cmd, stringArg(args, "cwd"), app.ParseIntAny(args["timeout_sec"], 0), stringArg(args, "approval_token"), onProgress)
	case "ssh_transfer":
		direction := stringArg(args, "direction")
		if direction == "" {
			return nil, errorsx.New(errorsx.CodeInvalidParams, "direction is required")
		}
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
		switch strings.ToLower(direction) {
		case "upload":
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
				app.ParseBoolAny(args["recursive"], false),
				app.ParseBoolAny(args["resume"], false),
				onProgress,
			)
		case "download":
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
				app.ParseBoolAny(args["recursive"], false),
				app.ParseBoolAny(args["resume"], false),
				onProgress,
			)
		default:
			return nil, errorsx.New(errorsx.CodeInvalidParams, "direction must be one of: upload, download")
		}
	case "ssh_credentials_prompt":
		profileID, err := app.RequireString(args, "profile_id")
		if err != nil {
			return nil, err
		}
		in := app.CredentialPromptInput{
			ProfileID: profileID,
			Fields:    app.ParseStringSliceAny(args["fields"]),
			Mode:      stringArg(args, "prompt_mode"),
			Notify:    notify,
		}
		return s.svc.CredentialPrompt(in)
	case "ssh_key_setup":
		profileID, err := app.RequireString(args, "profile_id")
		if err != nil {
			return nil, err
		}
		in := app.KeySetupInput{
			ProfileID: profileID,
			ScanDir:   stringArg(args, "scan_dir"),
			Mode:      stringArg(args, "prompt_mode"),
			Notify:    notify,
		}
		return s.svc.KeySetup(in)
	default:
		return s.callCanonicalTool(name, args)
	}
}

// callTool is the original non-context entry point (used by existing tests).
func (s *Server) callTool(name string, args map[string]any) (map[string]any, error) {
	if args == nil {
		args = map[string]any{}
	}
	if _, ok := canonicalToolNames[name]; !ok {
		return nil, errorsx.New(errorsx.CodeInvalidParams, "unknown tool: "+name)
	}
	return s.callCanonicalTool(name, args)
}

func (s *Server) callCanonicalTool(name string, args map[string]any) (map[string]any, error) {
	switch name {
	case "ssh_connect":
		in := model.ConnectionInput{
			ProfileID:   stringArg(args, "profile_id"),
			ProfileName: stringArg(args, "profile_name"),
			LimitDir:    stringArg(args, "limit_dir"),
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
	case "ssh_privilege":
		action := strings.ToLower(stringArg(args, "action"))
		if action == "" {
			action = "status"
		}
		switch action {
		case "status":
			return s.svc.PrivilegeStatus(stringArg(args, "connection_id"), app.ParseBoolAny(args["active_only"], true))
		case "revoke":
			grantID, err := app.RequireString(args, "grant_id")
			if err != nil {
				return nil, err
			}
			return s.svc.RevokePrivilege(grantID)
		default:
			return nil, errorsx.New(errorsx.CodeInvalidParams, "action must be one of: status, revoke")
		}
	case "ssh_read_file":
		connID, err := app.RequireString(args, "connection_id")
		if err != nil {
			return nil, err
		}
		p, err := app.RequireString(args, "path")
		if err != nil {
			return nil, err
		}
		return s.svc.ReadFile(
			connID, p,
			app.ParseIntAny(args["max_bytes"], 0),
			app.ParseIntAny(args["offset"], 0),
			app.ParseIntAny(args["limit"], 0),
			stringArg(args, "cwd"),
		)
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
		strip := app.ParseIntAny(args["strip"], 0)
		return s.svc.ApplyPatch(connID, patch, baseDir, app.ParseBoolAny(args["dry_run"], false), strip)
	case "ssh_disconnect":
		connID, err := app.RequireString(args, "connection_id")
		if err != nil {
			return nil, err
		}
		return s.svc.Disconnect(connID)
	case "ssh_profile":
		action := strings.ToLower(stringArg(args, "action"))
		if action == "" {
			action = "list"
		}
		switch action {
		case "list":
			return s.svc.ProfilesList()
		case "delete":
			profileID, err := app.RequireString(args, "profile_id")
			if err != nil {
				return nil, err
			}
			return s.svc.ProfileDelete(profileID, app.ParseBoolAny(args["delete_secrets"], true), stringArg(args, "confirm_token"))
		default:
			return nil, errorsx.New(errorsx.CodeInvalidParams, "action must be one of: list, delete")
		}
	case "ssh_cnote":
		return s.svc.Cnote(
			stringArg(args, "action"),
			stringArg(args, "profile_id"),
			stringArg(args, "profile_name"),
			stringArg(args, "content"),
		)
	case "ssh_profile_setup":
		step := strings.ToLower(stringArg(args, "step"))
		if step == "" {
			step = "template"
		}
		switch step {
		case "template":
			return s.svc.QuickSetupTemplate(stringArg(args, "purpose"), stringArg(args, "auth_mode"), stringArg(args, "username"))
		case "edit":
			profileID, err := app.RequireString(args, "profile_id")
			if err != nil {
				return nil, err
			}
			editRoots := app.ParseStringSliceAny(args["workspace_roots"])
			if len(editRoots) == 0 {
				if single := stringArg(args, "workspace_root"); single != "" {
					editRoots = []string{single}
				}
			}
			var editAllowedLocal *[]string
			if v, ok := args["allowed_local_paths"]; ok {
				parsed := app.ParseStringSliceAny(v)
				editAllowedLocal = &parsed
			}
			in := app.QuickSetupEditInput{
				ProfileID:         profileID,
				ProfileName:       stringPtrArg(args, "profile_name"),
				Host:              stringPtrArg(args, "host"),
				Port:              intPtrArg(args, "port"),
				Username:          stringPtrArg(args, "username"),
				AuthMode:          stringPtrArg(args, "auth_mode"),
				AuthPriority:      app.ParseStringSliceAny(args["auth_priority"]),
				WorkspaceRoots:    editRoots,
				AllowedLocalPaths: editAllowedLocal,
				KeyPath:           stringPtrArg(args, "key_path"),
				SecurityProfile:   stringPtrArg(args, "security_profile"),
				AllowRootUser:     boolPtrArg(args, "allow_root_user"),
				GrantTTLSec:       intPtrArg(args, "grant_ttl_sec"),
			}
			return s.svc.QuickSetupEdit(in)
		case "save":
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
			var saveAllowedLocal *[]string
			if v, ok := args["allowed_local_paths"]; ok {
				parsed := app.ParseStringSliceAny(v)
				saveAllowedLocal = &parsed
			}
			in := app.QuickSetupInput{
				Purpose:           purpose,
				ProfileID:         stringArg(args, "profile_id"),
				ProfileName:       stringArg(args, "profile_name"),
				Host:              host,
				Port:              app.ParseIntAny(args["port"], 22),
				Username:          username,
				AuthMode:          stringArg(args, "auth_mode"),
				WorkspaceRoots:    roots,
				AllowedLocalPaths: saveAllowedLocal,
				KeyPath:           stringArg(args, "key_path"),
				SecurityProfile:   stringArg(args, "security_profile"),
				AllowRootUser:     app.ParseBoolAny(args["allow_root_user"], false),
				GrantTTLSec:       app.ParseIntAny(args["grant_ttl_sec"], 0),
			}
			return s.svc.QuickSetupSave(in)
		default:
			return nil, errorsx.New(errorsx.CodeInvalidParams, "step must be one of: template, save, edit")
		}
	default:
		return nil, errorsx.New(errorsx.CodeInvalidParams, "unknown tool: "+name)
	}
}

var canonicalToolNames = map[string]struct{}{
	"ssh_connect":            {},
	"ssh_open_session":       {},
	"ssh_exec":               {},
	"ssh_connection_status":  {},
	"ssh_privilege":          {},
	"ssh_transfer":           {},
	"ssh_read_file":          {},
	"ssh_write_file":         {},
	"ssh_apply_patch":        {},
	"ssh_disconnect":         {},
	"ssh_profile":            {},
	"ssh_cnote":              {},
	"ssh_profile_setup":      {},
	"ssh_credentials_prompt": {},
	"ssh_key_setup":          {},
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

func stringPtrArg(args map[string]any, key string) *string {
	v, ok := args[key]
	if !ok || v == nil {
		return nil
	}
	s, ok := v.(string)
	if !ok {
		return nil
	}
	s = strings.TrimSpace(s)
	return &s
}

func intPtrArg(args map[string]any, key string) *int {
	v, ok := args[key]
	if !ok || v == nil {
		return nil
	}
	n := app.ParseIntAny(v, 0)
	return &n
}

func boolPtrArg(args map[string]any, key string) *bool {
	v, ok := args[key]
	if !ok || v == nil {
		return nil
	}
	b := app.ParseBoolAny(v, false)
	return &b
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
		case errorsx.CodeConnectionDead:
			code = -32010
		case errorsx.CodeReconnectFailed:
			code = -32011
		case errorsx.CodeFileExists:
			code = -32007
		case errorsx.CodeChecksumMismatch:
			code = -32008
		case errorsx.CodeChecksumUnavailable:
			code = -32009
		case errorsx.CodeResumeUnavailable:
			code = -32015
		case errorsx.CodeContentTooLarge:
			code = -32012
		case errorsx.CodeKeyPassphraseRequired:
			code = -32013
		case errorsx.CodeKeyNotFound:
			code = -32014
		case errorsx.CodeCancelled:
			code = -32800
		}
		data := map[string]any{"code": ce.Code}
		for k, v := range ce.Data {
			data[k] = v
		}
		return rpcError(id, code, ce.Message, data)
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

func writeMessage(w io.Writer, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	body = append(body, '\n')
	_, err = w.Write(body)
	return err
}

func newProgressReporter(s *Server, toolName string, token any) *progressReporter {
	if s == nil || (toolName != "ssh_exec" && toolName != "ssh_transfer" && toolName != "ssh_credentials_prompt" && toolName != "ssh_key_setup") {
		return nil
	}
	now := time.Now()
	return &progressReporter{
		server:            s,
		token:             token,
		flushInterval:     progressFlushInterval,
		heartbeatInterval: progressHeartbeatInterval,
		started:           now,
		lastSent:          now,
	}
}

func progressTokenFromParams(meta map[string]any, args map[string]any) any {
	token, ok := progressTokenFromMeta(meta)
	if ok {
		return token
	}
	if nested, ok := args["_meta"].(map[string]any); ok {
		token, ok = progressTokenFromMeta(nested)
		if ok {
			return token
		}
	}
	return nil
}

func progressTokenFromMeta(meta map[string]any) (any, bool) {
	if len(meta) == 0 {
		return nil, false
	}
	token, ok := meta["progressToken"]
	if !ok {
		return nil, false
	}
	switch token.(type) {
	case string, float64, int, int32, int64, uint, uint32, uint64:
		return token, true
	default:
		return nil, false
	}
}

func (r *progressReporter) Start(ctx context.Context) {
	if r == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(progressTickInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if msg, ok := r.nextTickMessage(); ok {
					r.emit(msg)
				}
			}
		}
	}()
}

func (r *progressReporter) OnProgress(p sshbridge.ExecProgress) {
	if r == nil {
		return
	}
	if msg, ok := r.appendChunk(normalizeProgressChunk(p.Stream, p.Chunk)); ok {
		r.emit(msg)
	}
}

func (r *progressReporter) Close() {
	if r == nil {
		return
	}
	if msg, ok := r.closePending(); ok {
		r.emit(msg)
	}
}

func (r *progressReporter) Discard() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	r.pending.Reset()
}

func (r *progressReporter) appendChunk(chunk string) (string, bool) {
	if chunk == "" {
		return "", false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return "", false
	}
	r.pending.WriteString(chunk)
	if countRunes(r.pending.String()) < progressMaxMessageRunes {
		return "", false
	}
	msg := truncateProgressMessage(r.pending.String())
	r.pending.Reset()
	r.lastSent = time.Now()
	return msg, true
}

func (r *progressReporter) nextTickMessage() (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return "", false
	}
	now := time.Now()
	if r.pending.Len() > 0 && now.Sub(r.lastSent) >= r.flushInterval {
		msg := truncateProgressMessage(r.pending.String())
		r.pending.Reset()
		r.lastSent = now
		return msg, true
	}
	if r.pending.Len() == 0 && now.Sub(r.lastSent) >= r.heartbeatInterval {
		r.lastSent = now
		return fmt.Sprintf("Command still running (%s elapsed).", formatElapsed(now.Sub(r.started))), true
	}
	return "", false
}

func (r *progressReporter) closePending() (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return "", false
	}
	r.closed = true
	if r.pending.Len() == 0 {
		return "", false
	}
	msg := truncateProgressMessage(r.pending.String())
	r.pending.Reset()
	return msg, true
}

func (r *progressReporter) emit(message string) {
	if r == nil || strings.TrimSpace(message) == "" {
		return
	}
	if r.token == nil {
		if !r.server.shouldEmitLogLevel(loggingLevelInfo) {
			return
		}
		payload := map[string]any{
			"jsonrpc": "2.0",
			"method":  "notifications/message",
			"params": map[string]any{
				"level":  loggingLevelName(loggingLevelInfo),
				"logger": "ssh_exec",
				"data":   message,
			},
		}
		r.server.writeMu.Lock()
		defer r.server.writeMu.Unlock()
		_ = writeMessage(r.server.out, payload)
		return
	}
	r.mu.Lock()
	r.seq++
	progress := r.seq
	r.mu.Unlock()
	payload := map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/progress",
		"params": map[string]any{
			"progressToken": r.token,
			"progress":      progress,
			"message":       message,
		},
	}
	r.server.writeMu.Lock()
	defer r.server.writeMu.Unlock()
	_ = writeMessage(r.server.out, payload)
}

func (s *Server) shouldEmitLogLevel(level loggingLevel) bool {
	return level >= loggingLevel(s.minLogLevel.Load())
}

func parseLoggingLevel(level string) (loggingLevel, bool) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return loggingLevelDebug, true
	case "info":
		return loggingLevelInfo, true
	case "notice":
		return loggingLevelNotice, true
	case "warning":
		return loggingLevelWarning, true
	case "error":
		return loggingLevelError, true
	case "critical":
		return loggingLevelCritical, true
	case "alert":
		return loggingLevelAlert, true
	case "emergency":
		return loggingLevelEmergency, true
	default:
		return 0, false
	}
}

func loggingLevelName(level loggingLevel) string {
	switch level {
	case loggingLevelDebug:
		return "debug"
	case loggingLevelInfo:
		return "info"
	case loggingLevelNotice:
		return "notice"
	case loggingLevelWarning:
		return "warning"
	case loggingLevelError:
		return "error"
	case loggingLevelCritical:
		return "critical"
	case loggingLevelAlert:
		return "alert"
	case loggingLevelEmergency:
		return "emergency"
	default:
		return "info"
	}
}

func normalizeProgressChunk(_ string, chunk string) string {
	if chunk == "" {
		return ""
	}
	chunk = strings.ReplaceAll(chunk, "\r\n", "\n")
	chunk = strings.ReplaceAll(chunk, "\r", "\n")
	return chunk
}

func truncateProgressMessage(msg string) string {
	msg = strings.Trim(msg, "\n")
	if msg == "" {
		return ""
	}
	runes := []rune(msg)
	if len(runes) <= progressMaxMessageRunes {
		return msg
	}
	return "...\n" + string(runes[len(runes)-progressMaxMessageRunes:])
}

func countRunes(s string) int {
	return len([]rune(s))
}

func formatElapsed(d time.Duration) string {
	if d < time.Minute {
		seconds := int(d.Round(time.Second) / time.Second)
		if seconds < 1 {
			seconds = 1
		}
		return fmt.Sprintf("%ds", seconds)
	}
	minutes := int(d / time.Minute)
	seconds := int((d % time.Minute) / time.Second)
	return fmt.Sprintf("%dm%02ds", minutes, seconds)
}

func toolDefs(ctlPath string) []map[string]any {
	return []map[string]any{
		tool(
			"ssh_connect",
			"Profile-based only. Requires profile_id or profile_name. If no profile exists, first call ssh_profile_setup(step=save) to create one. "+
				"Workflow: ssh_profile_setup(step=save) -> ssh_key_setup (if key auth) -> ssh_credentials_prompt (if needed) -> ssh_connect -> ssh_exec. "+
				"Optional limit_dir narrows runtime access to a specific subdirectory.",
			connectSchema(),
			mutatingAnnotations("Connect to SSH Host", true),
		),
		tool(
			"ssh_open_session",
			"Create a reusable shell session bound to an existing connection_id. Optional cwd/shell let later ssh_exec calls reuse context.",
			reqSchema([]string{"connection_id"}, "connection_id", "cwd", "shell"),
			mutatingAnnotations("Open Shell Session", false),
		),
		tool(
			"ssh_exec",
			"Run a command on remote host. Requires connection_id and command. Optional session_id/cwd/timeout_sec. Catastrophic commands (rm -rf /, fork bombs) are hard-denied. Dangerous commands (mkfs, shutdown) return approval_required. When approval_required is returned, the user must run `"+ctlPath+" approve <id>` in a separate terminal, then retry with approval_token.",
			reqSchema([]string{"connection_id", "command"}, "connection_id", "command", "session_id", "cwd", "timeout_sec", "approval_token"),
			mutatingAnnotations("Execute Remote Command", true),
		),
		tool(
			"ssh_connection_status",
			"Inspect SSH connection health. Optional connection_id targets one connection; without it returns all active in-memory connections. Optional timeout_sec controls health-check timeout.",
			reqSchema(nil, "connection_id", "timeout_sec"),
			readOnlyAnnotations("Check Connection Health", false),
		),
		tool(
			"ssh_privilege",
			"Manage privilege grants. action=status (default) inspects grants, optional connection_id narrows scope, active_only defaults true. action=revoke revokes a grant immediately by grant_id.",
			privilegeSchema(),
			mutatingAnnotations("Manage Privilege Grants", false),
		),
		tool(
			"ssh_transfer",
			"Transfer files or directories using scp client with existing connection_id (remote_path is workspace_roots guarded). Modern OpenSSH uses SFTP mode by default; Cssh retries legacy SCP when SFTP subsystem is unavailable. direction=upload(local->remote) or download(remote->local). Requires direction/connection_id/local_path/remote_path. Optional mode(create|overwrite), create_parents, verify_checksum, timeout_sec, allow_local_anywhere, approval_token. Set recursive=true for directory transfers. Set resume=true only for single-file overwrite transfers when both local and remote have rsync; otherwise retry without resume=true. Local path access: paths within cwd and the profile's allowed_local_paths (e.g. /tmp) are auto-allowed; paths outside both require allow_local_anywhere=true which triggers L2 approval showing the exact local and remote paths.",
			transferSchema(),
			destructiveAnnotations("Transfer File via SCP", true),
		),
		tool(
			"ssh_read_file",
			"Read remote file with line numbers. Returns numbered content + metadata (size, total_lines). "+
				"Use offset/limit for partial reads. Binary files return metadata only — use ssh_transfer to download. "+
				"Symlinks resolved and checked against workspace_roots.",
			readFileSchema(),
			readOnlyAnnotations("Read Remote File", true),
		),
		tool(
			"ssh_write_file",
			"Write remote file content inside workspace_roots (max 5 MB; use ssh_transfer for larger files). mode: create fails if exists, overwrite atomically replaces, append creates or appends. Default: overwrite.",
			reqSchema([]string{"connection_id", "path", "content"}, "connection_id", "path", "content", "mode", "cwd"),
			destructiveAnnotations("Write Remote File", true),
		),
		tool(
			"ssh_apply_patch",
			"Apply unified patch via patch(1) on remote host (workspace_roots guarded). Requires connection_id + patch_unified; base_dir defaults to '/'. Uses --batch --fuzz=0 for strict, non-interactive patching. Set dry_run=true to validate without modifying files. strip controls leading path component removal (patch -pN): 0 (default) for absolute/relative paths, 1 for standard git diff with a/ b/ prefixes.",
			reqSchema([]string{"connection_id", "patch_unified"}, "connection_id", "patch_unified", "base_dir", "dry_run", "strip"),
			destructiveAnnotations("Apply Patch on Remote", true),
		),
		tool(
			"ssh_disconnect",
			"Close an SSH connection and attached sessions. Requires connection_id.",
			reqSchema([]string{"connection_id"}, "connection_id"),
			annotations("Disconnect SSH", false, true, true, false),
		),
		tool(
			"ssh_profile",
			"Unified profile operations. action=list returns saved SSH profiles. action=delete deletes one profile by profile_id using confirmation token flow (first call returns confirm_required + confirm_token; second call includes confirm_token). Optional delete_secrets (default true) also removes password/key_passphrase/sudo_password from keychain.",
			profileSchema(),
			mutatingAnnotations("Manage SSH Profiles", false),
		),
		tool(
			"ssh_cnote",
			"Manage per-profile Cnote (connection note) — a persistent, per-profile scratchpad for the AI. "+
				"Use it to record observations, user preferences, environment quirks, or recurring instructions specific to this profile so that future sessions can pick up where you left off. "+
				"action=get reads the current Cnote. action=set overwrites it. action=append adds a new block (preferred for incremental notes). action=clear empties it. "+
				"The Cnote is automatically returned in ssh_connect responses; you do not need to call get after connecting. "+
				"Use profile_id when possible; profile_name is supported if unique.",
			cnoteSchema(),
			mutatingAnnotations("Manage Connection Notes", false),
		),
		tool(
			"ssh_profile_setup",
			"Unified quick setup flow. step=template returns onboarding form template. step=save persists SSH profile metadata. "+
				"step=edit modifies existing profile fields (provide profile_id + fields to change; auth_priority overrides auth_mode if both given). "+
				"For save step, provide purpose/host/username plus optional profile/workspace/auth/security fields. After save, call ssh_credentials_prompt for credential entry.",
			profileSetupSchema(),
			mutatingAnnotations("Setup SSH Profile", false),
		),
		tool(
			"ssh_credentials_prompt",
			"Open a secure local web form for the user to enter SSH credentials directly into the OS keychain. Credentials NEVER pass through AI. Default path is web prompt. If web is unavailable, tool returns manual `"+ctlPath+" secret set-*` commands with profile_id. Call this AFTER ssh_profile_setup(step=save) when auth requires password or key passphrase. For sudo, set fields=[\"sudo_password\"].",
			credentialPromptSchema(),
			mutatingAnnotations("Enter SSH Credentials", false),
		),
		tool(
			"ssh_key_setup",
			"Open a local form for the user to select an SSH private key and optional passphrase. "+
				"Scans directory for keys, shows passphrase status. Saves key_path to profile, passphrase to keychain. "+
				"AI never sees keys or passphrases. Use after profile creation when auth includes key, "+
				"or when KEY_PASSPHRASE_REQUIRED / KEY_NOT_FOUND errors occur.",
			keySetupSchema(),
			mutatingAnnotations("Setup SSH Key", false),
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
	for _, key := range []string{"profile_id", "profile_name", "limit_dir"} {
		props[key] = paramSchema(key)
	}
	return map[string]any{
		"type":        "object",
		"properties":  props,
		"description": "Provide profile_id or profile_name. Create a profile first with ssh_profile_setup(step=save) if none exists.",
	}
}

func readFileSchema() map[string]any {
	props := map[string]any{}
	for _, k := range []string{"connection_id", "path", "cwd"} {
		props[k] = paramSchema(k)
	}
	props["offset"] = map[string]any{
		"type":        "integer",
		"description": "Start line (1-based). Default 1.",
	}
	props["limit"] = map[string]any{
		"type":        "integer",
		"description": "Maximum lines to return. Default 2000.",
	}
	props["max_bytes"] = map[string]any{
		"type":        "integer",
		"description": "Byte cap on returned content. Default 524288 (512KB), max 2097152 (2MB).",
	}
	return map[string]any{
		"type":       "object",
		"properties": props,
		"required":   []string{"connection_id", "path"},
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

func transferSchema() map[string]any {
	props := map[string]any{}
	for _, k := range []string{"direction", "connection_id", "local_path", "remote_path", "cwd", "timeout_sec", "create_parents", "verify_checksum", "allow_local_anywhere", "approval_token", "recursive", "resume"} {
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
		"required":   []string{"direction", "connection_id", "local_path", "remote_path"},
	}
}

func privilegeSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"action":        map[string]any{"type": "string", "enum": []string{"status", "revoke"}, "description": "Privilege action. status lists grants. revoke requires grant_id."},
			"connection_id": paramSchema("connection_id"),
			"active_only":   paramSchema("active_only"),
			"grant_id":      paramSchema("grant_id"),
		},
	}
}

func profileSchema() map[string]any {
	return reqSchema(nil, "action", "profile_id", "delete_secrets", "confirm_token")
}

func cnoteSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"action": map[string]any{
				"type":        "string",
				"enum":        []string{"get", "set", "append", "clear"},
				"description": "Cnote action. get reads the current Cnote. set overwrites it. append adds a new block. clear empties it.",
			},
			"profile_id":   paramSchema("profile_id"),
			"profile_name": paramSchema("profile_name"),
			"content":      paramSchema("content"),
		},
	}
}

func profileSetupSchema() map[string]any {
	return reqSchema(nil, "step", "purpose", "profile_id", "profile_name", "host", "port", "username", "auth_mode", "auth_priority", "workspace_roots", "workspace_root", "allowed_local_paths", "key_path", "security_profile", "allow_root_user", "grant_ttl_sec")
}

func keySetupSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"profile_id":  paramSchema("profile_id"),
			"scan_dir":    map[string]any{"type": "string", "description": "Directory to scan for SSH keys. Defaults to ~/.ssh/"},
			"prompt_mode": paramSchema("prompt_mode"),
		},
		"required": []string{"profile_id"},
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
	case "workspace_roots":
		return map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Allowed remote root paths for read/write operations."}
	case "allowed_local_paths":
		return map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Local directories allowed for ssh_transfer without approval. Paths within these dirs and cwd are auto-allowed; paths outside require allow_local_anywhere + L2 approval. Defaults to system temp dirs (/tmp). Pass empty array to clear."}
	case "limit_dir":
		return map[string]any{"type": "string", "description": "Optional runtime restriction directory. When set, effective workspace_roots become this directory only (must be within configured roots)."}
	case "workspace_root":
		return map[string]any{"type": "string", "description": "Single workspace root (shortcut if not using workspace_roots array)."}
	case "security_profile":
		return map[string]any{"type": "string", "enum": []string{"easy_safe", "ops_strict"}, "description": "Security profile for privilege approval behavior."}
	case "allow_root_user":
		return map[string]any{"type": "boolean", "description": "Allow root SSH user for this profile."}
	case "grant_ttl_sec":
		return map[string]any{"type": "integer", "description": "Reusable grant lifetime. 0 = valid for entire connection (default). >0 = expires after N seconds."}
	case "delete_secrets":
		return map[string]any{"type": "boolean", "description": "When deleting profile, also delete password/key passphrase/sudo password from keychain. Default true."}
	case "confirm_token":
		return map[string]any{"type": "string", "description": "Confirmation token returned by ssh_profile action=delete first call."}
	case "action":
		return map[string]any{"type": "string", "enum": []string{"list", "delete"}, "description": "Profile action. list returns all profiles. delete requires profile_id (and may require confirm_token)."}
	case "step":
		return map[string]any{"type": "string", "enum": []string{"template", "save", "edit"}, "description": "Profile setup step. template returns form defaults; save persists profile metadata; edit modifies existing profile fields."}
	case "auth_priority":
		return map[string]any{"type": "array", "items": map[string]any{"type": "string", "enum": []string{"key", "password"}}, "description": "Explicit auth priority order. Overrides auth_mode if both provided."}
	case "direction":
		return map[string]any{"type": "string", "enum": []string{"upload", "download"}, "description": "Transfer direction. upload copies local_path to remote_path; download copies remote_path to local_path."}
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
		return map[string]any{"type": "string", "description": "Working directory for command execution. Validated against workspace_roots for write commands."}
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
		return map[string]any{"type": "integer", "description": "Byte cap on returned content. Default 524288 (512KB), max 2097152 (2MB)."}
	case "content":
		return map[string]any{"type": "string", "description": "File content payload for write operation."}
	case "mode":
		return map[string]any{"type": "string", "enum": []string{"create", "overwrite", "append"}, "description": "Write mode. create: fails if file exists. overwrite (default): atomic replace via temp file. append: creates file or appends to existing."}
	case "create_parents":
		return map[string]any{"type": "boolean", "description": "Create destination parent directories if missing. Default true."}
	case "verify_checksum":
		return map[string]any{"type": "boolean", "description": "For single files, verify SHA-256 between local and remote after transfer. For directories, verify file-count consistency and return verification_type/result. Default true."}
	case "allow_local_anywhere":
		return map[string]any{"type": "boolean", "description": "Allow local path outside cwd and the profile's allowed_local_paths. Triggers L2 approval showing the exact local/remote paths. Default false."}
	case "recursive":
		return map[string]any{"type": "boolean", "description": "Transfer entire directory recursively via scp -r. remote_path is the target directory itself (not its parent). Only mode=create is supported for directories (fails if target exists). overwrite is not supported for directories."}
	case "resume":
		return map[string]any{"type": "boolean", "description": "Resume interrupted transfer using rsync. Supported only for single-file overwrite transfers when both local and remote have rsync. If unavailable, retry without resume=true."}
	case "patch_unified":
		return map[string]any{"type": "string", "description": "Unified diff patch text."}
	case "base_dir":
		return map[string]any{"type": "string", "description": "Base directory to apply patch in."}
	case "dry_run":
		return map[string]any{"type": "boolean", "description": "Dry-run mode: validate patch without applying. Default false."}
	case "strip":
		return map[string]any{"type": "integer", "description": "Strip N leading path components from file names (patch -pN). 0 for absolute/relative paths (default), 1 for standard git diff a/b/ prefix format."}
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

func tool(name, desc string, input map[string]any, ann ...map[string]any) map[string]any {
	t := map[string]any{"name": name, "description": desc, "inputSchema": input}
	if len(ann) > 0 && ann[0] != nil {
		t["annotations"] = ann[0]
	}
	return t
}

// annotations builds an MCP tool annotations object (MCP spec 2025-03-26).
func annotations(title string, readOnly, destructive, idempotent, openWorld bool) map[string]any {
	return map[string]any{
		"title":           title,
		"readOnlyHint":    readOnly,
		"destructiveHint": destructive,
		"idempotentHint":  idempotent,
		"openWorldHint":   openWorld,
	}
}

func readOnlyAnnotations(title string, openWorld bool) map[string]any {
	return annotations(title, true, false, true, openWorld)
}

func mutatingAnnotations(title string, openWorld bool) map[string]any {
	return annotations(title, false, false, false, openWorld)
}

func destructiveAnnotations(title string, openWorld bool) map[string]any {
	return annotations(title, false, true, false, openWorld)
}
