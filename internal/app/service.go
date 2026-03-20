package app

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"cssh/internal/approvals"
	"cssh/internal/audit"
	"cssh/internal/config"
	"cssh/internal/errorsx"
	"cssh/internal/model"
	"cssh/internal/resolve"
	"cssh/internal/security"
	"cssh/internal/sshbridge"
	"cssh/internal/store"
	"cssh/internal/util"
)

type Service struct {
	cfg       model.Config
	profiles  *store.ProfileStore
	cnotes    *store.ProfileNoteStore
	secrets   store.SecretStore
	approvals *approvals.Store
	grants    *approvals.GrantStore
	audit     *audit.Logger
	ssh       *sshbridge.Manager

	deleteMu     sync.Mutex
	deleteTokens map[string]profileDeleteConfirm
}

type profileDeleteConfirm struct {
	ProfileID string
	ExpiresAt time.Time
}

var lookPath = exec.LookPath

func NewService(cfg model.Config) *Service {
	svc := &Service{
		cfg:          cfg,
		profiles:     store.NewProfileStore(cfg.ProfilesFile),
		cnotes:       store.NewProfileNoteStore(cfg.RuntimeDir),
		secrets:      store.NewSecretStore(),
		approvals:    approvals.NewStore(pathJoin(cfg.RuntimeDir, "approvals.jsonl")),
		grants:       approvals.NewGrantStore(pathJoin(cfg.RuntimeDir, "grants.json")),
		audit:        audit.NewLogger(cfg.LogsDir),
		ssh:          sshbridge.NewManager(cfg.RuntimeDir, cfg.DefaultShell, cfg.DefaultTimeoutSec),
		deleteTokens: map[string]profileDeleteConfirm{},
	}
	svc.ssh.SetOnReconnect(func(connectionID, reason string) {
		_ = svc.grants.RevokeByConnection(connectionID)
		_ = svc.audit.Write(model.AuditEvent{
			Timestamp:    time.Now().UTC(),
			TraceID:      util.NewID("trace"),
			Type:         "ssh_auto_reconnect",
			ConnectionID: connectionID,
			Status:       "ok",
			Detail:       reason,
		})
	})
	return svc
}

// Shutdown closes all SSH connections. Call on process exit.
func (s *Service) Shutdown() { s.ssh.Shutdown() }

// enrichWithReconnectInfo adds reconnect metadata to a response if the
// connection was auto-reconnected since the last call.
func (s *Service) enrichWithReconnectInfo(resp map[string]any, connectionID string) {
	reconnected, reason := s.ssh.ReconnectInfo(connectionID)
	if reconnected {
		resp["reconnected"] = true
		resp["reconnect_reason"] = reason
	}
}

func pathJoin(a, b string) string {
	if strings.HasSuffix(a, "/") {
		return a + b
	}
	return a + "/" + b
}

func (s *Service) ensureProfileCnotePath(profile *model.Profile) string {
	if strings.TrimSpace(profile.NotePath) == "" {
		profile.NotePath = s.cnotes.ResolvePath(profile.ID)
	}
	return profile.NotePath
}

func (s *Service) persistProfileCnotePath(profile *model.Profile) error {
	if profile == nil {
		return nil
	}
	if strings.TrimSpace(profile.NotePath) != "" {
		return nil
	}
	profile.NotePath = s.cnotes.ResolvePath(profile.ID)
	return s.profiles.Upsert(*profile)
}

func (s *Service) readProfileCnote(profile *model.Profile) (string, string, error) {
	path := s.ensureProfileCnotePath(profile)
	if err := s.cnotes.Ensure(path); err != nil {
		return "", "", err
	}
	content, err := s.cnotes.Read(path)
	if err != nil {
		return "", "", err
	}
	return path, strings.TrimRight(content, "\n"), nil
}

func cnotePreview(content string) string {
	trimmed := strings.TrimSpace(strings.ReplaceAll(content, "\n", " "))
	if len(trimmed) <= 120 {
		return trimmed
	}
	return trimmed[:120] + "..."
}

func (s *Service) ProfileStore() *store.ProfileStore   { return s.profiles }
func (s *Service) CnoteStore() *store.ProfileNoteStore { return s.cnotes }
func (s *Service) SecretStore() store.SecretStore      { return s.secrets }
func (s *Service) Approvals() *approvals.Store         { return s.approvals }
func (s *Service) Grants() *approvals.GrantStore       { return s.grants }

func (s *Service) AuditToolCall(tool, status, detail string) {
	tool = strings.TrimSpace(tool)
	if tool == "" {
		return
	}
	_ = s.audit.Write(model.AuditEvent{
		Timestamp: time.Now().UTC(),
		TraceID:   util.NewID("trace"),
		Type:      "tool_call",
		Command:   tool,
		Status:    status,
		Detail:    strings.TrimSpace(detail),
	})
}

func (s *Service) Connect(input model.ConnectionInput) (map[string]any, error) {
	traceID := util.NewID("trace")
	connModel, err := s.resolveConnectionInput(input)
	if err != nil {
		return nil, err
	}
	if !connModel.AllowPublicHost && !security.IsPrivateOrLoopbackHost(connModel.Host) {
		return nil, errorsx.New(errorsx.CodeInvalidParams, "public host denied by policy; use VPN/Tailscale address or enable allow_public_host")
	}

	conn, err := s.ssh.Connect(connModel)
	if err != nil {
		return nil, err
	}
	_ = s.audit.Write(model.AuditEvent{
		Timestamp:       time.Now().UTC(),
		TraceID:         traceID,
		Type:            "ssh_connect",
		ConnectionID:    conn.ID,
		Host:            conn.Host,
		Status:          "ok",
		SecurityProfile: conn.SecurityProfile,
	})
	resp := map[string]any{
		"connection_id":    conn.ID,
		"capabilities":     []string{"exec", "file_read", "file_write", "file_transfer", "search", "patch", "tail"},
		"workspace_roots":  conn.WorkspaceRoots,
		"security_profile": conn.SecurityProfile,
	}
	if strings.TrimSpace(conn.ProfileID) != "" {
		resp["cnote_path"] = conn.CnotePath
		resp["cnote"] = conn.Cnote
		cnotePresent := strings.TrimSpace(conn.Cnote) != ""
		resp["cnote_present"] = cnotePresent
		if cnotePresent {
			resp["cnote_hint"] = "This profile has a Cnote — follow the instructions/preferences within. Use ssh_cnote(action=append) to add new observations during this session."
		} else {
			resp["cnote_hint"] = "This profile has no Cnote yet. If you discover useful preferences, environment details, or recurring patterns during this session, consider recording them with ssh_cnote(action=append) so future sessions benefit."
		}
	}
	if strings.TrimSpace(conn.LimitDir) != "" {
		resp["limit_dir"] = conn.LimitDir
	}
	if conn.AllowPublicHost && !security.IsPrivateOrLoopbackHost(conn.Host) {
		resp["warnings"] = []string{"connected to a public host because allow_public_host=true; verify profile and remote host trust"}
	}
	return resp, nil
}

func (s *Service) OpenSession(connectionID, cwd, shell string) (map[string]any, error) {
	traceID := util.NewID("trace")
	session, err := s.ssh.OpenSession(connectionID, cwd, shell)
	if err != nil {
		return nil, err
	}
	_ = s.audit.Write(model.AuditEvent{
		Timestamp:    time.Now().UTC(),
		TraceID:      traceID,
		Type:         "ssh_open_session",
		ConnectionID: connectionID,
		SessionID:    session.ID,
		Status:       "ok",
	})
	return map[string]any{"session_id": session.ID}, nil
}

func (s *Service) Exec(connectionID, sessionID, command, cwd string, timeoutSec int, approvalToken string) (map[string]any, error) {
	return s.ExecWithContext(context.Background(), connectionID, sessionID, command, cwd, timeoutSec, approvalToken)
}

func (s *Service) ExecWithContext(ctx context.Context, connectionID, sessionID, command, cwd string, timeoutSec int, approvalToken string) (map[string]any, error) {
	return s.ExecWithProgress(ctx, connectionID, sessionID, command, cwd, timeoutSec, approvalToken, nil)
}

func (s *Service) ExecWithProgress(ctx context.Context, connectionID, sessionID, command, cwd string, timeoutSec int, approvalToken string, onProgress sshbridge.ExecProgressFn) (map[string]any, error) {
	if ctx.Err() != nil {
		return nil, errorsx.New(errorsx.CodeCancelled, "request cancelled")
	}
	traceID := util.NewID("trace")
	auditCommand := sanitizeCommandForAudit(command)
	conn, err := s.ssh.GetConnection(connectionID)
	if err != nil {
		return nil, err
	}
	policy := security.EvaluateExecPolicyWithProfile(command, conn.MaxAutoRisk, conn.AllowReboot, conn.AllowDiskOps, conn.DenyPatterns, conn.WorkspaceRoots, conn.SecurityProfile)
	authz := privilegeAuthz{}

	// DenyAlways: hard deny, no override possible
	if policy.DenyClass == model.DenyAlways {
		_ = s.audit.Write(model.AuditEvent{
			Timestamp:       time.Now().UTC(),
			TraceID:         traceID,
			Type:            "ssh_exec",
			ConnectionID:    connectionID,
			SessionID:       sessionID,
			Command:         auditCommand,
			RiskLevel:       string(policy.RiskLevel),
			Status:          "denied_always",
			SecurityProfile: conn.SecurityProfile,
			Capability:      policy.Capability,
			CommandHash:     policy.TemplateHash,
		})
		return map[string]any{
			"status":     "denied",
			"deny_class": string(model.DenyAlways),
			"reason":     policy.Reason,
		}, nil
	}

	// DenyNeedApprove: requires out-of-band human approval via csshctl approve
	if policy.DenyClass == model.DenyNeedApprove {
		authz, err = s.authorizePrivilege(connectionID, sessionID, policy.Capability, command, policy.Template, policy.TemplateHash, policy.RiskLevel, policy.Reason, approvalToken, conn.Host, conn.Username, policy.Reusable, conn.GrantTTLSec)
		if err != nil {
			return nil, err
		}
		if !authz.Allowed {
			_ = s.audit.Write(model.AuditEvent{
				Timestamp:       time.Now().UTC(),
				TraceID:         traceID,
				Type:            "ssh_exec",
				ConnectionID:    connectionID,
				SessionID:       sessionID,
				Command:         auditCommand,
				RiskLevel:       string(policy.RiskLevel),
				Status:          "approval_required",
				SecurityProfile: conn.SecurityProfile,
				Capability:      policy.Capability,
				CommandHash:     policy.TemplateHash,
				ConfirmMode:     authz.ConfirmMode,
			})
			return authz.StatusResp, nil
		}
	}

	runCommand := command
	runInput := ""
	if policy.Capability == "sudo_exec" && s.cfg.SudoEnabled {
		var statusResp map[string]any
		runCommand, runInput, statusResp, err = s.prepareSudoCommand(*conn, command)
		if err != nil {
			return nil, err
		}
		if statusResp != nil {
			return statusResp, nil
		}
	}

	res, err := s.ssh.ExecWithProgressCtx(ctx, connectionID, sessionID, runCommand, cwd, timeoutSec, runInput, onProgress)
	if err != nil {
		return nil, err
	}
	status := "ok"
	if res.ExitCode != 0 {
		status = "nonzero_exit"
	}
	_ = s.audit.Write(model.AuditEvent{
		Timestamp:       time.Now().UTC(),
		TraceID:         traceID,
		Type:            "ssh_exec",
		ConnectionID:    connectionID,
		SessionID:       sessionID,
		Host:            conn.Host,
		Command:         auditCommand,
		RiskLevel:       string(policy.RiskLevel),
		Status:          status,
		ExitCode:        res.ExitCode,
		DurationMS:      res.DurationMS,
		SecurityProfile: conn.SecurityProfile,
		Capability:      policy.Capability,
		CommandHash:     policy.TemplateHash,
		ConfirmMode:     authz.ConfirmMode,
		GrantID:         authz.GrantID,
	})
	stdout, stdoutTrunc, stdoutOrigLen := truncateOutput(res.Stdout)
	stderr, stderrTrunc, stderrOrigLen := truncateOutput(res.Stderr)

	// Best-effort save full output to remote temp file if anything was truncated.
	var overflowPath string
	if stdoutTrunc || stderrTrunc {
		var combined strings.Builder
		if stdoutTrunc {
			combined.WriteString("=== STDOUT ===\n")
			combined.WriteString(res.Stdout)
			combined.WriteString("\n")
		}
		if stderrTrunc {
			combined.WriteString("=== STDERR ===\n")
			combined.WriteString(res.Stderr)
			combined.WriteString("\n")
		}
		overflowPath = s.saveFullOutputRemote(connectionID, combined.String())
	}

	resp := map[string]any{
		"exit_code":   res.ExitCode,
		"stdout":      stdout,
		"stderr":      stderr,
		"duration_ms": res.DurationMS,
	}

	if stdoutTrunc || stderrTrunc {
		truncMeta := map[string]any{}
		if stdoutTrunc {
			truncMeta["stdout_original_bytes"] = stdoutOrigLen
		}
		if stderrTrunc {
			truncMeta["stderr_original_bytes"] = stderrOrigLen
		}
		if overflowPath != "" {
			truncMeta["full_output_path"] = overflowPath
			truncMeta["retrieve_hint"] = "Use ssh_read_file or ssh_exec with: cat " + overflowPath
		}
		resp["truncated"] = truncMeta
	}

	s.enrichWithReconnectInfo(resp, connectionID)
	return resp, nil
}

func (s *Service) ConnectionStatus(connectionID string, timeoutSec int) (map[string]any, error) {
	traceID := util.NewID("trace")
	if timeoutSec <= 0 {
		timeoutSec = 5
	}
	buildStatus := func(conn model.Connection) (map[string]any, error) {
		alive, socketExists, msg, err := s.ssh.CheckConnection(conn.ID, timeoutSec)
		if err != nil {
			return nil, err
		}
		sessions := s.ssh.ListSessionsByConnection(conn.ID)
		sessionItems := make([]map[string]any, 0, len(sessions))
		for _, sess := range sessions {
			sessionItems = append(sessionItems, map[string]any{
				"session_id": sess.ID,
				"cwd":        sess.CWD,
				"shell":      sess.Shell,
				"created_at": sess.CreatedAt.Format(time.RFC3339),
			})
		}
		return map[string]any{
			"connection_id":         conn.ID,
			"host":                  conn.Host,
			"port":                  conn.Port,
			"username":              conn.Username,
			"workspace_roots":       conn.WorkspaceRoots,
			"limit_dir":             conn.LimitDir,
			"security_profile":      conn.SecurityProfile,
			"created_at":            conn.CreatedAt.Format(time.RFC3339),
			"connected":             alive,
			"control_socket_exists": socketExists,
			"status_message":        msg,
			"session_count":         len(sessionItems),
			"sessions":              sessionItems,
			"checked_at":            time.Now().UTC().Format(time.RFC3339),
		}, nil
	}

	if strings.TrimSpace(connectionID) != "" {
		conn, err := s.ssh.GetConnection(connectionID)
		if err != nil {
			return nil, err
		}
		item, err := buildStatus(*conn)
		if err != nil {
			return nil, err
		}
		out := map[string]any{"connections": []map[string]any{item}}
		_ = s.audit.Write(model.AuditEvent{
			Timestamp:    time.Now().UTC(),
			TraceID:      traceID,
			Type:         "ssh_connection_status",
			ConnectionID: connectionID,
			Status:       "ok",
		})
		return out, nil
	}

	conns := s.ssh.ListConnections()
	sort.Slice(conns, func(i, j int) bool {
		if conns[i].CreatedAt.Equal(conns[j].CreatedAt) {
			return conns[i].ID < conns[j].ID
		}
		return conns[i].CreatedAt.Before(conns[j].CreatedAt)
	})
	items := make([]map[string]any, 0, len(conns))
	for _, conn := range conns {
		item, err := buildStatus(conn)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	out := map[string]any{"connections": items}
	_ = s.audit.Write(model.AuditEvent{
		Timestamp: time.Now().UTC(),
		TraceID:   traceID,
		Type:      "ssh_connection_status",
		Status:    "ok",
		Detail:    "all_connections",
	})
	return out, nil
}

func (s *Service) PrivilegeStatus(connectionID string, activeOnly bool) (map[string]any, error) {
	traceID := util.NewID("trace")
	items, err := s.grants.List(connectionID, activeOnly)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(items))
	for _, g := range items {
		out = append(out, map[string]any{
			"grant_id":              g.ID,
			"connection_id":         g.ConnectionID,
			"capability":            g.Capability,
			"command_template_hash": g.CommandHash,
			"risk_level":            g.RiskLevel,
			"status":                g.Status,
			"created_at":            g.CreatedAt.Format(time.RFC3339),
			"expires_at": func() string {
				if g.ExpiresAt.IsZero() {
					return "session"
				}
				return g.ExpiresAt.Format(time.RFC3339)
			}(),
			"approved_by": g.ApprovedBy,
			"source":      g.Source,
		})
	}
	resp := map[string]any{"grants": out}
	_ = s.audit.Write(model.AuditEvent{
		Timestamp:    time.Now().UTC(),
		TraceID:      traceID,
		Type:         "ssh_privilege",
		ConnectionID: connectionID,
		Status:       "ok",
	})
	return resp, nil
}

func (s *Service) RevokePrivilege(grantID string) (map[string]any, error) {
	traceID := util.NewID("trace")
	g, err := s.grants.Revoke(grantID)
	if err != nil {
		return nil, err
	}
	if g == nil {
		return nil, errorsx.New(errorsx.CodeInvalidParams, "grant_id not found")
	}
	resp := map[string]any{
		"revoked":               true,
		"grant_id":              g.ID,
		"connection_id":         g.ConnectionID,
		"capability":            g.Capability,
		"command_template_hash": g.CommandHash,
		"status":                g.Status,
	}
	_ = s.audit.Write(model.AuditEvent{
		Timestamp:    time.Now().UTC(),
		TraceID:      traceID,
		Type:         "ssh_privilege",
		ConnectionID: g.ConnectionID,
		Status:       "ok",
		GrantID:      g.ID,
	})
	return resp, nil
}

func (s *Service) UploadFile(connectionID, localPath, remotePath, mode, cwd string, timeoutSec int, createParents, verifyChecksum, allowLocalAnywhere bool, approvalToken string, recursive, resume bool, onProgress sshbridge.ExecProgressFn) (map[string]any, error) {
	traceID := util.NewID("trace")
	timeoutSec = normalizeTransferTimeout(timeoutSec)
	mode, err := normalizeTransferMode(mode)
	if err != nil {
		return nil, err
	}

	conn, err := s.ssh.GetConnection(connectionID)
	if err != nil {
		return nil, err
	}
	authz := privilegeAuthz{}
	if allowLocalAnywhere {
		template := "ssh_transfer direction=upload allow_local_anywhere"
		authz, err = s.authorizePrivilege(
			connectionID,
			"",
			"local_anywhere_transfer",
			template,
			template,
			security.HashCommandTemplate(template),
			model.RiskL2,
			"allow_local_anywhere requires explicit approval",
			approvalToken,
			conn.Host,
			conn.Username,
			false, // not reusable: explicit privilege escalation
			conn.GrantTTLSec,
		)
		if err != nil {
			return nil, err
		}
		if !authz.Allowed {
			_ = s.audit.Write(model.AuditEvent{
				Timestamp:       time.Now().UTC(),
				TraceID:         traceID,
				Type:            "ssh_transfer",
				ConnectionID:    connectionID,
				Host:            conn.Host,
				RiskLevel:       string(model.RiskL2),
				Status:          "approval_required",
				SecurityProfile: conn.SecurityProfile,
				Capability:      "local_anywhere_transfer",
				CommandHash:     security.HashCommandTemplate(template),
				ConfirmMode:     authz.ConfirmMode,
			})
			return authz.StatusResp, nil
		}
	}

	localAbs, err := security.ResolveLocalPath(localPath)
	if err != nil {
		return nil, errorsx.New(errorsx.CodeInvalidParams, "local_path is invalid")
	}
	if err := ensureLocalPathAllowed(localAbs, allowLocalAnywhere); err != nil {
		return nil, err
	}
	info, err := os.Stat(localAbs)
	if err != nil {
		return nil, errorsx.New(errorsx.CodeInvalidParams, "local_path not found")
	}
	isDir := info.IsDir()
	if isDir && !recursive {
		return nil, errorsx.New(errorsx.CodeInvalidParams,
			"local_path is a directory; set recursive=true to transfer directories")
	}
	if !isDir && !info.Mode().IsRegular() {
		return nil, errorsx.New(errorsx.CodeInvalidParams, "local_path must be a regular file or directory")
	}
	// recursive=true on a regular file: silently ignore, transfer as single file
	if !isDir {
		recursive = false
		if resume {
			if err := validateResumeMode(mode); err != nil {
				return nil, err
			}
		}
	}

	if isDir {
		if mode == "overwrite" {
			return nil, errorsx.New(errorsx.CodeInvalidParams,
				"overwrite is not supported for directory transfers; remove the target first with ssh_exec if needed")
		}
		if resume {
			return nil, errorsx.New(errorsx.CodeInvalidParams,
				"resume is not supported for directory transfers")
		}
		fileCount, totalBytes, err := localDirStats(localAbs)
		if err != nil {
			return nil, errorsx.New(errorsx.CodeInvalidParams, err.Error())
		}
		if err := security.ValidateLocalDirSymlinks(localAbs); err != nil {
			return nil, errorsx.New(errorsx.CodeInvalidParams, "directory contains unsafe symlinks: "+err.Error())
		}
		return s.uploadDirectory(traceID, connectionID, conn, localAbs, remotePath, cwd, timeoutSec, createParents, verifyChecksum, fileCount, totalBytes, onProgress)
	}

	// --- single file upload ---
	remoteResolved := s.resolveAndCheckPath(conn, remotePath, cwd)
	if remoteResolved == "" {
		return nil, errorsx.New(errorsx.CodePathForbidden, "remote_path is outside workspace_roots")
	}

	// Resume path: use rsync if available
	if resume {
		if err := s.ensureResumeAvailable(connectionID); err != nil {
			return nil, err
		}
		return s.uploadFileWithResume(traceID, connectionID, conn, localAbs, remoteResolved, timeoutSec, createParents, verifyChecksum, onProgress)
	}

	if createParents {
		if err := s.remoteMkdirAll(connectionID, path.Dir(remoteResolved)); err != nil {
			return nil, err
		}
	}

	uploadTarget := remoteResolved
	remoteTemp := ""
	if mode == "create" {
		remoteTemp = transferTempPath(remoteResolved)
		uploadTarget = remoteTemp
	}
	transferRes, err := s.ssh.UploadFile(connectionID, localAbs, uploadTarget, timeoutSec, false, onProgress)
	auditDetail := transferAuditDetail(localAbs+" -> "+remoteResolved, transferRes)
	durationMS := transferRes.DurationMS
	if err != nil {
		if remoteTemp != "" {
			s.remoteRemoveFile(connectionID, remoteTemp)
		}
		s.writeTransferAudit(traceID, "ssh_transfer", connectionID, conn.Host, remoteResolved, "nonzero_exit", auditDetail, durationMS)
		return nil, err
	}
	if mode == "create" {
		if err := s.remoteInstallCreateOnly(connectionID, remoteTemp, remoteResolved); err != nil {
			s.remoteRemoveFile(connectionID, remoteTemp)
			s.writeTransferAudit(traceID, "ssh_transfer", connectionID, conn.Host, remoteResolved, "nonzero_exit", auditDetail, durationMS)
			return nil, err
		}
	}

	localSHA := ""
	remoteSHA := ""
	if verifyChecksum {
		localSHA, err = localFileSHA256(localAbs)
		if err != nil {
			return nil, errorsx.New(errorsx.CodeInternal, err.Error())
		}
		remoteSHA, err = s.remoteFileSHA256(connectionID, remoteResolved, timeoutSec)
		if err != nil {
			return nil, err
		}
		if err := ensureChecksumsMatch(localSHA, remoteSHA); err != nil {
			s.writeTransferAudit(traceID, "ssh_transfer", connectionID, conn.Host, remoteResolved, "checksum_mismatch", auditDetail, durationMS)
			return nil, err
		}
	}

	s.writeTransferAudit(traceID, "ssh_transfer", connectionID, conn.Host, remoteResolved, "ok", auditDetail, durationMS)
	resp := map[string]any{
		"bytes":             info.Size(),
		"local_sha256":      localSHA,
		"remote_sha256":     remoteSHA,
		"local_path":        localAbs,
		"remote_path":       remoteResolved,
		"duration_ms":       durationMS,
		"transfer_protocol": transferRes.Protocol,
		"fallback_used":     transferRes.FallbackUsed,
	}
	if transferRes.FallbackUsed && transferRes.FallbackReason != "" {
		resp["fallback_reason"] = transferRes.FallbackReason
	}
	s.enrichWithReconnectInfo(resp, connectionID)
	return resp, nil
}

func (s *Service) uploadDirectory(traceID, connectionID string, conn *model.Connection, localAbs, remotePath, cwd string, timeoutSec int, createParents, verifyChecksum bool, fileCount int, totalBytes int64, onProgress sshbridge.ExecProgressFn) (map[string]any, error) {
	remoteResolved := s.resolveAndCheckPath(conn, remotePath, cwd)
	if remoteResolved == "" {
		return nil, errorsx.New(errorsx.CodePathForbidden, "remote_path is outside workspace_roots")
	}

	// Ensure target doesn't exist + create parent
	if err := s.remoteEnsureNewDir(connectionID, remoteResolved, createParents); err != nil {
		return nil, err
	}

	transferRes, err := s.ssh.UploadFile(connectionID, localAbs, remoteResolved, timeoutSec, true, onProgress)
	auditDetail := transferAuditDetail(fmt.Sprintf("%s -> %s (dir, %d files, %d bytes)", localAbs, remoteResolved, fileCount, totalBytes), transferRes)
	durationMS := transferRes.DurationMS
	if err != nil {
		s.writeTransferAudit(traceID, "ssh_transfer", connectionID, conn.Host, remoteResolved, "nonzero_exit", auditDetail, durationMS)
		return nil, err
	}

	// Best-effort file count verification
	verificationType, verificationResult := "none", "skipped"
	if verifyChecksum {
		remoteCount, countErr := s.remoteFileCount(connectionID, remoteResolved, timeoutSec)
		if countErr != nil {
			s.writeTransferAudit(traceID, "ssh_transfer", connectionID, conn.Host, remoteResolved, "verification_failed", auditDetail, durationMS)
			return nil, countErr
		}
		verificationType, verificationResult, err = directoryVerificationResult(true, fileCount, remoteCount)
		if err != nil {
			s.writeTransferAudit(traceID, "ssh_transfer", connectionID, conn.Host, remoteResolved, "verification_mismatch", auditDetail, durationMS)
			return nil, err
		}
	}

	s.writeTransferAudit(traceID, "ssh_transfer", connectionID, conn.Host, remoteResolved, "ok", auditDetail, durationMS)
	resp := map[string]any{
		"transfer_type":       "directory",
		"file_count":          fileCount,
		"total_bytes":         totalBytes,
		"bytes":               totalBytes,
		"verification_type":   verificationType,
		"verification_result": verificationResult,
		"local_path":          localAbs,
		"remote_path":         remoteResolved,
		"duration_ms":         durationMS,
		"transfer_protocol":   transferRes.Protocol,
		"fallback_used":       transferRes.FallbackUsed,
	}
	if transferRes.FallbackUsed && transferRes.FallbackReason != "" {
		resp["fallback_reason"] = transferRes.FallbackReason
	}
	s.enrichWithReconnectInfo(resp, connectionID)
	return resp, nil
}

func (s *Service) uploadFileWithResume(traceID, connectionID string, conn *model.Connection, localAbs, remoteResolved string, timeoutSec int, createParents, verifyChecksum bool, onProgress sshbridge.ExecProgressFn) (map[string]any, error) {
	if createParents {
		if err := s.remoteMkdirAll(connectionID, path.Dir(remoteResolved)); err != nil {
			return nil, err
		}
	}

	var transferRes sshbridge.TransferResult
	var err error
	transferRes, err = s.ssh.RunRsync(connectionID, timeoutSec, localAbs, remoteResolved, true, onProgress)

	auditDetail := transferAuditDetail(localAbs+" -> "+remoteResolved, transferRes)
	durationMS := transferRes.DurationMS
	if err != nil {
		s.writeTransferAudit(traceID, "ssh_transfer", connectionID, conn.Host, remoteResolved, "nonzero_exit", auditDetail, durationMS)
		return nil, err
	}

	info, err := os.Stat(localAbs)
	if err != nil {
		return nil, errorsx.New(errorsx.CodeInternal, err.Error())
	}

	localSHA := ""
	remoteSHA := ""
	if verifyChecksum {
		localSHA, err = localFileSHA256(localAbs)
		if err != nil {
			return nil, errorsx.New(errorsx.CodeInternal, err.Error())
		}
		remoteSHA, err = s.remoteFileSHA256(connectionID, remoteResolved, timeoutSec)
		if err != nil {
			return nil, err
		}
		if err := ensureChecksumsMatch(localSHA, remoteSHA); err != nil {
			s.writeTransferAudit(traceID, "ssh_transfer", connectionID, conn.Host, remoteResolved, "checksum_mismatch", auditDetail, durationMS)
			return nil, err
		}
	}

	s.writeTransferAudit(traceID, "ssh_transfer", connectionID, conn.Host, remoteResolved, "ok", auditDetail, durationMS)
	resp := map[string]any{
		"bytes":             info.Size(),
		"local_sha256":      localSHA,
		"remote_sha256":     remoteSHA,
		"local_path":        localAbs,
		"remote_path":       remoteResolved,
		"duration_ms":       durationMS,
		"transfer_protocol": transferRes.Protocol,
		"fallback_used":     transferRes.FallbackUsed,
	}
	if transferRes.FallbackUsed && transferRes.FallbackReason != "" {
		resp["fallback_reason"] = transferRes.FallbackReason
	}
	s.enrichWithReconnectInfo(resp, connectionID)
	return resp, nil
}

func (s *Service) DownloadFile(connectionID, remotePath, localPath, mode, cwd string, timeoutSec int, createParents, verifyChecksum, allowLocalAnywhere bool, approvalToken string, recursive, resume bool, onProgress sshbridge.ExecProgressFn) (map[string]any, error) {
	traceID := util.NewID("trace")
	timeoutSec = normalizeTransferTimeout(timeoutSec)
	mode, err := normalizeTransferMode(mode)
	if err != nil {
		return nil, err
	}

	conn, err := s.ssh.GetConnection(connectionID)
	if err != nil {
		return nil, err
	}
	authz := privilegeAuthz{}
	if allowLocalAnywhere {
		template := "ssh_transfer direction=download allow_local_anywhere"
		authz, err = s.authorizePrivilege(
			connectionID,
			"",
			"local_anywhere_transfer",
			template,
			template,
			security.HashCommandTemplate(template),
			model.RiskL2,
			"allow_local_anywhere requires explicit approval",
			approvalToken,
			conn.Host,
			conn.Username,
			false, // not reusable: explicit privilege escalation
			conn.GrantTTLSec,
		)
		if err != nil {
			return nil, err
		}
		if !authz.Allowed {
			_ = s.audit.Write(model.AuditEvent{
				Timestamp:       time.Now().UTC(),
				TraceID:         traceID,
				Type:            "ssh_transfer",
				ConnectionID:    connectionID,
				Host:            conn.Host,
				RiskLevel:       string(model.RiskL2),
				Status:          "approval_required",
				SecurityProfile: conn.SecurityProfile,
				Capability:      "local_anywhere_transfer",
				CommandHash:     security.HashCommandTemplate(template),
				ConfirmMode:     authz.ConfirmMode,
			})
			return authz.StatusResp, nil
		}
	}

	remoteResolved := s.resolveAndCheckPath(conn, remotePath, cwd)
	if remoteResolved == "" {
		return nil, errorsx.New(errorsx.CodePathForbidden, "remote_path is outside workspace_roots")
	}

	pathType, err := s.remotePathType(connectionID, remoteResolved)
	if err != nil {
		return nil, err
	}
	switch pathType {
	case "directory":
		if !recursive {
			return nil, errorsx.New(errorsx.CodeInvalidParams,
				"remote_path is a directory; set recursive=true to transfer directories")
		}
		if mode == "overwrite" {
			return nil, errorsx.New(errorsx.CodeInvalidParams,
				"overwrite is not supported for directory transfers; remove the target first with ssh_exec if needed")
		}
		if resume {
			return nil, errorsx.New(errorsx.CodeInvalidParams,
				"resume is not supported for directory transfers")
		}
		return s.downloadDirectory(traceID, connectionID, conn, remoteResolved, localPath, timeoutSec, createParents, verifyChecksum, allowLocalAnywhere, onProgress)
	case "file":
		// fall through to single-file download
	default:
		return nil, errorsx.New(errorsx.CodeInvalidParams, "remote_path not found")
	}

	localAbs, err := security.ResolveLocalPath(localPath)
	if err != nil {
		return nil, errorsx.New(errorsx.CodeInvalidParams, "local_path is invalid")
	}
	if err := ensureLocalPathAllowed(localAbs, allowLocalAnywhere); err != nil {
		return nil, err
	}

	// Resume path: use rsync if available
	if resume {
		if err := validateResumeMode(mode); err != nil {
			return nil, err
		}
		if err := s.ensureResumeAvailable(connectionID); err != nil {
			return nil, err
		}
		return s.downloadFileWithResume(traceID, connectionID, conn, remoteResolved, localAbs, timeoutSec, createParents, verifyChecksum, onProgress)
	}

	if createParents {
		if err := os.MkdirAll(filepath.Dir(localAbs), 0o755); err != nil {
			return nil, errorsx.New(errorsx.CodeInternal, err.Error())
		}
	}
	if mode == "create" {
		if _, err := os.Stat(localAbs); err == nil {
			return nil, errorsx.New(errorsx.CodeFileExists, "local target exists")
		} else if !os.IsNotExist(err) {
			return nil, errorsx.New(errorsx.CodeInternal, err.Error())
		}
	}

	downloadTarget := localAbs
	localTemp := ""
	if mode == "create" {
		localTemp = transferTempPath(localAbs)
		downloadTarget = localTemp
	}
	transferRes, err := s.ssh.DownloadFile(connectionID, remoteResolved, downloadTarget, timeoutSec, false, onProgress)
	auditDetail := transferAuditDetail(remoteResolved+" -> "+localAbs, transferRes)
	durationMS := transferRes.DurationMS
	if err != nil {
		if localTemp != "" {
			_ = os.Remove(localTemp)
		}
		s.writeTransferAudit(traceID, "ssh_transfer", connectionID, conn.Host, remoteResolved, "nonzero_exit", auditDetail, durationMS)
		return nil, err
	}
	if mode == "create" {
		if err := installLocalCreateOnly(localTemp, localAbs); err != nil {
			s.writeTransferAudit(traceID, "ssh_transfer", connectionID, conn.Host, remoteResolved, "nonzero_exit", auditDetail, durationMS)
			return nil, err
		}
	}
	info, err := os.Stat(localAbs)
	if err != nil {
		return nil, errorsx.New(errorsx.CodeInternal, err.Error())
	}
	if !info.Mode().IsRegular() {
		return nil, errorsx.New(errorsx.CodeInternal, "downloaded file is not regular")
	}

	localSHA := ""
	remoteSHA := ""
	if verifyChecksum {
		remoteSHA, err = s.remoteFileSHA256(connectionID, remoteResolved, timeoutSec)
		if err != nil {
			return nil, err
		}
		localSHA, err = localFileSHA256(localAbs)
		if err != nil {
			return nil, errorsx.New(errorsx.CodeInternal, err.Error())
		}
		if err := ensureChecksumsMatch(localSHA, remoteSHA); err != nil {
			s.writeTransferAudit(traceID, "ssh_transfer", connectionID, conn.Host, remoteResolved, "checksum_mismatch", auditDetail, durationMS)
			return nil, err
		}
	}

	s.writeTransferAudit(traceID, "ssh_transfer", connectionID, conn.Host, remoteResolved, "ok", auditDetail, durationMS)
	resp := map[string]any{
		"bytes":             info.Size(),
		"local_sha256":      localSHA,
		"remote_sha256":     remoteSHA,
		"local_path":        localAbs,
		"remote_path":       remoteResolved,
		"duration_ms":       durationMS,
		"transfer_protocol": transferRes.Protocol,
		"fallback_used":     transferRes.FallbackUsed,
	}
	if transferRes.FallbackUsed && transferRes.FallbackReason != "" {
		resp["fallback_reason"] = transferRes.FallbackReason
	}
	s.enrichWithReconnectInfo(resp, connectionID)
	return resp, nil
}

func (s *Service) downloadDirectory(traceID, connectionID string, conn *model.Connection, remoteResolved, localPath string, timeoutSec int, createParents, verifyChecksum, allowLocalAnywhere bool, onProgress sshbridge.ExecProgressFn) (map[string]any, error) {
	localAbs, err := security.ResolveLocalPath(localPath)
	if err != nil {
		return nil, errorsx.New(errorsx.CodeInvalidParams, "local_path is invalid")
	}
	if err := ensureLocalPathAllowed(localAbs, allowLocalAnywhere); err != nil {
		return nil, err
	}

	// mode=create: local path must not exist
	if _, err := os.Stat(localAbs); err == nil {
		return nil, errorsx.New(errorsx.CodeFileExists, "local target exists")
	} else if !os.IsNotExist(err) {
		return nil, errorsx.New(errorsx.CodeInternal, err.Error())
	}
	if createParents {
		if err := os.MkdirAll(filepath.Dir(localAbs), 0o755); err != nil {
			return nil, errorsx.New(errorsx.CodeInternal, err.Error())
		}
	}

	remoteCount := 0
	if verifyChecksum {
		remoteCount, err = s.remoteFileCount(connectionID, remoteResolved, timeoutSec)
		if err != nil {
			return nil, err
		}
	}

	transferRes, err := s.ssh.DownloadFile(connectionID, remoteResolved, localAbs, timeoutSec, true, onProgress)
	auditDetail := transferAuditDetail(fmt.Sprintf("%s -> %s (dir)", remoteResolved, localAbs), transferRes)
	durationMS := transferRes.DurationMS
	if err != nil {
		_ = os.RemoveAll(localAbs) // clean up partial download
		s.writeTransferAudit(traceID, "ssh_transfer", connectionID, conn.Host, remoteResolved, "nonzero_exit", auditDetail, durationMS)
		return nil, err
	}

	// Post-download: validate symlinks
	if symlinkErr := security.ValidateLocalDirSymlinks(localAbs); symlinkErr != nil {
		_ = os.RemoveAll(localAbs) // remove tainted directory
		s.writeTransferAudit(traceID, "ssh_transfer", connectionID, conn.Host, remoteResolved, "symlink_violation", auditDetail, durationMS)
		return nil, errorsx.New(errorsx.CodeInvalidParams, "downloaded directory contains unsafe symlinks: "+symlinkErr.Error())
	}

	localCount, localBytes, _ := localDirStats(localAbs)

	verificationType, verificationResult, err := directoryVerificationResult(verifyChecksum, remoteCount, localCount)
	if err != nil {
		s.writeTransferAudit(traceID, "ssh_transfer", connectionID, conn.Host, remoteResolved, "verification_mismatch", auditDetail, durationMS)
		return nil, err
	}

	s.writeTransferAudit(traceID, "ssh_transfer", connectionID, conn.Host, remoteResolved, "ok", auditDetail, durationMS)
	resp := map[string]any{
		"transfer_type":       "directory",
		"file_count":          localCount,
		"total_bytes":         localBytes,
		"bytes":               localBytes,
		"verification_type":   verificationType,
		"verification_result": verificationResult,
		"local_path":          localAbs,
		"remote_path":         remoteResolved,
		"duration_ms":         durationMS,
		"transfer_protocol":   transferRes.Protocol,
		"fallback_used":       transferRes.FallbackUsed,
	}
	if transferRes.FallbackUsed && transferRes.FallbackReason != "" {
		resp["fallback_reason"] = transferRes.FallbackReason
	}
	s.enrichWithReconnectInfo(resp, connectionID)
	return resp, nil
}

func (s *Service) downloadFileWithResume(traceID, connectionID string, conn *model.Connection, remoteResolved, localAbs string, timeoutSec int, createParents, verifyChecksum bool, onProgress sshbridge.ExecProgressFn) (map[string]any, error) {
	if createParents {
		if err := os.MkdirAll(filepath.Dir(localAbs), 0o755); err != nil {
			return nil, errorsx.New(errorsx.CodeInternal, err.Error())
		}
	}

	var transferRes sshbridge.TransferResult
	var err error
	transferRes, err = s.ssh.RunRsync(connectionID, timeoutSec, remoteResolved, localAbs, false, onProgress)

	auditDetail := transferAuditDetail(remoteResolved+" -> "+localAbs, transferRes)
	durationMS := transferRes.DurationMS
	if err != nil {
		s.writeTransferAudit(traceID, "ssh_transfer", connectionID, conn.Host, remoteResolved, "nonzero_exit", auditDetail, durationMS)
		return nil, err
	}

	info, err := os.Stat(localAbs)
	if err != nil {
		return nil, errorsx.New(errorsx.CodeInternal, err.Error())
	}

	localSHA := ""
	remoteSHA := ""
	if verifyChecksum {
		remoteSHA, err = s.remoteFileSHA256(connectionID, remoteResolved, timeoutSec)
		if err != nil {
			return nil, err
		}
		localSHA, err = localFileSHA256(localAbs)
		if err != nil {
			return nil, errorsx.New(errorsx.CodeInternal, err.Error())
		}
		if err := ensureChecksumsMatch(localSHA, remoteSHA); err != nil {
			s.writeTransferAudit(traceID, "ssh_transfer", connectionID, conn.Host, remoteResolved, "checksum_mismatch", auditDetail, durationMS)
			return nil, err
		}
	}

	s.writeTransferAudit(traceID, "ssh_transfer", connectionID, conn.Host, remoteResolved, "ok", auditDetail, durationMS)
	resp := map[string]any{
		"bytes":             info.Size(),
		"local_sha256":      localSHA,
		"remote_sha256":     remoteSHA,
		"local_path":        localAbs,
		"remote_path":       remoteResolved,
		"duration_ms":       durationMS,
		"transfer_protocol": transferRes.Protocol,
		"fallback_used":     transferRes.FallbackUsed,
	}
	if transferRes.FallbackUsed && transferRes.FallbackReason != "" {
		resp["fallback_reason"] = transferRes.FallbackReason
	}
	s.enrichWithReconnectInfo(resp, connectionID)
	return resp, nil
}

const (
	readFileDefaultMaxBytes = 512 * 1024     // 512KB
	readFileHardMaxBytes    = 2 * 1024 * 1024 // 2MB
	readFileDefaultOffset   = 1
	readFileDefaultLimit    = 2000
)

type readFileResult struct {
	RealPath     string
	Size         int64
	TotalLines   int
	Binary       bool
	MimeEncoding string
	Content      string
	LineStart    int
	LineEnd      int
	Truncated    bool
}

func normalizeReadFileParams(maxBytes, offset, limit int) (int, int, int) {
	if maxBytes <= 0 {
		maxBytes = readFileDefaultMaxBytes
	}
	if maxBytes > readFileHardMaxBytes {
		maxBytes = readFileHardMaxBytes
	}
	if offset <= 0 {
		offset = readFileDefaultOffset
	}
	if limit <= 0 {
		limit = readFileDefaultLimit
	}
	return maxBytes, offset, limit
}

func buildReadFileCmd(quotedPath string, offset, limit, maxBytes int) string {
	return fmt.Sprintf(`_p=%s
_rp="$(realpath -e "$_p" 2>/dev/null || readlink -f "$_p" 2>/dev/null)" || exit 1
test -f "$_rp" || exit 2
_sz=$(wc -c < "$_rp") || exit 3
_sz=${_sz##* }
_me=""
_bin=false
if command -v file >/dev/null 2>&1; then
  _me="$(file -b --mime-encoding "$_rp" 2>/dev/null)" || true
  case "$_me" in binary) _bin=true;; esac
else
  _n=$(head -c 8192 "$_rp" | tr -cd '\000' | wc -c | tr -d ' ')
  [ "${_n:-0}" -gt 0 ] 2>/dev/null && _bin=true
fi
if [ "$_bin" = true ]; then
  printf '%%s\n%%s\n0\n%%s\n%%s\n' "$_rp" "$_sz" "$_bin" "$_me"
  exit 0
fi
_lc=$(wc -l < "$_rp") && _lc=${_lc##* } || _lc=0
printf '%%s\n%%s\n%%s\n%%s\n%%s\n' "$_rp" "$_sz" "$_lc" "$_bin" "$_me"
awk -v s=%d -v e=%d 'NR>=s&&NR<=e{printf "%%6d\t%%s\n",NR,$0}NR>e{exit}' "$_rp" | head -c %d`,
		quotedPath, offset, offset+limit-1, maxBytes)
}

func parseLeadingLineNum(line string) int {
	idx := strings.IndexByte(line, '\t')
	if idx < 0 {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(line[:idx]))
	if err != nil {
		return 0
	}
	return n
}

func parseReadFileOutput(stdout string, maxBytes int) (readFileResult, error) {
	parts := strings.SplitN(stdout, "\n", 6)
	if len(parts) < 5 {
		return readFileResult{}, fmt.Errorf("malformed read_file output: expected at least 5 header lines, got %d", len(parts))
	}
	var r readFileResult
	r.RealPath = parts[0]
	size, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
	if err != nil {
		return readFileResult{}, fmt.Errorf("invalid size: %q", parts[1])
	}
	r.Size = size
	totalLines, err := strconv.Atoi(strings.TrimSpace(parts[2]))
	if err != nil {
		return readFileResult{}, fmt.Errorf("invalid total_lines: %q", parts[2])
	}
	r.TotalLines = totalLines
	r.Binary = strings.TrimSpace(parts[3]) == "true"
	r.MimeEncoding = strings.TrimSpace(parts[4])

	if r.Binary {
		return r, nil
	}

	content := ""
	if len(parts) == 6 {
		content = parts[5]
	}

	if content != "" {
		lines := strings.Split(content, "\n")
		// Trim trailing empty line from final newline
		if len(lines) > 0 && lines[len(lines)-1] == "" {
			lines = lines[:len(lines)-1]
		}
		if len(lines) > 0 {
			r.LineStart = parseLeadingLineNum(lines[0])
			r.LineEnd = parseLeadingLineNum(lines[len(lines)-1])
		}
	}

	r.Content = content
	r.Truncated = len(content) >= maxBytes
	if r.LineEnd > r.TotalLines {
		r.TotalLines = r.LineEnd
	}
	return r, nil
}

func buildReadFileResponse(parsed readFileResult) map[string]any {
	resp := map[string]any{
		"size": parsed.Size,
	}
	if parsed.Binary {
		resp["binary"] = true
		resp["content"] = ""
		if parsed.MimeEncoding != "" {
			resp["mime_encoding"] = parsed.MimeEncoding
		}
		resp["note"] = "use ssh_transfer to download"
		return resp
	}
	resp["content"] = parsed.Content
	resp["total_lines"] = parsed.TotalLines
	resp["line_start"] = parsed.LineStart
	resp["line_end"] = parsed.LineEnd
	resp["truncated"] = parsed.Truncated
	return resp
}

func (s *Service) ReadFile(connectionID, filePath string, maxBytes, offset, limit int, cwd string) (map[string]any, error) {
	traceID := util.NewID("trace")
	conn, err := s.ssh.GetConnection(connectionID)
	if err != nil {
		return nil, err
	}
	maxBytes, offset, limit = normalizeReadFileParams(maxBytes, offset, limit)

	// Text-level pre-check (fast fail for obviously bad paths)
	resolved := s.resolveAndCheckPath(conn, filePath, cwd)
	if resolved == "" {
		return nil, errorsx.New(errorsx.CodePathForbidden, "path is outside workspace_roots")
	}

	cmd := buildReadFileCmd(util.ShellQuote(resolved), offset, limit, maxBytes)
	res, err := s.ssh.Exec(connectionID, "", cmd, "", 60)
	if err != nil {
		return nil, err
	}
	switch res.ExitCode {
	case 0:
		// success
	case 1:
		return nil, errorsx.New(errorsx.CodeInvalidParams, "path not found or cannot resolve symlink")
	case 2:
		return nil, errorsx.New(errorsx.CodeInvalidParams, "path is not a regular file")
	case 3:
		return nil, errorsx.New(errorsx.CodeInvalidParams, "cannot read file (permission denied or I/O error)")
	default:
		return nil, commandResultError(res, "read file failed")
	}

	parsed, err := parseReadFileOutput(res.Stdout, maxBytes)
	if err != nil {
		return nil, errorsx.New(errorsx.CodeInvalidParams, err.Error())
	}

	// Security-critical: check the resolved real path against workspace_roots
	if !security.IsWithinRoots(parsed.RealPath, conn.WorkspaceRoots) {
		return nil, errorsx.New(errorsx.CodePathForbidden, "resolved path is outside workspace_roots")
	}

	resp := buildReadFileResponse(parsed)

	_ = s.audit.Write(model.AuditEvent{
		Timestamp:    time.Now().UTC(),
		TraceID:      traceID,
		Type:         "ssh_read_file",
		ConnectionID: connectionID,
		FilePath:     parsed.RealPath,
		Status:       "ok",
	})
	s.enrichWithReconnectInfo(resp, connectionID)
	return resp, nil
}

const maxWriteFileBytes = 5 * 1024 * 1024 // 5 MB

const (
	execOutputTruncateThreshold = 128 * 1024 // 128KB per stream triggers truncation
	execOutputHeadBytes         = 16 * 1024  // keep first 16KB
	execOutputTailBytes         = 48 * 1024  // keep last 48KB (results/errors usually most relevant)
	execOverflowSaveTimeout     = 30         // seconds for remote save
)

// truncateOutput returns a head+tail truncated version of s if it exceeds the
// threshold. It adjusts cut points to avoid splitting multi-byte UTF-8 chars.
func truncateOutput(s string) (result string, truncated bool, originalLen int) {
	originalLen = len(s)
	if originalLen <= execOutputTruncateThreshold {
		return s, false, originalLen
	}

	// Advance head boundary to a valid rune start to avoid splitting a multi-byte char.
	head := execOutputHeadBytes
	for head < originalLen && head < execOutputHeadBytes+3 && !utf8.RuneStart(s[head]) {
		head++
	}

	// Retreat tail start to a valid rune start.
	tailStart := originalLen - execOutputTailBytes
	for tailStart > head && tailStart < originalLen && !utf8.RuneStart(s[tailStart]) {
		tailStart++
	}

	marker := fmt.Sprintf(
		"\n\n--- OUTPUT TRUNCATED ---\nShowing first %d and last %d of %d bytes.\n--- END TRUNCATION NOTICE ---\n\n",
		head, originalLen-tailStart, originalLen,
	)
	return s[:head] + marker + s[tailStart:], true, originalLen
}

// saveFullOutputRemote saves full command output to a temp file on the remote
// host. Best-effort: returns the remote path on success or "" on failure.
func (s *Service) saveFullOutputRemote(connectionID, content string) string {
	remotePath := "/tmp/cssh-exec-" + util.NewID("out") + ".log"
	ctx, cancel := context.WithTimeout(context.Background(), execOverflowSaveTimeout*time.Second)
	defer cancel()
	cmd := "cat > " + util.ShellQuote(remotePath)
	res, err := s.ssh.ExecWithInputCtx(ctx, connectionID, "", cmd, "", execOverflowSaveTimeout, content)
	if err != nil || res.ExitCode != 0 {
		return ""
	}
	return remotePath
}

// buildWriteFileCmd constructs a shell command that reads base64 data from stdin
// and writes the decoded content to resolved. Returns ("", error) for invalid mode.
func buildWriteFileCmd(resolved, mode string) (string, error) {
	q := util.ShellQuote(resolved)
	dir := path.Dir(resolved)
	mkdir := "mkdir -p " + util.ShellQuote(dir)

	switch mode {
	case "create":
		// set -C (noclobber) as secondary guard; explicit existence check with exit 17 as primary.
		return mkdir + " && set -C; if [ -e " + q + " ]; then exit 17; fi; " +
			"base64 -d > " + q, nil
	case "append":
		return mkdir + " && base64 -d >> " + q, nil
	case "overwrite":
		// Atomic: write to temp file in same directory, then mv.
		// trap ensures temp file cleanup on any failure.
		return mkdir + ` && _t="$(mktemp ` + util.ShellQuote(dir) + `/tmp.XXXXXX)" && ` +
			`trap 'rm -f "$_t"' EXIT && ` +
			`base64 -d > "$_t" && ` +
			`{ [ -e ` + q + ` ] && chmod --reference=` + q + ` "$_t" 2>/dev/null; true; } && ` +
			`mv -f "$_t" ` + q, nil
	default:
		return "", errorsx.New(errorsx.CodeInvalidParams, "mode must be create|overwrite|append")
	}
}

func (s *Service) WriteFile(connectionID, filePath, content, mode, cwd string) (map[string]any, error) {
	if len(content) > maxWriteFileBytes {
		return nil, errorsx.New(errorsx.CodeContentTooLarge,
			fmt.Sprintf("content exceeds %d bytes; use ssh_transfer for large files", maxWriteFileBytes))
	}
	traceID := util.NewID("trace")
	conn, err := s.ssh.GetConnection(connectionID)
	if err != nil {
		return nil, err
	}
	resolved := s.resolveAndCheckPath(conn, filePath, cwd)
	if resolved == "" {
		return nil, errorsx.New(errorsx.CodePathForbidden, "path is outside workspace_roots")
	}
	if mode == "" {
		mode = "overwrite"
	}
	cmd, err := buildWriteFileCmd(resolved, mode)
	if err != nil {
		return nil, err
	}
	enc := base64.StdEncoding.EncodeToString([]byte(content))
	res, err := s.ssh.ExecWithInput(connectionID, "", cmd, "", 60, enc)
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		if res.ExitCode == 17 {
			return nil, errorsx.New(errorsx.CodeFileExists, "target already exists")
		}
		return nil, errorsx.New(errorsx.CodeInternal, strings.TrimSpace(res.Stderr))
	}
	_ = s.audit.Write(model.AuditEvent{
		Timestamp:    time.Now().UTC(),
		TraceID:      traceID,
		Type:         "ssh_write_file",
		ConnectionID: connectionID,
		FilePath:     resolved,
		RiskLevel:    string(model.RiskL1),
		Status:       "ok",
	})
	resp := map[string]any{"bytes_written": len(content)}
	s.enrichWithReconnectInfo(resp, connectionID)
	return resp, nil
}

func (s *Service) ApplyPatch(connectionID, patchUnified, baseDir string, dryRun bool, strip int) (map[string]any, error) {
	traceID := util.NewID("trace")
	conn, err := s.ssh.GetConnection(connectionID)
	if err != nil {
		return nil, err
	}
	base := s.resolveAndCheckPath(conn, baseDir, "")
	if base == "" {
		return nil, errorsx.New(errorsx.CodePathForbidden, "base_dir is outside workspace_roots")
	}
	enc := base64.StdEncoding.EncodeToString([]byte(patchUnified))

	patchFlags := fmt.Sprintf("--batch --fuzz=0 -p%d", strip)
	if dryRun {
		patchFlags += " --dry-run"
	}
	cmd := "cd " + util.ShellQuote(base) + " && echo " + util.ShellQuote(enc) + " | base64 -d | patch " + patchFlags

	res, err := s.ssh.Exec(connectionID, "", cmd, "", 120)
	if err != nil {
		return nil, err
	}
	out := res.Stdout + "\n" + res.Stderr

	totalHunks := countPatchHunks(patchUnified)
	var filesPatched []string
	hunksFailed := 0
	for _, line := range strings.Split(out, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "patching file ") {
			filesPatched = append(filesPatched, strings.TrimPrefix(l, "patching file "))
		}
		if strings.HasPrefix(l, "Hunk #") && strings.Contains(l, "FAILED") {
			hunksFailed++
		}
	}
	hunksApplied := totalHunks - hunksFailed

	if res.ExitCode != 0 {
		summary := fmt.Sprintf("patch failed: %d hunk(s) applied, %d hunk(s) FAILED across %d file(s)\n%s",
			hunksApplied, hunksFailed, len(filesPatched), strings.TrimSpace(out))
		return nil, errorsx.New(errorsx.CodeInternal, summary)
	}

	if !dryRun {
		_ = s.audit.Write(model.AuditEvent{
			Timestamp:    time.Now().UTC(),
			TraceID:      traceID,
			Type:         "ssh_apply_patch",
			ConnectionID: connectionID,
			FilePath:     base,
			RiskLevel:    string(model.RiskL1),
			Status:       "ok",
		})
	}

	resp := map[string]any{
		"files_changed": len(filesPatched),
		"hunks_applied": hunksApplied,
		"dry_run":       dryRun,
	}
	if dryRun {
		resp["message"] = "dry-run succeeded; no files were modified"
	}
	s.enrichWithReconnectInfo(resp, connectionID)
	return resp, nil
}

func countPatchHunks(patch string) int {
	n := 0
	for _, line := range strings.Split(patch, "\n") {
		if strings.HasPrefix(line, "@@") {
			n++
		}
	}
	return n
}

func (s *Service) Disconnect(connectionID string) (map[string]any, error) {
	traceID := util.NewID("trace")
	host := ""
	conn, _ := s.ssh.GetConnection(connectionID)
	if conn != nil {
		host = conn.Host
	}
	_ = s.grants.RevokeByConnection(connectionID)
	if err := s.ssh.Disconnect(connectionID); err != nil {
		_ = s.audit.Write(model.AuditEvent{
			Timestamp:    time.Now().UTC(),
			TraceID:      traceID,
			Type:         "ssh_disconnect",
			ConnectionID: connectionID,
			Host:         host,
			Status:       "error",
			Detail:       err.Error(),
		})
		return nil, err
	}
	_ = s.audit.Write(model.AuditEvent{
		Timestamp:    time.Now().UTC(),
		TraceID:      traceID,
		Type:         "ssh_disconnect",
		ConnectionID: connectionID,
		Host:         host,
		Status:       "ok",
	})
	return map[string]any{"closed": true}, nil
}

func (s *Service) resolveAndCheckPath(conn *model.Connection, input, cwd string) string {
	resolved := security.NormalizeRemotePath(input, cwd)
	if !security.IsWithinRoots(resolved, conn.WorkspaceRoots) {
		return ""
	}
	return resolved
}

func normalizeTransferTimeout(timeoutSec int) int {
	if timeoutSec <= 0 {
		return 300
	}
	return timeoutSec
}

func normalizeTransferMode(mode string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(mode))
	if v == "" {
		return "create", nil
	}
	if v != "create" && v != "overwrite" {
		return "", errorsx.New(errorsx.CodeInvalidParams, "mode must be create|overwrite")
	}
	return v, nil
}

func validateResumeMode(mode string) error {
	if mode == "overwrite" {
		return nil
	}
	return errorsx.New(errorsx.CodeInvalidParams, "resume requires mode=overwrite; retry with mode=overwrite or remove resume=true")
}

func hasLocalRsync() bool {
	_, err := lookPath("rsync")
	return err == nil
}

func resumeUnavailableError(localOK, remoteOK bool) error {
	switch {
	case !localOK && !remoteOK:
		return errorsx.New(errorsx.CodeResumeUnavailable, "resume requested but rsync is unavailable locally and on the remote host; retry without resume=true")
	case !localOK:
		return errorsx.New(errorsx.CodeResumeUnavailable, "resume requested but local rsync is unavailable; retry without resume=true")
	default:
		return errorsx.New(errorsx.CodeResumeUnavailable, "resume requested but remote host has no rsync; retry without resume=true")
	}
}

func (s *Service) ensureResumeAvailable(connectionID string) error {
	localOK := hasLocalRsync()
	remoteOK := s.ssh.HasRsync(connectionID)
	if localOK && remoteOK {
		return nil
	}
	return resumeUnavailableError(localOK, remoteOK)
}

func ensureLocalPathAllowed(localPath string, allowLocalAnywhere bool) error {
	if allowLocalAnywhere {
		return nil
	}
	wd, err := os.Getwd()
	if err != nil {
		return errorsx.New(errorsx.CodeInternal, err.Error())
	}
	if !security.IsWithinLocalRoot(localPath, wd) {
		return errorsx.New(errorsx.CodePathForbidden, "local_path is outside current working directory; set allow_local_anywhere=true to override")
	}
	return nil
}

func (s *Service) remotePathExists(connectionID, remotePath string) (bool, error) {
	res, err := s.ssh.Exec(connectionID, "", "test -e "+util.ShellQuote(remotePath), "", 30)
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0, nil
}

func (s *Service) remoteRegularFileExists(connectionID, remotePath string) (bool, error) {
	res, err := s.ssh.Exec(connectionID, "", "test -f "+util.ShellQuote(remotePath), "", 30)
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0, nil
}

// remotePathType returns "directory", "file", or "missing" for a remote path.
func (s *Service) remotePathType(connectionID, remotePath string) (string, error) {
	cmd := "if [ -d " + util.ShellQuote(remotePath) + " ]; then echo directory; elif [ -f " + util.ShellQuote(remotePath) + " ]; then echo file; else echo missing; fi"
	res, err := s.ssh.Exec(connectionID, "", cmd, "", 30)
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", commandResultError(res, "remote path type check failed")
	}
	return strings.TrimSpace(res.Stdout), nil
}

// remoteEnsureNewDir checks that the target doesn't exist, then creates its parent.
// Exit 17 = target exists (maps to CodeFileExists).
func (s *Service) remoteEnsureNewDir(connectionID, targetPath string, createParents bool) error {
	q := util.ShellQuote(targetPath)
	var cmd string
	if createParents {
		parentQ := util.ShellQuote(path.Dir(targetPath))
		cmd = "test -e " + q + " && exit 17 || mkdir -p " + parentQ
	} else {
		// "|| true" prevents exit code 1 (target doesn't exist) from being treated as error
		cmd = "test -e " + q + " && exit 17 || true"
	}
	res, err := s.ssh.Exec(connectionID, "", cmd, "", 30)
	if err != nil {
		return err
	}
	if res.ExitCode == 17 {
		return errorsx.New(errorsx.CodeFileExists, "remote target already exists")
	}
	if res.ExitCode != 0 {
		return commandResultError(res, "remote directory preparation failed")
	}
	return nil
}

// localDirStats walks a local directory, counting regular files and summing sizes.
// Enforces limits: max 100k files, max 10GB total.
func localDirStats(dirPath string) (fileCount int, totalBytes int64, err error) {
	const maxFiles = 100_000
	const maxBytes = 10 * 1024 * 1024 * 1024 // 10GB
	err = filepath.WalkDir(dirPath, func(_ string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil // skip symlinks, devices etc for counting
		}
		fileCount++
		if fileCount > maxFiles {
			return fmt.Errorf("directory exceeds maximum file count (%d)", maxFiles)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		totalBytes += info.Size()
		if totalBytes > maxBytes {
			return fmt.Errorf("directory exceeds maximum total size (10 GB)")
		}
		return nil
	})
	return fileCount, totalBytes, err
}

// remoteFileCount counts regular files in a remote directory.
func (s *Service) remoteFileCount(connectionID, dirPath string, timeoutSec int) (int, error) {
	cmd := "find " + util.ShellQuote(dirPath) + " -type f | wc -l"
	sec := timeoutSec
	if sec <= 0 {
		sec = 300
	}
	res, err := s.ssh.Exec(connectionID, "", cmd, "", sec)
	if err != nil {
		return 0, err
	}
	if res.ExitCode != 0 {
		return 0, commandResultError(res, "remote file count failed")
	}
	count, err := strconv.Atoi(strings.TrimSpace(res.Stdout))
	if err != nil {
		return 0, fmt.Errorf("parse remote file count: %w", err)
	}
	return count, nil
}

func (s *Service) remoteMkdirAll(connectionID, remoteDir string) error {
	res, err := s.ssh.Exec(connectionID, "", "mkdir -p "+util.ShellQuote(remoteDir), "", 30)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		msg := strings.TrimSpace(res.Stderr)
		if msg == "" {
			msg = strings.TrimSpace(res.Stdout)
		}
		if msg == "" {
			msg = "mkdir -p failed"
		}
		return errorsx.New(errorsx.CodeInternal, msg)
	}
	return nil
}

func (s *Service) remoteInstallCreateOnly(connectionID, tempPath, targetPath string) error {
	cmd := strings.Join([]string{
		"if ln " + util.ShellQuote(tempPath) + " " + util.ShellQuote(targetPath) + " >/dev/null 2>&1; then",
		"rm -f " + util.ShellQuote(tempPath),
		"elif [ -e " + util.ShellQuote(targetPath) + " ]; then",
		"rm -f " + util.ShellQuote(tempPath),
		"exit 17",
		"elif (set -C; cat " + util.ShellQuote(tempPath) + " > " + util.ShellQuote(targetPath) + ") 2>/dev/null; then",
		"rm -f " + util.ShellQuote(tempPath),
		"else",
		"rc=$?",
		"rm -f " + util.ShellQuote(tempPath),
		"if [ -e " + util.ShellQuote(targetPath) + " ]; then exit 17; fi",
		"exit $rc",
		"fi",
	}, "\n")
	res, err := s.ssh.Exec(connectionID, "", cmd, "", 30)
	if err != nil {
		return err
	}
	if res.ExitCode == 17 {
		return errorsx.New(errorsx.CodeFileExists, "remote target exists")
	}
	if res.ExitCode != 0 {
		msg := strings.TrimSpace(res.Stderr)
		if msg == "" {
			msg = strings.TrimSpace(res.Stdout)
		}
		if msg == "" {
			msg = "remote target finalize failed"
		}
		return errorsx.New(errorsx.CodeInternal, msg)
	}
	return nil
}

func (s *Service) remoteRemoveFile(connectionID, remotePath string) {
	_, _ = s.ssh.Exec(connectionID, "", "rm -f "+util.ShellQuote(remotePath), "", 30)
}

func transferTempPath(targetPath string) string {
	return fmt.Sprintf("%s.cssh-tmp-%s", targetPath, util.NewID("xfer"))
}

func installLocalCreateOnly(tempPath, targetPath string) error {
	if err := os.Link(tempPath, targetPath); err == nil {
		if err := os.Remove(tempPath); err != nil {
			return errorsx.New(errorsx.CodeInternal, err.Error())
		}
		return nil
	} else if os.IsExist(err) {
		_ = os.Remove(tempPath)
		return errorsx.New(errorsx.CodeFileExists, "local target exists")
	}
	if err := copyLocalFileCreateOnly(tempPath, targetPath); err != nil {
		_ = os.Remove(tempPath)
		if os.IsExist(err) {
			return errorsx.New(errorsx.CodeFileExists, "local target exists")
		}
		return errorsx.New(errorsx.CodeInternal, err.Error())
	}
	if err := os.Remove(tempPath); err != nil {
		return errorsx.New(errorsx.CodeInternal, err.Error())
	}
	return nil
}

func copyLocalFileCreateOnly(tempPath, targetPath string) error {
	src, err := os.Open(tempPath)
	if err != nil {
		return err
	}
	defer src.Close()
	info, err := src.Stat()
	if err != nil {
		return err
	}
	dst, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		_ = os.Remove(targetPath)
		return err
	}
	if err := dst.Close(); err != nil {
		_ = os.Remove(targetPath)
		return err
	}
	return nil
}

func localFileSHA256(localPath string) (string, error) {
	f, err := os.Open(localPath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (s *Service) remoteFileSHA256(connectionID, remotePath string, timeoutSec int) (string, error) {
	sec := timeoutSec
	if sec <= 0 {
		sec = 300
	}
	cmd := buildRemoteSHA256Command(remotePath)
	res, err := s.ssh.Exec(connectionID, "", cmd, "", sec)
	if err != nil {
		return "", err
	}
	if res.ExitCode == 127 {
		return "", errorsx.New(errorsx.CodeChecksumUnavailable, "remote host has no sha256 tool (sha256sum/shasum)")
	}
	if res.ExitCode != 0 {
		msg := strings.TrimSpace(res.Stderr)
		if msg == "" {
			msg = strings.TrimSpace(res.Stdout)
		}
		if msg == "" {
			msg = "remote checksum command failed"
		}
		return "", errorsx.New(errorsx.CodeInternal, msg)
	}
	h := strings.TrimSpace(res.Stdout)
	if h == "" {
		return "", errorsx.New(errorsx.CodeChecksumUnavailable, "remote checksum output is empty")
	}
	fields := strings.Fields(h)
	if len(fields) == 0 {
		return "", errorsx.New(errorsx.CodeChecksumUnavailable, "remote checksum output is empty")
	}
	return fields[0], nil
}

func buildRemoteSHA256Command(remotePath string) string {
	return strings.Join([]string{
		"if command -v sha256sum >/dev/null 2>&1; then",
		"sha256sum " + util.ShellQuote(remotePath) + " | awk '{print $1}';",
		"elif command -v shasum >/dev/null 2>&1; then",
		"shasum -a 256 " + util.ShellQuote(remotePath) + " | awk '{print $1}';",
		"else",
		"exit 127;",
		"fi",
	}, " ")
}

func ensureChecksumsMatch(localSHA, remoteSHA string) error {
	if localSHA == remoteSHA {
		return nil
	}
	return errorsx.New(errorsx.CodeChecksumMismatch, "sha256 mismatch between local and remote file")
}

func directoryVerificationResult(enabled bool, expectedCount, actualCount int) (string, string, error) {
	if !enabled {
		return "none", "skipped", nil
	}
	if expectedCount == actualCount {
		return "file_count", "match", nil
	}
	return "file_count", "mismatch", errorsx.New(errorsx.CodeInternal,
		fmt.Sprintf("directory verification mismatch: expected %d files, got %d", expectedCount, actualCount))
}

func transferAuditDetail(base string, tr sshbridge.TransferResult) string {
	detail := strings.TrimSpace(base)
	if tr.Protocol == "" {
		return detail
	}
	extra := "protocol=" + tr.Protocol
	if tr.FallbackUsed {
		extra += ", fallback_used=true"
		if tr.FallbackReason != "" {
			extra += ", fallback_reason=" + tr.FallbackReason
		}
	}
	if detail == "" {
		return extra
	}
	return detail + " (" + extra + ")"
}

func (s *Service) writeTransferAudit(traceID, typ, connectionID, host, filePath, status, detail string, durationMS int64) {
	_ = s.audit.Write(model.AuditEvent{
		Timestamp:    time.Now().UTC(),
		TraceID:      traceID,
		Type:         typ,
		ConnectionID: connectionID,
		Host:         host,
		FilePath:     filePath,
		Status:       status,
		Detail:       detail,
		DurationMS:   durationMS,
	})
}

func commandResultError(res sshbridge.ExecResult, fallback string) error {
	msg := strings.TrimSpace(res.Stderr)
	if msg == "" {
		msg = strings.TrimSpace(res.Stdout)
	}
	if msg == "" {
		msg = fallback
	}
	return errorsx.New(errorsx.CodeInternal, msg)
}

type privilegeAuthz struct {
	Allowed     bool
	StatusResp  map[string]any
	ConfirmMode string
	ApprovedBy  string
	GrantID     string
}

// grantExpiry returns the expiry time for a privilege grant.
// ttlSec=0 → session-scoped (zero time, never expires by TTL; revoked on disconnect).
// ttlSec>0 → now + ttlSec seconds.
func grantExpiry(now time.Time, ttlSec int) time.Time {
	if ttlSec <= 0 {
		return time.Time{} // zero value = session-scoped
	}
	return now.Add(time.Duration(ttlSec) * time.Second)
}

func (s *Service) authorizePrivilege(connectionID, sessionID, capability, command, commandTpl, commandHash string, risk model.RiskLevel, reason, token, host, username string, reusable bool, grantTTLSec int) (privilegeAuthz, error) {
	now := time.Now().UTC()
	statusResp := func(approvalID string, reqReason string) map[string]any {
		return map[string]any{
			"status":               "approval_required",
			"approval_id":          approvalID,
			"reason":               reqReason,
			"risk_level":           risk,
			"capability":           capability,
			"host":                 host,
			"username":             username,
			"deny_class":           string(model.DenyNeedApprove),
			"approve_instructions": resolve.QuotedPath() + " approve " + approvalID,
		}
	}

	if token != "" {
		// First read the request to validate matching fields.
		req, err := s.approvals.Get(token)
		if err != nil {
			return privilegeAuthz{}, err
		}
		if req == nil {
			return privilegeAuthz{}, errorsx.New(errorsx.CodeApprovalRequired, "approval token not found")
		}
		if req.Status == model.ApprovalRejected {
			return privilegeAuthz{}, errorsx.New(errorsx.CodeApprovalRejected, "approval rejected")
		}
		if req.Status != model.ApprovalApproved {
			return privilegeAuthz{Allowed: false, StatusResp: statusResp(req.ID, req.Reason), ConfirmMode: "approval_queue"}, nil
		}
		if req.ConnectionID != connectionID {
			return privilegeAuthz{}, errorsx.New(errorsx.CodeApprovalRejected, "approval token does not match current operation")
		}
		if strings.TrimSpace(req.Command) != strings.TrimSpace(sanitizeCommandForAudit(command)) {
			return privilegeAuthz{}, errorsx.New(errorsx.CodeApprovalRejected, "approval token does not match current command")
		}
		if strings.TrimSpace(req.Capability) != "" && req.Capability != capability {
			return privilegeAuthz{}, errorsx.New(errorsx.CodeApprovalRejected, "approval token does not match current capability")
		}
		// Reject tokens from before a reconnect (generation mismatch).
		if conn, err := s.ssh.GetConnection(connectionID); err == nil && req.Generation != conn.Generation {
			return privilegeAuthz{}, errorsx.New(errorsx.CodeApprovalRejected, "approval token invalidated by connection reconnect")
		}
		// Atomically mark as used. MarkUsed returns nil if already consumed
		// or not approved, preventing concurrent double-use.
		updated, err := s.approvals.MarkUsed(req.ID)
		if err != nil {
			return privilegeAuthz{}, err
		}
		if updated == nil {
			return privilegeAuthz{}, errorsx.New(errorsx.CodeApprovalRejected, "approval token already consumed")
		}
		// For reusable commands (policy upgrades), create a cached grant so
		// similar commands auto-approve without a fresh token.
		grantID := ""
		if reusable && commandHash != "" {
			g := model.PrivilegeGrant{
				ID:           util.NewID("grn"),
				CreatedAt:    now,
				ExpiresAt:    grantExpiry(now, grantTTLSec),
				Status:       model.PrivilegeGrantActive,
				ConnectionID: connectionID,
				Capability:   capability,
				CommandHash:  commandHash,
				RiskLevel:    risk,
				ApprovedBy:   updated.ApprovedBy,
				Source:       "approval:" + req.ID,
			}
			_ = s.grants.Create(g)
			grantID = g.ID
		}
		return privilegeAuthz{
			Allowed:     true,
			ConfirmMode: "approval_token",
			ApprovedBy:  updated.ApprovedBy,
			GrantID:     grantID,
		}, nil
	}

	// For reusable commands without a token, check for an active cached grant.
	if reusable && commandHash != "" {
		grant, err := s.grants.FindActive(connectionID, capability, commandHash, now)
		if err == nil && grant != nil {
			return privilegeAuthz{
				Allowed:     true,
				ConfirmMode: "grant_cache",
				ApprovedBy:  grant.ApprovedBy,
				GrantID:     grant.ID,
			}, nil
		}
	}

	var connGeneration uint64
	if conn, err := s.ssh.GetConnection(connectionID); err == nil {
		connGeneration = conn.Generation
	}
	req := model.ApprovalRequest{
		ID:           util.NewID("apr"),
		CreatedAt:    now,
		Status:       model.ApprovalPending,
		Command:      sanitizeCommandForAudit(command),
		ConnectionID: connectionID,
		SessionID:    sessionID,
		Host:         host,
		Username:     username,
		RiskLevel:    risk,
		DenyClass:    model.DenyNeedApprove,
		Capability:   capability,
		CommandTpl:   commandTpl,
		CommandHash:  commandHash,
		Reason:       reason,
		RequestedBy:  "mcp",
		Reusable:     reusable,
		Generation:   connGeneration,
	}
	if err := s.approvals.Create(req); err != nil {
		return privilegeAuthz{}, err
	}
	return privilegeAuthz{
		Allowed:     false,
		StatusResp:  statusResp(req.ID, req.Reason),
		ConfirmMode: "approval_queue",
	}, nil
}

func (s *Service) issueProfileDeleteToken(profileID string) string {
	s.deleteMu.Lock()
	defer s.deleteMu.Unlock()
	now := time.Now().UTC()
	for k, v := range s.deleteTokens {
		if now.After(v.ExpiresAt) {
			delete(s.deleteTokens, k)
		}
	}
	token := util.NewID("del")
	s.deleteTokens[token] = profileDeleteConfirm{
		ProfileID: profileID,
		ExpiresAt: now.Add(5 * time.Minute),
	}
	return token
}

func (s *Service) validateAndConsumeProfileDeleteToken(profileID, token string) error {
	s.deleteMu.Lock()
	defer s.deleteMu.Unlock()
	rec, ok := s.deleteTokens[token]
	if !ok {
		return errorsx.New(errorsx.CodeInvalidParams, "confirm_token is invalid or expired")
	}
	delete(s.deleteTokens, token)
	if rec.ProfileID != profileID {
		return errorsx.New(errorsx.CodeInvalidParams, "confirm_token does not match profile_id")
	}
	if time.Now().UTC().After(rec.ExpiresAt) {
		return errorsx.New(errorsx.CodeInvalidParams, "confirm_token is expired")
	}
	return nil
}

func (s *Service) prepareSudoCommand(conn model.Connection, command string) (string, string, map[string]any, error) {
	if !security.LooksLikeSudo(command) {
		return command, "", nil, nil
	}
	if security.IsPipedSudo(command) {
		return "", "", nil, errorsx.New(errorsx.CodeInvalidParams,
			"piped sudo (e.g. 'curl | sudo bash') cannot receive password via stdin; "+
				"split into separate commands: download the file first, then run 'sudo bash <file>'")
	}
	if !s.cfg.SudoEnabled {
		return "", "", nil, errorsx.New(errorsx.CodeInvalidParams, "sudo execution is disabled by policy")
	}
	profileID := strings.TrimSpace(conn.ProfileID)
	if profileID == "" {
		return "", "", nil, errorsx.New(errorsx.CodeInvalidParams, "sudo requires profile-based connection")
	}
	secret, err := s.secrets.Get(profileID, "sudo_password")
	if err != nil || strings.TrimSpace(secret) == "" {
		return "", "", map[string]any{
			"status":          "credential_required",
			"credential_kind": "sudo_password",
			"profile_id":      profileID,
			"message":         "sudo_password is missing; prompt user to enter it securely",
			"next_action": map[string]any{
				"tool":      "ssh_credentials_prompt",
				"arguments": map[string]any{"profile_id": profileID, "fields": []string{"sudo_password"}, "prompt_mode": "web"},
			},
		}, nil
	}

	cmd := strings.TrimSpace(command)
	if cmd == "sudo" {
		return "", "", nil, errorsx.New(errorsx.CodeInvalidParams, "sudo command is incomplete")
	}
	rest := strings.TrimSpace(strings.TrimPrefix(cmd, "sudo"))
	if !strings.HasPrefix(rest, "-S ") && rest != "-S" && !strings.Contains(rest, " -S ") {
		rest = "-S -p '' " + rest
	}
	return "sudo " + rest, secret + "\n", nil, nil
}

var (
	auditKVSecretRE   = regexp.MustCompile(`(?i)\b(password|passwd|passphrase|token|secret|api[_-]?key|access[_-]?key)\s*=\s*([^\s;|&]+)`)
	auditFlagSecretRE = regexp.MustCompile(`(?i)\b(--?(?:password|passphrase|token|secret|api[_-]?key|access[_-]?key)|-p)\s+([^\s;|&]+)`)
	auditURLSecretRE  = regexp.MustCompile(`://([^:@/\s]+):([^@/\s]+)@`)
)

func sanitizeCommandForAudit(command string) string {
	out := strings.TrimSpace(command)
	if out == "" {
		return out
	}
	out = auditKVSecretRE.ReplaceAllString(out, "$1=***")
	out = auditFlagSecretRE.ReplaceAllString(out, "$1 ***")
	out = auditURLSecretRE.ReplaceAllString(out, "://$1:***@")
	return out
}

func (s *Service) resolveConnectionInput(input model.ConnectionInput) (model.Connection, error) {
	if input.ProfileID == "" && input.ProfileName == "" {
		return model.Connection{}, errorsx.New(errorsx.CodeInvalidParams,
			"profile_id or profile_name is required; create a profile first with ssh_profile_setup(step=save)")
	}
	p, err := s.resolveProfileRef(input.ProfileID, input.ProfileName)
	if err != nil {
		return model.Connection{}, err
	}
	if strings.EqualFold(strings.TrimSpace(p.Username), "root") && !p.AllowRootUser && !s.cfg.AllowRootLogin {
		return model.Connection{}, errorsx.New(errorsx.CodeInvalidParams, "root user is denied by policy; enable allow_root_user in profile to override")
	}
	allowPublic := p.AllowPublicHost || s.cfg.AllowPublicHost
	if input.AllowPublicHost != nil {
		allowPublic = *input.AllowPublicHost
	}
	password, _ := s.secrets.Get(p.ID, "password")
	keyPassphrase, _ := s.secrets.Get(p.ID, "key_passphrase")
	sudoPassword, _ := s.secrets.Get(p.ID, "sudo_password")
	securityProfile := strings.TrimSpace(p.SecurityProfile)
	if securityProfile == "" {
		securityProfile = s.cfg.SecurityProfileDefault
	}
	if securityProfile == "" {
		securityProfile = "easy_safe"
	}
	roots := append([]string{}, p.WorkspaceRoots...)
	limitDir, roots, err := applyLimitDir(input.LimitDir, roots)
	if err != nil {
		return model.Connection{}, err
	}
	cnotePath, cnote, err := s.readProfileCnote(p)
	if err != nil {
		return model.Connection{}, err
	}
	maxAutoRisk := p.MaxAutoRisk
	if strings.TrimSpace(maxAutoRisk) == "" && strings.EqualFold(securityProfile, "ops_strict") {
		maxAutoRisk = "L1"
	}

	// Phase 6: passphrase pre-detection for key-based auth
	if containsStr(p.AuthPriority, "key") && strings.TrimSpace(p.KeyPath) != "" {
		expandedKeyPath := config.ExpandHome(strings.TrimSpace(p.KeyPath))
		if _, statErr := os.Stat(expandedKeyPath); os.IsNotExist(statErr) {
			return model.Connection{}, &errorsx.CsshError{
				Code:    errorsx.CodeKeyNotFound,
				Message: fmt.Sprintf("key file not found: %s; use ssh_key_setup to select a key", expandedKeyPath),
				Data: map[string]any{
					"profile_id": p.ID,
					"key_path":   expandedKeyPath,
					"hint": map[string]any{
						"tool":      "ssh_key_setup",
						"arguments": map[string]any{"profile_id": p.ID},
					},
				},
			}
		}
		needsPass, checkErr := CheckKeyPassphrase(expandedKeyPath)
		if checkErr == nil && needsPass {
			// Check ssh-agent first
			inAgent, _ := IsKeyLoadedInAgent(expandedKeyPath)
			if !inAgent {
				// Check keychain
				if strings.TrimSpace(keyPassphrase) == "" {
					return model.Connection{}, &errorsx.CsshError{
						Code:    errorsx.CodeKeyPassphraseRequired,
						Message: fmt.Sprintf("key %s requires a passphrase but none is available in agent or keychain", expandedKeyPath),
						Data: map[string]any{
							"profile_id": p.ID,
							"key_path":   expandedKeyPath,
							"hint": map[string]any{
								"tool":      "ssh_credentials_prompt",
								"arguments": map[string]any{"profile_id": p.ID, "fields": []string{"key_passphrase"}},
							},
						},
					}
				}
			}
		}
	}

	return model.Connection{
		ProfileID:       p.ID,
		Host:            p.Host,
		Port:            p.Port,
		Username:        p.Username,
		AuthPriority:    append([]string{}, p.AuthPriority...),
		KeyPath:         p.KeyPath,
		KeyPassphrase:   keyPassphrase,
		Password:        password,
		SudoPassword:    sudoPassword,
		WorkspaceRoots:  roots,
		LimitDir:        limitDir,
		AllowPublicHost: allowPublic,
		SecurityProfile: securityProfile,
		AllowRootUser:   p.AllowRootUser,
		MaxAutoRisk:     maxAutoRisk,
		AllowReboot:     p.AllowReboot,
		AllowDiskOps:    p.AllowDiskOps,
		DenyPatterns:    append([]string{}, p.DenyPatterns...),
		GrantTTLSec:     p.GrantTTLSec,
		CnotePath:       cnotePath,
		Cnote:           cnote,
	}, nil
}

func applyLimitDir(raw string, roots []string) (string, []string, error) {
	limit := strings.TrimSpace(raw)
	if limit == "" {
		return "", roots, nil
	}
	if !strings.HasPrefix(limit, "/") {
		return "", nil, errorsx.New(errorsx.CodeInvalidParams, "limit_dir must be an absolute path")
	}
	limit = path.Clean(limit)
	if !security.IsWithinRoots(limit, roots) {
		return "", nil, errorsx.New(errorsx.CodeInvalidParams, "limit_dir must be within workspace_roots")
	}
	return limit, []string{limit}, nil
}

func (s *Service) resolveProfileRef(profileID, profileName string) (*model.Profile, error) {
	if strings.TrimSpace(profileID) != "" {
		p, err := s.profiles.Get(strings.TrimSpace(profileID))
		if err != nil {
			return nil, err
		}
		if p == nil {
			return nil, errorsx.New(errorsx.CodeInvalidParams, "profile_id not found")
		}
		return p, nil
	}
	name := strings.TrimSpace(profileName)
	if name == "" {
		return nil, errorsx.New(errorsx.CodeInvalidParams, "profile reference is empty")
	}
	items, err := s.profiles.List()
	if err != nil {
		return nil, err
	}
	match := []model.Profile{}
	for _, p := range items {
		if strings.EqualFold(p.Name, name) || strings.EqualFold(p.ID, name) {
			match = append(match, p)
		}
	}
	if len(match) == 0 {
		return nil, errorsx.New(errorsx.CodeInvalidParams, "profile_name not found")
	}
	if len(match) > 1 {
		return nil, errorsx.New(errorsx.CodeInvalidParams, "profile_name is ambiguous; use profile_id")
	}
	cp := match[0]
	return &cp, nil
}

func PrettyJSON(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

func ParseBoolAny(v any, d bool) bool {
	if v == nil {
		return d
	}
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(x, "true")
	default:
		return d
	}
}

func ParseIntAny(v any, d int) int {
	if v == nil {
		return d
	}
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(x))
		if err == nil {
			return n
		}
	}
	return d
}

func ParseStringSliceAny(v any) []string {
	if v == nil {
		return nil
	}
	switch x := v.(type) {
	case string:
		s := strings.TrimSpace(x)
		if s == "" {
			return nil
		}
		parts := strings.Split(s, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				out = append(out, p)
			}
		}
		return out
	case []string:
		out := make([]string, 0, len(x))
		for _, it := range x {
			it = strings.TrimSpace(it)
			if it != "" {
				out = append(out, it)
			}
		}
		return out
	}
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, it := range arr {
		s, ok := it.(string)
		if ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

func RequireString(args map[string]any, key string) (string, error) {
	v, ok := args[key]
	if !ok {
		return "", errorsx.New(errorsx.CodeInvalidParams, fmt.Sprintf("%s is required", key))
	}
	s, ok := v.(string)
	if !ok || strings.TrimSpace(s) == "" {
		return "", errorsx.New(errorsx.CodeInvalidParams, fmt.Sprintf("%s must be a non-empty string", key))
	}
	return s, nil
}
