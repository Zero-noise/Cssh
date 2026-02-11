package app

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cssh/internal/approvals"
	"cssh/internal/audit"
	"cssh/internal/config"
	"cssh/internal/errorsx"
	"cssh/internal/model"
	"cssh/internal/security"
	"cssh/internal/sshbridge"
	"cssh/internal/store"
	"cssh/internal/util"
)

type Service struct {
	cfg       model.Config
	profiles  *store.ProfileStore
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

func NewService(cfg model.Config) *Service {
	return &Service{
		cfg:          cfg,
		profiles:     store.NewProfileStore(cfg.ProfilesFile),
		secrets:      store.NewSecretStore(),
		approvals:    approvals.NewStore(pathJoin(cfg.RuntimeDir, "approvals.jsonl")),
		grants:       approvals.NewGrantStore(pathJoin(cfg.RuntimeDir, "grants.json")),
		audit:        audit.NewLogger(cfg.LogsDir),
		ssh:          sshbridge.NewManager(cfg.RuntimeDir, cfg.DefaultShell, cfg.DefaultTimeoutSec),
		deleteTokens: map[string]profileDeleteConfirm{},
	}
}

func pathJoin(a, b string) string {
	if strings.HasSuffix(a, "/") {
		return a + b
	}
	return a + "/" + b
}

func (s *Service) ProfileStore() *store.ProfileStore { return s.profiles }
func (s *Service) SecretStore() store.SecretStore    { return s.secrets }
func (s *Service) Approvals() *approvals.Store       { return s.approvals }
func (s *Service) Grants() *approvals.GrantStore     { return s.grants }

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
	return map[string]any{
		"connection_id":    conn.ID,
		"capabilities":     []string{"exec", "file_read", "file_write", "file_transfer", "search", "patch", "tail"},
		"workspace_roots":  conn.WorkspaceRoots,
		"security_profile": conn.SecurityProfile,
	}, nil
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
	traceID := util.NewID("trace")
	auditCommand := sanitizeCommandForAudit(command)
	conn, err := s.ssh.GetConnection(connectionID)
	if err != nil {
		return nil, err
	}
	policy := security.EvaluateExecPolicy(command)
	authz := privilegeAuthz{}
	needsApprove, approveReason := shouldRequireApproval(conn.SecurityProfile, policy)
	if needsApprove {
		authz, err = s.authorizePrivilege(connectionID, sessionID, policy.Capability, command, policy.Template, policy.TemplateHash, policy.RiskLevel, approveReason, approvalToken)
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
				GrantTTLsec:     authz.GrantTTLsec,
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

	res, err := s.ssh.ExecWithInput(connectionID, sessionID, runCommand, cwd, timeoutSec, runInput)
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
		GrantID:         authz.GrantID,
		GrantTTLsec:     authz.GrantTTLsec,
		ConfirmMode:     authz.ConfirmMode,
	})
	return map[string]any{
		"exit_code":   res.ExitCode,
		"stdout":      res.Stdout,
		"stderr":      res.Stderr,
		"duration_ms": res.DurationMS,
		"grant_id":    authz.GrantID,
	}, nil
}

func (s *Service) ConnectionStatus(connectionID string, timeoutSec int) (map[string]any, error) {
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
		return map[string]any{"connections": []map[string]any{item}}, nil
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
	return map[string]any{"connections": items}, nil
}

func (s *Service) PrivilegeStatus(connectionID string, activeOnly bool) (map[string]any, error) {
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
			"expires_at":            g.ExpiresAt.Format(time.RFC3339),
			"approved_by":           g.ApprovedBy,
			"source":                g.Source,
		})
	}
	return map[string]any{"grants": out}, nil
}

func (s *Service) RevokePrivilege(grantID string) (map[string]any, error) {
	g, err := s.grants.Revoke(grantID)
	if err != nil {
		return nil, err
	}
	if g == nil {
		return nil, errorsx.New(errorsx.CodeInvalidParams, "grant_id not found")
	}
	return map[string]any{
		"revoked":               true,
		"grant_id":              g.ID,
		"connection_id":         g.ConnectionID,
		"capability":            g.Capability,
		"command_template_hash": g.CommandHash,
		"status":                g.Status,
	}, nil
}

func (s *Service) UploadFile(connectionID, localPath, remotePath, mode, cwd string, timeoutSec int, createParents, verifyChecksum, allowLocalAnywhere bool, approvalToken string) (map[string]any, error) {
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
	if err := s.ensureConnectionAlive(connectionID); err != nil {
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
				GrantTTLsec:     authz.GrantTTLsec,
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
	if !info.Mode().IsRegular() {
		return nil, errorsx.New(errorsx.CodeInvalidParams, "local_path must be a regular file")
	}

	remoteResolved := s.resolveAndCheckPath(conn, remotePath, cwd)
	if remoteResolved == "" {
		return nil, errorsx.New(errorsx.CodePathForbidden, "remote_path is outside workspace_roots")
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
	transferRes, err := s.ssh.UploadFile(connectionID, localAbs, uploadTarget, timeoutSec)
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
		"grant_id":          authz.GrantID,
	}
	if transferRes.FallbackUsed && transferRes.FallbackReason != "" {
		resp["fallback_reason"] = transferRes.FallbackReason
	}
	return resp, nil
}

func (s *Service) DownloadFile(connectionID, remotePath, localPath, mode, cwd string, timeoutSec int, createParents, verifyChecksum, allowLocalAnywhere bool, approvalToken string) (map[string]any, error) {
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
	if err := s.ensureConnectionAlive(connectionID); err != nil {
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
				GrantTTLsec:     authz.GrantTTLsec,
				ConfirmMode:     authz.ConfirmMode,
			})
			return authz.StatusResp, nil
		}
	}

	remoteResolved := s.resolveAndCheckPath(conn, remotePath, cwd)
	if remoteResolved == "" {
		return nil, errorsx.New(errorsx.CodePathForbidden, "remote_path is outside workspace_roots")
	}
	isFile, err := s.remoteRegularFileExists(connectionID, remoteResolved)
	if err != nil {
		return nil, err
	}
	if !isFile {
		return nil, errorsx.New(errorsx.CodeInvalidParams, "remote_path not found or not a regular file")
	}

	localAbs, err := security.ResolveLocalPath(localPath)
	if err != nil {
		return nil, errorsx.New(errorsx.CodeInvalidParams, "local_path is invalid")
	}
	if err := ensureLocalPathAllowed(localAbs, allowLocalAnywhere); err != nil {
		return nil, err
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
	transferRes, err := s.ssh.DownloadFile(connectionID, remoteResolved, downloadTarget, timeoutSec)
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
		"grant_id":          authz.GrantID,
	}
	if transferRes.FallbackUsed && transferRes.FallbackReason != "" {
		resp["fallback_reason"] = transferRes.FallbackReason
	}
	return resp, nil
}

func (s *Service) ReadFile(connectionID, filePath string, maxBytes int, cwd string) (map[string]any, error) {
	traceID := util.NewID("trace")
	conn, err := s.ssh.GetConnection(connectionID)
	if err != nil {
		return nil, err
	}
	if maxBytes <= 0 {
		maxBytes = 65536
	}
	resolved := s.resolveAndCheckPath(conn, filePath, cwd)
	if resolved == "" {
		return nil, errorsx.New(errorsx.CodePathForbidden, "path is outside workspace_roots")
	}

	sizeRes, err := s.ssh.Exec(connectionID, "", "wc -c < "+util.ShellQuote(resolved), "", 60)
	if err != nil {
		return nil, err
	}
	sizeStr := strings.TrimSpace(sizeRes.Stdout)
	size, _ := strconv.Atoi(sizeStr)
	res, err := s.ssh.Exec(connectionID, "", "head -c "+strconv.Itoa(maxBytes)+" "+util.ShellQuote(resolved), "", 60)
	if err != nil {
		return nil, err
	}
	truncated := size > maxBytes
	_ = s.audit.Write(model.AuditEvent{
		Timestamp:    time.Now().UTC(),
		TraceID:      traceID,
		Type:         "ssh_read_file",
		ConnectionID: connectionID,
		FilePath:     resolved,
		Status:       "ok",
	})
	return map[string]any{"content": res.Stdout, "truncated": truncated}, nil
}

func (s *Service) WriteFile(connectionID, filePath, content, mode, cwd string) (map[string]any, error) {
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
	enc := base64.StdEncoding.EncodeToString([]byte(content))
	dir := path.Dir(resolved)
	cmd := "mkdir -p " + util.ShellQuote(dir) + "; "
	switch mode {
	case "create":
		cmd += "if [ -e " + util.ShellQuote(resolved) + " ]; then exit 17; fi; "
		cmd += "echo " + util.ShellQuote(enc) + " | base64 -d > " + util.ShellQuote(resolved)
	case "append":
		cmd += "echo " + util.ShellQuote(enc) + " | base64 -d >> " + util.ShellQuote(resolved)
	case "overwrite":
		cmd += "echo " + util.ShellQuote(enc) + " | base64 -d > " + util.ShellQuote(resolved)
	default:
		return nil, errorsx.New(errorsx.CodeInvalidParams, "mode must be create|overwrite|append")
	}
	res, err := s.ssh.Exec(connectionID, "", cmd, "", 60)
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		if res.ExitCode == 17 {
			return nil, errorsx.New(errorsx.CodeInvalidParams, "target exists")
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
	return map[string]any{"bytes_written": len(content)}, nil
}

func (s *Service) ApplyPatch(connectionID, patchUnified, baseDir string) (map[string]any, error) {
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
	cmd := strings.Join([]string{
		"tmp=$(mktemp)",
		"echo " + util.ShellQuote(enc) + " | base64 -d > \"$tmp\"",
		"cd " + util.ShellQuote(base),
		"patch -p0 < \"$tmp\"",
		"rc=$?",
		"rm -f \"$tmp\"",
		"exit $rc",
	}, "; ")
	res, err := s.ssh.Exec(connectionID, "", cmd, "", 120)
	if err != nil {
		return nil, err
	}
	out := res.Stdout + "\n" + res.Stderr
	filesChanged := 0
	hunksApplied := 0
	rejects := 0
	for _, line := range strings.Split(out, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "patching file ") {
			filesChanged++
		}
		if strings.Contains(l, "Hunk #") {
			hunksApplied++
		}
		if strings.Contains(l, ".rej") || strings.Contains(strings.ToLower(l), "failed") {
			rejects++
		}
	}
	if res.ExitCode != 0 {
		return nil, errorsx.New(errorsx.CodeInternal, strings.TrimSpace(out))
	}
	_ = s.audit.Write(model.AuditEvent{
		Timestamp:    time.Now().UTC(),
		TraceID:      traceID,
		Type:         "ssh_apply_patch",
		ConnectionID: connectionID,
		FilePath:     base,
		RiskLevel:    string(model.RiskL1),
		Status:       "ok",
	})
	return map[string]any{"files_changed": filesChanged, "hunks_applied": hunksApplied, "rejects": rejects}, nil
}

func (s *Service) ListDir(connectionID, dir string, depth int, cwd string) (map[string]any, error) {
	conn, err := s.ssh.GetConnection(connectionID)
	if err != nil {
		return nil, err
	}
	if depth <= 0 {
		depth = 1
	}
	resolved := s.resolveAndCheckPath(conn, dir, cwd)
	if resolved == "" {
		return nil, errorsx.New(errorsx.CodePathForbidden, "path is outside workspace_roots")
	}
	cmd := "find " + util.ShellQuote(resolved) + " -mindepth 1 -maxdepth " + strconv.Itoa(depth) + " -print"
	res, err := s.ssh.Exec(connectionID, "", cmd, "", 60)
	if err != nil {
		return nil, err
	}
	lines := splitNonEmpty(res.Stdout)
	entries := make([]map[string]any, 0, len(lines))
	for _, it := range lines {
		entries = append(entries, map[string]any{"path": it})
	}
	return map[string]any{"entries": entries}, nil
}

func (s *Service) SearchText(connectionID, basePath, pattern, glob string, limit int, cwd string) (map[string]any, error) {
	conn, err := s.ssh.GetConnection(connectionID)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 50
	}
	resolved := s.resolveAndCheckPath(conn, basePath, cwd)
	if resolved == "" {
		return nil, errorsx.New(errorsx.CodePathForbidden, "path is outside workspace_roots")
	}
	var cmd string
	if glob == "" {
		cmd = "grep -R -n -E -- " + util.ShellQuote(pattern) + " " + util.ShellQuote(resolved) + " | head -n " + strconv.Itoa(limit)
	} else {
		cmd = "find " + util.ShellQuote(resolved) + " -type f -name " + util.ShellQuote(glob) + " -exec grep -n -E -- " + util.ShellQuote(pattern) + " {} + | head -n " + strconv.Itoa(limit)
	}
	res, err := s.ssh.Exec(connectionID, "", cmd, "", 60)
	if err != nil {
		return nil, err
	}
	matches := make([]map[string]any, 0)
	for _, line := range splitNonEmpty(res.Stdout) {
		// format: file:line:snippet
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}
		ln, _ := strconv.Atoi(parts[1])
		matches = append(matches, map[string]any{
			"file":    parts[0],
			"line":    ln,
			"snippet": parts[2],
		})
	}
	return map[string]any{"matches": matches}, nil
}

func (s *Service) TailLog(connectionID, filePath string, lines int, cwd string) (map[string]any, error) {
	conn, err := s.ssh.GetConnection(connectionID)
	if err != nil {
		return nil, err
	}
	if lines <= 0 {
		lines = 200
	}
	resolved := s.resolveAndCheckPath(conn, filePath, cwd)
	if resolved == "" {
		return nil, errorsx.New(errorsx.CodePathForbidden, "path is outside workspace_roots")
	}
	cmd := "tail -n " + strconv.Itoa(lines) + " " + util.ShellQuote(resolved)
	res, err := s.ssh.Exec(connectionID, "", cmd, "", 60)
	if err != nil {
		return nil, err
	}
	return map[string]any{"content": res.Stdout}, nil
}

func (s *Service) Disconnect(connectionID string) (map[string]any, error) {
	_ = s.grants.RevokeByConnection(connectionID)
	if err := s.ssh.Disconnect(connectionID); err != nil {
		return nil, err
	}
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

func (s *Service) ensureConnectionAlive(connectionID string) error {
	alive, _, msg, err := s.ssh.CheckConnection(connectionID, 5)
	if err != nil {
		return err
	}
	if !alive {
		if strings.TrimSpace(msg) == "" {
			msg = "ssh control connection is not alive"
		}
		return errorsx.New(errorsx.CodeInternal, msg)
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
	}, "; ")
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

func splitNonEmpty(s string) []string {
	parts := strings.Split(s, "\n")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

type privilegeAuthz struct {
	Allowed      bool
	StatusResp   map[string]any
	GrantID      string
	GrantTTLsec  int
	ConfirmMode  string
	Reusable     bool
	ApprovedBy   string
	TemplateHash string
}

func (s *Service) authorizePrivilege(connectionID, sessionID, capability, command, commandTpl, commandHash string, risk model.RiskLevel, reason, token string) (privilegeAuthz, error) {
	conn, err := s.ssh.GetConnection(connectionID)
	if err != nil {
		return privilegeAuthz{}, err
	}
	now := time.Now().UTC()
	ttlSec := s.approvalTTL(conn)
	reusable := ttlSec > 0
	statusResp := func(approvalID string, reqReason string) map[string]any {
		return map[string]any{
			"status":                          "approval_required",
			"approval_id":                     approvalID,
			"reason":                          reqReason,
			"risk_level":                      risk,
			"capability":                      capability,
			"command_template_hash":           commandHash,
			"grant_ttl_sec":                   ttlSec,
			"grant_reusable":                  reusable,
			"confirmation_required_each_time": !reusable,
			"next_action": map[string]any{
				"tool": "ssh_approve_request",
				"arguments": map[string]any{
					"approval_id": approvalID,
					"decision":    "approve",
				},
			},
		}
	}

	if reusable {
		existing, err := s.grants.FindActive(connectionID, capability, commandHash, now)
		if err != nil {
			return privilegeAuthz{}, err
		}
		if existing != nil {
			return privilegeAuthz{
				Allowed:      true,
				GrantID:      existing.ID,
				GrantTTLsec:  ttlSec,
				ConfirmMode:  "cached_grant",
				Reusable:     true,
				ApprovedBy:   existing.ApprovedBy,
				TemplateHash: commandHash,
			}, nil
		}
	}

	if token != "" {
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
			return privilegeAuthz{Allowed: false, StatusResp: statusResp(req.ID, req.Reason), GrantTTLsec: ttlSec, Reusable: reusable, ConfirmMode: "approval_queue"}, nil
		}
		if req.ConnectionID != connectionID {
			return privilegeAuthz{}, errorsx.New(errorsx.CodeApprovalRejected, "approval token does not match current operation")
		}
		if strings.TrimSpace(req.CommandHash) != "" {
			if req.CommandHash != commandHash {
				return privilegeAuthz{}, errorsx.New(errorsx.CodeApprovalRejected, "approval token does not match current operation")
			}
		} else if strings.TrimSpace(req.Command) != strings.TrimSpace(command) {
			return privilegeAuthz{}, errorsx.New(errorsx.CodeApprovalRejected, "approval token does not match current command")
		}
		if strings.TrimSpace(req.Capability) != "" && req.Capability != capability {
			return privilegeAuthz{}, errorsx.New(errorsx.CodeApprovalRejected, "approval token does not match current capability")
		}
		if !reusable {
			if req.UsedAt != nil {
				return privilegeAuthz{}, errorsx.New(errorsx.CodeApprovalRejected, "approval token already consumed")
			}
			updated, err := s.approvals.MarkUsed(req.ID)
			if err != nil {
				return privilegeAuthz{}, err
			}
			if updated == nil {
				return privilegeAuthz{}, errorsx.New(errorsx.CodeApprovalRejected, "approval token not found")
			}
			req = updated
		}
		authz := privilegeAuthz{
			Allowed:      true,
			GrantTTLsec:  ttlSec,
			ConfirmMode:  "approval_token",
			Reusable:     reusable,
			ApprovedBy:   req.ApprovedBy,
			TemplateHash: commandHash,
		}
		if reusable {
			grantID, err := s.createPrivilegeGrant(connectionID, capability, commandHash, risk, req.ApprovedBy, "approval_token", ttlSec, now)
			if err != nil {
				return privilegeAuthz{}, err
			}
			authz.GrantID = grantID
		}
		return authz, nil
	}

	req := model.ApprovalRequest{
		ID:           util.NewID("apr"),
		CreatedAt:    now,
		Status:       model.ApprovalPending,
		Command:      sanitizeCommandForAudit(command),
		ConnectionID: connectionID,
		SessionID:    sessionID,
		RiskLevel:    risk,
		Capability:   capability,
		CommandTpl:   commandTpl,
		CommandHash:  commandHash,
		GrantTTLsec:  ttlSec,
		Reason:       reason,
		RequestedBy:  "mcp",
	}
	if err := s.approvals.Create(req); err != nil {
		return privilegeAuthz{}, err
	}
	return privilegeAuthz{
		Allowed:     false,
		StatusResp:  statusResp(req.ID, req.Reason),
		GrantTTLsec: ttlSec,
		ConfirmMode: "approval_queue",
		Reusable:    reusable,
	}, nil
}

func (s *Service) approvalTTL(conn *model.Connection) int {
	if isEasySafeProfile(conn.SecurityProfile) {
		if s.cfg.EasySafeApprovalTTLsec < 0 {
			return 0
		}
		return s.cfg.EasySafeApprovalTTLsec
	}
	if s.cfg.NonEasyApprovalTTLsec < 0 {
		return 0
	}
	return s.cfg.NonEasyApprovalTTLsec
}

func (s *Service) createPrivilegeGrant(connectionID, capability, commandHash string, risk model.RiskLevel, approvedBy, source string, ttlSec int, now time.Time) (string, error) {
	if ttlSec <= 0 {
		return "", nil
	}
	g := model.PrivilegeGrant{
		ID:           util.NewID("grt"),
		CreatedAt:    now,
		ExpiresAt:    now.Add(time.Duration(ttlSec) * time.Second),
		Status:       model.PrivilegeGrantActive,
		ConnectionID: connectionID,
		Capability:   capability,
		CommandHash:  commandHash,
		RiskLevel:    risk,
		ApprovedBy:   approvedBy,
		Source:       source,
	}
	if err := s.grants.Create(g); err != nil {
		return "", err
	}
	return g.ID, nil
}

func isEasySafeProfile(profile string) bool {
	return strings.EqualFold(strings.TrimSpace(profile), "easy_safe")
}

func shouldRequireApproval(securityProfile string, policy security.ExecPolicyDecision) (bool, string) {
	if !isEasySafeProfile(securityProfile) {
		return true, "security profile requires explicit approval for every command"
	}
	return policy.NeedsApprove, policy.Reason
}

func (s *Service) ApproveRequest(approvalID, decision, actor, rejectReason string) (map[string]any, error) {
	id := strings.TrimSpace(approvalID)
	if id == "" {
		return nil, errorsx.New(errorsx.CodeInvalidParams, "approval_id is required")
	}
	decision = strings.ToLower(strings.TrimSpace(decision))
	if decision == "" {
		decision = "approve"
	}
	if strings.TrimSpace(actor) == "" {
		actor = "mcp_user"
	}
	status := model.ApprovalApproved
	switch decision {
	case "approve", "approved":
		status = model.ApprovalApproved
	case "reject", "rejected":
		status = model.ApprovalRejected
		if strings.TrimSpace(rejectReason) == "" {
			rejectReason = "rejected by mcp user"
		}
	default:
		return nil, errorsx.New(errorsx.CodeInvalidParams, "decision must be approve or reject")
	}

	updated, err := s.approvals.Resolve(id, status, actor, rejectReason)
	if err != nil {
		return nil, err
	}
	if updated == nil {
		return nil, errorsx.New(errorsx.CodeInvalidParams, "approval_id not found")
	}
	res := map[string]any{
		"approval_id":        updated.ID,
		"requested_decision": decision,
		"status":             updated.Status,
		"approved_by":        updated.ApprovedBy,
		"reject_reason":      updated.RejectReason,
		"approval_token":     updated.ID,
	}
	if updated.ResolvedAt != nil {
		res["resolved_at"] = updated.ResolvedAt.Format(time.RFC3339)
	}
	return res, nil
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
	if input.ProfileID != "" || input.ProfileName != "" {
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
			WorkspaceRoots:  append([]string{}, p.WorkspaceRoots...),
			AllowPublicHost: allowPublic,
			SecurityProfile: securityProfile,
			AllowRootUser:   p.AllowRootUser,
		}, nil
	}

	if s.cfg.ConnectRequireProfile {
		return model.Connection{}, errorsx.New(errorsx.CodeInvalidParams, "direct host connection denied by policy; use profile_id/profile_name")
	}
	if input.Host == "" || input.Username == "" {
		return model.Connection{}, errorsx.New(errorsx.CodeInvalidParams, "provide profile_id/profile_name or host/username")
	}
	if strings.EqualFold(strings.TrimSpace(input.Username), "root") && !s.cfg.AllowRootLogin {
		return model.Connection{}, errorsx.New(errorsx.CodeInvalidParams, "root user is denied by policy")
	}
	allowPublic := s.cfg.AllowPublicHost
	if input.AllowPublicHost != nil {
		allowPublic = *input.AllowPublicHost
	}
	authPriority := []string{"key", "password"}
	if input.AuthMode != "" {
		switch strings.ToLower(strings.TrimSpace(input.AuthMode)) {
		case "hybrid":
			authPriority = []string{"key", "password"}
		case "key", "password":
			authPriority = []string{strings.ToLower(strings.TrimSpace(input.AuthMode))}
		default:
			return model.Connection{}, errorsx.New(errorsx.CodeInvalidParams, "auth_mode must be key|password|hybrid")
		}
	}
	password := ""
	if input.PasswordRef != "" {
		val, err := s.secrets.Get(input.PasswordRef, "password")
		if err == nil {
			password = val
		}
	}
	keyPath := input.KeyRef
	if keyPath == "" {
		keyPath = "~/.ssh/id_rsa"
	}
	roots := input.WorkspaceRoots
	if len(roots) == 0 {
		roots = []string{"/"}
	}
	for i := range roots {
		roots[i] = path.Clean(roots[i])
	}
	securityProfile := strings.TrimSpace(s.cfg.SecurityProfileDefault)
	if securityProfile == "" {
		securityProfile = "easy_safe"
	}
	return model.Connection{
		Host:            input.Host,
		Port:            input.Port,
		Username:        input.Username,
		AuthPriority:    authPriority,
		KeyPath:         config.ExpandHome(keyPath),
		Password:        password,
		WorkspaceRoots:  roots,
		AllowPublicHost: allowPublic,
		SecurityProfile: securityProfile,
		AllowRootUser:   s.cfg.AllowRootLogin,
	}, nil
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
