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
	"sort"
	"strconv"
	"strings"
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
	audit     *audit.Logger
	ssh       *sshbridge.Manager
}

func NewService(cfg model.Config) *Service {
	return &Service{
		cfg:       cfg,
		profiles:  store.NewProfileStore(cfg.ProfilesFile),
		secrets:   store.NewSecretStore(),
		approvals: approvals.NewStore(pathJoin(cfg.RuntimeDir, "approvals.jsonl")),
		audit:     audit.NewLogger(cfg.LogsDir),
		ssh:       sshbridge.NewManager(cfg.RuntimeDir, cfg.DefaultShell, cfg.DefaultTimeoutSec),
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
		Timestamp:    time.Now().UTC(),
		TraceID:      traceID,
		Type:         "ssh_connect",
		ConnectionID: conn.ID,
		Host:         conn.Host,
		Status:       "ok",
	})
	return map[string]any{
		"connection_id":   conn.ID,
		"capabilities":    []string{"exec", "file_read", "file_write", "file_transfer", "search", "patch", "tail"},
		"workspace_roots": conn.WorkspaceRoots,
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
	conn, err := s.ssh.GetConnection(connectionID)
	if err != nil {
		return nil, err
	}
	risk, reason := security.ClassifyCommandRisk(command)
	if risk == model.RiskL2 {
		ok, statusResp, err := s.checkApproval(connectionID, sessionID, command, reason, approvalToken)
		if err != nil {
			return nil, err
		}
		if !ok {
			_ = s.audit.Write(model.AuditEvent{
				Timestamp:    time.Now().UTC(),
				TraceID:      traceID,
				Type:         "ssh_exec",
				ConnectionID: connectionID,
				SessionID:    sessionID,
				Command:      command,
				RiskLevel:    string(risk),
				Status:       "approval_required",
			})
			return statusResp, nil
		}
	}

	res, err := s.ssh.Exec(connectionID, sessionID, command, cwd, timeoutSec)
	if err != nil {
		return nil, err
	}
	status := "ok"
	if res.ExitCode != 0 {
		status = "nonzero_exit"
	}
	_ = s.audit.Write(model.AuditEvent{
		Timestamp:    time.Now().UTC(),
		TraceID:      traceID,
		Type:         "ssh_exec",
		ConnectionID: connectionID,
		SessionID:    sessionID,
		Host:         conn.Host,
		Command:      command,
		RiskLevel:    string(risk),
		Status:       status,
		ExitCode:     res.ExitCode,
		DurationMS:   res.DurationMS,
	})
	return map[string]any{
		"exit_code":   res.ExitCode,
		"stdout":      res.Stdout,
		"stderr":      res.Stderr,
		"duration_ms": res.DurationMS,
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

func (s *Service) UploadFile(connectionID, localPath, remotePath, mode, cwd string, timeoutSec int, createParents, verifyChecksum, allowLocalAnywhere bool) (map[string]any, error) {
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
	durationMS, err := s.ssh.UploadFile(connectionID, localAbs, uploadTarget, timeoutSec)
	if err != nil {
		if remoteTemp != "" {
			s.remoteRemoveFile(connectionID, remoteTemp)
		}
		s.writeTransferAudit(traceID, "ssh_upload_file", connectionID, conn.Host, remoteResolved, "nonzero_exit", localAbs+" -> "+remoteResolved, durationMS)
		return nil, err
	}
	if mode == "create" {
		if err := s.remoteInstallCreateOnly(connectionID, remoteTemp, remoteResolved); err != nil {
			s.writeTransferAudit(traceID, "ssh_upload_file", connectionID, conn.Host, remoteResolved, "nonzero_exit", localAbs+" -> "+remoteResolved, durationMS)
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
			s.writeTransferAudit(traceID, "ssh_upload_file", connectionID, conn.Host, remoteResolved, "checksum_mismatch", localAbs+" -> "+remoteResolved, durationMS)
			return nil, err
		}
	}

	s.writeTransferAudit(traceID, "ssh_upload_file", connectionID, conn.Host, remoteResolved, "ok", localAbs+" -> "+remoteResolved, durationMS)
	return map[string]any{
		"bytes":         info.Size(),
		"local_sha256":  localSHA,
		"remote_sha256": remoteSHA,
		"local_path":    localAbs,
		"remote_path":   remoteResolved,
		"duration_ms":   durationMS,
	}, nil
}

func (s *Service) DownloadFile(connectionID, remotePath, localPath, mode, cwd string, timeoutSec int, createParents, verifyChecksum, allowLocalAnywhere bool) (map[string]any, error) {
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
	durationMS, err := s.ssh.DownloadFile(connectionID, remoteResolved, downloadTarget, timeoutSec)
	if err != nil {
		if localTemp != "" {
			_ = os.Remove(localTemp)
		}
		s.writeTransferAudit(traceID, "ssh_download_file", connectionID, conn.Host, remoteResolved, "nonzero_exit", remoteResolved+" -> "+localAbs, durationMS)
		return nil, err
	}
	if mode == "create" {
		if err := installLocalCreateOnly(localTemp, localAbs); err != nil {
			s.writeTransferAudit(traceID, "ssh_download_file", connectionID, conn.Host, remoteResolved, "nonzero_exit", remoteResolved+" -> "+localAbs, durationMS)
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
			s.writeTransferAudit(traceID, "ssh_download_file", connectionID, conn.Host, remoteResolved, "checksum_mismatch", remoteResolved+" -> "+localAbs, durationMS)
			return nil, err
		}
	}

	s.writeTransferAudit(traceID, "ssh_download_file", connectionID, conn.Host, remoteResolved, "ok", remoteResolved+" -> "+localAbs, durationMS)
	return map[string]any{
		"bytes":         info.Size(),
		"local_sha256":  localSHA,
		"remote_sha256": remoteSHA,
		"local_path":    localAbs,
		"remote_path":   remoteResolved,
		"duration_ms":   durationMS,
	}, nil
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

func (s *Service) checkApproval(connectionID, sessionID, command, reason, token string) (bool, map[string]any, error) {
	if token != "" {
		req, err := s.approvals.Get(token)
		if err != nil {
			return false, nil, err
		}
		if req == nil {
			return false, nil, errorsx.New(errorsx.CodeApprovalRequired, "approval token not found")
		}
		if req.Status == model.ApprovalRejected {
			return false, nil, errorsx.New(errorsx.CodeApprovalRejected, "approval rejected")
		}
		if req.Status == model.ApprovalApproved {
			if req.Command != command || req.ConnectionID != connectionID {
				return false, nil, errorsx.New(errorsx.CodeApprovalRejected, "approval token does not match current command")
			}
			return true, nil, nil
		}
		return false, map[string]any{
			"status":      "approval_required",
			"approval_id": req.ID,
			"reason":      req.Reason,
			"risk_level":  req.RiskLevel,
		}, nil
	}

	req := model.ApprovalRequest{
		ID:           util.NewID("apr"),
		CreatedAt:    time.Now().UTC(),
		Status:       model.ApprovalPending,
		Command:      command,
		ConnectionID: connectionID,
		SessionID:    sessionID,
		RiskLevel:    model.RiskL2,
		Reason:       reason,
		RequestedBy:  "mcp",
	}
	if err := s.approvals.Create(req); err != nil {
		return false, nil, err
	}
	return false, map[string]any{
		"status":      "approval_required",
		"approval_id": req.ID,
		"reason":      req.Reason,
		"risk_level":  req.RiskLevel,
	}, nil
}

func (s *Service) resolveConnectionInput(input model.ConnectionInput) (model.Connection, error) {
	if input.ProfileID != "" || input.ProfileName != "" {
		p, err := s.resolveProfileRef(input.ProfileID, input.ProfileName)
		if err != nil {
			return model.Connection{}, err
		}
		allowPublic := p.AllowPublicHost || s.cfg.AllowPublicHost
		if input.AllowPublicHost != nil {
			allowPublic = *input.AllowPublicHost
		}
		password, _ := s.secrets.Get(p.ID, "password")
		keyPassphrase, _ := s.secrets.Get(p.ID, "key_passphrase")
		return model.Connection{
			Host:            p.Host,
			Port:            p.Port,
			Username:        p.Username,
			AuthPriority:    append([]string{}, p.AuthPriority...),
			KeyPath:         p.KeyPath,
			KeyPassphrase:   keyPassphrase,
			Password:        password,
			WorkspaceRoots:  append([]string{}, p.WorkspaceRoots...),
			AllowPublicHost: allowPublic,
		}, nil
	}

	if input.Host == "" || input.Username == "" {
		return model.Connection{}, errorsx.New(errorsx.CodeInvalidParams, "provide profile_id/profile_name or host/username")
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
	return model.Connection{
		Host:            input.Host,
		Port:            input.Port,
		Username:        input.Username,
		AuthPriority:    authPriority,
		KeyPath:         config.ExpandHome(keyPath),
		Password:        password,
		WorkspaceRoots:  roots,
		AllowPublicHost: allowPublic,
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
