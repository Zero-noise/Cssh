package app

import (
	"path"
	"regexp"
	"strings"
	"time"

	"cssh/internal/config"
	"cssh/internal/errorsx"
	"cssh/internal/model"
	"cssh/internal/security"
	"cssh/internal/util"
)

type QuickSetupInput struct {
	Purpose         string
	ProfileID       string
	ProfileName     string
	Host            string
	Port            int
	Username        string
	AuthMode        string
	WorkspaceRoots  []string
	KeyPath         string
	AllowPublicHost bool
	SecurityProfile string
	AllowRootUser   bool
}

func (s *Service) QuickSetupTemplate(purpose, authMode, username string) (map[string]any, error) {
	traceID := util.NewID("trace")
	authMode = normalizeAuthMode(authMode)
	if username == "" {
		username = "ubuntu"
	}
	defaultRoot := defaultWorkspaceRoot(purpose, username)
	defaults := map[string]any{
		"profile_name":      strings.TrimSpace(purpose),
		"port":              22,
		"auth_mode":         authMode,
		"workspace_roots":   []string{defaultRoot},
		"allow_public_host": true,
		"key_path":          "~/.ssh/id_ed25519",
		"security_profile":  normalizeSecurityProfileDefault(s.cfg.SecurityProfileDefault),
		"allow_root_user":   false,
	}

	fields := []map[string]any{
		{"name": "purpose", "label": "Connection Purpose", "type": "string", "required": true, "placeholder": "debug jsonl worker"},
		{"name": "profile_name", "label": "Profile Name", "type": "string", "required": false, "placeholder": "rayna-dev"},
		{"name": "profile_id", "label": "Profile ID", "type": "string", "required": false, "placeholder": "rayna-dev-100-88-0-10"},
		{"name": "host", "label": "SSH Host", "type": "string", "required": true, "placeholder": "100.100.1.20 or devbox.ts.net"},
		{"name": "port", "label": "SSH Port", "type": "integer", "required": false, "default": 22},
		{"name": "username", "label": "SSH User", "type": "string", "required": true, "default": username},
		{"name": "auth_mode", "label": "Auth Mode", "type": "string", "required": false, "enum": []string{"hybrid", "key", "password"}, "default": authMode},
		{"name": "workspace_roots", "label": "Workspace Roots", "type": "array", "required": false, "default": []string{defaultRoot}},
		{"name": "key_path", "label": "Private Key Path", "type": "string", "required": false, "default": "~/.ssh/id_ed25519"},
		{"name": "allow_public_host", "label": "Allow Public Host", "type": "boolean", "required": false, "default": true},
		{"name": "security_profile", "label": "Security Profile", "type": "string", "required": false, "enum": []string{"easy_safe", "ops_strict"}, "default": normalizeSecurityProfileDefault(s.cfg.SecurityProfileDefault)},
		{"name": "allow_root_user", "label": "Allow Root User", "type": "boolean", "required": false, "default": false},
	}

	resp := map[string]any{
		"title":    "SSH Quick Setup Form",
		"summary":  "Fill profile fields first. Credentials are entered later via ssh_credentials_prompt and saved directly into OS keychain.",
		"fields":   fields,
		"defaults": defaults,
		"next_action": map[string]any{
			"tool": "ssh_profile_setup",
			"arguments": map[string]any{
				"step": "save",
			},
			"note": "After saving, use ssh_credentials_prompt for secure credential entry.",
		},
	}
	_ = s.audit.Write(model.AuditEvent{
		Timestamp: time.Now().UTC(),
		TraceID:   traceID,
		Type:      "ssh_profile_setup",
		Status:    "ok",
		Detail:    "step=template",
	})
	return resp, nil
}

func (s *Service) QuickSetupSave(in QuickSetupInput) (map[string]any, error) {
	traceID := util.NewID("trace")
	if strings.TrimSpace(in.Purpose) == "" {
		return nil, errorsx.New(errorsx.CodeInvalidParams, "purpose is required")
	}
	if strings.TrimSpace(in.Host) == "" || strings.TrimSpace(in.Username) == "" {
		return nil, errorsx.New(errorsx.CodeInvalidParams, "host and username are required")
	}

	authMode := normalizeAuthMode(in.AuthMode)
	if in.Port <= 0 {
		in.Port = 22
	}
	if len(in.WorkspaceRoots) == 0 {
		in.WorkspaceRoots = []string{defaultWorkspaceRoot(in.Purpose, in.Username)}
	}
	for i := range in.WorkspaceRoots {
		in.WorkspaceRoots[i] = path.Clean(strings.TrimSpace(in.WorkspaceRoots[i]))
	}

	if authMode != "password" && strings.TrimSpace(in.KeyPath) == "" {
		in.KeyPath = "~/.ssh/id_ed25519"
	}
	profileID := strings.TrimSpace(in.ProfileID)
	if profileID == "" {
		profileID = buildProfileID(in.Purpose, in.Host)
	}
	profileName := strings.TrimSpace(in.ProfileName)
	if profileName == "" {
		profileName = strings.TrimSpace(in.Purpose)
	}

	authPriority := []string{"key", "password"}
	switch authMode {
	case "key":
		authPriority = []string{"key"}
	case "password":
		authPriority = []string{"password"}
	case "hybrid":
		authPriority = []string{"key", "password"}
	}

	profile := model.Profile{
		ID:                profileID,
		Name:              profileName,
		Host:              strings.TrimSpace(in.Host),
		Port:              in.Port,
		Username:          strings.TrimSpace(in.Username),
		AuthPriority:      authPriority,
		KeyPath:           config.ExpandHome(strings.TrimSpace(in.KeyPath)),
		WorkspaceRoots:    in.WorkspaceRoots,
		AllowPublicHost:   in.AllowPublicHost,
		SecurityProfile:   normalizeSecurityProfileDefault(in.SecurityProfile),
		AllowRootUser:     in.AllowRootUser,
		ToolPolicyVersion: 2,
	}
	if profile.SecurityProfile == "" {
		profile.SecurityProfile = normalizeSecurityProfileDefault(s.cfg.SecurityProfileDefault)
	}
	if profile.SecurityProfile == "" {
		profile.SecurityProfile = "easy_safe"
	}
	applyProfileSecurityDefaults(&profile)
	if err := s.profiles.Upsert(profile); err != nil {
		return nil, err
	}

	secretsSaved := map[string]bool{
		"password":       s.hasSecretValue(profileID, "password"),
		"key_passphrase": s.hasSecretValue(profileID, "key_passphrase"),
		"sudo_password":  s.hasSecretValue(profileID, "sudo_password"),
	}

	warnings := []string{}
	if !profile.AllowPublicHost && !security.IsPrivateOrLoopbackHost(profile.Host) {
		warnings = append(warnings, "host looks public; connection will be blocked unless allow_public_host=true or VPN address is used")
	}

	result := map[string]any{
		"saved":            true,
		"profile_id":       profileID,
		"profile_name":     profileName,
		"auth_priority":    authPriority,
		"workspace_roots":  profile.WorkspaceRoots,
		"security_profile": profile.SecurityProfile,
		"secrets_saved":    secretsSaved,
		"warnings":         warnings,
		"connect_hint": map[string]any{
			"tool":      "ssh_connect",
			"arguments": map[string]any{"profile_id": profileID},
		},
	}

	needsCredentials := false
	credentialFields := []string{}
	if containsStr(authPriority, "password") && !secretsSaved["password"] {
		needsCredentials = true
		credentialFields = append(credentialFields, "password")
	}
	if containsStr(authPriority, "key") && !secretsSaved["key_passphrase"] {
		needsCredentials = true
		credentialFields = append(credentialFields, "key_passphrase")
	}
	if needsCredentials {
		manualCmds := manualCredentialCommands(profileID, credentialFields)
		result["credentials_hint"] = map[string]any{
			"tool":            "ssh_credentials_prompt",
			"arguments":       map[string]any{"profile_id": profileID, "fields": credentialFields},
			"manual_commands": manualCmds,
			"message":         "Default flow: use ssh_credentials_prompt (web) with profile_id " + profileID + ". If web is unavailable, run: " + strings.Join(manualCmds, " ; ") + ". If csshctl is not in PATH, use an absolute path. Run them in another terminal tab/window to continue without restarting; or run them after closing this session, then restart Claude Code/Codex and resume this conversation.",
		}
	}

	_ = s.audit.Write(model.AuditEvent{
		Timestamp: time.Now().UTC(),
		TraceID:   traceID,
		Type:      "ssh_profile_setup",
		Status:    "ok",
		Detail:    "step=save profile_id=" + profileID,
	})
	return result, nil
}

func (s *Service) hasSecretValue(profileID, kind string) bool {
	v, err := s.secrets.Get(profileID, kind)
	if err != nil {
		return false
	}
	return strings.TrimSpace(v) != ""
}

func (s *Service) ProfilesList() (map[string]any, error) {
	traceID := util.NewID("trace")
	items, err := s.profiles.List()
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(items))
	for _, p := range items {
		out = append(out, map[string]any{
			"id":                p.ID,
			"name":              p.Name,
			"host":              p.Host,
			"port":              p.Port,
			"username":          p.Username,
			"auth_priority":     p.AuthPriority,
			"workspace_roots":   p.WorkspaceRoots,
			"allow_public_host": p.AllowPublicHost,
			"security_profile":  p.SecurityProfile,
			"allow_root_user":   p.AllowRootUser,
		})
	}
	resp := map[string]any{"profiles": out}
	_ = s.audit.Write(model.AuditEvent{
		Timestamp: time.Now().UTC(),
		TraceID:   traceID,
		Type:      "ssh_profile",
		Status:    "ok",
		Detail:    "action=list",
	})
	return resp, nil
}

func (s *Service) ProfileDelete(profileID string, deleteSecrets bool, confirmToken string) (map[string]any, error) {
	traceID := util.NewID("trace")
	id := strings.TrimSpace(profileID)
	if id == "" {
		return nil, errorsx.New(errorsx.CodeInvalidParams, "profile_id is required")
	}
	p, err := s.profiles.Get(id)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, errorsx.New(errorsx.CodeInvalidParams, "profile_id not found")
	}
	if strings.TrimSpace(confirmToken) == "" {
		token := s.issueProfileDeleteToken(id)
		resp := map[string]any{
			"status":          "confirm_required",
			"profile_id":      id,
			"profile_name":    p.Name,
			"confirm_token":   token,
			"confirm_ttl_sec": 300,
			"message":         "Deletion requires confirmation token. Retry with confirm_token to proceed.",
		}
		_ = s.audit.Write(model.AuditEvent{
			Timestamp: time.Now().UTC(),
			TraceID:   traceID,
			Type:      "ssh_profile",
			Status:    "confirm_required",
			Detail:    "action=delete profile_id=" + id,
		})
		return resp, nil
	}
	if err := s.validateAndConsumeProfileDeleteToken(id, confirmToken); err != nil {
		return nil, err
	}
	if err := s.profiles.Delete(id); err != nil {
		return nil, err
	}
	secretsDeleted := []string{}
	if deleteSecrets {
		for _, kind := range []string{"password", "key_passphrase", "sudo_password"} {
			if err := s.secrets.Delete(id, kind); err == nil {
				secretsDeleted = append(secretsDeleted, kind)
			}
		}
	}
	resp := map[string]any{
		"deleted":         true,
		"profile_id":      id,
		"profile_name":    p.Name,
		"secrets_deleted": secretsDeleted,
	}
	_ = s.audit.Write(model.AuditEvent{
		Timestamp: time.Now().UTC(),
		TraceID:   traceID,
		Type:      "ssh_profile",
		Status:    "ok",
		Detail:    "action=delete profile_id=" + id,
	})
	return resp, nil
}

func normalizeSecurityProfileDefault(v string) string {
	mode := strings.ToLower(strings.TrimSpace(v))
	switch mode {
	case "", "easy_safe":
		return "easy_safe"
	case "ops_strict":
		return "ops_strict"
	default:
		return mode
	}
}

func normalizeAuthMode(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "key", "password", "hybrid":
		return v
	default:
		return "hybrid"
	}
}

func defaultWorkspaceRoot(purpose, username string) string {
	p := strings.ToLower(purpose)
	u := strings.TrimSpace(username)
	if u == "" {
		u = "ubuntu"
	}
	if strings.Contains(p, "deploy") || strings.Contains(p, "prod") || strings.Contains(p, "ops") {
		return "/"
	}
	if strings.Contains(p, "data") || strings.Contains(p, "ml") || strings.Contains(p, "train") {
		return "/home/" + u + "/workspace"
	}
	return "/home/" + u + "/project"
}

var nonSlug = regexp.MustCompile(`[^a-z0-9-]+`)

func buildProfileID(purpose, host string) string {
	left := slugify(purpose)
	if left == "" {
		left = "ssh"
	}
	right := slugify(host)
	if right == "" {
		right = "host"
	}
	id := left + "-" + right
	if len(id) > 48 {
		id = id[:48]
	}
	return strings.Trim(id, "-")
}

func slugify(in string) string {
	v := strings.ToLower(strings.TrimSpace(in))
	v = strings.ReplaceAll(v, ".", "-")
	v = strings.ReplaceAll(v, "_", "-")
	v = strings.ReplaceAll(v, " ", "-")
	v = nonSlug.ReplaceAllString(v, "-")
	v = strings.Trim(v, "-")
	for strings.Contains(v, "--") {
		v = strings.ReplaceAll(v, "--", "-")
	}
	return v
}

// applyProfileSecurityDefaults sets policy field defaults based on security_profile.
// ops_strict defaults to MaxAutoRisk="L1" (every L2 command requires approval).
func applyProfileSecurityDefaults(p *model.Profile) {
	if strings.EqualFold(p.SecurityProfile, "ops_strict") && strings.TrimSpace(p.MaxAutoRisk) == "" {
		p.MaxAutoRisk = "L1"
	}
}

func containsStr(slice []string, target string) bool {
	for _, s := range slice {
		if s == target {
			return true
		}
	}
	return false
}
