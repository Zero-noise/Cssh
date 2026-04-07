package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cssh/internal/model"
)

type testSecretStore struct {
	values map[string]string
}

func newTestSecretStore() *testSecretStore {
	return &testSecretStore{values: map[string]string{}}
}

func (s *testSecretStore) key(profileID, kind string) string {
	return profileID + ":" + kind
}

func (s *testSecretStore) Set(profileID, kind, value string) error {
	s.values[s.key(profileID, kind)] = value
	return nil
}

func (s *testSecretStore) Get(profileID, kind string) (string, error) {
	v, ok := s.values[s.key(profileID, kind)]
	if !ok {
		return "", fmt.Errorf("secret not found")
	}
	return v, nil
}

func (s *testSecretStore) Delete(profileID, kind string) error {
	delete(s.values, s.key(profileID, kind))
	return nil
}

func newTestService(t *testing.T) *Service {
	return newTestServiceWithSecurityProfile(t, "easy_safe")
}

func newTestServiceWithSecurityProfile(t *testing.T, securityProfile string) *Service {
	t.Helper()
	tmp := t.TempDir()
	cfg := model.Config{
		DefaultShell:           "bash -lc",
		DefaultTimeoutSec:      120,
		RuntimeDir:             filepath.Join(tmp, "runtime"),
		LogsDir:                filepath.Join(tmp, "logs"),
		ProfilesFile:           filepath.Join(tmp, "profiles.json"),
		SecurityProfileDefault: securityProfile,
		SudoEnabled:            true,
	}
	svc := NewService(cfg)
	svc.secrets = newTestSecretStore()
	return svc
}

func TestQuickSetupTemplateDefaults(t *testing.T) {
	svc := newTestService(t)
	res, err := svc.QuickSetupTemplate("debug jsonl", "", "devuser")
	if err != nil {
		t.Fatalf("template err: %v", err)
	}
	defaults, ok := res["defaults"].(map[string]any)
	if !ok {
		t.Fatalf("defaults missing")
	}
	if defaults["auth_mode"] != "hybrid" {
		t.Fatalf("auth_mode default mismatch: %#v", defaults["auth_mode"])
	}
	if defaults["security_profile"] != "easy_safe" {
		t.Fatalf("security_profile default mismatch: %#v", defaults["security_profile"])
	}
	roots, ok := defaults["workspace_roots"].([]string)
	if !ok || len(roots) != 1 || roots[0] != "/" {
		t.Fatalf("workspace_roots default mismatch: %#v", defaults["workspace_roots"])
	}
	fields, ok := res["fields"].([]map[string]any)
	if !ok {
		t.Fatalf("fields missing")
	}
	for _, field := range fields {
		name, _ := field["name"].(string)
		if name == "password" || name == "key_passphrase" {
			t.Fatalf("template should not include credential field %q", name)
		}
	}
}

func TestQuickSetupTemplateDefaultsForOpsStrict(t *testing.T) {
	svc := newTestServiceWithSecurityProfile(t, "ops_strict")
	res, err := svc.QuickSetupTemplate("ops box", "", "root")
	if err != nil {
		t.Fatalf("template err: %v", err)
	}
	defaults, ok := res["defaults"].(map[string]any)
	if !ok {
		t.Fatalf("defaults missing")
	}
	if defaults["security_profile"] != "ops_strict" {
		t.Fatalf("security_profile default mismatch: %#v", defaults["security_profile"])
	}
	roots, ok := defaults["workspace_roots"].([]string)
	if !ok || len(roots) != 1 || roots[0] != "/root" {
		t.Fatalf("workspace_roots default mismatch for ops_strict root user: %#v", defaults["workspace_roots"])
	}
}

func TestQuickSetupSavePersistsProfile(t *testing.T) {
	svc := newTestService(t)
	out, err := svc.QuickSetupSave(QuickSetupInput{
		Purpose:     "debug worker",
		ProfileName: "rayna-dev",
		Host:        "10.0.0.9",
		Username:    "ubuntu",
		AuthMode:    "password",
	})
	if err != nil {
		t.Fatalf("quick save err: %v", err)
	}
	profileID, _ := out["profile_id"].(string)
	if profileID == "" {
		t.Fatalf("profile_id missing")
	}
	p, err := svc.ProfileStore().Get(profileID)
	if err != nil {
		t.Fatalf("profile get err: %v", err)
	}
	if p == nil {
		t.Fatalf("profile not saved")
	}
	if p.Name != "rayna-dev" {
		t.Fatalf("unexpected profile name: %s", p.Name)
	}
	if p.NotePath == "" {
		t.Fatalf("expected note path to be persisted")
	}
	if _, err := os.Stat(p.NotePath); err != nil {
		t.Fatalf("expected cnote file to exist: %v", err)
	}
	if p.SecurityProfile != "easy_safe" {
		t.Fatalf("unexpected security_profile: %s", p.SecurityProfile)
	}
	if len(p.AuthPriority) != 1 || p.AuthPriority[0] != "password" {
		t.Fatalf("unexpected auth priority: %#v", p.AuthPriority)
	}
	if len(p.WorkspaceRoots) != 1 || p.WorkspaceRoots[0] != "/" {
		t.Fatalf("unexpected workspace roots: %#v", p.WorkspaceRoots)
	}
	secretsSaved, ok := out["secrets_saved"].(map[string]bool)
	if !ok {
		t.Fatalf("secrets_saved should be present")
	}
	if secretsSaved["password"] {
		t.Fatalf("password should not be marked saved before credential prompt")
	}
	hint, ok := out["credentials_hint"].(map[string]any)
	if !ok {
		t.Fatalf("credentials_hint should exist when password is missing")
	}
	msg, _ := hint["message"].(string)
	if !strings.Contains(msg, "continue without restarting") {
		t.Fatalf("credentials_hint should explain no-restart path: %q", msg)
	}
	if !strings.Contains(msg, "resume this conversation") {
		t.Fatalf("credentials_hint should explain resume path: %q", msg)
	}
	args, ok := hint["arguments"].(map[string]any)
	if !ok {
		t.Fatalf("credentials_hint arguments missing")
	}
	fields, ok := args["fields"].([]string)
	if !ok || len(fields) != 1 || fields[0] != "password" {
		t.Fatalf("unexpected credentials_hint fields: %#v", args["fields"])
	}
}

func TestQuickSetupSaveDefaultsWorkspaceRootForOpsStrict(t *testing.T) {
	svc := newTestService(t)
	out, err := svc.QuickSetupSave(QuickSetupInput{
		Purpose:         "ops worker",
		ProfileName:     "ops-dev",
		Host:            "10.0.0.10",
		Username:        "ubuntu",
		AuthMode:        "password",
		SecurityProfile: "ops_strict",
	})
	if err != nil {
		t.Fatalf("quick save err: %v", err)
	}
	profileID, _ := out["profile_id"].(string)
	p, err := svc.ProfileStore().Get(profileID)
	if err != nil {
		t.Fatalf("profile get err: %v", err)
	}
	if p == nil {
		t.Fatalf("profile not saved")
	}
	if len(p.WorkspaceRoots) != 1 || p.WorkspaceRoots[0] != "/home/ubuntu" {
		t.Fatalf("unexpected workspace roots for ops_strict: %#v", p.WorkspaceRoots)
	}
}

func TestQuickSetupRejectsUnknownSecurityProfile(t *testing.T) {
	svc := newTestService(t)
	_, err := svc.QuickSetupSave(QuickSetupInput{
		Purpose:         "test",
		Host:            "10.0.0.1",
		Username:        "ubuntu",
		AuthMode:        "password",
		SecurityProfile: "typo_safe",
	})
	if err == nil {
		t.Fatal("expected error for unknown security_profile")
	}
	if !strings.Contains(err.Error(), "unknown security_profile") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCnoteSetAndResolveConnectionInput(t *testing.T) {
	svc := newTestService(t)
	out, err := svc.QuickSetupSave(QuickSetupInput{
		Purpose:     "debug worker",
		ProfileName: "rayna-dev",
		Host:        "10.0.0.9",
		Username:    "ubuntu",
		AuthMode:    "password",
	})
	if err != nil {
		t.Fatalf("quick save err: %v", err)
	}
	profileID, _ := out["profile_id"].(string)
	if _, err := svc.Cnote("set", profileID, "", "下载大文件时统一落到 /mnt/ssd"); err != nil {
		t.Fatalf("cnote set err: %v", err)
	}

	conn, err := svc.resolveConnectionInput(model.ConnectionInput{ProfileID: profileID})
	if err != nil {
		t.Fatalf("resolve connection err: %v", err)
	}
	if conn.Cnote != "下载大文件时统一落到 /mnt/ssd" {
		t.Fatalf("unexpected cnote: %#v", conn.Cnote)
	}
	if conn.CnotePath == "" {
		t.Fatalf("expected cnote path to be present")
	}
}

func TestProfilesListIncludesCnoteMetadata(t *testing.T) {
	svc := newTestService(t)
	out, err := svc.QuickSetupSave(QuickSetupInput{
		Purpose:     "debug worker",
		ProfileName: "rayna-dev",
		Host:        "100.100.1.9",
		Username:    "ubuntu",
		AuthMode:    "password",
	})
	if err != nil {
		t.Fatalf("quick save err: %v", err)
	}
	profileID, _ := out["profile_id"].(string)
	if _, err := svc.Cnote("append", profileID, "", "下载大文件时统一落到 /mnt/ssd"); err != nil {
		t.Fatalf("cnote append err: %v", err)
	}

	list, err := svc.ProfilesList()
	if err != nil {
		t.Fatalf("profiles list err: %v", err)
	}
	profiles, ok := list["profiles"].([]map[string]any)
	if !ok || len(profiles) != 1 {
		t.Fatalf("unexpected profiles payload: %#v", list["profiles"])
	}
	if profiles[0]["has_cnote"] != true {
		t.Fatalf("expected has_cnote=true, got %#v", profiles[0]["has_cnote"])
	}
	if !strings.Contains(profiles[0]["cnote_preview"].(string), "/mnt/ssd") {
		t.Fatalf("unexpected cnote preview: %#v", profiles[0]["cnote_preview"])
	}
}

func TestQuickSetupSaveNoHintWhenSecretsExist(t *testing.T) {
	svc := newTestService(t)
	sec := svc.secrets.(*testSecretStore)
	_ = sec.Set("existing-id", "password", "x")
	_ = sec.Set("existing-id", "key_passphrase", "y")

	out, err := svc.QuickSetupSave(QuickSetupInput{
		Purpose:   "debug worker",
		ProfileID: "existing-id",
		Host:      "100.100.1.9",
		Username:  "ubuntu",
		AuthMode:  "hybrid",
	})
	if err != nil {
		t.Fatalf("quick save err: %v", err)
	}
	secretsSaved, ok := out["secrets_saved"].(map[string]bool)
	if !ok {
		t.Fatalf("secrets_saved should be present")
	}
	if !secretsSaved["password"] || !secretsSaved["key_passphrase"] {
		t.Fatalf("existing secrets should be reflected: %#v", secretsSaved)
	}
	if _, ok := out["credentials_hint"]; ok {
		t.Fatalf("credentials_hint should be omitted when required secrets already exist")
	}
}

func TestResolveConnectionByProfileName(t *testing.T) {
	svc := newTestService(t)
	if err := svc.ProfileStore().Upsert(model.Profile{
		ID:             "rayna-dev-1",
		Name:           "rayna-dev",
		Host:           "100.100.2.1",
		Port:           22,
		Username:       "ubuntu",
		AuthPriority:   []string{"key"},
		WorkspaceRoots: []string{"/home/ubuntu"},
	}); err != nil {
		t.Fatalf("upsert profile: %v", err)
	}
	conn, err := svc.resolveConnectionInput(model.ConnectionInput{ProfileName: "rayna-dev"})
	if err != nil {
		t.Fatalf("resolve by name: %v", err)
	}
	if conn.Host != "100.100.2.1" {
		t.Fatalf("unexpected host: %s", conn.Host)
	}
}

func TestBuildProfileID(t *testing.T) {
	got := buildProfileID("Debug JSONL", "devbox.ts.net")
	if got == "" {
		t.Fatalf("empty profile id")
	}
	if got != "debug-jsonl-devbox-ts-net" {
		t.Fatalf("unexpected id: %s", got)
	}
}

func TestResolveConnectionInputRequiresProfile(t *testing.T) {
	svc := newTestService(t)
	_, err := svc.resolveConnectionInput(model.ConnectionInput{})
	if err == nil {
		t.Fatalf("expected error when no profile specified")
	}
}

func TestProfileDeleteRemovesProfileAndSecrets(t *testing.T) {
	svc := newTestService(t)
	sec := svc.secrets.(*testSecretStore)
	if err := svc.ProfileStore().Upsert(model.Profile{
		ID:             "to-del",
		Name:           "to-del",
		Host:           "100.100.2.8",
		Port:           22,
		Username:       "ubuntu",
		AuthPriority:   []string{"password"},
		WorkspaceRoots: []string{"/home/ubuntu"},
	}); err != nil {
		t.Fatalf("upsert profile: %v", err)
	}
	_ = sec.Set("to-del", "password", "x")
	_ = sec.Set("to-del", "key_passphrase", "y")
	_ = sec.Set("to-del", "sudo_password", "z")
	cnote, err := svc.Cnote("set", "to-del", "", "下载大文件时统一落到 /mnt/ssd")
	if err != nil {
		t.Fatalf("cnote set: %v", err)
	}
	cnotePath, _ := cnote["cnote_path"].(string)

	first, err := svc.ProfileDelete("to-del", true, "")
	if err != nil {
		t.Fatalf("profile delete: %v", err)
	}
	token, _ := first["confirm_token"].(string)
	if token == "" {
		t.Fatalf("confirm_token should be returned")
	}
	out, err := svc.ProfileDelete("to-del", true, token)
	if err != nil {
		t.Fatalf("profile delete confirm: %v", err)
	}
	if deleted, _ := out["deleted"].(bool); !deleted {
		t.Fatalf("deleted should be true")
	}
	p, err := svc.ProfileStore().Get("to-del")
	if err != nil {
		t.Fatalf("profile get: %v", err)
	}
	if p != nil {
		t.Fatalf("profile should be deleted")
	}
	if _, ok := sec.values["to-del:password"]; ok {
		t.Fatalf("password secret should be deleted")
	}
	if _, ok := sec.values["to-del:key_passphrase"]; ok {
		t.Fatalf("key_passphrase secret should be deleted")
	}
	if _, ok := sec.values["to-del:sudo_password"]; ok {
		t.Fatalf("sudo_password secret should be deleted")
	}
	if _, err := os.Stat(cnotePath); !os.IsNotExist(err) {
		t.Fatalf("cnote file should be deleted, got err=%v", err)
	}
}

func TestQuickSetupSaveDefaultAllowedLocalPaths(t *testing.T) {
	svc := newTestService(t)
	out, err := svc.QuickSetupSave(QuickSetupInput{
		Purpose:  "test local paths",
		Host:     "10.0.0.11",
		Username: "ubuntu",
	})
	if err != nil {
		t.Fatalf("quick save: %v", err)
	}
	paths, ok := out["allowed_local_paths"].([]string)
	if !ok || len(paths) == 0 {
		t.Fatalf("expected non-empty allowed_local_paths in response, got %v", out["allowed_local_paths"])
	}
	profileID, _ := out["profile_id"].(string)
	p, err := svc.ProfileStore().Get(profileID)
	if err != nil || p == nil {
		t.Fatalf("get profile: %v", err)
	}
	if len(p.AllowedLocalPaths) == 0 {
		t.Fatalf("profile should have default allowed_local_paths")
	}
}

func TestQuickSetupSaveExplicitEmptyAllowedLocalPaths(t *testing.T) {
	svc := newTestService(t)
	empty := []string{}
	out, err := svc.QuickSetupSave(QuickSetupInput{
		Purpose:           "no whitelist",
		Host:              "10.0.0.13",
		Username:          "ubuntu",
		AllowedLocalPaths: &empty,
	})
	if err != nil {
		t.Fatalf("quick save: %v", err)
	}
	profileID, _ := out["profile_id"].(string)
	p, err := svc.ProfileStore().Get(profileID)
	if err != nil || p == nil {
		t.Fatalf("get profile: %v", err)
	}
	if len(p.AllowedLocalPaths) != 0 {
		t.Fatalf("explicit empty should result in no allowed paths, got %v", p.AllowedLocalPaths)
	}
}

func TestQuickSetupEditAllowedLocalPaths(t *testing.T) {
	svc := newTestService(t)
	// Create profile with defaults
	_, err := svc.QuickSetupSave(QuickSetupInput{
		Purpose:  "edit test",
		Host:     "10.0.0.12",
		Username: "ubuntu",
	})
	if err != nil {
		t.Fatalf("quick save: %v", err)
	}
	profileID := "edit-test-10-0-0-12"

	// Verify defaults exist
	p, _ := svc.ProfileStore().Get(profileID)
	if len(p.AllowedLocalPaths) == 0 {
		t.Fatalf("expected defaults after save")
	}

	// Edit with nil -> should NOT change
	_, err = svc.QuickSetupEdit(QuickSetupEditInput{
		ProfileID:         profileID,
		AllowedLocalPaths: nil,
	})
	if err != nil {
		t.Fatalf("edit nil: %v", err)
	}
	p, _ = svc.ProfileStore().Get(profileID)
	if len(p.AllowedLocalPaths) == 0 {
		t.Fatalf("nil edit should preserve existing paths")
	}

	// Edit with empty slice -> should clear
	empty := []string{}
	_, err = svc.QuickSetupEdit(QuickSetupEditInput{
		ProfileID:         profileID,
		AllowedLocalPaths: &empty,
	})
	if err != nil {
		t.Fatalf("edit clear: %v", err)
	}
	p, _ = svc.ProfileStore().Get(profileID)
	if len(p.AllowedLocalPaths) != 0 {
		t.Fatalf("empty slice edit should clear paths, got %v", p.AllowedLocalPaths)
	}

	// Edit with new paths -> should set
	newPaths := []string{t.TempDir()}
	_, err = svc.QuickSetupEdit(QuickSetupEditInput{
		ProfileID:         profileID,
		AllowedLocalPaths: &newPaths,
	})
	if err != nil {
		t.Fatalf("edit set: %v", err)
	}
	p, _ = svc.ProfileStore().Get(profileID)
	if len(p.AllowedLocalPaths) != 1 {
		t.Fatalf("expected 1 path after edit, got %v", p.AllowedLocalPaths)
	}
}

func TestQuickSetupEditShell(t *testing.T) {
	svc := newTestService(t)
	_, err := svc.QuickSetupSave(QuickSetupInput{
		Purpose:  "shell test",
		Host:     "10.0.0.20",
		Username: "ubuntu",
	})
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	profileID := "shell-test-10-0-0-20"

	// Initially shell is empty (undetected).
	p, _ := svc.ProfileStore().Get(profileID)
	if p.Shell != "" {
		t.Fatalf("expected empty shell after save, got %q", p.Shell)
	}

	// Set valid shell value.
	v := "sh -c"
	_, err = svc.QuickSetupEdit(QuickSetupEditInput{
		ProfileID: profileID,
		Shell:     &v,
	})
	if err != nil {
		t.Fatalf("edit sh -c: %v", err)
	}
	p, _ = svc.ProfileStore().Get(profileID)
	if p.Shell != "sh -c" {
		t.Fatalf("expected shell = %q, got %q", "sh -c", p.Shell)
	}

	// Set "auto" → clears to empty for re-detection.
	v = "auto"
	_, err = svc.QuickSetupEdit(QuickSetupEditInput{
		ProfileID: profileID,
		Shell:     &v,
	})
	if err != nil {
		t.Fatalf("edit auto: %v", err)
	}
	p, _ = svc.ProfileStore().Get(profileID)
	if p.Shell != "" {
		t.Fatalf("expected empty shell after auto, got %q", p.Shell)
	}

	// Set __raw__.
	v = "__raw__"
	_, err = svc.QuickSetupEdit(QuickSetupEditInput{
		ProfileID: profileID,
		Shell:     &v,
	})
	if err != nil {
		t.Fatalf("edit __raw__: %v", err)
	}
	p, _ = svc.ProfileStore().Get(profileID)
	if p.Shell != "__raw__" {
		t.Fatalf("expected shell = %q, got %q", "__raw__", p.Shell)
	}

	// Invalid value → rejected.
	v = "zsh -c"
	_, err = svc.QuickSetupEdit(QuickSetupEditInput{
		ProfileID: profileID,
		Shell:     &v,
	})
	if err == nil {
		t.Fatal("expected error for invalid shell value")
	}
	if !strings.Contains(err.Error(), "invalid shell") {
		t.Fatalf("expected 'invalid shell' error, got: %v", err)
	}
	// Shell should remain unchanged after failed edit.
	p, _ = svc.ProfileStore().Get(profileID)
	if p.Shell != "__raw__" {
		t.Fatalf("shell should be unchanged after failed edit, got %q", p.Shell)
	}

	// nil Shell → no change.
	_, err = svc.QuickSetupEdit(QuickSetupEditInput{
		ProfileID: profileID,
		Shell:     nil,
	})
	if err != nil {
		t.Fatalf("edit nil: %v", err)
	}
	p, _ = svc.ProfileStore().Get(profileID)
	if p.Shell != "__raw__" {
		t.Fatalf("nil edit should preserve shell, got %q", p.Shell)
	}
}

func TestQuickSetupSave_SSHOptionsValidation(t *testing.T) {
	svc := newTestService(t)

	// Allowed options pass.
	_, err := svc.QuickSetupSave(QuickSetupInput{
		Purpose:  "legacy router",
		Host:     "10.0.0.1",
		Username: "admin",
		SSHOptions: map[string]string{
			"HostKeyAlgorithms": "+ssh-rsa",
		},
	})
	if err != nil {
		t.Fatalf("allowed ssh_options should pass: %v", err)
	}

	// ProxyCommand rejected.
	_, err = svc.QuickSetupSave(QuickSetupInput{
		Purpose:  "evil",
		Host:     "10.0.0.2",
		Username: "admin",
		SSHOptions: map[string]string{
			"ProxyCommand": "nc %h %p",
		},
	})
	if err == nil {
		t.Fatal("ProxyCommand should be rejected")
	}
	if !strings.Contains(err.Error(), "ProxyCommand") {
		t.Fatalf("error should mention ProxyCommand: %v", err)
	}

	// Space in value allowed (RekeyLimit).
	_, err = svc.QuickSetupSave(QuickSetupInput{
		Purpose:  "rekey test",
		Host:     "10.0.0.3",
		Username: "admin",
		SSHOptions: map[string]string{
			"RekeyLimit": "1G 1h",
		},
	})
	if err != nil {
		t.Fatalf("space in RekeyLimit should be allowed: %v", err)
	}
}

func TestQuickSetupEdit_SSHOptionsClearAndPreserve(t *testing.T) {
	svc := newTestService(t)

	// Create profile with ssh_options.
	out, err := svc.QuickSetupSave(QuickSetupInput{
		Purpose:  "test opts",
		Host:     "10.0.0.5",
		Username: "ubuntu",
		SSHOptions: map[string]string{
			"Ciphers": "aes128-ctr",
		},
	})
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	profileID := out["profile_id"].(string)
	p, _ := svc.ProfileStore().Get(profileID)
	if len(p.SSHOptions) != 1 || p.SSHOptions["Ciphers"] != "aes128-ctr" {
		t.Fatalf("initial ssh_options mismatch: %v", p.SSHOptions)
	}

	// nil SSHOptions → preserve.
	_, err = svc.QuickSetupEdit(QuickSetupEditInput{
		ProfileID:  profileID,
		SSHOptions: nil,
	})
	if err != nil {
		t.Fatalf("edit nil: %v", err)
	}
	p, _ = svc.ProfileStore().Get(profileID)
	if len(p.SSHOptions) != 1 {
		t.Fatalf("nil edit should preserve ssh_options, got: %v", p.SSHOptions)
	}

	// Empty map → clear.
	empty := map[string]string{}
	_, err = svc.QuickSetupEdit(QuickSetupEditInput{
		ProfileID:  profileID,
		SSHOptions: &empty,
	})
	if err != nil {
		t.Fatalf("edit empty: %v", err)
	}
	p, _ = svc.ProfileStore().Get(profileID)
	if len(p.SSHOptions) != 0 {
		t.Fatalf("empty edit should clear ssh_options, got: %v", p.SSHOptions)
	}

	// Non-nil map → replace.
	newOpts := map[string]string{"MACs": "hmac-sha2-256"}
	_, err = svc.QuickSetupEdit(QuickSetupEditInput{
		ProfileID:  profileID,
		SSHOptions: &newOpts,
	})
	if err != nil {
		t.Fatalf("edit replace: %v", err)
	}
	p, _ = svc.ProfileStore().Get(profileID)
	if p.SSHOptions["MACs"] != "hmac-sha2-256" {
		t.Fatalf("replace should set new value, got: %v", p.SSHOptions)
	}
}

func TestQuickSetupEdit_SSHOptionsValidation(t *testing.T) {
	svc := newTestService(t)

	out, err := svc.QuickSetupSave(QuickSetupInput{
		Purpose:  "validate edit",
		Host:     "10.0.0.6",
		Username: "ubuntu",
	})
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	profileID := out["profile_id"].(string)

	// Disallowed key in edit → error.
	bad := map[string]string{"LocalForward": "8080:localhost:80"}
	_, err = svc.QuickSetupEdit(QuickSetupEditInput{
		ProfileID:  profileID,
		SSHOptions: &bad,
	})
	if err == nil {
		t.Fatal("LocalForward should be rejected in edit")
	}
}
