package app

import (
	"fmt"
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
	t.Helper()
	tmp := t.TempDir()
	cfg := model.Config{
		DefaultShell:           "bash -lc",
		DefaultTimeoutSec:      120,
		RuntimeDir:             filepath.Join(tmp, "runtime"),
		LogsDir:                filepath.Join(tmp, "logs"),
		ProfilesFile:           filepath.Join(tmp, "profiles.json"),
		SecurityProfileDefault: "easy_safe",
		ConnectRequireProfile:  true,
		EasySafeApprovalTTLsec: 900,
		ApprovalMode:           "terminal",
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

func TestQuickSetupSavePersistsProfile(t *testing.T) {
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
	if p.SecurityProfile != "easy_safe" {
		t.Fatalf("unexpected security_profile: %s", p.SecurityProfile)
	}
	if len(p.AuthPriority) != 1 || p.AuthPriority[0] != "password" {
		t.Fatalf("unexpected auth priority: %#v", p.AuthPriority)
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
		WorkspaceRoots: []string{"/home/ubuntu/project"},
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

func TestResolveConnectionInputDirectDeniedByPolicy(t *testing.T) {
	svc := newTestService(t)
	_, err := svc.resolveConnectionInput(model.ConnectionInput{
		Host:     "100.100.1.9",
		Username: "ubuntu",
	})
	if err == nil {
		t.Fatalf("expected direct connection to be denied")
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
		WorkspaceRoots: []string{"/home/ubuntu/project"},
	}); err != nil {
		t.Fatalf("upsert profile: %v", err)
	}
	_ = sec.Set("to-del", "password", "x")
	_ = sec.Set("to-del", "key_passphrase", "y")
	_ = sec.Set("to-del", "sudo_password", "z")

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
}
