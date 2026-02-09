package app

import (
	"strings"
	"testing"
)

func TestNormalizeCredentialFields(t *testing.T) {
	fields, invalid := normalizeCredentialFields([]string{
		"password",
		" key_passphrase ",
		"PASSWORD",
		"token",
		"",
	})
	if len(invalid) != 1 || invalid[0] != "token" {
		t.Fatalf("unexpected invalid fields: %#v", invalid)
	}
	if len(fields) != 2 || fields[0] != "password" || fields[1] != "key_passphrase" {
		t.Fatalf("unexpected normalized fields: %#v", fields)
	}
}

func TestNormalizeCredentialFieldsSudoPassword(t *testing.T) {
	fields, invalid := normalizeCredentialFields([]string{"sudo_password"})
	if len(invalid) != 0 {
		t.Fatalf("sudo_password should be valid, got invalid: %#v", invalid)
	}
	if len(fields) != 1 || fields[0] != "sudo_password" {
		t.Fatalf("unexpected normalized fields: %#v", fields)
	}
}

func TestManualCredentialInstructions(t *testing.T) {
	msg := manualCredentialInstructions("dev-1", []string{"password", "key_passphrase"})
	if !strings.Contains(msg, "csshctl secret set-password --profile dev-1") {
		t.Fatalf("missing set-password command: %s", msg)
	}
	if !strings.Contains(msg, "csshctl secret set-key-passphrase --profile dev-1") {
		t.Fatalf("missing set-key-passphrase command: %s", msg)
	}
}

func TestManualCredentialInstructionsSudoPassword(t *testing.T) {
	msg := manualCredentialInstructions("dev-1", []string{"sudo_password"})
	if !strings.Contains(msg, "csshctl secret set-sudo-password --profile dev-1") {
		t.Fatalf("missing set-sudo-password command: %s", msg)
	}
}

func TestNormalizePromptMode(t *testing.T) {
	if normalizePromptMode("terminal") != "terminal" {
		t.Fatalf("terminal mode mismatch")
	}
	if normalizePromptMode("web") != "web" {
		t.Fatalf("web mode mismatch")
	}
	if normalizePromptMode("") != "auto" {
		t.Fatalf("empty mode should default to auto")
	}
}

func TestCanUseTerminalPromptNoPanic(t *testing.T) {
	_ = canUseTerminalPrompt()
}
