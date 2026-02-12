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
	if !strings.Contains(msg, "continue without restarting") {
		t.Fatalf("missing no-restart instruction: %s", msg)
	}
	if !strings.Contains(msg, "resume this conversation") {
		t.Fatalf("missing resume instruction: %s", msg)
	}
}

func TestManualCredentialInstructionsSudoPassword(t *testing.T) {
	msg := manualCredentialInstructions("dev-1", []string{"sudo_password"})
	if !strings.Contains(msg, "csshctl secret set-sudo-password --profile dev-1") {
		t.Fatalf("missing set-sudo-password command: %s", msg)
	}
}

func TestManualCredentialCommands(t *testing.T) {
	cmds := manualCredentialCommands("dev-1", []string{"password", "key_passphrase", "sudo_password"})
	if len(cmds) != 3 {
		t.Fatalf("unexpected command count: %d", len(cmds))
	}
	for _, cmd := range cmds {
		if !strings.HasPrefix(cmd, "csshctl secret ") {
			t.Fatalf("command should use local csshctl: %s", cmd)
		}
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
