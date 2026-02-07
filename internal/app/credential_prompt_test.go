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

func TestManualCredentialInstructions(t *testing.T) {
	msg := manualCredentialInstructions("dev-1", []string{"password", "key_passphrase"})
	if !strings.Contains(msg, "csshctl secret set-password --profile dev-1") {
		t.Fatalf("missing set-password command: %s", msg)
	}
	if !strings.Contains(msg, "csshctl secret set-key-passphrase --profile dev-1") {
		t.Fatalf("missing set-key-passphrase command: %s", msg)
	}
}
