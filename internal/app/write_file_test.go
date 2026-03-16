package app

import (
	"strings"
	"testing"

	"cssh/internal/errorsx"
)

func TestBuildWriteFileCmdOverwrite(t *testing.T) {
	cmd, err := buildWriteFileCmd("/home/user/file.txt", "overwrite")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(cmd, "mktemp") {
		t.Error("overwrite mode should use mktemp")
	}
	if !strings.Contains(cmd, "trap") {
		t.Error("overwrite mode should include trap for cleanup")
	}
	if !strings.Contains(cmd, "mv -f") {
		t.Error("overwrite mode should use mv -f for atomic replace")
	}
	if !strings.Contains(cmd, "base64 -d") {
		t.Error("should read base64 from stdin")
	}
	if !strings.Contains(cmd, "chmod --reference=") {
		t.Error("overwrite mode should attempt to preserve permissions")
	}
}

func TestBuildWriteFileCmdCreate(t *testing.T) {
	cmd, err := buildWriteFileCmd("/home/user/file.txt", "create")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(cmd, "set -C") {
		t.Error("create mode should set noclobber")
	}
	if !strings.Contains(cmd, "exit 17") {
		t.Error("create mode should exit 17 when file exists")
	}
	if !strings.Contains(cmd, "base64 -d >") {
		t.Error("should decode base64 from stdin to file")
	}
}

func TestBuildWriteFileCmdAppend(t *testing.T) {
	cmd, err := buildWriteFileCmd("/home/user/file.txt", "append")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(cmd, ">>") {
		t.Error("append mode should use >> operator")
	}
	if !strings.Contains(cmd, "base64 -d") {
		t.Error("should decode base64 from stdin")
	}
}

func TestBuildWriteFileCmdInvalidMode(t *testing.T) {
	_, err := buildWriteFileCmd("/home/user/file.txt", "delete")
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
	ce, ok := err.(*errorsx.CsshError)
	if !ok {
		t.Fatalf("expected CsshError, got %T", err)
	}
	if ce.Code != errorsx.CodeInvalidParams {
		t.Errorf("expected CodeInvalidParams, got %s", ce.Code)
	}
}

func TestBuildWriteFileCmdShellQuoting(t *testing.T) {
	cmd, err := buildWriteFileCmd("/home/user/it's a file.txt", "create")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The path with single quote should be properly escaped.
	if !strings.Contains(cmd, `'\''`) {
		t.Error("single quote in path should be escaped")
	}
}

func TestMaxWriteFileBytes(t *testing.T) {
	if maxWriteFileBytes != 5*1024*1024 {
		t.Errorf("maxWriteFileBytes should be 5 MB, got %d", maxWriteFileBytes)
	}
}
