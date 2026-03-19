package app

import (
	"fmt"
	"strings"
	"testing"

	"cssh/internal/security"
)

// --- Constants ---

func TestReadFileConstants(t *testing.T) {
	if readFileDefaultMaxBytes != 512*1024 {
		t.Errorf("readFileDefaultMaxBytes should be 512KB, got %d", readFileDefaultMaxBytes)
	}
	if readFileHardMaxBytes != 2*1024*1024 {
		t.Errorf("readFileHardMaxBytes should be 2MB, got %d", readFileHardMaxBytes)
	}
	if readFileDefaultOffset != 1 {
		t.Errorf("readFileDefaultOffset should be 1, got %d", readFileDefaultOffset)
	}
	if readFileDefaultLimit != 2000 {
		t.Errorf("readFileDefaultLimit should be 2000, got %d", readFileDefaultLimit)
	}
}

// --- normalizeReadFileParams ---

func TestNormalizeReadFileParamsDefaults(t *testing.T) {
	mb, off, lim := normalizeReadFileParams(0, 0, 0)
	if mb != readFileDefaultMaxBytes {
		t.Errorf("maxBytes: got %d, want %d", mb, readFileDefaultMaxBytes)
	}
	if off != readFileDefaultOffset {
		t.Errorf("offset: got %d, want %d", off, readFileDefaultOffset)
	}
	if lim != readFileDefaultLimit {
		t.Errorf("limit: got %d, want %d", lim, readFileDefaultLimit)
	}
}

func TestNormalizeReadFileParamsClamping(t *testing.T) {
	mb, off, lim := normalizeReadFileParams(10*1024*1024, -1, -1)
	if mb != readFileHardMaxBytes {
		t.Errorf("maxBytes should be clamped to %d, got %d", readFileHardMaxBytes, mb)
	}
	if off != readFileDefaultOffset {
		t.Errorf("offset should default to %d for negative, got %d", readFileDefaultOffset, off)
	}
	if lim != readFileDefaultLimit {
		t.Errorf("limit should default to %d for negative, got %d", readFileDefaultLimit, lim)
	}
}

func TestNormalizeReadFileParamsPassthrough(t *testing.T) {
	mb, off, lim := normalizeReadFileParams(100, 5, 10)
	if mb != 100 || off != 5 || lim != 10 {
		t.Errorf("valid params should pass through unchanged: got (%d, %d, %d)", mb, off, lim)
	}
}

// --- buildReadFileCmd ---

func TestBuildReadFileCmdBasic(t *testing.T) {
	cmd := buildReadFileCmd("'/home/user/file.txt'", 1, 2000, 524288)
	for _, want := range []string{"realpath", "wc -c", "awk", "head -c"} {
		if !strings.Contains(cmd, want) {
			t.Errorf("command should contain %q", want)
		}
	}
}

func TestBuildReadFileCmdShellQuoting(t *testing.T) {
	cmd := buildReadFileCmd("'/home/user/it'\\''s a file.txt'", 1, 100, 1024)
	if !strings.Contains(cmd, `'\''`) {
		t.Error("single quote in path should be escaped")
	}
}

func TestBuildReadFileCmdOffsetLimit(t *testing.T) {
	cmd := buildReadFileCmd("'/test'", 10, 10, 1024)
	if !strings.Contains(cmd, "s=10") {
		t.Error("awk should use s=10")
	}
	if !strings.Contains(cmd, "e=19") {
		t.Error("awk should use e=19 (offset+limit-1)")
	}
}

func TestBuildReadFileCmdMaxBytes(t *testing.T) {
	cmd := buildReadFileCmd("'/test'", 1, 100, 99999)
	if !strings.Contains(cmd, "head -c 99999") {
		t.Error("head -c should use maxBytes value")
	}
}

func TestBuildReadFileCmdPermissionGuard(t *testing.T) {
	cmd := buildReadFileCmd("'/test'", 1, 100, 1024)
	if !strings.Contains(cmd, "exit 3") {
		t.Error("should exit 3 when wc -c fails (e.g. permission denied)")
	}
}

func TestBuildReadFileCmdBinaryCheck(t *testing.T) {
	cmd := buildReadFileCmd("'/test'", 1, 100, 1024)
	if !strings.Contains(cmd, "file -b --mime-encoding") {
		t.Error("should include file command for binary detection")
	}
	if !strings.Contains(cmd, `tr -cd '\000'`) {
		t.Error("should include NUL byte fallback detection")
	}
}

// --- parseLeadingLineNum ---

func TestParseLeadingLineNum(t *testing.T) {
	cases := []struct {
		input string
		want  int
	}{
		{"     1\tdata", 1},
		{"  1000\tdata", 1000},
		{"42\tdata", 42},
		{"noTab", 0},
		{"abc\tdata", 0},
		{"\tdata", 0},
	}
	for _, tc := range cases {
		got := parseLeadingLineNum(tc.input)
		if got != tc.want {
			t.Errorf("parseLeadingLineNum(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

// --- parseReadFileOutput ---

func TestParseReadFileOutputNormal(t *testing.T) {
	stdout := "/home/user/file.txt\n12345\n500\nfalse\nutf-8\n     1\tfirst line\n     2\tsecond line\n"
	r, err := parseReadFileOutput(stdout, 524288)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.RealPath != "/home/user/file.txt" {
		t.Errorf("RealPath = %q", r.RealPath)
	}
	if r.Size != 12345 {
		t.Errorf("Size = %d", r.Size)
	}
	if r.TotalLines != 500 {
		t.Errorf("TotalLines = %d", r.TotalLines)
	}
	if r.Binary {
		t.Error("Binary should be false")
	}
	if r.MimeEncoding != "utf-8" {
		t.Errorf("MimeEncoding = %q", r.MimeEncoding)
	}
	if r.LineStart != 1 {
		t.Errorf("LineStart = %d", r.LineStart)
	}
	if r.LineEnd != 2 {
		t.Errorf("LineEnd = %d", r.LineEnd)
	}
	if r.Truncated {
		t.Error("Truncated should be false")
	}
}

func TestParseReadFileOutputBinary(t *testing.T) {
	stdout := "/usr/bin/ls\n137432\n0\ntrue\nbinary\n"
	r, err := parseReadFileOutput(stdout, 524288)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.Binary {
		t.Error("Binary should be true")
	}
	if r.Content != "" {
		t.Errorf("Content should be empty for binary, got %q", r.Content)
	}
	if r.TotalLines != 0 {
		t.Error("TotalLines should be 0 for binary")
	}
}

func TestParseReadFileOutputMalformed(t *testing.T) {
	_, err := parseReadFileOutput("only\ntwo\nlines", 1024)
	if err == nil {
		t.Fatal("expected error for malformed output")
	}
}

func TestParseReadFileOutputEmptyFile(t *testing.T) {
	stdout := "/home/user/empty.txt\n0\n0\nfalse\nutf-8\n"
	r, err := parseReadFileOutput(stdout, 524288)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Size != 0 {
		t.Errorf("Size = %d", r.Size)
	}
	if r.TotalLines != 0 {
		t.Errorf("TotalLines = %d", r.TotalLines)
	}
	if r.Content != "" {
		t.Errorf("Content should be empty, got %q", r.Content)
	}
}

func TestParseReadFileOutputTruncated(t *testing.T) {
	// content length >= maxBytes → Truncated
	content := strings.Repeat("x", 100)
	stdout := fmt.Sprintf("/f\n200\n10\nfalse\nutf-8\n     1\t%s", content)
	r, err := parseReadFileOutput(stdout, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.Truncated {
		t.Error("should be truncated when content length >= maxBytes")
	}
}

func TestParseReadFileOutputNotTruncated(t *testing.T) {
	stdout := "/f\n200\n10\nfalse\nutf-8\n     1\thello\n"
	r, err := parseReadFileOutput(stdout, 524288)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Truncated {
		t.Error("should not be truncated when content < maxBytes")
	}
}

func TestParseReadFileOutputLineNumbers(t *testing.T) {
	stdout := "/f\n100\n50\nfalse\nutf-8\n    10\tline10\n    11\tline11\n    12\tline12\n"
	r, err := parseReadFileOutput(stdout, 524288)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.LineStart != 10 {
		t.Errorf("LineStart = %d, want 10", r.LineStart)
	}
	if r.LineEnd != 12 {
		t.Errorf("LineEnd = %d, want 12", r.LineEnd)
	}
}

func TestParseReadFileOutputMimeEncoding(t *testing.T) {
	stdout := "/f\n100\n5\nfalse\nus-ascii\n     1\thi\n"
	r, err := parseReadFileOutput(stdout, 524288)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.MimeEncoding != "us-ascii" {
		t.Errorf("MimeEncoding = %q, want us-ascii", r.MimeEncoding)
	}
}

func TestParseReadFileOutputSymlinkPath(t *testing.T) {
	// The parser should extract the real resolved path from line 1
	stdout := "/etc/shadow\n1000\n20\nfalse\nutf-8\n     1\troot:*:19000:0:99999:7:::\n"
	r, err := parseReadFileOutput(stdout, 524288)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.RealPath != "/etc/shadow" {
		t.Errorf("RealPath = %q, want /etc/shadow", r.RealPath)
	}
}

// --- buildReadFileResponse ---

func TestBuildReadFileResponseNormal(t *testing.T) {
	parsed := readFileResult{
		RealPath:   "/home/user/file.txt",
		Size:       1234,
		TotalLines: 50,
		Content:    "     1\tfirst\n     2\tsecond\n",
		LineStart:  1,
		LineEnd:    2,
		Truncated:  false,
	}
	resp := buildReadFileResponse(parsed)
	if resp["size"] != int64(1234) {
		t.Errorf("size = %v", resp["size"])
	}
	if resp["total_lines"] != 50 {
		t.Errorf("total_lines = %v", resp["total_lines"])
	}
	if resp["line_start"] != 1 {
		t.Errorf("line_start = %v", resp["line_start"])
	}
	if resp["line_end"] != 2 {
		t.Errorf("line_end = %v", resp["line_end"])
	}
	if resp["truncated"] != false {
		t.Error("truncated should be false")
	}
	if _, ok := resp["binary"]; ok {
		t.Error("normal file should not have binary key")
	}
}

func TestBuildReadFileResponseBinary(t *testing.T) {
	parsed := readFileResult{
		RealPath:     "/usr/bin/ls",
		Size:         137432,
		Binary:       true,
		MimeEncoding: "binary",
	}
	resp := buildReadFileResponse(parsed)
	if resp["binary"] != true {
		t.Error("binary should be true")
	}
	if resp["content"] != "" {
		t.Error("content should be empty for binary")
	}
	if resp["note"] != "use ssh_transfer to download" {
		t.Errorf("note = %v", resp["note"])
	}
	if resp["mime_encoding"] != "binary" {
		t.Errorf("mime_encoding = %v", resp["mime_encoding"])
	}
}

func TestBuildReadFileResponseTruncated(t *testing.T) {
	parsed := readFileResult{
		Size:      100000,
		Content:   "some content",
		Truncated: true,
	}
	resp := buildReadFileResponse(parsed)
	if resp["truncated"] != true {
		t.Error("truncated should be true")
	}
}

func TestBuildReadFileResponseBinaryNoMime(t *testing.T) {
	parsed := readFileResult{
		Size:   5000,
		Binary: true,
	}
	resp := buildReadFileResponse(parsed)
	if _, ok := resp["mime_encoding"]; ok {
		t.Error("should not include mime_encoding when empty")
	}
}

// --- Security: IsWithinRoots with parsed realpath ---

func TestReadFileSymlinkSecurityCheck(t *testing.T) {
	cases := []struct {
		realPath string
		roots    []string
		allowed  bool
	}{
		{"/home/user/file", []string{"/home/user"}, true},
		{"/etc/shadow", []string{"/home/user"}, false},
		{"/home/user/subdir/file", []string{"/home/user"}, true},
		{"/home/user", []string{"/home/user"}, true},
		{"/home/userfoo", []string{"/home/user"}, false},
	}
	for _, tc := range cases {
		got := security.IsWithinRoots(tc.realPath, tc.roots)
		if got != tc.allowed {
			t.Errorf("IsWithinRoots(%q, %v) = %v, want %v", tc.realPath, tc.roots, got, tc.allowed)
		}
	}
}
