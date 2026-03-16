package app

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncateOutput_BelowThreshold(t *testing.T) {
	input := strings.Repeat("a", execOutputTruncateThreshold-1)
	result, truncated, origLen := truncateOutput(input)
	if truncated {
		t.Fatal("should not be truncated")
	}
	if result != input {
		t.Fatal("result should equal input")
	}
	if origLen != len(input) {
		t.Fatalf("origLen = %d, want %d", origLen, len(input))
	}
}

func TestTruncateOutput_ExactThreshold(t *testing.T) {
	input := strings.Repeat("b", execOutputTruncateThreshold)
	result, truncated, _ := truncateOutput(input)
	if truncated {
		t.Fatal("should not be truncated at exact threshold")
	}
	if result != input {
		t.Fatal("result should equal input")
	}
}

func TestTruncateOutput_AboveThreshold(t *testing.T) {
	size := execOutputTruncateThreshold + 10000
	input := strings.Repeat("x", size)
	result, truncated, origLen := truncateOutput(input)
	if !truncated {
		t.Fatal("should be truncated")
	}
	if origLen != size {
		t.Fatalf("origLen = %d, want %d", origLen, size)
	}
	// Result must contain head content.
	if !strings.HasPrefix(result, strings.Repeat("x", execOutputHeadBytes)) {
		t.Fatal("result should start with head bytes")
	}
	// Result must contain tail content.
	if !strings.HasSuffix(result, strings.Repeat("x", execOutputTailBytes)) {
		t.Fatal("result should end with tail bytes")
	}
	// Must contain truncation marker.
	if !strings.Contains(result, "--- OUTPUT TRUNCATED ---") {
		t.Fatal("result should contain truncation marker")
	}
	if !strings.Contains(result, "--- END TRUNCATION NOTICE ---") {
		t.Fatal("result should contain end marker")
	}
	// Result should be smaller than the original.
	if len(result) >= size {
		t.Fatalf("result length %d should be less than original %d", len(result), size)
	}
}

func TestTruncateOutput_UTF8Boundary(t *testing.T) {
	// Build a string where multi-byte chars sit at the cut boundary.
	// U+00E9 (é) is 2 bytes: 0xC3 0xA9.
	prefix := strings.Repeat("a", execOutputHeadBytes-1) + "é" // ends 1 byte past headBytes
	middle := strings.Repeat("m", execOutputTruncateThreshold)
	// Place a multi-byte char near where the tail would start.
	suffix := "é" + strings.Repeat("z", execOutputTailBytes)
	input := prefix + middle + suffix

	result, truncated, _ := truncateOutput(input)
	if !truncated {
		t.Fatal("should be truncated")
	}
	if !utf8.ValidString(result) {
		t.Fatal("result must be valid UTF-8")
	}
	if !strings.Contains(result, "--- OUTPUT TRUNCATED ---") {
		t.Fatal("missing truncation marker")
	}
}

func TestTruncateOutput_Empty(t *testing.T) {
	result, truncated, origLen := truncateOutput("")
	if truncated {
		t.Fatal("empty string should not be truncated")
	}
	if result != "" {
		t.Fatal("result should be empty")
	}
	if origLen != 0 {
		t.Fatal("origLen should be 0")
	}
}

func TestTruncateOutput_MarkerContent(t *testing.T) {
	size := execOutputTruncateThreshold * 2
	input := strings.Repeat("d", size)
	result, truncated, _ := truncateOutput(input)
	if !truncated {
		t.Fatal("should be truncated")
	}
	expectedHead := fmt.Sprintf("first %d", execOutputHeadBytes)
	if !strings.Contains(result, expectedHead) {
		t.Fatalf("marker should contain %q", expectedHead)
	}
	expectedTail := fmt.Sprintf("last %d", execOutputTailBytes)
	if !strings.Contains(result, expectedTail) {
		t.Fatalf("marker should contain %q", expectedTail)
	}
	expectedTotal := fmt.Sprintf("of %d bytes", size)
	if !strings.Contains(result, expectedTotal) {
		t.Fatalf("marker should contain %q", expectedTotal)
	}
}

func TestTruncationConstants(t *testing.T) {
	if execOutputHeadBytes+execOutputTailBytes >= execOutputTruncateThreshold {
		t.Fatalf("head (%d) + tail (%d) must be less than threshold (%d)",
			execOutputHeadBytes, execOutputTailBytes, execOutputTruncateThreshold)
	}
}
