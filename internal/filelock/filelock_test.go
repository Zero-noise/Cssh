package filelock

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestLockUnlock(t *testing.T) {
	dir := t.TempDir()
	dataPath := filepath.Join(dir, "data.json")

	unlock, err := Lock(dataPath)
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	// Lock file should exist.
	if _, err := os.Stat(dataPath + ".lock"); err != nil {
		t.Fatalf("lock file missing: %v", err)
	}
	unlock()
}

func TestLockSerializesGoroutines(t *testing.T) {
	dir := t.TempDir()
	dataPath := filepath.Join(dir, "counter.json")

	const n = 50
	var mu sync.Mutex
	var order []int

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			unlock, err := Lock(dataPath)
			if err != nil {
				t.Errorf("Lock: %v", err)
				return
			}
			mu.Lock()
			order = append(order, id)
			mu.Unlock()
			unlock()
		}(i)
	}
	wg.Wait()

	if len(order) != n {
		t.Fatalf("expected %d entries, got %d", n, len(order))
	}
}

func TestAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")

	data := []byte(`{"hello":"world"}`)
	if err := AtomicWrite(path, data, 0o600); err != nil {
		t.Fatalf("AtomicWrite: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(data) {
		t.Fatalf("content mismatch: got %q, want %q", got, data)
	}

	// Verify no temp files left behind.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("expected 1 file, got %d", len(entries))
	}
}
