package filelock

import (
	"fmt"
	"os"
	"path/filepath"
)

// AtomicWrite writes data to a temp file in the same directory as path, then
// renames it over path. This ensures readers never see a partially-written file.
// The caller should hold the file lock for path before calling this.
func AtomicWrite(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp.*")
	if err != nil {
		return fmt.Errorf("atomic write: create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		// Clean up temp file on any error path.
		if tmpName != "" {
			os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("atomic write: write: %w", err)
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return fmt.Errorf("atomic write: chmod: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("atomic write: close: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("atomic write: rename: %w", err)
	}
	tmpName = "" // prevent deferred cleanup
	return nil
}
