// Package filelock provides cross-process file locking using flock(2).
package filelock

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Unlocker releases a held file lock. Must be called exactly once.
type Unlocker func()

// Lock acquires an exclusive flock on "<dataPath>.lock", creating the lock
// file and parent directories as needed. It blocks until the lock is obtained.
// The returned Unlocker must be called to release the lock.
func Lock(dataPath string) (Unlocker, error) {
	lockPath := dataPath + ".lock"
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return nil, fmt.Errorf("filelock: mkdir: %w", err)
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("filelock: open: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("filelock: flock: %w", err)
	}
	return func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
