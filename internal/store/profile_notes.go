package store

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"cssh/internal/filelock"
)

var invalidProfileNotePathChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

type ProfileNoteStore struct {
	baseDir string
	mu      sync.Mutex
}

func NewProfileNoteStore(runtimeDir string) *ProfileNoteStore {
	return &ProfileNoteStore{baseDir: filepath.Join(runtimeDir, "profiles")}
}

func (s *ProfileNoteStore) ResolvePath(profileID string) string {
	name := invalidProfileNotePathChars.ReplaceAllString(strings.TrimSpace(profileID), "_")
	name = strings.Trim(name, "._-")
	if name == "" {
		name = "profile"
	}
	sum := sha256.Sum256([]byte(profileID))
	suffix := hex.EncodeToString(sum[:])[:10]
	return filepath.Join(s.baseDir, name+"-"+suffix, "cnote.md")
}

func (s *ProfileNoteStore) Ensure(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := filelock.Lock(path)
	if err != nil {
		return err
	}
	defer unlock()
	return s.ensureLocked(path)
}

func (s *ProfileNoteStore) Read(path string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := filelock.Lock(path)
	if err != nil {
		return "", err
	}
	defer unlock()
	if err := s.ensureLocked(path); err != nil {
		return "", err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (s *ProfileNoteStore) Set(path, content string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := filelock.Lock(path)
	if err != nil {
		return err
	}
	defer unlock()
	if err := s.ensureLocked(path); err != nil {
		return err
	}
	return filelock.AtomicWrite(path, []byte(content), 0o600)
}

func (s *ProfileNoteStore) Append(path, content string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := filelock.Lock(path)
	if err != nil {
		return "", err
	}
	defer unlock()
	if err := s.ensureLocked(path); err != nil {
		return "", err
	}
	current, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	merged := mergeNoteContent(string(current), content)
	if err := filelock.AtomicWrite(path, []byte(merged), 0o600); err != nil {
		return "", err
	}
	return merged, nil
}

func (s *ProfileNoteStore) Delete(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := filelock.Lock(path)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		unlock()
		return err
	}
	unlock()
	_ = os.Remove(path + ".lock")
	dir := filepath.Dir(path)
	if dir != "" {
		_ = os.Remove(dir)
	}
	return nil
}

func (s *ProfileNoteStore) ensureLocked(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return os.WriteFile(path, []byte(""), 0o600)
	}
	return nil
}

func mergeNoteContent(current, extra string) string {
	cur := strings.TrimRight(current, "\n")
	add := strings.TrimSpace(extra)
	switch {
	case cur == "":
		return add + "\n"
	case add == "":
		return cur + "\n"
	default:
		return cur + "\n\n" + add + "\n"
	}
}
