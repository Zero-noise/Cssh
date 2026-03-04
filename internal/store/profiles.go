package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"cssh/internal/filelock"
	"cssh/internal/model"
)

type ProfileStore struct {
	path string
	mu   sync.Mutex
}

func NewProfileStore(path string) *ProfileStore {
	return &ProfileStore{path: path}
}

func (s *ProfileStore) ensure() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(s.path); errors.Is(err, os.ErrNotExist) {
		return os.WriteFile(s.path, []byte("[]\n"), 0o600)
	}
	return nil
}

func (s *ProfileStore) loadAll() ([]model.Profile, error) {
	if err := s.ensure(); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}
	var out []model.Profile
	if len(b) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *ProfileStore) saveAll(items []model.Profile) error {
	b, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return filelock.AtomicWrite(s.path, b, 0o600)
}

func (s *ProfileStore) List() ([]model.Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := filelock.Lock(s.path)
	if err != nil {
		return nil, err
	}
	defer unlock()
	return s.loadAll()
}

func (s *ProfileStore) Get(id string) (*model.Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := filelock.Lock(s.path)
	if err != nil {
		return nil, err
	}
	defer unlock()
	items, err := s.loadAll()
	if err != nil {
		return nil, err
	}
	for i := range items {
		if items[i].ID == id {
			cp := items[i]
			return &cp, nil
		}
	}
	return nil, nil
}

func (s *ProfileStore) Upsert(p model.Profile) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := filelock.Lock(s.path)
	if err != nil {
		return err
	}
	defer unlock()
	items, err := s.loadAll()
	if err != nil {
		return err
	}
	updated := false
	for i := range items {
		if items[i].ID == p.ID {
			items[i] = p
			updated = true
			break
		}
	}
	if !updated {
		items = append(items, p)
	}
	return s.saveAll(items)
}

func (s *ProfileStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := filelock.Lock(s.path)
	if err != nil {
		return err
	}
	defer unlock()
	items, err := s.loadAll()
	if err != nil {
		return err
	}
	out := make([]model.Profile, 0, len(items))
	for _, it := range items {
		if it.ID != id {
			out = append(out, it)
		}
	}
	return s.saveAll(out)
}
