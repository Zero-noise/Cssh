package approvals

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"cssh/internal/model"
)

type GrantStore struct {
	path string
	mu   sync.Mutex
}

func NewGrantStore(path string) *GrantStore {
	return &GrantStore{path: path}
}

func (s *GrantStore) ensure() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(s.path); errors.Is(err, os.ErrNotExist) {
		return os.WriteFile(s.path, []byte("[]\n"), 0o600)
	}
	return nil
}

func (s *GrantStore) loadAll() ([]model.PrivilegeGrant, error) {
	if err := s.ensure(); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}
	var out []model.PrivilegeGrant
	if len(b) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *GrantStore) saveAll(items []model.PrivilegeGrant) error {
	b, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(s.path, b, 0o600)
}

func (s *GrantStore) Create(g model.PrivilegeGrant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	items, err := s.loadAll()
	if err != nil {
		return err
	}
	items = append(items, g)
	return s.saveAll(items)
}

func (s *GrantStore) Revoke(id string) (*model.PrivilegeGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	items, err := s.loadAll()
	if err != nil {
		return nil, err
	}
	var updated *model.PrivilegeGrant
	now := time.Now().UTC()
	for i := range items {
		if items[i].ID != id {
			continue
		}
		if items[i].Status == model.PrivilegeGrantRevoked {
			cp := items[i]
			updated = &cp
			break
		}
		items[i].Status = model.PrivilegeGrantRevoked
		items[i].RevokedAt = &now
		cp := items[i]
		updated = &cp
		break
	}
	if updated == nil {
		return nil, nil
	}
	if err := s.saveAll(items); err != nil {
		return nil, err
	}
	return updated, nil
}

func (s *GrantStore) RevokeByConnection(connectionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	items, err := s.loadAll()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	changed := false
	for i := range items {
		if items[i].ConnectionID != connectionID || items[i].Status != model.PrivilegeGrantActive {
			continue
		}
		items[i].Status = model.PrivilegeGrantRevoked
		items[i].RevokedAt = &now
		changed = true
	}
	if !changed {
		return nil
	}
	return s.saveAll(items)
}

func (s *GrantStore) FindActive(connectionID, capability, commandHash string, now time.Time) (*model.PrivilegeGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	items, err := s.loadAll()
	if err != nil {
		return nil, err
	}
	changed := false
	for i := range items {
		if items[i].Status != model.PrivilegeGrantActive {
			continue
		}
		if !items[i].ExpiresAt.IsZero() && now.After(items[i].ExpiresAt) {
			items[i].Status = model.PrivilegeGrantExpired
			changed = true
			continue
		}
		if items[i].ConnectionID == connectionID && items[i].Capability == capability && items[i].CommandHash == commandHash {
			cp := items[i]
			if changed {
				if err := s.saveAll(items); err != nil {
					return nil, err
				}
			}
			return &cp, nil
		}
	}
	if changed {
		if err := s.saveAll(items); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

func (s *GrantStore) List(connectionID string, activeOnly bool) ([]model.PrivilegeGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	items, err := s.loadAll()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	changed := false
	out := make([]model.PrivilegeGrant, 0, len(items))
	for i := range items {
		if items[i].Status == model.PrivilegeGrantActive && !items[i].ExpiresAt.IsZero() && now.After(items[i].ExpiresAt) {
			items[i].Status = model.PrivilegeGrantExpired
			changed = true
		}
		if connectionID != "" && items[i].ConnectionID != connectionID {
			continue
		}
		if activeOnly && items[i].Status != model.PrivilegeGrantActive {
			continue
		}
		out = append(out, items[i])
	}
	if changed {
		if err := s.saveAll(items); err != nil {
			return nil, err
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}
