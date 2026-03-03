package approvals

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"cssh/internal/model"
)

type Store struct {
	path string
	mu   sync.Mutex
}

func NewStore(path string) *Store {
	return &Store{path: path}
}

func (s *Store) ensure() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(s.path); errors.Is(err, os.ErrNotExist) {
		return os.WriteFile(s.path, nil, 0o600)
	}
	return nil
}

func (s *Store) loadAll() ([]model.ApprovalRequest, error) {
	if err := s.ensure(); err != nil {
		return nil, err
	}
	f, err := os.Open(s.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []model.ApprovalRequest
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		line := scan.Bytes()
		if len(line) == 0 {
			continue
		}
		var req model.ApprovalRequest
		if err := json.Unmarshal(line, &req); err != nil {
			continue
		}
		out = append(out, req)
	}
	if err := scan.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) rewriteAll(items []model.ApprovalRequest) error {
	if err := s.ensure(); err != nil {
		return err
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, it := range items {
		if err := enc.Encode(it); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) Create(req model.ApprovalRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensure(); err != nil {
		return err
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(req)
}

func (s *Store) Get(id string) (*model.ApprovalRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
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

func (s *Store) List(status string) ([]model.ApprovalRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	items, err := s.loadAll()
	if err != nil {
		return nil, err
	}
	if status != "" {
		out := make([]model.ApprovalRequest, 0, len(items))
		for _, it := range items {
			if string(it.Status) == status {
				out = append(out, it)
			}
		}
		items = out
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})
	return items, nil
}

func (s *Store) Resolve(id string, status model.ApprovalStatus, actor, reason string) (*model.ApprovalRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	items, err := s.loadAll()
	if err != nil {
		return nil, err
	}
	var updated *model.ApprovalRequest
	now := time.Now().UTC()
	for i := range items {
		if items[i].ID != id {
			continue
		}
		if items[i].Status != model.ApprovalPending {
			cp := items[i]
			updated = &cp
			break
		}
		items[i].Status = status
		items[i].ResolvedAt = &now
		if status == model.ApprovalApproved {
			items[i].ApprovedBy = actor
		} else if status == model.ApprovalRejected {
			items[i].ApprovedBy = actor
			items[i].RejectReason = reason
		}
		cp := items[i]
		updated = &cp
		break
	}
	if updated == nil {
		return nil, nil
	}
	if err := s.rewriteAll(items); err != nil {
		return nil, err
	}
	return updated, nil
}

// MarkUsed atomically stamps UsedAt on an approved request.
// Returns (nil, nil) if the request is not found, not approved, or already used.
// This is the single point of concurrency control for one-time-use tokens.
func (s *Store) MarkUsed(id string) (*model.ApprovalRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	items, err := s.loadAll()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	for i := range items {
		if items[i].ID != id {
			continue
		}
		if items[i].Status != model.ApprovalApproved {
			return nil, nil
		}
		if items[i].UsedAt != nil {
			return nil, nil
		}
		items[i].UsedAt = &now
		cp := items[i]
		if err := s.rewriteAll(items); err != nil {
			return nil, err
		}
		return &cp, nil
	}
	return nil, nil
}
