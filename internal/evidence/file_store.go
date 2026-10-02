package evidence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/google/uuid"
)

type FileStore struct {
	root string
	mu   sync.RWMutex
}

func NewFileStore(root string) (*FileStore, error) {
	if root == "" {
		return nil, fmt.Errorf("evidence store root is required")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("creating evidence store: %w", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return nil, fmt.Errorf("securing evidence store: %w", err)
	}
	return &FileStore{root: root}, nil
}

func (s *FileStore) Add(r Record) error {
	if s == nil {
		return fmt.Errorf("evidence store unavailable")
	}
	if r.ID == uuid.Nil || !r.VerifyIntegrity() {
		return fmt.Errorf("invalid evidence record")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	path := s.recordPath(r.ID)
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("evidence record %s already exists", r.ID)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("checking evidence record: %w", err)
	}
	return writeJSONAtomic(path, r)
}

func (s *FileStore) Get(id uuid.UUID) (Record, error) {
	if s == nil {
		return Record{}, fmt.Errorf("evidence store unavailable")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.readRecord(id)
}

func (s *FileStore) ForFinding(findingID uuid.UUID) []Record {
	if s == nil || findingID == uuid.Nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.filter(func(r Record) bool { return r.FindingID == findingID })
}

func (s *FileStore) ForCampaign(campaignID uuid.UUID) []Record {
	if s == nil || campaignID == uuid.Nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.filter(func(r Record) bool { return r.CampaignID == campaignID })
}

func (s *FileStore) recordPath(id uuid.UUID) string {
	return filepath.Join(s.root, id.String()+".json")
}

func (s *FileStore) readRecord(id uuid.UUID) (Record, error) {
	b, err := os.ReadFile(s.recordPath(id))
	if err != nil {
		return Record{}, fmt.Errorf("reading evidence record %s: %w", id, err)
	}
	var r Record
	if err := json.Unmarshal(b, &r); err != nil {
		return Record{}, fmt.Errorf("decoding evidence record %s: %w", id, err)
	}
	if r.ID != id || !r.VerifyIntegrity() {
		return Record{}, fmt.Errorf("evidence record %s failed integrity verification", id)
	}
	return r, nil
}

func (s *FileStore) filter(keep func(Record) bool) []Record {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return nil
	}
	out := make([]Record, 0)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		id, err := uuid.Parse(entry.Name()[:len(entry.Name())-len(".json")])
		if err != nil {
			continue
		}
		r, err := s.readRecord(id)
		if err == nil && keep(r) {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID.String() < out[j].ID.String()
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

func writeJSONAtomic(path string, value any) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("creating temporary state file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("securing temporary state file: %w", err)
	}
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(value); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("encoding state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("syncing state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing state: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("committing state: %w", err)
	}
	return nil
}
