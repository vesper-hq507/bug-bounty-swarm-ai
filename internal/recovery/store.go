package recovery

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/uuid"
)

type Store interface {
	Save(Checkpoint) error
	Load(uuid.UUID) (Checkpoint, error)
}

type FileStore struct {
	root string
	mu   sync.RWMutex
}

func NewFileStore(root string) (*FileStore, error) {
	if root == "" {
		return nil, fmt.Errorf("recovery store root is required")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("creating recovery store: %w", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return nil, fmt.Errorf("securing recovery store: %w", err)
	}
	return &FileStore{root: root}, nil
}

func (s *FileStore) Save(c Checkpoint) error {
	if s == nil || !c.VerifyIntegrity() {
		return fmt.Errorf("invalid checkpoint")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeCheckpointAtomic(s.path(c.CampaignID), c)
}

func (s *FileStore) Load(campaignID uuid.UUID) (Checkpoint, error) {
	if s == nil {
		return Checkpoint{}, fmt.Errorf("recovery store unavailable")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, err := os.ReadFile(s.path(campaignID))
	if err != nil {
		return Checkpoint{}, fmt.Errorf("reading checkpoint for campaign %s: %w", campaignID, err)
	}
	var c Checkpoint
	if err := json.Unmarshal(b, &c); err != nil {
		return Checkpoint{}, fmt.Errorf("decoding checkpoint for campaign %s: %w", campaignID, err)
	}
	if c.CampaignID != campaignID || !c.VerifyIntegrity() {
		return Checkpoint{}, fmt.Errorf("checkpoint for campaign %s failed integrity verification", campaignID)
	}
	return c, nil
}

func (s *FileStore) path(campaignID uuid.UUID) string {
	return filepath.Join(s.root, campaignID.String()+".json")
}

func writeCheckpointAtomic(path string, c Checkpoint) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".checkpoint-*")
	if err != nil {
		return fmt.Errorf("creating temporary checkpoint: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(c); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("encoding checkpoint: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("syncing checkpoint: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("committing checkpoint: %w", err)
	}
	return nil
}
