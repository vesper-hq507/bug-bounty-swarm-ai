package monitor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type Store interface {
	Load(target string) (Snapshot, bool, error)
	Save(Snapshot) error
}

type FileStore struct {
	root string
	mu   sync.RWMutex
}

func NewFileStore(root string) (*FileStore, error) {
	if root == "" {
		return nil, fmt.Errorf("monitor store root is required")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("creating monitor store: %w", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return nil, fmt.Errorf("securing monitor store: %w", err)
	}
	return &FileStore{root: root}, nil
}

func (s *FileStore) Load(target string) (Snapshot, bool, error) {
	if s == nil {
		return Snapshot{}, false, fmt.Errorf("monitor store unavailable")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, err := os.ReadFile(s.path(target))
	if os.IsNotExist(err) {
		return Snapshot{}, false, nil
	}
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("reading monitor snapshot: %w", err)
	}
	var snapshot Snapshot
	if err := json.Unmarshal(b, &snapshot); err != nil {
		return Snapshot{}, false, fmt.Errorf("decoding monitor snapshot: %w", err)
	}
	if snapshot.Target != target {
		return Snapshot{}, false, fmt.Errorf("monitor snapshot target mismatch")
	}
	return snapshot, true, nil
}

func (s *FileStore) Save(snapshot Snapshot) error {
	if s == nil {
		return fmt.Errorf("monitor store unavailable")
	}
	if snapshot.Target == "" {
		return fmt.Errorf("monitor snapshot target is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	path := s.path(snapshot.Target)
	tmp, err := os.CreateTemp(s.root, ".monitor-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(snapshot); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("committing monitor snapshot: %w", err)
	}
	return nil
}

func (s *FileStore) path(target string) string {
	sum := sha256.Sum256([]byte(target))
	return filepath.Join(s.root, hex.EncodeToString(sum[:])+".json")
}
