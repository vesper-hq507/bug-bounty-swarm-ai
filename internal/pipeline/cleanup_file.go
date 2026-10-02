package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

type FileCleanupRegistry struct {
	root string
	mu   sync.Mutex
	exec func(context.Context, string) error
}

func NewFileCleanupRegistry(root string, execFn func(context.Context, string) error) (*FileCleanupRegistry, error) {
	if root == "" {
		return nil, fmt.Errorf("cleanup store root is required")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("creating cleanup store: %w", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return nil, fmt.Errorf("securing cleanup store: %w", err)
	}
	return &FileCleanupRegistry{root: root, exec: execFn}, nil
}

func (r *FileCleanupRegistry) Register(_ context.Context, campaignID uuid.UUID, command, target string) error {
	if r == nil {
		return fmt.Errorf("cleanup registry unavailable")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	actions, err := r.loadLocked(campaignID)
	if err != nil {
		return err
	}
	actions = append(actions, CleanupAction{
		ID: uuid.New(), CampaignID: campaignID, Command: command, Target: target,
		RegisteredAt: time.Now().UTC(), Status: "pending",
	})
	return r.saveLocked(campaignID, actions)
}

func (r *FileCleanupRegistry) PendingCleanup(_ context.Context, campaignID uuid.UUID) ([]CleanupAction, error) {
	if r == nil {
		return nil, fmt.Errorf("cleanup registry unavailable")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	actions, err := r.loadLocked(campaignID)
	if err != nil {
		return nil, err
	}
	out := make([]CleanupAction, 0, len(actions))
	for i := range actions {
		if actions[i].Status == "pending" {
			out = append(out, actions[i])
		}
	}
	return out, nil
}

func (r *FileCleanupRegistry) RunCleanup(ctx context.Context, campaignID uuid.UUID) *CleanupReport {
	report := &CleanupReport{CampaignID: campaignID}
	if r == nil {
		return report
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	actions, err := r.loadLocked(campaignID)
	if err != nil {
		return report
	}
	for i := range actions {
		if actions[i].Status == "pending" {
			report.TotalCount++
		}
	}
	for i := len(actions) - 1; i >= 0; i-- {
		if actions[i].Status != "pending" {
			continue
		}
		action := &actions[i]
		now := time.Now().UTC()
		action.ExecutedAt = &now
		if r.exec != nil {
			if err := r.exec(ctx, action.Command); err != nil {
				action.Status = "failed"
				report.Failed = append(report.Failed, *action)
				_ = r.saveLocked(campaignID, actions)
				continue
			}
		}
		action.Status = "executed"
		report.Executed = append(report.Executed, *action)
		_ = r.saveLocked(campaignID, actions)
	}
	return report
}

func (r *FileCleanupRegistry) loadLocked(campaignID uuid.UUID) ([]CleanupAction, error) {
	b, err := os.ReadFile(r.path(campaignID))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading cleanup ledger: %w", err)
	}
	var actions []CleanupAction
	if err := json.Unmarshal(b, &actions); err != nil {
		return nil, fmt.Errorf("decoding cleanup ledger: %w", err)
	}
	return actions, nil
}

func (r *FileCleanupRegistry) saveLocked(campaignID uuid.UUID, actions []CleanupAction) error {
	path := r.path(campaignID)
	tmp, err := os.CreateTemp(r.root, ".cleanup-*")
	if err != nil {
		return fmt.Errorf("creating temporary cleanup ledger: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(actions); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("encoding cleanup ledger: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("syncing cleanup ledger: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("committing cleanup ledger: %w", err)
	}
	return nil
}

func (r *FileCleanupRegistry) path(campaignID uuid.UUID) string {
	return filepath.Join(r.root, campaignID.String()+".json")
}

var _ CleanupRegistryIface = (*FileCleanupRegistry)(nil)
