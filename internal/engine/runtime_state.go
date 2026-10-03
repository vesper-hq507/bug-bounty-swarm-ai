package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/evidence"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/guidance"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/monitor"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/recovery"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/swarm/provenance"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/workflow"
	"github.com/google/uuid"
)

const defaultStateDir = ".pentestswarm/state"

type runtimePersistence struct {
	root       string
	evidence   evidence.Store
	recovery   recovery.Store
	cleanup    pipeline.CleanupRegistryIface
	monitor    monitor.Store
	swarmKeys  provenance.Keyring
	identities []recovery.IdentityRef
}

func (r *Runner) prepareRuntimePersistence(cc CampaignConfig) (*runtimePersistence, error) {
	root := strings.TrimSpace(cc.StateDir)
	if root == "" {
		root = defaultStateDir
	}
	ev := r.evidence
	if ev == nil {
		store, err := evidence.NewFileStore(filepath.Join(root, "evidence"))
		if err != nil {
			return nil, err
		}
		ev = store
	}
	rec := r.recovery
	if rec == nil {
		store, err := recovery.NewFileStore(filepath.Join(root, "recovery"))
		if err != nil {
			return nil, err
		}
		rec = store
	}
	cleanup := r.cleanup
	if !r.cleanupExplicit {
		store, err := pipeline.NewFileCleanupRegistry(filepath.Join(root, "cleanup"), pipeline.DefaultCleanupExec)
		if err != nil {
			return nil, err
		}
		cleanup = store
	}
	if cleanup == nil {
		return nil, fmt.Errorf("cleanup registry unavailable")
	}
	mon, err := monitor.NewFileStore(filepath.Join(root, "monitor"))
	if err != nil {
		return nil, err
	}
	keys, err := provenance.NewFileKeyring(filepath.Join(root, "provenance"))
	if err != nil {
		return nil, err
	}
	return &runtimePersistence{
		root: root, evidence: ev, recovery: rec, cleanup: cleanup, monitor: mon,
		swarmKeys: keys,
	}, nil
}

func (p *runtimePersistence) checkpoint(ctx context.Context, campaignID uuid.UUID, phase, policyVersion, blackboardCursor string, completed, skipped []string) error {
	if p == nil || p.recovery == nil {
		return fmt.Errorf("recovery persistence unavailable")
	}
	pending, err := p.cleanup.PendingCleanup(ctx, campaignID)
	if err != nil {
		return fmt.Errorf("reading pending cleanup for checkpoint: %w", err)
	}
	cleanupIDs := make([]uuid.UUID, 0, len(pending))
	for i := range pending {
		cleanupIDs = append(cleanupIDs, pending[i].ID)
	}
	cp, err := recovery.NewCheckpoint(recovery.Checkpoint{
		CampaignID: campaignID, Phase: phase, BlackboardCursor: blackboardCursor,
		PolicyVersion: policyVersion,
		Identities: append([]recovery.IdentityRef(nil), p.identities...),
		CompletedActionIDs: append([]string(nil), completed...),
		SkippedActionIDs: append([]string(nil), skipped...),
		CleanupActionIDs: cleanupIDs,
	})
	if err != nil {
		return err
	}
	if err := p.recovery.Save(cp); err != nil {
		return fmt.Errorf("saving recovery checkpoint: %w", err)
	}
	return nil
}


func (p *runtimePersistence) saveWorkflow(campaignID uuid.UUID, analysis workflow.Analysis) error {
	if p == nil {
		return fmt.Errorf("runtime persistence unavailable")
	}
	return p.writeJSON("workflow", campaignID.String()+".json", analysis)
}

func (p *runtimePersistence) saveGuidance(campaignID uuid.UUID, recs []guidance.Recommendation) error {
	if p == nil {
		return fmt.Errorf("runtime persistence unavailable")
	}
	return p.writeJSON("guidance", campaignID.String()+".json", recs)
}

func (p *runtimePersistence) writeJSON(dir, name string, value any) error {
	root := filepath.Join(p.root, dir)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return fmt.Errorf("creating %s state directory: %w", dir, err)
	}
	path := filepath.Join(root, name)
	tmp, err := os.CreateTemp(root, ".runtime-*")
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
	if err := enc.Encode(value); err != nil {
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
		return fmt.Errorf("committing %s state: %w", dir, err)
	}
	return nil
}
