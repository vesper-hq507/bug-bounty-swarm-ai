package engine

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/evidence"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/recovery"
	"github.com/google/uuid"
)

const defaultStateDir = ".pentestswarm/state"

type runtimePersistence struct {
	evidence   evidence.Store
	recovery   recovery.Store
	cleanup    pipeline.CleanupRegistryIface
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
	return &runtimePersistence{evidence: ev, recovery: rec, cleanup: cleanup}, nil
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
