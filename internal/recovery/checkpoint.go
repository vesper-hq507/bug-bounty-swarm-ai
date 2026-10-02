package recovery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/identity"
	"github.com/google/uuid"
)

type IdentityRef struct {
	ID         identity.ID
	SessionRef identity.SessionRef
}

type ApprovalRef struct {
	ActionID string
	Class    string
}

type Checkpoint struct {
	CampaignID           uuid.UUID
	Phase                string
	BlackboardCursor     string
	PolicyVersion        string
	Identities           []IdentityRef
	CompletedActionIDs   []string
	SkippedActionIDs     []string
	OutstandingApprovals []ApprovalRef
	CleanupActionIDs     []uuid.UUID
	UpdatedAt            time.Time
	IntegrityHash        string
}

func NewCheckpoint(c Checkpoint) (Checkpoint, error) {
	if c.CampaignID == uuid.Nil || c.PolicyVersion == "" {
		return Checkpoint{}, fmt.Errorf("campaign id and policy version are required")
	}
	c.UpdatedAt = time.Now().UTC()
	c.IntegrityHash = c.computeIntegrity()
	return c, nil
}

func (c Checkpoint) VerifyIntegrity() bool {
	return c.IntegrityHash != "" && c.computeIntegrity() == c.IntegrityHash
}

func (c Checkpoint) computeIntegrity() string {
	cp := c
	cp.IntegrityHash = ""
	b, _ := json.Marshal(cp)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

type MemoryStore struct {
	mu    sync.RWMutex
	items map[uuid.UUID]Checkpoint
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{items: map[uuid.UUID]Checkpoint{}}
}

func (s *MemoryStore) Save(c Checkpoint) error {
	if s == nil || !c.VerifyIntegrity() {
		return fmt.Errorf("invalid checkpoint")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[c.CampaignID] = c
	return nil
}

func (s *MemoryStore) Load(campaignID uuid.UUID) (Checkpoint, error) {
	if s == nil {
		return Checkpoint{}, fmt.Errorf("recovery store unavailable")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.items[campaignID]
	if !ok {
		return Checkpoint{}, fmt.Errorf("checkpoint for campaign %s not found", campaignID)
	}
	return c, nil
}
