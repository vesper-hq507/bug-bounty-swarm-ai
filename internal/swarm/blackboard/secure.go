package blackboard

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/swarm/provenance"
	"github.com/google/uuid"
)

// WriterProvider returns a Board whose writes are cryptographically bound to a
// single agent identity. Reads still traverse the common verified board.
type WriterProvider interface {
	Writer(agentName string) Board
}

// SecureBoard is the runtime trust boundary for swarm shared state. Unbound
// writes are rejected. Callers receive a per-agent Writer, which signs every
// finding and prevents that caller from claiming another AgentName.
type SecureBoard struct {
	base    Board
	keyring provenance.Keyring
}

func NewSecureBoard(base Board, keyring provenance.Keyring) (*SecureBoard, error) {
	if base == nil {
		return nil, fmt.Errorf("blackboard base is required")
	}
	if keyring == nil {
		return nil, fmt.Errorf("blackboard provenance keyring is required")
	}
	return &SecureBoard{base: base, keyring: keyring}, nil
}

func (b *SecureBoard) Writer(agentName string) Board {
	return &boundWriter{secure: b, agentName: strings.TrimSpace(agentName)}
}

func (b *SecureBoard) Write(context.Context, Finding, ...WriteOption) (uuid.UUID, error) {
	return uuid.Nil, fmt.Errorf("unbound blackboard write rejected; use an agent-bound writer")
}

func (b *SecureBoard) Query(ctx context.Context, p Predicate) ([]Finding, error) {
	findings, err := b.base.Query(ctx, p)
	if err != nil {
		return nil, err
	}
	for i := range findings {
		if err := b.verifyFinding(findings[i]); err != nil {
			return nil, fmt.Errorf("blackboard provenance verification: %w", err)
		}
	}
	return findings, nil
}

func (b *SecureBoard) Subscribe(ctx context.Context, p Predicate) (<-chan Finding, error) {
	subCtx, cancel := context.WithCancel(ctx)
	source, err := b.base.Subscribe(subCtx, p)
	if err != nil {
		cancel()
		return nil, err
	}
	out := make(chan Finding, 32)
	go func() {
		defer close(out)
		defer cancel()
		for {
			select {
			case <-subCtx.Done():
				return
			case f, ok := <-source:
				if !ok {
					return
				}
				if b.verifyFinding(f) != nil {
					// Fail closed: one untrusted shared-memory entry stops this
					// subscription instead of reaching a downstream agent.
					return
				}
				select {
				case <-subCtx.Done():
					return
				case out <- f:
				}
			}
		}
	}()
	return out, nil
}

func (b *SecureBoard) Cursor(ctx context.Context, campaignID uuid.UUID, agentName string) (uuid.UUID, error) {
	return b.base.Cursor(ctx, campaignID, agentName)
}

func (b *SecureBoard) CommitCursor(ctx context.Context, campaignID uuid.UUID, agentName string, findingID uuid.UUID) error {
	return b.base.CommitCursor(ctx, campaignID, agentName, findingID)
}

func (b *SecureBoard) Pheromone(ctx context.Context, findingID uuid.UUID) (float64, error) {
	return b.base.Pheromone(ctx, findingID)
}

func (b *SecureBoard) Supersede(ctx context.Context, oldID, newID uuid.UUID) error {
	return b.base.Supersede(ctx, oldID, newID)
}

func (b *SecureBoard) Budget(ctx context.Context, campaignID uuid.UUID) (Budget, error) {
	return b.base.Budget(ctx, campaignID)
}

func (b *SecureBoard) UpdateBudget(ctx context.Context, campaignID uuid.UUID, deltaHours float64, deltaTokens int64) error {
	return b.base.UpdateBudget(ctx, campaignID, deltaHours, deltaTokens)
}

func (b *SecureBoard) SetBudgetLimits(ctx context.Context, campaignID uuid.UUID, maxHours float64, maxTokens int64) error {
	return b.base.SetBudgetLimits(ctx, campaignID, maxHours, maxTokens)
}

func (b *SecureBoard) AgentBudget(ctx context.Context, campaignID uuid.UUID, agent string) (AgentBudget, error) {
	return b.base.AgentBudget(ctx, campaignID, agent)
}

func (b *SecureBoard) ChargeAgent(ctx context.Context, campaignID uuid.UUID, agent string, tokens int64) error {
	return b.base.ChargeAgent(ctx, campaignID, agent, tokens)
}

func (b *SecureBoard) SetAgentBudget(ctx context.Context, campaignID uuid.UUID, agent string, maxTokens, warnAtTokens int64) error {
	return b.base.SetAgentBudget(ctx, campaignID, agent, maxTokens, warnAtTokens)
}

func (b *SecureBoard) verifyFinding(f Finding) error {
	if f.AgentName == "" || f.CampaignID == uuid.Nil {
		return fmt.Errorf("finding %s has incomplete authorship fields", f.ID)
	}
	if f.ProvenanceSignedUnix == 0 || len(f.ProvenancePublicKey) == 0 || len(f.ProvenanceSignature) == 0 {
		return fmt.Errorf("finding %s from %q is unsigned", f.ID, f.AgentName)
	}
	trusted, err := b.keyring.PublicKey(f.AgentName)
	if err != nil {
		return err
	}
	if !bytes.Equal(trusted, f.ProvenancePublicKey) {
		return fmt.Errorf("finding %s agent %q used an untrusted signing key", f.ID, f.AgentName)
	}
	return provenance.Verify(
		trusted,
		f.ProvenanceSignature,
		f.CampaignID.String(),
		f.AgentName,
		string(f.Type),
		f.Target,
		f.Data,
		f.ProvenanceSignedUnix,
	)
}

type boundWriter struct {
	secure    *SecureBoard
	agentName string
}

func (b *boundWriter) Write(ctx context.Context, f Finding, opts ...WriteOption) (uuid.UUID, error) {
	if b == nil || b.secure == nil {
		return uuid.Nil, fmt.Errorf("bound blackboard writer unavailable")
	}
	if b.agentName == "" {
		return uuid.Nil, fmt.Errorf("bound blackboard writer has empty agent identity")
	}
	if f.AgentName != "" && f.AgentName != b.agentName {
		return uuid.Nil, fmt.Errorf("agent %q cannot write as %q", b.agentName, f.AgentName)
	}
	f.AgentName = b.agentName
	if len(f.Data) == 0 {
		f.Data = []byte(`{}`)
	}
	signer, err := b.secure.keyring.Signer(b.agentName)
	if err != nil {
		return uuid.Nil, err
	}
	f.ProvenanceSignedUnix = time.Now().UTC().UnixNano()
	f.ProvenancePublicKey = append([]byte(nil), signer.PublicKey()...)
	f.ProvenanceSignature = signer.Sign(
		f.CampaignID.String(),
		f.AgentName,
		string(f.Type),
		f.Target,
		f.Data,
		f.ProvenanceSignedUnix,
	)
	if err := b.secure.verifyFinding(f); err != nil {
		return uuid.Nil, fmt.Errorf("refusing unsigned/untrusted finding: %w", err)
	}
	return b.secure.base.Write(ctx, f, opts...)
}

func (b *boundWriter) Query(ctx context.Context, p Predicate) ([]Finding, error) {
	return b.secure.Query(ctx, p)
}
func (b *boundWriter) Subscribe(ctx context.Context, p Predicate) (<-chan Finding, error) {
	return b.secure.Subscribe(ctx, p)
}
func (b *boundWriter) Cursor(ctx context.Context, campaignID uuid.UUID, agentName string) (uuid.UUID, error) {
	return b.secure.Cursor(ctx, campaignID, agentName)
}
func (b *boundWriter) CommitCursor(ctx context.Context, campaignID uuid.UUID, agentName string, findingID uuid.UUID) error {
	return b.secure.CommitCursor(ctx, campaignID, agentName, findingID)
}
func (b *boundWriter) Pheromone(ctx context.Context, findingID uuid.UUID) (float64, error) {
	return b.secure.Pheromone(ctx, findingID)
}
func (b *boundWriter) Supersede(ctx context.Context, oldID, newID uuid.UUID) error {
	return b.secure.Supersede(ctx, oldID, newID)
}
func (b *boundWriter) Budget(ctx context.Context, campaignID uuid.UUID) (Budget, error) {
	return b.secure.Budget(ctx, campaignID)
}
func (b *boundWriter) UpdateBudget(ctx context.Context, campaignID uuid.UUID, deltaHours float64, deltaTokens int64) error {
	return b.secure.UpdateBudget(ctx, campaignID, deltaHours, deltaTokens)
}
func (b *boundWriter) SetBudgetLimits(ctx context.Context, campaignID uuid.UUID, maxHours float64, maxTokens int64) error {
	return b.secure.SetBudgetLimits(ctx, campaignID, maxHours, maxTokens)
}
func (b *boundWriter) AgentBudget(ctx context.Context, campaignID uuid.UUID, agent string) (AgentBudget, error) {
	return b.secure.AgentBudget(ctx, campaignID, agent)
}
func (b *boundWriter) ChargeAgent(ctx context.Context, campaignID uuid.UUID, agent string, tokens int64) error {
	return b.secure.ChargeAgent(ctx, campaignID, agent, tokens)
}
func (b *boundWriter) SetAgentBudget(ctx context.Context, campaignID uuid.UUID, agent string, maxTokens, warnAtTokens int64) error {
	return b.secure.SetAgentBudget(ctx, campaignID, agent, maxTokens, warnAtTokens)
}

var _ Board = (*SecureBoard)(nil)
var _ Board = (*boundWriter)(nil)
var _ WriterProvider = (*SecureBoard)(nil)
