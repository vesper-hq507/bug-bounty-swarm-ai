package recovery

import (
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/identity"
	"github.com/google/uuid"
)

func TestCheckpointPersistsReferencesWithoutSessionSecrets(t *testing.T) {
	campaignID := uuid.New()
	c, err := NewCheckpoint(Checkpoint{
		CampaignID:    campaignID,
		Phase:         "exploit",
		PolicyVersion: "policy-v2",
		Identities: []IdentityRef{
			{ID: identity.ID("user-a"), SessionRef: identity.SessionRef("vault:user-a")},
		},
		CompletedActionIDs: []string{"action-1"},
		CleanupActionIDs:   []uuid.UUID{uuid.New()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !c.VerifyIntegrity() {
		t.Fatal("checkpoint failed integrity verification")
	}
	if c.Identities[0].SessionRef != "vault:user-a" {
		t.Fatalf("session reference lost: %+v", c.Identities)
	}
}

func TestCheckpointIntegrityDetectsMutation(t *testing.T) {
	c, err := NewCheckpoint(Checkpoint{
		CampaignID:    uuid.New(),
		Phase:         "recon",
		PolicyVersion: "policy-v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	c.Phase = "tampered"
	if c.VerifyIntegrity() {
		t.Fatal("tampered checkpoint must fail integrity verification")
	}
}

func TestMemoryStoreRoundTrip(t *testing.T) {
	campaignID := uuid.New()
	c, err := NewCheckpoint(Checkpoint{
		CampaignID:    campaignID,
		Phase:         "classify",
		PolicyVersion: "policy-v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryStore()
	if err := store.Save(c); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load(campaignID)
	if err != nil {
		t.Fatal(err)
	}
	if got.IntegrityHash != c.IntegrityHash || got.Phase != "classify" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}
