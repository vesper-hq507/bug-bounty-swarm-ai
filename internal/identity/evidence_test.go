package identity

import (
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/evidence"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/policygateway"
	"github.com/google/uuid"
)

func TestRecordIdentityObservationCreatesProvenanceRef(t *testing.T) {
	store := evidence.NewMemoryStore()
	campaignID := uuid.New()
	ref, err := recordIdentityObservation(
		store,
		campaignID,
		Identity{ID: "user-a", Alias: "User A", Role: RoleUser},
		ObjectRef{Type: "record", ID: "1"},
		"GET",
		"https://example.test/records/1",
		[]byte(`{"id":"1","token":"secret"}`),
		200,
		policygateway.Decision{ID: "decision-1", ActionID: "action-1", PolicyVersion: "policy-1"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if ref == "" {
		t.Fatal("expected evidence reference")
	}
}
