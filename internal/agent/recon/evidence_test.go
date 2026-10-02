package recon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/evidence"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/policygateway"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
	"github.com/google/uuid"
)

func TestReconHTTPObservationCreatesProvenance(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	store := evidence.NewMemoryStore()
	recorder := newObservationRecorder(store, uuid.New())
	ctx := withObservationRecorder(context.Background(), recorder)
	gateway := policygateway.New(policygateway.Policy{
		Scope: scope.ScopeDefinition{AllowedCIDRs: []string{"127.0.0.0/8"}},
	})
	client := newReconHTTPClient(gateway, "recon-test", nil)

	if status := probeStatus(ctx, client, http.MethodGet, srv.URL); status != http.StatusNoContent {
		t.Fatalf("status = %d", status)
	}
	if err := recorder.Err(); err != nil {
		t.Fatal(err)
	}
	refs := recorder.Refs()
	if len(refs) != 1 || refs[0].RecordID == "" || refs[0].IntegrityHash == "" {
		t.Fatalf("provenance refs = %+v", refs)
	}
}
