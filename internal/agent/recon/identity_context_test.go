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

func TestReconHTTPPolicyUsesConfiguredIdentity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	var audit policygateway.AuditRecord
	gateway := policygateway.New(policygateway.Policy{
		Scope: scope.ScopeDefinition{AllowedCIDRs: []string{"127.0.0.0/8"}},
	}, policygateway.WithAuditSink(func(record policygateway.AuditRecord) {
		audit = record
	}))

	recorder := newObservationRecorder(evidence.NewMemoryStore(), uuid.New())
	recorder.setIdentity("user-a", "User A")
	ctx := withObservationRecorder(context.Background(), recorder)
	client := newReconHTTPClient(gateway, "recon-test", nil)
	if status := probeStatus(ctx, client, http.MethodGet, srv.URL); status != http.StatusNoContent {
		t.Fatalf("status = %d", status)
	}
	if audit.Action.ActorID != "user-a" {
		t.Fatalf("actor = %q, want user-a", audit.Action.ActorID)
	}
	if audit.Action.Metadata["identity_alias"] != "User A" || audit.Action.Metadata["agent"] != "recon-test" {
		t.Fatalf("metadata = %+v", audit.Action.Metadata)
	}
}
