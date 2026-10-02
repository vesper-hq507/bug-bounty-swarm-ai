package tools

import (
	"context"
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/policygateway"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

func TestCoordinatorResultCarriesPolicyProvenance(t *testing.T) {
	tool := &fakeTool{name: "fake", available: true}
	c := newFakeCoordinator(tool)
	c.SetPolicyGateway(policygateway.New(policygateway.Policy{
		Scope: scope.ScopeDefinition{AllowedDomains: []string{"tgt"}},
	}))
	_, ch := c.RunSelected(
		context.Background(),
		[]string{"fake"},
		"tgt",
		&scope.ScopeDefinition{AllowedDomains: []string{"tgt"}},
		Options{"_campaign_id": "campaign-1"},
	)
	got := drain(ch)
	if len(got) != 1 {
		t.Fatalf("results = %+v", got)
	}
	if got[0].ActionID == "" || got[0].DecisionID == "" || got[0].PolicyVersion == "" || got[0].ActorID == "" {
		t.Fatalf("missing policy provenance: %+v", got[0])
	}
}
