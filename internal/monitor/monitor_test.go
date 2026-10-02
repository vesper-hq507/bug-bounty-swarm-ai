package monitor

import (
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
)

func TestDiffCreatesTargetedPlanForNewEndpoint(t *testing.T) {
	before := Snapshot{
		Target: "https://example.test",
		Endpoints: []Endpoint{{Method: "GET", URL: "https://example.test/api/me"}},
	}
	after := Snapshot{
		Target: "https://example.test",
		Endpoints: []Endpoint{
			{Method: "GET", URL: "https://example.test/api/me"},
			{Method: "POST", URL: "https://example.test/api/invoices", Parameters: []string{"tenant_id", "amount"}},
		},
	}
	got := Diff(before, after)
	if len(got.Changes) != 1 || got.Changes[0].Kind != ChangeNewEndpoint {
		t.Fatalf("changes = %+v", got.Changes)
	}
	if len(got.Suggestions) != 1 || got.Suggestions[0].Scope != "targeted-change-only" {
		t.Fatalf("suggestions = %+v", got.Suggestions)
	}
	if got.Suggestions[0].Test != "classify-new-endpoint" {
		t.Fatalf("test = %q", got.Suggestions[0].Test)
	}
}

func TestDiffPrioritizesAPISchemaChange(t *testing.T) {
	before := Snapshot{APISchemas: map[string]string{"openapi": "old"}}
	after := Snapshot{APISchemas: map[string]string{"openapi": "new"}}
	got := Diff(before, after)
	if len(got.Changes) != 1 || got.Changes[0].Kind != ChangeAPISchema || got.Changes[0].Priority != 90 {
		t.Fatalf("changes = %+v", got.Changes)
	}
	if got.Suggestions[0].Test != "review-api-schema-diff" {
		t.Fatalf("suggestion = %+v", got.Suggestions[0])
	}
}

func TestDiffDetectsChangedParametersWithoutWholeScopeRescan(t *testing.T) {
	before := Snapshot{Endpoints: []Endpoint{{
		Method: "GET", URL: "https://example.test/api/orders", Parameters: []string{"page"},
	}}}
	after := Snapshot{Endpoints: []Endpoint{{
		Method: "GET", URL: "https://example.test/api/orders", Parameters: []string{"page", "owner_id"},
	}}}
	got := Diff(before, after)
	if len(got.Changes) != 1 || got.Changes[0].Kind != ChangeEndpointParameters {
		t.Fatalf("changes = %+v", got.Changes)
	}
	for i := range got.Suggestions {
		if got.Suggestions[i].Scope != "targeted-change-only" {
			t.Fatalf("non-targeted suggestion = %+v", got.Suggestions[i])
		}
	}
}

func TestFromAttackSurfaceProducesStableInventory(t *testing.T) {
	surface := pipeline.AttackSurface{
		Target: "https://example.test",
		Subdomains: []pipeline.SubdomainRecord{{Domain: "b.example.test"}, {Domain: "a.example.test"}},
		Hosts: []pipeline.HostRecord{{IP: "192.0.2.2"}, {IP: "192.0.2.1"}},
		Endpoints: []pipeline.EndpointRecord{{
			URL: "https://example.test/search", Parameters: []string{"z", "a"},
		}},
		Technologies: map[string]string{"go": "1.26"},
	}
	got := FromAttackSurface(surface)
	if got.Subdomains[0] != "a.example.test" || got.Hosts[0] != "192.0.2.1" {
		t.Fatalf("unstable inventory: %+v", got)
	}
	if got.Endpoints[0].Method != "GET" || got.Endpoints[0].Parameters[0] != "a" {
		t.Fatalf("endpoint normalization failed: %+v", got.Endpoints[0])
	}
}
