package guidance

import (
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/identity"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope/programterms"
)

func TestRecommendPrioritizesControlledIdentityDifferential(t *testing.T) {
	in := Input{
		Surface: pipeline.AttackSurface{
			Target: "https://example.test",
			Endpoints: []pipeline.EndpointRecord{{URL: "https://example.test/api/orders/1"}},
		},
		Identities: []identity.Identity{
			{ID: "user-a", Alias: "User A", Role: identity.RoleUser, SessionRef: "vault:a"},
			{ID: "user-b", Alias: "User B", Role: identity.RoleUser, SessionRef: "vault:b"},
		},
	}
	got := Recommend(in, 5)
	if len(got) == 0 || got[0].Test != "bola-idor-differential" {
		t.Fatalf("recommendations = %+v", got)
	}
	if got[0].RequiredIdentity != "two controlled authenticated users" {
		t.Fatalf("identity requirement = %q", got[0].RequiredIdentity)
	}
}

func TestRecommendSuppressesDisallowedPath(t *testing.T) {
	in := Input{
		Surface: pipeline.AttackSurface{
			Target: "https://example.test",
			Endpoints: []pipeline.EndpointRecord{{
				URL: "https://example.test/admin/users",
				Parameters: []string{"id"},
			}},
		},
		Constraints: programterms.Constraints{DisallowedPaths: []string{"/admin"}},
	}
	got := Recommend(in, 10)
	for _, r := range got {
		if r.Target == "https://example.test/admin/users" {
			t.Fatalf("disallowed path leaked into guidance: %+v", r)
		}
	}
}

func TestRecommendMarksAutomationIncompatible(t *testing.T) {
	in := Input{
		Surface: pipeline.AttackSurface{
			Target: "https://example.test",
			Endpoints: []pipeline.EndpointRecord{{
				URL: "https://example.test/search",
				Parameters: []string{"q"},
			}},
		},
		Constraints: programterms.Constraints{NoAutomatedScanning: true},
	}
	got := Recommend(in, 10)
	found := false
	for _, r := range got {
		if r.Test == "parameter-input-validation" {
			found = true
			if r.PolicyCompatible {
				t.Fatalf("automated parameter guidance must be policy-incompatible: %+v", r)
			}
		}
	}
	if !found {
		t.Fatal("expected parameter recommendation")
	}
}

func TestCompletedTestIsNotRecommendedAgain(t *testing.T) {
	in := Input{
		Surface: pipeline.AttackSurface{
			Target: "https://example.test",
			Endpoints: []pipeline.EndpointRecord{{URL: "https://example.test/login"}},
		},
		Completed: []string{"session-boundary-check"},
	}
	got := Recommend(in, 10)
	for _, r := range got {
		if r.Test == "session-boundary-check" {
			t.Fatalf("completed test was re-recommended: %+v", r)
		}
	}
}


func TestRecommendAddsBoundedRealtimeObservation(t *testing.T) {
	in := Input{
		Surface: pipeline.AttackSurface{
			Target: "https://example.test",
			Endpoints: []pipeline.EndpointRecord{{
				URL: "https://example.test/events",
				Method: "GET",
				Protocol: "sse",
			}},
		},
	}
	got := Recommend(in, 10)
	for _, r := range got {
		if r.Test == "realtime-stream-observation" {
			if r.ApprovalClass != "read-only" || r.Tool != "pentestswarm realtime observe" {
				t.Fatalf("realtime recommendation = %+v", r)
			}
			return
		}
	}
	t.Fatalf("missing realtime recommendation: %+v", got)
}
