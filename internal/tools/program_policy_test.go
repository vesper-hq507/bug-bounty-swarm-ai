package tools

import (
	"slices"
	"testing"
)

func TestProjectDiscoveryPolicyArgs_RateAndHeaders(t *testing.T) {
	opts := Options{
		"program_max_rps": 2.8,
		"program_required_headers": map[string]string{
			"X-Bugbounty-User": "researcher",
		},
	}
	got := projectDiscoveryPolicyArgs(opts)
	wantParts := []string{"-rl", "2", "-H", "X-Bugbounty-User: researcher"}
	for _, want := range wantParts {
		if !slices.Contains(got, want) {
			t.Fatalf("policy args %v missing %q", got, want)
		}
	}
}

func TestProjectDiscoveryPolicyArgs_SubRPSUsesMinuteCap(t *testing.T) {
	got := projectDiscoveryPolicyArgs(Options{"program_max_rps": 0.5})
	if len(got) != 2 || got[0] != "-rlm" || got[1] != "30" {
		t.Fatalf("sub-RPS args = %v, want [-rlm 30]", got)
	}
}

func TestIntegerRPS_RejectsSubRPS(t *testing.T) {
	if _, err := integerRPS(Options{"program_max_rps": 0.5}); err == nil {
		t.Fatal("expected sub-1 RPS to be rejected for integer-only adapter")
	}
}
