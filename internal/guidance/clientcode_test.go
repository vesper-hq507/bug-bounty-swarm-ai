package guidance

import (
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/monitor"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope/programterms"
)

func TestFromMonitorPreservesClientCodeHypothesis(t *testing.T) {
	diff := monitor.DiffResult{Suggestions: []monitor.RetestSuggestion{{
		Priority:         94,
		Target:           "https://example.test/api/private",
		Test:             "review-client-route",
		Hypothesis:       "client code exposed a new route",
		ExpectedSignal:   "server authorization is classified",
		RequiredIdentity: "controlled user",
		ApprovalClass:    "observe",
		Why:              "static signal",
		Scope:            "targeted-change-only",
		StopCondition:    "one bounded request",
	}}}
	got := FromMonitor(diff, programterms.Constraints{})
	if len(got) != 1 {
		t.Fatalf("recommendations = %+v", got)
	}
	if got[0].Hypothesis != "client code exposed a new route" || got[0].RequiredIdentity != "controlled user" {
		t.Fatalf("recommendation = %+v", got[0])
	}
}

func TestFromMonitorSuppressesDisallowedClientRoute(t *testing.T) {
	diff := monitor.DiffResult{Suggestions: []monitor.RetestSuggestion{{
		Priority: 94,
		Target: "https://example.test/admin/internal",
		Test: "review-client-route",
		Why: "static signal",
		Scope: "targeted-change-only",
		StopCondition: "one bounded request",
	}}}
	got := FromMonitor(diff, programterms.Constraints{DisallowedPaths: []string{"/admin"}})
	if len(got) != 0 {
		t.Fatalf("disallowed client route leaked into guidance: %+v", got)
	}
}
