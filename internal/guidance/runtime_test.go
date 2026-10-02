package guidance

import (
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/monitor"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope/programterms"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/workflow"
)

func TestFromMonitorFeedsTargetedGuidance(t *testing.T) {
	diff := monitor.DiffResult{Suggestions: []monitor.RetestSuggestion{{
		Priority: 95,
		Target: "https://example.test/api/new",
		Test: "classify-new-endpoint",
		Why: "new endpoint",
		StopCondition: "stop after classification",
	}}}
	got := FromMonitor(diff, programterms.Constraints{})
	if len(got) != 1 || got[0].Test != "classify-new-endpoint" || got[0].ApprovalClass != "observe" {
		t.Fatalf("guidance = %+v", got)
	}
}

func TestFromWorkflowCreatesOwnershipAndRaceGuidance(t *testing.T) {
	a := workflow.Analysis{
		Hypotheses: []workflow.Hypothesis{{
			Kind: workflow.HypothesisOwnership,
			WorkflowID: "orders:42",
			Action: "refund",
			URL: "https://example.test/orders/42/refund",
			Reason: "non-owner succeeded",
			ExpectedSafe: "reject non-owner",
			ApprovalClass: "stateful",
		}},
		RaceCandidates: []workflow.RaceCandidate{{
			WorkflowID: "orders:42",
			Action: "refund",
			URL: "https://example.test/orders/42/refund",
			PolicyCompatible: true,
			RequiresApproval: true,
			Reason: "bounded race may be useful",
		}},
	}
	got := FromWorkflow(a, programterms.Constraints{MaxRequestsPerSecond: 5})
	if len(got) != 2 {
		t.Fatalf("guidance = %+v", got)
	}
	if got[0].Test != "workflow-ownership-boundary" || got[0].ApprovalClass != "state-change" {
		t.Fatalf("first = %+v", got[0])
	}
}

func TestMergeDeduplicatesByTestAndTarget(t *testing.T) {
	r := Recommendation{Priority: 10, Test: "same", Target: "x", PolicyCompatible: true}
	got := Merge(10, []Recommendation{r}, []Recommendation{r})
	if len(got) != 1 {
		t.Fatalf("merged = %+v", got)
	}
}
