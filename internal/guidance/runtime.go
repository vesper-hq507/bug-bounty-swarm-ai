package guidance

import (
	"fmt"
	"sort"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/monitor"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope/programterms"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/workflow"
)

func FromMonitor(diff monitor.DiffResult, constraints programterms.Constraints) []Recommendation {
	out := make([]Recommendation, 0, len(diff.Suggestions))
	for i := range diff.Suggestions {
		s := &diff.Suggestions[i]
		if !pathAllowed(s.Target, constraints.DisallowedPaths) {
			continue
		}
		hypothesis := s.Hypothesis
		if hypothesis == "" {
			hypothesis = "A target-surface change may introduce a new or altered security boundary."
		}
		expected := s.ExpectedSignal
		if expected == "" {
			expected = "The changed surface is classified and any new authorization, input, or workflow boundary is identified."
		}
		identity := s.RequiredIdentity
		if identity == "" {
			identity = "same controlled identity context used for the baseline when authentication is required"
		}
		approval := s.ApprovalClass
		if approval == "" {
			approval = "observe"
		}
		r := Recommendation{
			Priority:         s.Priority,
			Hypothesis:       hypothesis,
			Tool:             "hunter-guidance",
			Test:             s.Test,
			ExpectedSignal:   expected,
			PolicyCompatible: true,
			RequiredIdentity: identity,
			ApprovalClass:    approval,
			Why:              s.Why,
			StopCondition:    s.StopCondition,
			Target:           s.Target,
		}
		out = append(out, applyPolicy(r, constraints))
	}
	return sortRecommendations(out)
}

func FromWorkflow(a workflow.Analysis, constraints programterms.Constraints) []Recommendation {
	out := make([]Recommendation, 0, len(a.Hypotheses)+len(a.RaceCandidates))
	for i := range a.Hypotheses {
		h := &a.Hypotheses[i]
		priority := 88
		tool := "workflow + httpreq"
		switch h.Kind {
		case workflow.HypothesisOwnership:
			priority = 99
			tool = "workflow + identity-diff"
		case workflow.HypothesisRoleBoundary:
			priority = 96
			tool = "workflow + identity-diff"
		case workflow.HypothesisSequenceBypass:
			priority = 94
		case workflow.HypothesisTerminalBypass:
			priority = 92
		}
		approvalClass := "observe"
		if h.ApprovalClass == "stateful" {
			approvalClass = "state-change"
		}
		r := Recommendation{
			Priority:         priority,
			Hypothesis:       h.Reason,
			Tool:             tool,
			Test:             "workflow-" + string(h.Kind),
			ExpectedSignal:   h.ExpectedSafe,
			PolicyCompatible: true,
			RequiredIdentity: "same controlled identity context as the observed workflow",
			ApprovalClass:    approvalClass,
			Why:              fmt.Sprintf("Observed workflow %s produced a concrete business-logic hypothesis.", h.WorkflowID),
			StopCondition:    "Stop after one bounded reproduction attempt with preserved evidence.",
			Target:           h.URL,
		}
		out = append(out, applyPolicy(r, constraints))
	}
	for i := range a.RaceCandidates {
		rc := &a.RaceCandidates[i]
		r := Recommendation{
			Priority:         90,
			Hypothesis:       "A state-changing workflow action may be vulnerable to a concurrency/TOCTOU condition.",
			Tool:             "httpreq --race",
			Test:             "bounded-race-validation",
			ExpectedSignal:   "A single-use or bounded action succeeds more times than the workflow invariant permits.",
			PolicyCompatible: rc.PolicyCompatible,
			RequiredIdentity: "same controlled identity context as the observed workflow",
			ApprovalClass:    "concurrency",
			Why:              rc.Reason,
			StopCondition:    "Run only one bounded concurrency attempt within the program rate limit, then stop.",
			Target:           rc.URL,
		}
		if !rc.PolicyCompatible {
			r.PolicyReason = rc.Reason
		}
		r = applyPolicy(r, constraints)
		out = append(out, r)
	}
	return sortRecommendations(out)
}

func Merge(limit int, groups ...[]Recommendation) []Recommendation {
	seen := map[string]struct{}{}
	out := make([]Recommendation, 0)
	for _, group := range groups {
		for i := range group {
			r := group[i]
			key := r.Test + "\n" + r.Target
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, r)
		}
	}
	out = sortRecommendations(out)
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func sortRecommendations(in []Recommendation) []Recommendation {
	sort.SliceStable(in, func(i, j int) bool {
		if in[i].PolicyCompatible != in[j].PolicyCompatible {
			return in[i].PolicyCompatible
		}
		if in[i].Priority == in[j].Priority {
			if in[i].Test == in[j].Test {
				return in[i].Target < in[j].Target
			}
			return in[i].Test < in[j].Test
		}
		return in[i].Priority > in[j].Priority
	})
	return in
}
