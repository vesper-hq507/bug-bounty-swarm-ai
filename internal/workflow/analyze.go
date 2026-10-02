package workflow

import (
	"fmt"
	"sort"
	"strings"
)

type Rule struct {
	ID            string   `json:"id"`
	Action        string   `json:"action"`
	AllowedRoles  []string `json:"allowed_roles,omitempty"`
	RequiresOwner bool     `json:"requires_owner,omitempty"`
	RequiredPrior []string `json:"required_prior,omitempty"`
	ForbidFrom    []string `json:"forbid_from,omitempty"`
	Description   string   `json:"description,omitempty"`
}

type HypothesisKind string

const (
	HypothesisRoleBoundary   HypothesisKind = "role-boundary"
	HypothesisOwnership      HypothesisKind = "ownership-boundary"
	HypothesisSequenceBypass HypothesisKind = "sequence-bypass"
	HypothesisTerminalBypass HypothesisKind = "terminal-state-bypass"
)

type Hypothesis struct {
	Kind          HypothesisKind `json:"kind"`
	RuleID        string         `json:"rule_id"`
	WorkflowID    string         `json:"workflow_id"`
	Action        string         `json:"action"`
	URL           string         `json:"url,omitempty"`
	ActorID       string         `json:"actor_id"`
	ObjectID      string         `json:"object_id,omitempty"`
	EvidenceRefs  []string       `json:"evidence_refs,omitempty"`
	Reason        string         `json:"reason"`
	ExpectedSafe  string         `json:"expected_safe_behavior"`
	ApprovalClass string         `json:"approval_class"`
}

type RaceCandidate struct {
	WorkflowID       string   `json:"workflow_id"`
	Action           string   `json:"action"`
	URL              string   `json:"url"`
	EvidenceRefs     []string `json:"evidence_refs,omitempty"`
	RequiresApproval bool     `json:"requires_approval"`
	PolicyCompatible bool     `json:"policy_compatible"`
	Reason           string   `json:"reason"`
}

type Analysis struct {
	Graph          Graph           `json:"graph"`
	Hypotheses     []Hypothesis    `json:"hypotheses"`
	RaceCandidates []RaceCandidate `json:"race_candidates,omitempty"`
}

func Analyze(events []Event, rules []Rule, maxRequestsPerSecond float64) Analysis {
	sorted := append([]Event(nil), events...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].WorkflowID == sorted[j].WorkflowID {
			return sorted[i].Sequence < sorted[j].Sequence
		}
		return sorted[i].WorkflowID < sorted[j].WorkflowID
	})

	out := Analysis{Graph: BuildGraph(sorted)}
	history := map[string]map[string]struct{}{}
	ruleByAction := make(map[string][]Rule, len(rules))
	for i := range rules {
		rule := rules[i]
		ruleByAction[strings.ToLower(strings.TrimSpace(rule.Action))] = append(ruleByAction[strings.ToLower(strings.TrimSpace(rule.Action))], rule)
	}

	for i := range sorted {
		e := &sorted[i]
		if _, ok := history[e.WorkflowID]; !ok {
			history[e.WorkflowID] = map[string]struct{}{}
		}
		matchingRules := ruleByAction[strings.ToLower(strings.TrimSpace(e.Action))]
		for j := range matchingRules {
			out.Hypotheses = append(out.Hypotheses, evaluateRule(*e, matchingRules[j], history[e.WorkflowID])...)
		}
		history[e.WorkflowID][strings.ToLower(strings.TrimSpace(e.Action))] = struct{}{}
	}

	out.RaceCandidates = inferRaceCandidates(sorted, maxRequestsPerSecond)
	return out
}

func evaluateRule(e Event, rule Rule, prior map[string]struct{}) []Hypothesis {
	var out []Hypothesis
	if len(rule.AllowedRoles) > 0 && !containsFold(rule.AllowedRoles, e.ActorRole) && successStatus(e.StatusCode) {
		out = append(out, Hypothesis{
			Kind:          HypothesisRoleBoundary,
			RuleID:        rule.ID,
			WorkflowID:    e.WorkflowID,
			Action:        e.Action,
			URL:           e.URL,
			ActorID:       e.ActorID,
			ObjectID:      e.ObjectID,
			EvidenceRefs:  append([]string(nil), e.EvidenceRefs...),
			Reason:        fmt.Sprintf("role %q successfully performed %q but allowed roles are %v", e.ActorRole, e.Action, rule.AllowedRoles),
			ExpectedSafe:  "The action should be rejected for roles outside the rule's allowed set.",
			ApprovalClass: approvalClassFor(e),
		})
	}
	if rule.RequiresOwner && e.ObjectOwner != "" && e.ActorID != e.ObjectOwner && successStatus(e.StatusCode) {
		out = append(out, Hypothesis{
			Kind:          HypothesisOwnership,
			RuleID:        rule.ID,
			WorkflowID:    e.WorkflowID,
			Action:        e.Action,
			URL:           e.URL,
			ActorID:       e.ActorID,
			ObjectID:      e.ObjectID,
			EvidenceRefs:  append([]string(nil), e.EvidenceRefs...),
			Reason:        fmt.Sprintf("non-owner %q successfully performed %q on object owned by %q", e.ActorID, e.Action, e.ObjectOwner),
			ExpectedSafe:  "The server should reject object mutation or access by a non-owner unless explicitly delegated.",
			ApprovalClass: approvalClassFor(e),
		})
	}
	for _, needed := range rule.RequiredPrior {
		if _, ok := prior[strings.ToLower(strings.TrimSpace(needed))]; !ok && successStatus(e.StatusCode) {
			out = append(out, Hypothesis{
				Kind:          HypothesisSequenceBypass,
				RuleID:        rule.ID,
				WorkflowID:    e.WorkflowID,
				Action:        e.Action,
				ActorID:       e.ActorID,
				ObjectID:      e.ObjectID,
				EvidenceRefs:  append([]string(nil), e.EvidenceRefs...),
				Reason:        fmt.Sprintf("action %q succeeded without required prior action %q", e.Action, needed),
				ExpectedSafe:  "The server should enforce required workflow preconditions, not only client-side sequence.",
				ApprovalClass: approvalClassFor(e),
			})
			break
		}
	}
	if containsFold(rule.ForbidFrom, e.StateBefore) && successStatus(e.StatusCode) {
		out = append(out, Hypothesis{
			Kind:          HypothesisTerminalBypass,
			RuleID:        rule.ID,
			WorkflowID:    e.WorkflowID,
			Action:        e.Action,
			URL:           e.URL,
			ActorID:       e.ActorID,
			ObjectID:      e.ObjectID,
			EvidenceRefs:  append([]string(nil), e.EvidenceRefs...),
			Reason:        fmt.Sprintf("action %q succeeded from forbidden state %q", e.Action, e.StateBefore),
			ExpectedSafe:  "The server should reject transitions from terminal or otherwise forbidden workflow states.",
			ApprovalClass: approvalClassFor(e),
		})
	}
	return out
}

func inferRaceCandidates(events []Event, maxRPS float64) []RaceCandidate {
	seen := map[string]RaceCandidate{}
	for i := range events {
		e := &events[i]
		if !e.MutatesState() || e.URL == "" {
			continue
		}
		key := strings.ToUpper(e.Method) + " " + e.URL + " " + e.Action
		if _, ok := seen[key]; ok {
			continue
		}
		candidate := RaceCandidate{
			WorkflowID:       e.WorkflowID,
			Action:           e.Action,
			URL:              e.URL,
			EvidenceRefs:     append([]string(nil), e.EvidenceRefs...),
			RequiresApproval: true,
			PolicyCompatible: maxRPS >= 2,
			Reason:           "state-changing endpoint may merit a bounded concurrency check only with explicit approval and sufficient policy rate allowance",
		}
		if maxRPS < 2 {
			candidate.Reason = "race testing is not eligible: policy rate allowance is below 2 requests/second or unspecified"
		}
		seen[key] = candidate
	}
	out := make([]RaceCandidate, 0, len(seen))
	for _, candidate := range seen {
		out = append(out, candidate)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].WorkflowID == out[j].WorkflowID {
			return out[i].Action < out[j].Action
		}
		return out[i].WorkflowID < out[j].WorkflowID
	})
	return out
}

func successStatus(code int) bool { return code >= 200 && code < 300 }

func containsFold(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(want)) {
			return true
		}
	}
	return false
}
