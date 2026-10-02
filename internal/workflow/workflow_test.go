package workflow

import "testing"

func TestAnalyzeFindsSequenceRoleOwnershipAndTerminalViolations(t *testing.T) {
	events := []Event{
		{
			WorkflowID: "order-1", Sequence: 1,
			StateBefore: "new", StateAfter: "refunded",
			Action: "refund", Method: "POST", URL: "https://example.test/orders/1/refund",
			ActorID: "user-b", ActorRole: "user", ObjectID: "order-1", ObjectOwner: "user-a",
			StatusCode: 200, EvidenceRefs: []string{"evidence:1"},
		},
		{
			WorkflowID: "order-1", Sequence: 2,
			StateBefore: "refunded", StateAfter: "shipped",
			Action: "ship", Method: "POST", URL: "https://example.test/orders/1/ship",
			ActorID: "user-b", ActorRole: "user", ObjectID: "order-1", ObjectOwner: "user-a",
			StatusCode: 200, EvidenceRefs: []string{"evidence:2"},
		},
	}
	rules := []Rule{
		{
			ID: "refund-rule", Action: "refund",
			AllowedRoles: []string{"admin"},
			RequiresOwner: true,
			RequiredPrior: []string{"capture-payment"},
		},
		{
			ID: "ship-rule", Action: "ship",
			ForbidFrom: []string{"refunded", "cancelled"},
		},
	}
	got := Analyze(events, rules, 5)
	kinds := map[HypothesisKind]bool{}
	for i := range got.Hypotheses {
		kinds[got.Hypotheses[i].Kind] = true
	}
	for _, kind := range []HypothesisKind{
		HypothesisRoleBoundary,
		HypothesisOwnership,
		HypothesisSequenceBypass,
		HypothesisTerminalBypass,
	} {
		if !kinds[kind] {
			t.Fatalf("missing %s in %+v", kind, got.Hypotheses)
		}
	}
	if len(got.RaceCandidates) == 0 || !got.RaceCandidates[0].RequiresApproval {
		t.Fatalf("expected gated race candidate: %+v", got.RaceCandidates)
	}
}

func TestRaceCandidateBlockedByLowPolicyRate(t *testing.T) {
	got := Analyze([]Event{{
		WorkflowID: "checkout-1", Sequence: 1,
		StateBefore: "cart", StateAfter: "paid",
		Action: "checkout", Method: "POST", URL: "https://example.test/checkout",
		StatusCode: 200,
	}}, nil, 1)
	if len(got.RaceCandidates) != 1 {
		t.Fatalf("race candidates = %+v", got.RaceCandidates)
	}
	if got.RaceCandidates[0].PolicyCompatible {
		t.Fatal("race candidate must be blocked under <2 RPS policy")
	}
}

func TestPlanReplayRequiresApprovalForMutation(t *testing.T) {
	g := Graph{
		States: map[string]State{
			"new": {Name: "new"},
			"paid": {Name: "paid"},
		},
		Transitions: []Transition{{
			ID: "pay", From: State{Name: "new"}, To: State{Name: "paid"},
			Action: "pay", Method: "POST", URL: "https://example.test/pay",
			ApprovalClass: "stateful", MutatesState: true,
		}},
	}
	steps, err := PlanReplay(g, "new", "paid", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 1 || steps[0].Executable || steps[0].Reason == "" {
		t.Fatalf("replay steps = %+v", steps)
	}

	approved, err := PlanReplay(g, "new", "paid", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(approved) != 1 || !approved[0].Executable {
		t.Fatalf("approved replay = %+v", approved)
	}
}

func TestBuildGraphDeduplicatesObservedTransition(t *testing.T) {
	events := []Event{
		{WorkflowID: "w1", Sequence: 1, StateBefore: "a", StateAfter: "b", Action: "next", Method: "GET"},
		{WorkflowID: "w1", Sequence: 2, StateBefore: "a", StateAfter: "b", Action: "next", Method: "GET"},
	}
	g := BuildGraph(events)
	if len(g.Transitions) != 1 {
		t.Fatalf("transitions = %+v", g.Transitions)
	}
}
