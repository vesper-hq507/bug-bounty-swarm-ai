package workflow

import "testing"

func TestCollectorDerivesObjectWorkflowAndState(t *testing.T) {
	c := NewCollector()
	first := c.Observe(Observation{
		Method: "GET",
		URL: "https://example.test/api/orders/42",
		ActorID: "user-a",
		StatusCode: 200,
		ResponseBody: []byte(`{"id":42,"status":"pending","owner_id":"user-a"}`),
		EvidenceRefs: []string{"evidence:one"},
	})
	second := c.Observe(Observation{
		Method: "POST",
		URL: "https://example.test/api/orders/42/refund",
		ActorID: "user-a",
		StatusCode: 200,
		ResponseBody: []byte(`{"status":"refunded","owner_id":"user-a"}`),
		EvidenceRefs: []string{"evidence:two"},
	})
	if first.ObjectID != "42" || first.StateAfter != "pending" {
		t.Fatalf("first = %+v", first)
	}
	if second.StateBefore != "pending" || second.StateAfter != "refunded" || second.Action != "refund" {
		t.Fatalf("second = %+v", second)
	}
	if first.WorkflowID != second.WorkflowID {
		t.Fatalf("workflow ids differ: %q vs %q", first.WorkflowID, second.WorkflowID)
	}
	if second.Sequence != 2 {
		t.Fatalf("sequence = %d", second.Sequence)
	}
}

func TestCollectorFallsBackToHTTPState(t *testing.T) {
	c := NewCollector()
	got := c.Observe(Observation{
		Method: "GET", URL: "https://example.test/api/me",
		StatusCode: 403,
	})
	if got.StateAfter != "http-403" || got.StateBefore != "unknown" {
		t.Fatalf("event = %+v", got)
	}
}
