package browser

import "testing"

func TestFilterAPIPreservesPolicyProvenance(t *testing.T) {
	in := []APIRequest{{
		Method: "GET",
		URL: "https://app.example.com/api/me",
		Type: "Fetch",
		Status: 200,
		ActionID: "browser:GET",
		DecisionID: "decision-1",
		PolicyVersion: "policy-1",
	}}
	out := filterAPI("https://app.example.com/", in)
	if len(out) != 1 {
		t.Fatalf("expected one API request, got %+v", out)
	}
	if out[0].ActionID != "browser:GET" || out[0].DecisionID != "decision-1" || out[0].PolicyVersion != "policy-1" {
		t.Fatalf("policy provenance lost: %+v", out[0])
	}
}
