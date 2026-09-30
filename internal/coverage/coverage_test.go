package coverage

import "strings"

import "testing"

// Blocked + no recon → LOW confidence and an explicit "not secure" zero-finding
// message (Vamsi #10 — the confident zero-finding report).
func TestAssess_BlockedZeroFindingIsInconclusive(t *testing.T) {
	a := Assess(Inputs{Target: "https://groww.in", BlockedSignals: 5, ReconObservations: 0})
	if a.Confidence != LevelLow {
		t.Errorf("confidence = %s, want low", a.Confidence)
	}
	if !a.Blocked || a.Reached {
		t.Errorf("expected blocked+not-reached, got blocked=%v reached=%v", a.Blocked, a.Reached)
	}
	if !strings.Contains(a.Summary, "INCONCLUSIVE") || !strings.Contains(strings.ToUpper(a.Summary), "NOT") {
		t.Errorf("zero-finding summary must be qualified, got: %q", a.Summary)
	}
}

// Reached but zero findings → an honest limited-negative, not "secure".
func TestAssess_ReachedZeroFindingIsLimitedNegative(t *testing.T) {
	a := Assess(Inputs{Target: "https://app", ReconObservations: 20, Endpoints: 12})
	if a.Blocked || !a.Reached {
		t.Errorf("expected reached, got blocked=%v reached=%v", a.Blocked, a.Reached)
	}
	if strings.Contains(a.Summary, "INCONCLUSIVE") {
		t.Errorf("a reached target with no findings is a real negative, not inconclusive: %q", a.Summary)
	}
	if !strings.Contains(a.Summary, "not a security guarantee") {
		t.Errorf("must still avoid implying the app is secure: %q", a.Summary)
	}
}

// Findings that reached the report without proof are surfaced as UNVERIFIED
// (Vamsi #4).
func TestAssess_UnverifiedFindingsCaveated(t *testing.T) {
	a := Assess(Inputs{Target: "https://app", ReconObservations: 30, Endpoints: 10, Verified: 1, Unverified: 3})
	if a.TotalFindings != 4 {
		t.Errorf("total = %d, want 4", a.TotalFindings)
	}
	var found bool
	for _, c := range a.Caveats {
		if strings.Contains(c, "UNVERIFIED") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an UNVERIFIED caveat, got %v", a.Caveats)
	}
	// Findings present but none verified → not high confidence.
	if a.Confidence == LevelHigh {
		t.Errorf("unverified-heavy result should not be high confidence")
	}
}

// A well-covered, verified result earns high confidence.
func TestAssess_HighConfidence(t *testing.T) {
	a := Assess(Inputs{Target: "https://app", ReconObservations: 40, Endpoints: 15, Verified: 5})
	if a.Confidence != LevelHigh {
		t.Errorf("confidence = %s, want high", a.Confidence)
	}
	if len(a.Caveats) != 0 {
		t.Errorf("clean high-confidence run should have no caveats, got %v", a.Caveats)
	}
}

// A WAF present alongside real responses is not treated as "blocked".
func TestAssess_WAFWithResponsesNotBlocked(t *testing.T) {
	a := Assess(Inputs{Target: "https://app", ReconObservations: 25, Endpoints: 8, BlockedSignals: 2, Verified: 2})
	if a.Blocked {
		t.Errorf("WAF present but responses observed should not be 'blocked'")
	}
}
