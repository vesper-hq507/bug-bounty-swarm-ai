package verify

import (
	"context"
	"errors"
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/swarm/blackboard"
)

// fakeEvidence reports a fixed corroboration state.
type fakeEvidence struct {
	count        int
	toolGrounded bool
}

func (f fakeEvidence) SupportingSignals(ctx context.Context, target string) (int, bool) {
	return f.count, f.toolGrounded
}

// fakeVerifier records calls and returns a scripted verdict.
type fakeVerifier struct {
	real  bool
	conf  float64
	err   error
	calls int
}

func (f *fakeVerifier) Verify(ctx context.Context, c Candidate) (bool, float64, error) {
	f.calls++
	return f.real, f.conf, f.err
}

const cheap = "deepseek/deepseek-v4.1-flash" // economy tier
const frontier = "claude-opus-4-7"           // frontier tier

func cand(sev pipeline.Severity, model string) Candidate {
	return Candidate{Target: "https://t/api", Type: blackboard.TypeCVEMatch, Severity: sev, Model: model, Pheromone: 0.5}
}

// A frontier-sourced judgment is trusted as-is — never escalated, no spend.
func TestDecide_FrontierTrustedNoSpend(t *testing.T) {
	v := &fakeVerifier{real: false}
	c := New(Policy{MaxVerifications: 10}, v)
	var ev Evidence = fakeEvidence{}
	d, _ := c.Decide(context.Background(), cand(pipeline.SeverityCritical, frontier), ev)
	if d != Pass {
		t.Errorf("frontier judgment decision = %v, want Pass", d)
	}
	if v.calls != 0 {
		t.Errorf("frontier judgment should not be verified, got %d calls", v.calls)
	}
}

// A tool-grounded target is promoted for free — the verifier is never called.
func TestDecide_ToolGroundedPromotedFree(t *testing.T) {
	v := &fakeVerifier{}
	c := New(Policy{MaxVerifications: 10}, v)
	var ev Evidence = fakeEvidence{toolGrounded: true}
	d, p := c.Decide(context.Background(), cand(pipeline.SeverityCritical, cheap), ev)
	if d != Promote {
		t.Fatalf("tool-grounded decision = %v, want Promote", d)
	}
	if p < 0.85 {
		t.Errorf("promoted weight = %.2f, want >= 0.85", p)
	}
	if v.calls != 0 {
		t.Errorf("free corroboration must not spend a verification, got %d", v.calls)
	}
}

// Two independent signals corroborate for free too.
func TestDecide_MultiSignalPromotedFree(t *testing.T) {
	v := &fakeVerifier{}
	c := New(Policy{MaxVerifications: 10}, v)
	var ev Evidence = fakeEvidence{count: 2}
	if d, _ := c.Decide(context.Background(), cand(pipeline.SeverityHigh, cheap), ev); d != Promote {
		t.Errorf("multi-signal decision = %v, want Promote", d)
	}
	if v.calls != 0 {
		t.Errorf("multi-signal must be free, got %d calls", v.calls)
	}
}

// A low-stakes, uncorroborated cheap judgment is NOT worth paying for — Pass,
// no spend. This is the core cost protection.
func TestDecide_LowStakesNeverSpends(t *testing.T) {
	v := &fakeVerifier{real: true, conf: 0.9}
	c := New(Policy{MaxVerifications: 10}, v)
	var ev Evidence = fakeEvidence{}
	d, _ := c.Decide(context.Background(), cand(pipeline.SeverityLow, cheap), ev)
	if d != Pass {
		t.Errorf("low-stakes decision = %v, want Pass", d)
	}
	if v.calls != 0 {
		t.Errorf("low-stakes must never verify, got %d calls", v.calls)
	}
}

// High-stakes + uncorroborated + cheap → one paid verification; a false verdict
// rejects the phantom before it can cost the exploit agent.
func TestDecide_HighStakesRejectsPhantom(t *testing.T) {
	v := &fakeVerifier{real: false}
	c := New(Policy{MaxVerifications: 10}, v)
	var ev Evidence = fakeEvidence{}
	d, p := c.Decide(context.Background(), cand(pipeline.SeverityCritical, cheap), ev)
	if d != Reject {
		t.Fatalf("decision = %v, want Reject", d)
	}
	if p != 0 {
		t.Errorf("rejected weight = %.2f, want 0", p)
	}
	if v.calls != 1 {
		t.Errorf("expected exactly 1 verification, got %d", v.calls)
	}
}

// A true verdict promotes and lifts the weight to at least the verifier's confidence.
func TestDecide_HighStakesPromotesReal(t *testing.T) {
	v := &fakeVerifier{real: true, conf: 0.92}
	c := New(Policy{MaxVerifications: 10}, v)
	var ev Evidence = fakeEvidence{}
	d, p := c.Decide(context.Background(), cand(pipeline.SeverityHigh, cheap), ev)
	if d != Promote {
		t.Fatalf("decision = %v, want Promote", d)
	}
	if p < 0.92 {
		t.Errorf("promoted weight = %.2f, want >= verifier confidence 0.92", p)
	}
}

// The per-campaign cap is a hard ceiling: once spent, further high-stakes
// candidates fall back to the passive gate (Pass) rather than spending more.
func TestDecide_BudgetCapProtectsCost(t *testing.T) {
	v := &fakeVerifier{real: false}
	c := New(Policy{MaxVerifications: 1}, v)
	var ev Evidence = fakeEvidence{}
	// first high-stakes call spends the only verification
	c.Decide(context.Background(), cand(pipeline.SeverityCritical, cheap), ev)
	// second must not spend
	d, _ := c.Decide(context.Background(), cand(pipeline.SeverityCritical, cheap), ev)
	if d != Pass {
		t.Errorf("over-budget decision = %v, want Pass (fallback to passive gate)", d)
	}
	if v.calls != 1 {
		t.Errorf("verifier called %d times, want 1 (cap enforced)", v.calls)
	}
	if c.Verifications() != 1 {
		t.Errorf("Verifications() = %d, want 1", c.Verifications())
	}
}

// A verifier error must not punish the candidate — fall back to Pass.
func TestDecide_VerifierErrorFallsBack(t *testing.T) {
	v := &fakeVerifier{err: errors.New("timeout")}
	c := New(Policy{MaxVerifications: 5}, v)
	var ev Evidence = fakeEvidence{}
	if d, _ := c.Decide(context.Background(), cand(pipeline.SeverityCritical, cheap), ev); d != Pass {
		t.Errorf("verifier-error decision = %v, want Pass", d)
	}
}

// MaxVerifications=0 (or nil verifier) disables paid escalation entirely —
// free-corroboration + passive gate only.
func TestDecide_EscalationDisabled(t *testing.T) {
	v := &fakeVerifier{real: false}
	c := New(Policy{MaxVerifications: 0}, v)
	var ev Evidence = fakeEvidence{}
	if d, _ := c.Decide(context.Background(), cand(pipeline.SeverityCritical, cheap), ev); d != Pass {
		t.Errorf("escalation-disabled decision = %v, want Pass", d)
	}
	if v.calls != 0 {
		t.Errorf("no verification should occur when disabled, got %d", v.calls)
	}
}
