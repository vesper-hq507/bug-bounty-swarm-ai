// Package verify adds an active corroboration layer at the boundary where one
// agent's judgment is passed to a stronger downstream agent — without eroding
// the cost win that makes a heterogeneous swarm worthwhile.
//
// The passive gate (internal/swarm/quality) discounts a cheap model's judgment
// so it must survive decay to be seen. Active corroboration goes further: at
// the handoff it decides whether to Promote a signal (corroborated — raise its
// weight so it reaches the reasoner), Reject it (verified false — drop it), or
// Pass (leave it to the passive gate).
//
// The whole point of a heterogeneous swarm is spending less. Verifying every
// cheap-model judgment with a strong model would pay frontier prices on the
// bulk work and destroy that. So corroboration is cost-aware by construction,
// in this strict order:
//
//  1. Trust frontier-sourced judgments as-is — no re-check needed.
//  2. Free corroboration first: if a deterministic tool already grounds the
//     claim (nuclei/sqlmap hit) or two independent signals agree, promote it at
//     ZERO LLM cost. This handles the common case.
//  3. Low-stakes signals are never worth paying to verify — let the passive gate
//     and decay handle them.
//  4. Only a HIGH-STAKES, UNCORROBORATED judgment from a CHEAP model — the exact
//     slice where a wrong pass makes the exploit agent burn budget on a phantom
//     — triggers one paid strong-model verification, and only while a hard
//     per-campaign cap remains. Out of budget → fall back to the passive gate.
//
// Net: verification is the rare exception, it is bounded, and it pays for itself
// by preventing wasted downstream exploit spend — so it protects the "less
// money" property instead of eroding it.
package verify

import (
	"context"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/swarm/blackboard"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/swarm/quality"
)

// Decision is the outcome of corroborating a candidate at a context boundary.
type Decision int

const (
	// Pass leaves the candidate's weight unchanged — the passive pheromone gate
	// and decay decide its fate. The default, zero-cost outcome.
	Pass Decision = iota
	// Promote raises the candidate's weight so it reliably reaches the
	// downstream reasoner (it was corroborated).
	Promote
	// Reject drops the candidate — a paid verification found it isn't real.
	Reject
)

func (d Decision) String() string {
	switch d {
	case Promote:
		return "promote"
	case Reject:
		return "reject"
	default:
		return "pass"
	}
}

// Candidate is a judgment being handed from one agent to a stronger one.
type Candidate struct {
	Target    string
	Type      blackboard.FindingType
	Severity  pipeline.Severity
	Model     string  // the model that produced the judgment (→ reliability tier)
	Pheromone float64 // its current weight
}

// Verifier re-derives a judgment with a stronger model. It is kept behind an
// interface so the (expensive) call is made only when the policy allows, and so
// the policy is testable without a live model.
type Verifier interface {
	// Verify reports whether the candidate is a real, exploitable finding, with
	// a confidence in [0,1]. Implementations wrap a strong provider.
	Verify(ctx context.Context, c Candidate) (real bool, confidence float64, err error)
}

// Evidence is the read side the corroborator needs for free corroboration:
// independent support already sitting on the board for the same target.
type Evidence interface {
	// SupportingSignals returns how many independent signals reference the
	// target, and whether any of them is tool-grounded (a deterministic tool
	// result, not a model judgment).
	SupportingSignals(ctx context.Context, target string) (count int, toolGrounded bool)
}

// Policy configures the cost-aware corroboration gate.
type Policy struct {
	// TrustTierAtOrAbove: a candidate whose source-model tier factor is at or
	// above this is trusted without any re-check (a frontier judgment). Default
	// 1.0 (only frontier is auto-trusted).
	TrustTierAtOrAbove float64
	// HighStakes reports whether a candidate is worth a paid verification when
	// uncorroborated. If nil, DefaultHighStakes is used. Only high-stakes
	// signals can ever trigger a strong-model call.
	HighStakes func(Candidate) bool
	// MaxVerifications caps paid verification calls per campaign so corroboration
	// can never erode the cost savings. 0 disables paid escalation entirely
	// (free corroboration + passive gate only).
	MaxVerifications int
}

// DefaultHighStakes treats critical/high-severity judgments as worth verifying
// when uncorroborated — these are the ones that send the exploit agent spending.
func DefaultHighStakes(c Candidate) bool {
	return c.Severity == pipeline.SeverityCritical || c.Severity == pipeline.SeverityHigh
}

// Corroborator applies a Policy, counting paid verifications against the cap.
// Not safe for concurrent use; construct one per campaign (or guard it).
type Corroborator struct {
	policy   Policy
	verifier Verifier // may be nil (no paid escalation)
	evidence Evidence
	used     int
}

// New builds a Corroborator. verifier may be nil to run free-corroboration-only.
func New(policy Policy, evidence Evidence, verifier Verifier) *Corroborator {
	if policy.TrustTierAtOrAbove <= 0 {
		policy.TrustTierAtOrAbove = 1.0
	}
	if policy.HighStakes == nil {
		policy.HighStakes = DefaultHighStakes
	}
	return &Corroborator{policy: policy, verifier: verifier, evidence: evidence}
}

// Verifications returns how many paid verification calls have been spent.
func (c *Corroborator) Verifications() int { return c.used }

// Decide corroborates one candidate and returns the decision plus the weight to
// use if it is written (unchanged for Pass, raised for Promote, 0 for Reject).
func (c *Corroborator) Decide(ctx context.Context, cand Candidate) (Decision, float64) {
	// 1. Frontier-sourced judgment: trust as-is, no spend.
	if quality.TierFor(cand.Model).Factor >= c.policy.TrustTierAtOrAbove {
		return Pass, cand.Pheromone
	}

	// 2. Free corroboration: a tool result grounds it, or independent signals
	//    agree. Zero LLM cost — handles the common case.
	if c.evidence != nil {
		if n, toolGrounded := c.evidence.SupportingSignals(ctx, cand.Target); toolGrounded || n >= 2 {
			return Promote, promote(cand.Pheromone, 0.85)
		}
	}

	// 3. Low-stakes: never worth paying to verify — leave it to the passive gate.
	if !c.policy.HighStakes(cand) {
		return Pass, cand.Pheromone
	}

	// 4. High-stakes + uncorroborated + cheap: one paid verification, if the
	//    per-campaign cap allows. Otherwise fall back to the passive gate.
	if c.verifier == nil || c.used >= c.policy.MaxVerifications {
		return Pass, cand.Pheromone
	}
	c.used++
	real, conf, err := c.verifier.Verify(ctx, cand)
	if err != nil {
		// Verification failed (timeout, provider error) — don't punish the
		// candidate for our failure; let the passive gate decide.
		return Pass, cand.Pheromone
	}
	if !real {
		return Reject, 0
	}
	return Promote, promote(cand.Pheromone, conf)
}

// promote raises a weight toward a corroborated floor without ever lowering it
// or exceeding 1.0.
func promote(cur, floor float64) float64 {
	if floor > cur {
		cur = floor
	}
	if cur > 1 {
		cur = 1
	}
	if cur < 0 {
		cur = 0
	}
	return cur
}
