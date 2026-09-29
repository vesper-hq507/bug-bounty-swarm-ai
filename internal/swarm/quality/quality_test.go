package quality

import "testing"

// A cheap economy model must land in a lower tier than a frontier model, so its
// judgments start with a smaller pheromone weight.
func TestTierFor_OrdersByPrice(t *testing.T) {
	economy := TierFor("deepseek/deepseek-v4.1-flash") // ~$0.42 out
	frontier := TierFor("claude-opus-4-7")             // $75 out
	if economy.Factor >= frontier.Factor {
		t.Fatalf("economy factor %.2f should be below frontier factor %.2f", economy.Factor, frontier.Factor)
	}
	if economy.Name != "economy" {
		t.Errorf("cheap model tier = %q, want economy", economy.Name)
	}
	if frontier.Factor != 1.0 {
		t.Errorf("frontier factor = %.2f, want 1.0", frontier.Factor)
	}
}

// Unknown models default to the frontier tier — we only ever discount known
// cheap models, never inflate or over-penalise an unrecognised one.
func TestTierFor_UnknownIsTrusted(t *testing.T) {
	if f := TierFor("some/brand-new-model").Factor; f != 1.0 {
		t.Errorf("unknown model factor = %.2f, want 1.0 (trusted by default)", f)
	}
}

// Inferential findings from a cheap model are discounted; the same base from a
// frontier model is not.
func TestGatedPheromone_DiscountsCheapJudgments(t *testing.T) {
	base := 0.8
	cheap := GatedPheromone(base, "deepseek/deepseek-v4.1-flash", true)
	strong := GatedPheromone(base, "claude-opus-4-7", true)
	if cheap >= strong {
		t.Fatalf("cheap judgment %.3f should be discounted below frontier %.3f", cheap, strong)
	}
	if strong != base {
		t.Errorf("frontier judgment = %.3f, want unchanged base %.3f", strong, base)
	}
}

// Observational (tool-grounded) findings pass through unchanged regardless of
// the model — a cheap model transcribing an open port is still reliable.
func TestGatedPheromone_ObservationsNotDiscounted(t *testing.T) {
	base := 0.95
	got := GatedPheromone(base, "deepseek/deepseek-v4.1-flash", false)
	if got != base {
		t.Errorf("observation = %.3f, want unchanged base %.3f (tool-grounded, not a judgment)", got, base)
	}
}

// The result must stay a valid pheromone weight in (0,1].
func TestGatedPheromone_Clamps(t *testing.T) {
	if got := GatedPheromone(2.0, "claude-opus-4-7", true); got > 1.0 {
		t.Errorf("over-1 base not clamped: %.3f", got)
	}
	if got := GatedPheromone(0, "deepseek/deepseek-v4.1-flash", true); got <= 0 {
		t.Errorf("zero base produced non-positive pheromone: %.3f", got)
	}
}
