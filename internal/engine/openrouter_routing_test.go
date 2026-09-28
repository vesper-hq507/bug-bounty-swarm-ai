package engine

import (
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/llm"
)

// OpenRouter runs the same "mixture by task" as Together: bulk roles on the
// cheap DeepSeek V4.1 Flash, reasoning-heavy roles on GLM-5.3-Flash — all
// through one key, via OpenRouter's catalog.
func TestOpenRouterModelFor(t *testing.T) {
	cases := map[string]string{
		"exploit":    "z-ai/glm-5.3-flash",
		"classifier": "z-ai/glm-5.3-flash",
		"recon":      "deepseek/deepseek-v4.1-flash",
		"report":     "deepseek/deepseek-v4.1-flash",
	}
	for role, want := range cases {
		if got := openrouterModelFor(role); got != want {
			t.Errorf("openrouterModelFor(%q) = %q, want %q", role, got, want)
		}
	}
}

// The cost meter must price at the costliest model in the active OpenRouter mix
// so the budget cap never overspends, whichever role that turns out to be.
func TestOpenRouterMeterModelIsCostliest(t *testing.T) {
	meter := mixtureMeterModel(openrouterModelFor)
	meterHi := hiPrice(llm.PricingFor(meter))
	for _, role := range []string{"recon", "classifier", "exploit", "report"} {
		if got := hiPrice(llm.PricingFor(openrouterModelFor(role))); got > meterHi {
			t.Fatalf("meter model %q ($%.2f) is not the costliest — role %q costs $%.2f",
				meter, meterHi, role, got)
		}
	}
}
