package engine

import (
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/llm"
)

// The reasoning-heavy roles run on GLM-5.3-Flash; bulk roles stay on the
// cheap Llama model. This is the "mixture by task" the swarm advertises.
func TestTogetherModelFor(t *testing.T) {
	cases := map[string]string{
		"exploit":    "zai-org/GLM-5.3-Flash",
		"classifier": "zai-org/GLM-5.3-Flash",
		"recon":      "meta-llama/Llama-3.3-70B-Instruct-Turbo",
		"report":     "meta-llama/Llama-3.3-70B-Instruct-Turbo",
	}
	for role, want := range cases {
		if got := togetherModelFor(role); got != want {
			t.Errorf("togetherModelFor(%q) = %q, want %q", role, got, want)
		}
	}
}

// The cost meter must price at the *costliest* model in the active mix so the
// budget cap never overspends. Because GLM-5.3-Flash is cheaper than the bulk
// Llama model, the meter must pick Llama — not the exploit model — as its
// pricing basis. This guards the "never overspend" guarantee against future
// routing changes.
func TestTogetherMeterModelIsCostliest(t *testing.T) {
	meter := togetherMeterModel()
	meterHi := hiPrice(llm.PricingFor(meter))
	for _, role := range []string{"recon", "classifier", "exploit", "report"} {
		if got := hiPrice(llm.PricingFor(togetherModelFor(role))); got > meterHi {
			t.Fatalf("meter model %q ($%.2f) is not the costliest — role %q costs $%.2f",
				meter, meterHi, role, got)
		}
	}
	if meter != "meta-llama/Llama-3.3-70B-Instruct-Turbo" {
		t.Errorf("meter model = %q, want the Llama bulk model (currently the priciest per token)", meter)
	}
}

func hiPrice(p llm.Pricing) float64 {
	if p.OutputPerMillion > p.InputPerMillion {
		return p.OutputPerMillion
	}
	return p.InputPerMillion
}
