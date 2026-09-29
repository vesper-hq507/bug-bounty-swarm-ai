// Package quality guards a heterogeneous swarm against context poisoning.
//
// In a heterogeneous swarm different agents run different-quality models: a
// cheap, fast model does high-volume grunt work (recon parsing, enumeration)
// while a stronger model handles the reasoning-heavy steps. The risk a sharp
// observer raises is real — a low-quality model's *judgments* (a shaky CVE
// match, an overconfident "this looks like SQLi") can flow onto the shared
// blackboard and poison the context that stronger downstream agents reason
// over, burning their budget on phantom leads.
//
// The blackboard already carries the antidote: every finding has a pheromone
// weight, consumers gate on a MinPheromone floor, and weights decay so
// unreinforced signals die. This package ties that weight to the *reliability
// of the model that produced the signal*. An inferential finding from a cheap
// model starts at a discounted weight, so it must be corroborated (reinforced
// above the gate by a tool result or a stronger agent) to reach a downstream
// reasoner; if it is noise it decays below the floor and never enters the
// stronger model's context.
//
// Tool-grounded observations — a port is open, an endpoint returned 200, a
// nuclei template fired — are transcriptions of deterministic tool output and
// are trusted regardless of which model wrote them down, so they are never
// discounted. Only model *judgment* is gated.
package quality

import "github.com/Armur-Ai/Pentest-Swarm-AI/internal/llm"

// Tier is a model's reliability class. Factor multiplies the initial pheromone
// of an inferential finding the model contributes to the blackboard.
type Tier struct {
	Name   string
	Factor float64
}

// TierFor derives a reliability tier from a model's output price per million
// tokens — a robust, self-updating proxy for capability that needs no
// hand-maintained per-model table (frontier models cost more; economy models
// cost less). It reads the same pricing table the cost meter uses, so it stays
// correct as models and prices change. An unknown model prices at the default
// (frontier) tier, i.e. it is trusted — we only ever *discount*, never inflate.
func TierFor(model string) Tier {
	out := llm.PricingFor(model).OutputPerMillion
	switch {
	case out >= 8:
		return Tier{Name: "frontier", Factor: 1.0}
	case out >= 3:
		return Tier{Name: "strong", Factor: 0.9}
	case out >= 1:
		return Tier{Name: "mid", Factor: 0.78}
	default:
		return Tier{Name: "economy", Factor: 0.6}
	}
}

// GatedPheromone returns the initial pheromone an agent should assign to a
// finding it is writing. Inferential findings (model judgments) are scaled down
// by the source model's tier so a cheap model's guesses start below a stronger
// model's and must earn their place through corroboration. Observational
// findings (inferential=false) are tool-grounded facts and pass through
// unchanged. The result is clamped to (0,1].
func GatedPheromone(base float64, model string, inferential bool) float64 {
	if base <= 0 {
		base = 0.01
	}
	if base > 1 {
		base = 1
	}
	if !inferential {
		return base
	}
	p := base * TierFor(model).Factor
	if p < 0.01 {
		p = 0.01
	}
	return p
}
