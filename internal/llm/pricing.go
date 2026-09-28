package llm

// Pricing in USD per million tokens. Keep this table here so that the
// cost-estimator, the report ROI footer, and the live cost meter all
// read from a single source. Bumps to Anthropic's list prices only
// need to change these constants.
//
// Source: https://www.anthropic.com/pricing (updated 2026-04-21).
// Cached-input prices apply when prompt caching fires; otherwise input
// tokens are billed at the full rate.
type Pricing struct {
	InputPerMillion       float64
	CachedInputPerMillion float64
	OutputPerMillion      float64
}

// PricingFor returns the pricing table for a given model id. Covers
// Anthropic models plus the OpenAI-API-compatible vendors we route
// through 1.4.6 (Together AI, DeepSeek, Moonshot/Kimi, OpenAI). For
// vendors without prompt-caching equivalents, CachedInputPerMillion
// equals InputPerMillion — cache hits don't reduce cost.
//
// Unknown models default to the Sonnet tier — a safe middle-ground
// over/under-estimate rather than 0.
func PricingFor(model string) Pricing {
	switch model {
	// --- Anthropic ---
	case "claude-opus-4-7", "claude-opus-4-6":
		return Pricing{InputPerMillion: 15.0, CachedInputPerMillion: 1.50, OutputPerMillion: 75.0}
	case "claude-sonnet-4-6":
		return Pricing{InputPerMillion: 3.0, CachedInputPerMillion: 0.30, OutputPerMillion: 15.0}
	case "claude-haiku-4-5-20251001":
		return Pricing{InputPerMillion: 0.80, CachedInputPerMillion: 0.08, OutputPerMillion: 4.0}

	// --- Together AI (open-weight hosted) ---
	// Pricing snapshot per Together AI's published list at integration time.
	// See https://api.together.xyz/models. Update when Together rotates tiers.
	case "meta-llama/Llama-3.3-70B-Instruct-Turbo":
		return Pricing{InputPerMillion: 0.88, CachedInputPerMillion: 0.88, OutputPerMillion: 0.88}
	case "zai-org/GLM-5.3-Flash":
		// Z.ai's GLM-5.3-Flash — near-frontier agentic/coding reasoning at a
		// fraction of the cost (320B MoE, 18B active). Cheaper than DeepSeek-V3
		// yet stronger on the agentic leaderboard, so it's the swarm's default
		// exploit + classifier reasoner on Together. See togetherModelFor.
		return Pricing{InputPerMillion: 0.15, CachedInputPerMillion: 0.03, OutputPerMillion: 0.50}
	case "Qwen/Qwen2.5-72B-Instruct-Turbo":
		return Pricing{InputPerMillion: 1.20, CachedInputPerMillion: 1.20, OutputPerMillion: 1.20}
	case "deepseek-ai/DeepSeek-V3":
		return Pricing{InputPerMillion: 1.25, CachedInputPerMillion: 1.25, OutputPerMillion: 1.25}
	case "moonshotai/Kimi-K2-Instruct":
		return Pricing{InputPerMillion: 0.60, CachedInputPerMillion: 0.60, OutputPerMillion: 2.50}

	// --- Meta Model API (Muse Spark) ---
	case "muse-spark-1.3", "muse-spark-1.2", "muse-spark-1.1":
		return Pricing{InputPerMillion: 1.25, CachedInputPerMillion: 1.25, OutputPerMillion: 4.25}

	// --- OpenRouter slugs (gateway) ---
	// OpenRouter's own model IDs, distinct from the same models' direct-vendor
	// IDs above. Snapshot per each model's OpenRouter page; OpenRouter routes to
	// the cheapest healthy backend, so realised cost is at or below these.
	// Verify against https://openrouter.ai/<slug> when tiers rotate.
	case "deepseek/deepseek-v4.1-flash", "deepseek/deepseek-v4-flash":
		// DeepSeek V4.1 Flash — ~13B active params, 1M context, strong agentic
		// tool use at a fraction of frontier cost. The swarm's default bulk
		// model on OpenRouter (recon/report). See openrouterModelFor.
		return Pricing{InputPerMillion: 0.28, CachedInputPerMillion: 0.028, OutputPerMillion: 0.42}
	case "z-ai/glm-5.3-flash":
		// Z.ai's GLM-5.3-Flash via OpenRouter — same model as the Together
		// route's reasoner, used for the reasoning-heavy roles (classify,
		// exploit) in the OpenRouter mixture.
		return Pricing{InputPerMillion: 0.15, CachedInputPerMillion: 0.03, OutputPerMillion: 0.50}

	// --- DeepSeek direct ---
	case "deepseek-chat":
		return Pricing{InputPerMillion: 0.27, CachedInputPerMillion: 0.07, OutputPerMillion: 1.10}
	case "deepseek-reasoner":
		return Pricing{InputPerMillion: 0.55, CachedInputPerMillion: 0.14, OutputPerMillion: 2.19}

	// --- OpenAI direct ---
	case "gpt-4o":
		return Pricing{InputPerMillion: 2.50, CachedInputPerMillion: 1.25, OutputPerMillion: 10.0}
	case "gpt-4o-mini":
		return Pricing{InputPerMillion: 0.15, CachedInputPerMillion: 0.075, OutputPerMillion: 0.60}

	// --- Google Gemini (first-party API) ---
	// Snapshot per https://ai.google.dev/pricing. Gemini's "implicit cache"
	// applies automatically on long prompts; the cached price is the rate
	// you pay once cache fires.
	case "gemini-2.5-pro":
		return Pricing{InputPerMillion: 1.25, CachedInputPerMillion: 0.31, OutputPerMillion: 10.0}
	case "gemini-2.5-flash":
		return Pricing{InputPerMillion: 0.30, CachedInputPerMillion: 0.075, OutputPerMillion: 2.50}
	case "gemini-2.5-flash-lite":
		return Pricing{InputPerMillion: 0.10, CachedInputPerMillion: 0.025, OutputPerMillion: 0.40}
	case "gemini-1.5-pro":
		return Pricing{InputPerMillion: 1.25, CachedInputPerMillion: 0.31, OutputPerMillion: 5.0}
	case "gemini-1.5-flash":
		return Pricing{InputPerMillion: 0.075, CachedInputPerMillion: 0.01875, OutputPerMillion: 0.30}

	default:
		return Pricing{InputPerMillion: 3.0, CachedInputPerMillion: 0.30, OutputPerMillion: 15.0}
	}
}

// CostUSD returns the dollar cost of a Usage block at a given pricing.
// Cache-creation tokens are billed at the FULL input rate (Anthropic's
// docs call these 'cache writes'); cache-reads are billed at the
// cached rate.
func (p Pricing) CostUSD(u Usage) float64 {
	input := float64(u.InputTokens+u.CacheCreationInputTokens) * p.InputPerMillion / 1_000_000.0
	cached := float64(u.CacheReadInputTokens) * p.CachedInputPerMillion / 1_000_000.0
	output := float64(u.OutputTokens) * p.OutputPerMillion / 1_000_000.0
	return input + cached + output
}

// EstimateUSD is a blind pre-scan estimate based on target-size class
// heuristics. Used by `scan --estimate` to print a dollar figure before
// any packets fly — so researchers don't accidentally kick off a scan
// that'll cost more than the program's average bounty.
//
// targetClass is a rough bucket:
//
//	"small"  — single subdomain, <= 20 endpoints (e.g. a simple app)
//	"medium" — typical corporate site, 100-500 endpoints
//	"large"  — bug-bounty-program-scale, thousands of endpoints
func (p Pricing) EstimateUSD(targetClass string) (lowUSD, highUSD float64) {
	// Token-count ranges are calibrated against internal campaign logs.
	// Output ratio ~ 0.15 of input is typical for the classifier +
	// exploit agents on Claude.
	var lowIn, highIn int64
	switch targetClass {
	case "small":
		lowIn, highIn = 20_000, 80_000
	case "large":
		lowIn, highIn = 400_000, 1_500_000
	default: // medium / unknown
		lowIn, highIn = 80_000, 400_000
	}
	cost := func(in int64) float64 {
		out := int64(float64(in) * 0.15)
		return (float64(in) * p.InputPerMillion / 1_000_000.0) +
			(float64(out) * p.OutputPerMillion / 1_000_000.0)
	}
	return cost(lowIn), cost(highIn)
}
