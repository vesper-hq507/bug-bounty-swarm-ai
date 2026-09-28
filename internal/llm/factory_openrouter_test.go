package llm

import (
	"strings"
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/config"
)

// TestOpenRouterProvider_Defaults verifies the openrouter factory branch wires
// an OpenAI-wire provider to OpenRouter's endpoint and pins a tool-calling-
// capable default model (DeepSeek V4.1 Flash) when none is configured. The
// swarm's orchestrator depends on native function calling.
func TestOpenRouterProvider_Defaults(t *testing.T) {
	p, err := NewProvider(config.OrchestratorConfig{
		Provider: "openrouter",
		APIKey:   "sk-or-test",
	})
	if err != nil {
		t.Fatalf("NewProvider(openrouter): %v", err)
	}

	oai, ok := p.(*OpenAIProvider)
	if !ok {
		t.Fatalf("openrouter should build an *OpenAIProvider, got %T", p)
	}
	if oai.endpoint != "https://openrouter.ai/api/v1" {
		t.Errorf("endpoint = %q, want https://openrouter.ai/api/v1", oai.endpoint)
	}
	if oai.model != "deepseek/deepseek-v4.1-flash" {
		t.Errorf("model = %q, want deepseek/deepseek-v4.1-flash", oai.model)
	}
	if !oai.SupportsToolUse() {
		t.Error("openrouter should default to native tool use (swarm depends on it)")
	}
	if p.ContextWindow() <= 0 {
		t.Errorf("context window = %d, want > 0", p.ContextWindow())
	}
}

// TestOpenRouterProvider_ClaudeModelFallsBack verifies that a leftover Claude
// orchestrator model (the config default) is not sent to OpenRouter verbatim —
// it falls back to the pinned OpenRouter default instead.
func TestOpenRouterProvider_ClaudeModelFallsBack(t *testing.T) {
	p, err := NewProvider(config.OrchestratorConfig{
		Provider: "openrouter",
		APIKey:   "sk-or-test",
		Model:    "claude-sonnet-4-6",
	})
	if err != nil {
		t.Fatalf("NewProvider(openrouter): %v", err)
	}
	if oai := p.(*OpenAIProvider); oai.model != "deepseek/deepseek-v4.1-flash" {
		t.Errorf("model = %q, want the OpenRouter default (claude-* must not pass through)", oai.model)
	}
}

// TestOpenRouterProvider_CustomModel verifies an explicit OpenRouter slug passes
// straight through.
func TestOpenRouterProvider_CustomModel(t *testing.T) {
	p, err := NewProvider(config.OrchestratorConfig{
		Provider: "openrouter",
		APIKey:   "sk-or-test",
		Model:    "z-ai/glm-5.3-flash",
	})
	if err != nil {
		t.Fatalf("NewProvider(openrouter): %v", err)
	}
	if oai := p.(*OpenAIProvider); oai.model != "z-ai/glm-5.3-flash" {
		t.Errorf("model = %q, want z-ai/glm-5.3-flash", oai.model)
	}
}

// TestOpenRouterProvider_RequiresAPIKey verifies the factory fails fast with a
// clear message that points the user at OpenRouter's key page.
func TestOpenRouterProvider_RequiresAPIKey(t *testing.T) {
	_, err := NewProvider(config.OrchestratorConfig{Provider: "openrouter"})
	if err == nil {
		t.Fatal("expected error when openrouter has no api_key")
	}
	if !strings.Contains(err.Error(), "api_key") {
		t.Errorf("error should mention api_key: %v", err)
	}
	if !strings.Contains(err.Error(), "openrouter.ai") {
		t.Errorf("error should point at openrouter.ai: %v", err)
	}
}

// TestUnknownProvider_ErrorListsOpenRouter ensures the unknown-provider message
// advertises openrouter as a valid option.
func TestUnknownProvider_ErrorListsOpenRouter(t *testing.T) {
	_, err := NewProvider(config.OrchestratorConfig{Provider: "nonsense", APIKey: "x"})
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
	if !strings.Contains(err.Error(), "openrouter") {
		t.Errorf("error should list openrouter as a valid provider: %v", err)
	}
}

// TestOpenRouterPricing_IsCheap guards the "pennies per run" claim: the default
// OpenRouter models must be priced well below the frontier default tier.
func TestOpenRouterPricing_IsCheap(t *testing.T) {
	for _, model := range []string{"deepseek/deepseek-v4.1-flash", "z-ai/glm-5.3-flash"} {
		p := PricingFor(model)
		if p.OutputPerMillion <= 0 || p.OutputPerMillion > 2.0 {
			t.Errorf("%s output price $%.2f/Mtok — expected a cheap, non-default tier", model, p.OutputPerMillion)
		}
	}
}
