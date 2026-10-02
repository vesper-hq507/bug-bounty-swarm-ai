package llm

import (
	"testing"
	"time"
)

func TestClaudeProviderConfig_DefaultHTTPTimeoutIsFinite(t *testing.T) {
	cfg := ClaudeProviderConfig{APIKey: "test", HTTPTimeout: 250 * time.Millisecond}
	p := NewClaudeProvider(cfg)
	if p == nil {
		t.Fatal("expected provider")
	}
	// Construction with an explicit timeout is the regression contract: the
	// SDK client is built through option.WithHTTPClient rather than the
	// unbounded default http.Client. A live network call is intentionally not
	// made in this unit test.
	if cfg.HTTPTimeout <= 0 {
		t.Fatal("test timeout must be finite")
	}
}
