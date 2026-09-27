package chains

import (
	"context"
	"strings"
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/llm"
)

type fakeLLM struct {
	replies []string
	calls   int
}

func (f *fakeLLM) Complete(_ context.Context, _ llm.CompletionRequest) (*llm.CompletionResponse, error) {
	r := f.replies[min(f.calls, len(f.replies)-1)]
	f.calls++
	return &llm.CompletionResponse{Content: r}, nil
}
func min(a, b int) int { if a < b { return a }; return b }

const forged = "```yaml\nid: acme-ssrf-rce\nname: Acme SSRF to RCE\ncves: [CVE-2026-9999]\nproduct: Acme\nlinks:\n  - name: SSRF\n    cve: CVE-2026-9999\n    verify: benign canary callback\n```"

func TestForge_ValidFirstTry(t *testing.T) {
	ch, raw, err := Forge(context.Background(), &fakeLLM{replies: []string{forged}}, "some advisory", "CVE-2026-9999")
	if err != nil {
		t.Fatal(err)
	}
	if ch.ID != "acme-ssrf-rce" || len(ch.Links) != 1 {
		t.Fatalf("bad chain: %+v", ch)
	}
	if strings.Contains(raw, "```") {
		t.Error("raw YAML should have fences stripped")
	}
}

func TestForge_RepairsInvalid(t *testing.T) {
	bad := "id:\nlinks: []\n"                       // invalid
	f := &fakeLLM{replies: []string{bad, forged}}   // first invalid, repair returns valid
	ch, _, err := Forge(context.Background(), f, "advisory", "")
	if err != nil {
		t.Fatalf("repair should succeed: %v", err)
	}
	if ch.ID != "acme-ssrf-rce" || f.calls != 2 {
		t.Fatalf("expected repair on 2nd call, calls=%d chain=%+v", f.calls, ch)
	}
}

func TestForge_EmptyAdvisory(t *testing.T) {
	if _, _, err := Forge(context.Background(), &fakeLLM{replies: []string{forged}}, "  ", ""); err == nil {
		t.Error("empty advisory should error")
	}
}
