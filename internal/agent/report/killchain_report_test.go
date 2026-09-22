package report

import (
	"strings"
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/google/uuid"
)

func TestSummarizeAndRenderKillChains(t *testing.T) {
	findings := []pipeline.ClassifiedFinding{
		{ID: uuid.New(), Title: "Leaked API credential", AttackCategory: "credential", Severity: pipeline.SeverityHigh, CVSSScore: 8},
		{ID: uuid.New(), Title: "Admin privilege escalation", AttackCategory: "privilege", Severity: pipeline.SeverityCritical, CVSSScore: 9.5},
	}
	chains := summarizeKillChains(findings)
	if len(chains) == 0 || !strings.Contains(chains[0], "→") {
		t.Fatalf("expected a composed chain, got %v", chains)
	}

	md, err := NewRenderer().ToMarkdown(&pipeline.PentestReport{ID: uuid.New(), Target: "x", KillChains: chains})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(md), "## Kill Chains") || !strings.Contains(string(md), "→") {
		t.Errorf("Kill Chains section missing:\n%s", md)
	}
}
