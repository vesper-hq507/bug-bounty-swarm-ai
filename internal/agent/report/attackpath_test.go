package report

import (
	"strings"
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/google/uuid"
)

func TestSummarizeAndRenderAttackPath(t *testing.T) {
	findings := []pipeline.ClassifiedFinding{
		{ID: uuid.New(), Title: "Leaked API credential", AttackCategory: "credential", Severity: pipeline.SeverityHigh, CVSSScore: 8, Confidence: "high"},
		{ID: uuid.New(), Title: "BFLA admin function", AttackCategory: "bfla", Severity: pipeline.SeverityCritical, CVSSScore: 9.5, Confidence: "high"},
	}
	path := summarizeAttackPath(findings, "admin takeover")
	if len(path) < 2 || !strings.Contains(path[0], "admin takeover") {
		t.Fatalf("expected a rendered path to the objective, got %v", path)
	}
	md, err := NewRenderer().ToMarkdown(&pipeline.PentestReport{ID: uuid.New(), Target: "x", AttackPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(md), "## Attack Path to Objective") {
		t.Errorf("Attack Path section missing:\n%s", md)
	}
}
