package attackgraph

import (
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/google/uuid"
)

func f(title, cat string, sev pipeline.Severity, cvss float64) pipeline.ClassifiedFinding {
	return pipeline.ClassifiedFinding{ID: uuid.New(), Title: title, AttackCategory: cat, Severity: sev, CVSSScore: cvss, Confidence: pipeline.Confidence("high")}
}

func TestBuildFromFindings_PathToImpact(t *testing.T) {
	findings := []pipeline.ClassifiedFinding{
		f("Verbose error exposure", "exposure", pipeline.SeverityLow, 3),
		f("JWT alg:none accepted", "jwt", pipeline.SeverityHigh, 8),
		f("BFLA admin function", "bfla", pipeline.SeverityCritical, 9.5),
		f("Missing security header", "header", pipeline.SeverityLow, 2), // dead-end, no path to impact
	}
	g := BuildFromFindings(findings, "admin account takeover")

	path, prob := g.ShortestPath(EntryID, ObjectiveID())
	if len(path) == 0 || prob <= 0 {
		t.Fatalf("expected a reachable path to the objective, got %d hops prob=%.3f", len(path), prob)
	}
	// The objective must be reachable via the impactful BFLA finding.
	last := path[len(path)-1]
	if last.To != ObjectiveID() {
		t.Errorf("path should end at the objective, ends at %s", last.To)
	}
}

func TestBuildFromFindings_NoImpactUnreachable(t *testing.T) {
	// only low-value informational findings → no path to full compromise
	findings := []pipeline.ClassifiedFinding{
		f("Missing security header", "header", pipeline.SeverityLow, 2),
		f("Verbose errors", "exposure", pipeline.SeverityLow, 3),
	}
	g := BuildFromFindings(findings, "full compromise")
	if _, prob := g.ShortestPath(EntryID, ObjectiveID()); prob > 0 {
		t.Errorf("no impactful finding should mean the objective is unreachable, got prob=%.3f", prob)
	}
}

func TestBuildFromFindings_SSRFCloudPath(t *testing.T) {
	findings := []pipeline.ClassifiedFinding{
		f("SSRF in import URL", "ssrf", pipeline.SeverityHigh, 8),
	}
	g := BuildFromFindings(findings, "cloud account access")
	// SSRF alone should now reach the objective via the cloud-credentials node.
	if _, prob := g.ShortestPath(EntryID, ObjectiveID()); prob <= 0 {
		t.Fatal("SSRF should reach the objective via cloud credentials")
	}
	if g.Node("cap:cloud-creds") == nil {
		t.Error("expected a cloud-credentials capability node")
	}
}
