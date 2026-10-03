package cli

import (
	"strings"
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/bugbounty"
)

func TestHackerOneSubmissionInformationIncludesReproductionAndFix(t *testing.T) {
	got := hackerOneSubmissionInformation(bugbounty.HackerOneReport{
		VulnerabilityInformation: "## Summary\n\nIssue details",
		ProofOfConcept: "## Steps to Reproduce\n\n1. Observe safely",
		RecommendedFix: "Enforce authorization server-side.",
	})
	for _, want := range []string{"## Summary", "## Steps to Reproduce", "## Recommended Fix", "Enforce authorization"} {
		if !strings.Contains(got, want) {
			t.Fatalf("submission information missing %q: %s", want, got)
		}
	}
}
