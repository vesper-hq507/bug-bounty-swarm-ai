package chains

import (
	"strings"
	"testing"
)

func TestToPlaybook(t *testing.T) {
	c, err := parseChain([]byte(validChain), "demo")
	if err != nil {
		t.Fatal(err)
	}
	pb := c.ToPlaybook()
	// fingerprint + cve_detect + 2 links + report = 5 phases
	if len(pb.Phases) != 5 {
		t.Fatalf("expected 5 phases, got %d", len(pb.Phases))
	}
	if pb.Phases[0].Name != "fingerprint" || pb.Phases[len(pb.Phases)-1].Name != "report" {
		t.Errorf("phase order wrong: %s..%s", pb.Phases[0].Name, pb.Phases[len(pb.Phases)-1].Name)
	}
	// nuclei phase tags carry the CVEs (lowercased)
	det := pb.Phases[1]
	tags, _ := det.Tools[0].Options["tags"].([]string)
	if len(tags) != 2 || tags[0] != "cve-2026-0001" {
		t.Errorf("cve tags not compiled: %v", tags)
	}
	// link guidance carries the safe-verify text
	if !strings.Contains(pb.Phases[2].PostAnalysis, "benign canary") {
		t.Errorf("link verify guidance missing: %q", pb.Phases[2].PostAnalysis)
	}
}
