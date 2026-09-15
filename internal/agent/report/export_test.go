package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/google/uuid"
)

func sampleReport() *pipeline.PentestReport {
	return &pipeline.PentestReport{
		ID:               uuid.New(),
		Target:           "crapi.local",
		Objective:        "find all vulnerabilities",
		ExecutiveSummary: "Four issues found, one critical.",
		GeneratedAt:      time.Now(),
		Findings: []pipeline.ReportFinding{
			{ID: uuid.New(), Title: "JWT alg:none takeover", Severity: pipeline.SeverityCritical, CVSSScore: 9.8, Description: "Auth bypass."},
			{ID: uuid.New(), Title: "BOLA vehicle location", Severity: pipeline.SeverityHigh, CVSSScore: 8.1, Description: "Cross-user object access."},
		},
	}
}

// The shareable HTML must be a single self-contained file — no external asset
// refs — and must contain the findings.
func TestToShareableHTML_SelfContained(t *testing.T) {
	b, err := NewRenderer().ToShareableHTML(sampleReport())
	if err != nil {
		t.Fatal(err)
	}
	html := string(b)
	if !strings.Contains(html, "JWT alg:none takeover") || !strings.Contains(html, "crapi.local") {
		t.Error("shareable HTML missing report content")
	}
	for _, bad := range []string{"src=\"http", "href=\"http", "cdn", "googleapis"} {
		if strings.Contains(strings.ToLower(html), bad) {
			t.Errorf("shareable HTML references an external asset (%q) — must be self-contained", bad)
		}
	}
}

// With no converter available, ToPDF must fall back to writing print-ready HTML
// rather than failing.
func TestToPDF_FallbackWhenNoConverter(t *testing.T) {
	orig := resolveConverter
	resolveConverter = func(string) (string, bool) { return "", false } // pretend nothing is installed
	defer func() { resolveConverter = orig }()

	dir := t.TempDir()
	res, err := NewRenderer().ToPDF(sampleReport(), filepath.Join(dir, "report.pdf"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.UsedFallback {
		t.Error("expected fallback when no converter is present")
	}
	if !strings.HasSuffix(res.Path, ".html") {
		t.Errorf("fallback should write .html, got %s", res.Path)
	}
	if _, err := os.Stat(res.Path); err != nil {
		t.Errorf("fallback file not written: %v", err)
	}
	if res.Message == "" {
		t.Error("fallback should explain how to make the PDF by hand")
	}
}
