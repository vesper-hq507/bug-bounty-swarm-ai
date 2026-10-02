package bugbounty

import (
	"strings"
	"testing"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/google/uuid"
)

func TestFormatForHackerOneRedactsReproductionSecrets(t *testing.T) {
	finding := pipeline.ClassifiedFinding{
		ID:          uuid.New(),
		Title:       "Authorization bypass",
		Description: "Controlled reproduction.",
		Severity:    pipeline.SeverityHigh,
		Target:      "https://api.example.test/api/private",
		Reproduce: &pipeline.Reproduction{
			HTTPRequest: "GET /api/private HTTP/1.1\nAuthorization: Bearer top-secret-token\n",
			ExpectedIndicator: "private-data",
		},
		Evidence: []pipeline.Evidence{{
			Type: "provenance_record", Content: "Bearer another-secret",
			Timestamp: time.Now(),
		}},
	}
	report := FormatForHackerOne(finding)
	if strings.Contains(report.ProofOfConcept, "top-secret-token") || strings.Contains(report.ProofOfConcept, "another-secret") {
		t.Fatalf("secret leaked into PoC: %s", report.ProofOfConcept)
	}
	if !strings.Contains(report.ProofOfConcept, "Bearer [REDACTED]") {
		t.Fatalf("redaction marker missing: %s", report.ProofOfConcept)
	}
}

func TestFingerprintReportFindingUsesStructuredFields(t *testing.T) {
	finding := readyFinding()
	fp := FingerprintReportFinding("Acme", finding)
	if fp.Program != "acme" || fp.Asset != "api.example.test" {
		t.Fatalf("asset/program fingerprint = %+v", fp)
	}
	if fp.Method != "GET" || fp.Endpoint != "/api/invoices/123" {
		t.Fatalf("method/endpoint fingerprint = %+v", fp)
	}
	if fp.CWE != "CWE-639" || fp.Parameter != "invoice_id" {
		t.Fatalf("CWE/parameter fingerprint = %+v", fp)
	}
	if fp.EvidenceFingerprint == "" {
		t.Fatal("evidence fingerprint missing")
	}
}
