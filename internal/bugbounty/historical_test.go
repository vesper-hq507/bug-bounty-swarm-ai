package bugbounty

import (
	"testing"
)

func TestFingerprintHistoricalReportExtractsStructuredMetadata(t *testing.T) {
	fp := FingerprintHistoricalReport(HistoricalReportFingerprintInput{
		Program: "Acme",
		Title: "Authorization issue in invoice lookup",
		VulnerabilityInformation: "GET https://api.example.test/api/invoices/123?invoice_id=123 HTTP/1.1\nHost: api.example.test\nRelated: CVE-2026-12345",
		WeaknessName: "Authorization Bypass Through User-Controlled Key",
		WeaknessExternalID: "cwe-639",
		AssetIdentifier: "https://api.example.test",
	})
	if fp.Program != "acme" || fp.Asset != "api.example.test" {
		t.Fatalf("program/asset = %+v", fp)
	}
	if fp.Method != "GET" || fp.Endpoint != "/api/invoices/123" {
		t.Fatalf("request fingerprint = %+v", fp)
	}
	if fp.CWE != "CWE-639" || fp.Parameter != "invoice_id" {
		t.Fatalf("weakness/parameter = %+v", fp)
	}
	if len(fp.CVEIDs) != 1 || fp.CVEIDs[0] != "cve-2026-12345" {
		t.Fatalf("CVE IDs = %#v", fp.CVEIDs)
	}
	if !HistoricalFingerprintInformative(fp) {
		t.Fatal("rich historical fingerprint should be informative")
	}
}

func TestHistoricalFingerprintSparseReportUsesFallback(t *testing.T) {
	fp := FingerprintHistoricalReport(HistoricalReportFingerprintInput{
		Program: "acme",
		Title: "Generic security issue",
	})
	if HistoricalFingerprintInformative(fp) {
		t.Fatalf("sparse fingerprint must not be treated as structured: %+v", fp)
	}
}

func TestHistoricalFingerprintMatchesCurrentFindingDespiteDifferentTitle(t *testing.T) {
	current := FingerprintReportFinding("acme", readyFinding())
	historical := FingerprintHistoricalReport(HistoricalReportFingerprintInput{
		Program: "acme",
		Title: "Object authorization weakness",
		VulnerabilityInformation: "GET https://api.example.test/api/invoices/123?invoice_id=123 HTTP/1.1",
		WeaknessExternalID: "CWE-639",
		AssetIdentifier: "https://api.example.test",
	})
	match := CompareFingerprints(current, historical)
	if match.Score < 0.85 {
		t.Fatalf("structured historical match too weak: score=%.3f reasons=%v current=%+v historical=%+v",
			match.Score, match.Reasons, current, historical)
	}
}


func TestHistoricalStructuredFingerprintTriggersDuplicateReview(t *testing.T) {
	finding := readyFinding()
	fp := FingerprintHistoricalReport(HistoricalReportFingerprintInput{
		Program: "acme",
		Title: "Object authorization weakness",
		VulnerabilityInformation: "GET https://api.example.test/api/invoices/123?invoice_id=123 HTTP/1.1",
		WeaknessExternalID: "CWE-639",
		AssetIdentifier: "https://api.example.test",
	})
	prior := Submission{ID: "h1-42", Title: "Object authorization weakness", Fingerprint: &fp}
	pkg := PrepareSubmission("acme", finding, []Submission{prior})
	if pkg.State != StateDuplicateReview || !pkg.Duplicate.IsPossibleDuplicate {
		t.Fatalf("historical structured duplicate not detected: %+v", pkg.Duplicate)
	}
	if pkg.Duplicate.MatchedSubmissionID != "h1-42" {
		t.Fatalf("matched submission = %q", pkg.Duplicate.MatchedSubmissionID)
	}
}
