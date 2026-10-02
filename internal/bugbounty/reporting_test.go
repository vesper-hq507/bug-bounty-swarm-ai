package bugbounty

import (
	"testing"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/google/uuid"
)

func readyFinding() pipeline.ReportFinding {
	return pipeline.ReportFinding{
		ID:          uuid.New(),
		Title:       "IDOR in invoice endpoint parameter invoice_id",
		Severity:    pipeline.SeverityHigh,
		CVSSScore:   8.1,
		Description: "A non-owner can read another invoice.",
		AffectedComponents: []string{"https://api.example.test/api/invoices/123"},
		CWE: "CWE-639",
		Evidence: []pipeline.Evidence{{
			Type: "provenance_record",
			Content: "evidence:record-1",
			Timestamp: time.Now(),
			RecordID: "record-1",
			IntegrityHash: "abc123",
		}},
		Reproduce: &pipeline.Reproduction{
			HTTPRequest: "GET /api/invoices/123?invoice_id=123 HTTP/1.1\nHost: api.example.test\n",
			ExpectedIndicator: "invoice_id",
		},
	}
}

func TestStructuredFingerprintStrongMatch(t *testing.T) {
	a := FingerprintReportFinding("acme", readyFinding())
	b := a
	got := CompareFingerprints(a, b)
	if got.Score < 0.99 {
		t.Fatalf("score = %.3f reasons=%v", got.Score, got.Reasons)
	}
}

func TestPrepareSubmissionRequiresHumanApproval(t *testing.T) {
	finding := readyFinding()
	pkg := PrepareSubmission("acme", finding, nil)
	if pkg.State != StateSubmissionReady {
		t.Fatalf("state = %s", pkg.State)
	}
	if !pkg.Approval.Required || pkg.CanSubmit() {
		t.Fatalf("approval gate missing: %+v", pkg.Approval)
	}
	if err := pkg.Approve("researcher"); err != nil {
		t.Fatal(err)
	}
	if pkg.State != StateApproved || !pkg.CanSubmit() {
		t.Fatalf("approved package = %+v", pkg)
	}
}

func TestPrepareSubmissionStopsForDuplicateReview(t *testing.T) {
	finding := readyFinding()
	fp := FingerprintReportFinding("acme", finding)
	priors := []Submission{{
		ID: "prior-42",
		Title: "prior report",
		Fingerprint: &fp,
	}}
	pkg := PrepareSubmission("acme", finding, priors)
	if pkg.State != StateDuplicateReview || !pkg.Duplicate.IsPossibleDuplicate {
		t.Fatalf("duplicate state = %+v", pkg)
	}
	if err := pkg.Approve("researcher"); err == nil {
		t.Fatal("duplicate-review package must not be approved before review")
	}
	pkg.MarkDuplicateReviewed()
	if pkg.State != StateSubmissionReady {
		t.Fatalf("state after duplicate review = %s", pkg.State)
	}
}

func TestPrepareSubmissionStopsWhenProvenanceMissing(t *testing.T) {
	finding := readyFinding()
	finding.Evidence[0].RecordID = ""
	pkg := PrepareSubmission("acme", finding, nil)
	if pkg.State != StateNeedsEvidence {
		t.Fatalf("state = %s", pkg.State)
	}
	if err := pkg.Approve("researcher"); err == nil {
		t.Fatal("package without evidence provenance must not be approved")
	}
}
