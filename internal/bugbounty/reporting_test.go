package bugbounty

import (
	"testing"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/evidence"
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


func TestPrepareVerifiedSubmissionRequiresDurableVerifiedEvidence(t *testing.T) {
	store := evidence.NewMemoryStore()
	rec, err := evidence.New(evidence.Input{
		CampaignID: uuid.New(),
		ActionID: "action-1",
		DecisionID: "decision-1",
		PolicyVersion: "policy-v1",
		ActorID: "user-a",
		Verification: evidence.VerificationVerified,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Add(rec); err != nil {
		t.Fatal(err)
	}

	finding := readyFinding()
	finding.Evidence = []pipeline.Evidence{evidence.PipelineRef(rec, "verified acceptance evidence")}
	pkg := PrepareVerifiedSubmission("acme", finding, nil, store)
	if pkg.State != StateSubmissionReady || !pkg.EvidenceVerified {
		t.Fatalf("verified package = %+v", pkg)
	}
	if err := pkg.ApproveVerified("researcher", store); err != nil {
		t.Fatal(err)
	}
	if !pkg.CanSubmit() {
		t.Fatal("verified, human-approved package should be submit-eligible")
	}
}

func TestApproveVerifiedRejectsForgedEvidenceHash(t *testing.T) {
	store := evidence.NewMemoryStore()
	rec, err := evidence.New(evidence.Input{
		CampaignID: uuid.New(),
		ActionID: "action-1",
		DecisionID: "decision-1",
		PolicyVersion: "policy-v1",
		ActorID: "user-a",
		Verification: evidence.VerificationVerified,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Add(rec); err != nil {
		t.Fatal(err)
	}

	finding := readyFinding()
	ref := evidence.PipelineRef(rec, "verified acceptance evidence")
	finding.Evidence = []pipeline.Evidence{ref}
	pkg := PrepareVerifiedSubmission("acme", finding, nil, store)
	pkg.EvidenceIntegrity[ref.RecordID] = "forged"
	if err := pkg.ApproveVerified("researcher", store); err == nil {
		t.Fatal("forged evidence hash must block approval")
	}
	if pkg.State != StateNeedsEvidence || pkg.CanSubmit() {
		t.Fatalf("forged package state = %+v", pkg)
	}
}

func TestPrepareVerifiedSubmissionRejectsUnverifiedRecord(t *testing.T) {
	store := evidence.NewMemoryStore()
	rec, err := evidence.New(evidence.Input{
		CampaignID: uuid.New(),
		ActionID: "action-1",
		DecisionID: "decision-1",
		PolicyVersion: "policy-v1",
		ActorID: "user-a",
		Verification: evidence.VerificationUnverified,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Add(rec); err != nil {
		t.Fatal(err)
	}
	finding := readyFinding()
	finding.Evidence = []pipeline.Evidence{evidence.PipelineRef(rec, "unverified evidence")}
	pkg := PrepareVerifiedSubmission("acme", finding, nil, store)
	if pkg.State != StateNeedsEvidence || pkg.EvidenceVerified {
		t.Fatalf("unverified package = %+v", pkg)
	}
}


func TestApprovedPackageLosesSubmissionEligibilityIfEvidenceRevalidationFails(t *testing.T) {
	store := evidence.NewMemoryStore()
	rec, err := evidence.New(evidence.Input{
		CampaignID: uuid.New(),
		ActionID: "action-1",
		DecisionID: "decision-1",
		PolicyVersion: "policy-v1",
		ActorID: "user-a",
		Verification: evidence.VerificationVerified,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Add(rec); err != nil {
		t.Fatal(err)
	}
	finding := readyFinding()
	ref := evidence.PipelineRef(rec, "verified evidence")
	finding.Evidence = []pipeline.Evidence{ref}
	pkg := PrepareVerifiedSubmission("acme", finding, nil, store)
	if err := pkg.ApproveVerified("researcher", store); err != nil {
		t.Fatal(err)
	}
	if !pkg.CanSubmit() {
		t.Fatal("approved package should initially be eligible")
	}

	pkg.EvidenceIntegrity[ref.RecordID] = "forged-after-approval"
	pkg.ValidateEvidence(store)
	if pkg.CanSubmit() {
		t.Fatal("failed evidence revalidation must revoke submission eligibility")
	}
	if pkg.State != StateNeedsEvidence || pkg.Approval.Approved {
		t.Fatalf("revalidated package=%+v", pkg)
	}
}

func TestMarkSubmittedPersistsReceiptAndPreventsResend(t *testing.T) {
	store := evidence.NewMemoryStore()
	rec, err := evidence.New(evidence.Input{
		CampaignID: uuid.New(),
		ActionID: "action-1",
		DecisionID: "decision-1",
		PolicyVersion: "policy-v1",
		ActorID: "user-a",
		Verification: evidence.VerificationVerified,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Add(rec); err != nil {
		t.Fatal(err)
	}
	finding := readyFinding()
	finding.Evidence = []pipeline.Evidence{evidence.PipelineRef(rec, "verified evidence")}
	pkg := PrepareVerifiedSubmission("acme", finding, nil, store)
	if err := pkg.ApproveVerified("researcher", store); err != nil {
		t.Fatal(err)
	}
	if err := pkg.MarkSubmitted("hackerone", "12345"); err != nil {
		t.Fatal(err)
	}
	if pkg.State != StateSubmitted || pkg.Submission == nil ||
		pkg.Submission.Platform != "hackerone" || pkg.Submission.ExternalID != "12345" {
		t.Fatalf("submitted package=%+v", pkg)
	}
	if pkg.CanSubmit() {
		t.Fatal("submitted package must not be eligible for another send")
	}
	if err := pkg.MarkSubmitted("hackerone", "12346"); err == nil {
		t.Fatal("second submission receipt must be rejected")
	}
}
