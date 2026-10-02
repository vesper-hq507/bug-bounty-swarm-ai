package bugbounty

import (
	"fmt"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/google/uuid"
)

type SubmissionState string

const (
	StateCandidate       SubmissionState = "candidate"
	StateNeedsEvidence   SubmissionState = "needs-evidence"
	StateDuplicateReview SubmissionState = "duplicate-review"
	StateSubmissionReady SubmissionState = "submission-ready"
	StateApproved        SubmissionState = "approved"
)

type Approval struct {
	Required   bool      `json:"required"`
	Approved   bool      `json:"approved"`
	ApprovedBy string    `json:"approved_by,omitempty"`
	ApprovedAt time.Time `json:"approved_at,omitempty"`
}

type DuplicateAssessment struct {
	IsPossibleDuplicate bool     `json:"is_possible_duplicate"`
	Confidence          float64  `json:"confidence"`
	MatchedSubmissionID string   `json:"matched_submission_id,omitempty"`
	Reasons             []string `json:"reasons,omitempty"`
	Reviewed            bool     `json:"reviewed"`
}

type SubmissionPackage struct {
	ID                uuid.UUID           `json:"id"`
	Program           string              `json:"program"`
	FindingID         uuid.UUID           `json:"finding_id"`
	State             SubmissionState     `json:"state"`
	Report            HackerOneReport     `json:"report"`
	Fingerprint       FindingFingerprint  `json:"fingerprint"`
	Duplicate         DuplicateAssessment `json:"duplicate"`
	EvidenceRecordIDs []string            `json:"evidence_record_ids,omitempty"`
	ReproductionReady bool                `json:"reproduction_ready"`
	Approval          Approval            `json:"approval"`
	CreatedAt         time.Time           `json:"created_at"`
	UpdatedAt         time.Time           `json:"updated_at"`
}

func PrepareSubmission(program string, finding pipeline.ReportFinding, priors []Submission) SubmissionPackage {
	now := time.Now().UTC()
	pkg := SubmissionPackage{
		ID:                uuid.New(),
		Program:           strings.TrimSpace(program),
		FindingID:         finding.ID,
		State:             StateCandidate,
		Report:            formatReportFindingForH1(finding),
		Fingerprint:       FingerprintReportFinding(program, finding),
		EvidenceRecordIDs: provenanceRecordIDs(finding.Evidence),
		ReproductionReady: reproductionReady(finding.Reproduce),
		Approval:          Approval{Required: true},
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	pkg.Duplicate = assessDuplicates(pkg.Fingerprint, priors)
	pkg.refreshState()
	return pkg
}

func (p *SubmissionPackage) MarkDuplicateReviewed() {
	if p == nil {
		return
	}
	p.Duplicate.Reviewed = true
	p.UpdatedAt = time.Now().UTC()
	p.refreshState()
}

func (p *SubmissionPackage) Approve(actor string) error {
	if p == nil {
		return fmt.Errorf("submission package unavailable")
	}
	p.refreshState()
	if p.State != StateSubmissionReady {
		return fmt.Errorf("submission package is %s, not submission-ready", p.State)
	}
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return fmt.Errorf("approver identity is required")
	}
	p.Approval.Approved = true
	p.Approval.ApprovedBy = actor
	p.Approval.ApprovedAt = time.Now().UTC()
	p.UpdatedAt = p.Approval.ApprovedAt
	p.State = StateApproved
	return nil
}

func (p SubmissionPackage) CanSubmit() bool {
	return p.State == StateApproved && p.Approval.Required && p.Approval.Approved
}

func (p *SubmissionPackage) refreshState() {
	if p == nil || p.State == StateApproved {
		return
	}
	if len(p.EvidenceRecordIDs) == 0 || !p.ReproductionReady {
		p.State = StateNeedsEvidence
		return
	}
	if p.Duplicate.IsPossibleDuplicate && !p.Duplicate.Reviewed {
		p.State = StateDuplicateReview
		return
	}
	p.State = StateSubmissionReady
}

func assessDuplicates(candidate FindingFingerprint, priors []Submission) DuplicateAssessment {
	best := DuplicateAssessment{}
	for i := range priors {
		prior := &priors[i]
		if prior.Fingerprint == nil {
			similarity := wordOverlap(candidate.RootCause, normalizeRootCause(prior.Title))
			confidence := similarity * 0.75
			if confidence > best.Confidence {
				best.Confidence = confidence
				best.MatchedSubmissionID = prior.ID
				best.Reasons = []string{"title/root-cause fallback only; structured prior fingerprint unavailable"}
			}
			continue
		}
		match := CompareFingerprints(candidate, *prior.Fingerprint)
		if match.Score <= best.Confidence {
			continue
		}
		best.Confidence = match.Score
		best.MatchedSubmissionID = prior.ID
		best.Reasons = match.Reasons
	}
	best.IsPossibleDuplicate = best.Confidence >= 0.75
	return best
}

func provenanceRecordIDs(evidence []pipeline.Evidence) []string {
	var out []string
	for i := range evidence {
		e := &evidence[i]
		if e.RecordID != "" && e.IntegrityHash != "" {
			out = append(out, e.RecordID)
		}
	}
	return out
}

func reproductionReady(r *pipeline.Reproduction) bool {
	if r == nil || strings.TrimSpace(r.ExpectedIndicator) == "" {
		return false
	}
	return strings.TrimSpace(r.Command) != "" || strings.TrimSpace(r.HTTPRequest) != ""
}

func formatReportFindingForH1(f pipeline.ReportFinding) HackerOneReport {
	finding := pipeline.ClassifiedFinding{
		ID:          f.ID,
		Title:       f.Title,
		Description: f.Description,
		CVSSScore:   f.CVSSScore,
		CVSSVector:  f.CVSSVector,
		Severity:    f.Severity,
		Evidence:    f.Evidence,
		Target:      firstAffectedComponent(f.AffectedComponents),
		Reproduce:   f.Reproduce,
	}
	return FormatForHackerOne(finding)
}

func firstAffectedComponent(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
