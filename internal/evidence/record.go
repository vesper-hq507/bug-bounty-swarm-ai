package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type VerificationStatus string

const (
	VerificationUnverified VerificationStatus = "unverified"
	VerificationVerified   VerificationStatus = "verified"
	VerificationRejected   VerificationStatus = "rejected"
)

type ArtifactRef struct {
	Kind string
	Ref  string
	Hash string
}

type Redaction struct {
	Field  string
	Reason string
}

type Record struct {
	ID                  uuid.UUID
	CampaignID          uuid.UUID
	FindingID           uuid.UUID
	ActionID            string
	DecisionID          string
	PolicyVersion       string
	ActorID             string
	IdentityAlias       string
	Tool                string
	RequestFingerprint  string
	ResponseFingerprint string
	CommandFingerprint  string
	RequestExcerpt      string
	ResponseExcerpt     string
	Artifacts           []ArtifactRef
	PoCID               string
	Verification        VerificationStatus
	Redactions          []Redaction
	CreatedAt           time.Time
	IntegrityHash       string
}

type Input struct {
	CampaignID          uuid.UUID
	FindingID           uuid.UUID
	ActionID            string
	DecisionID          string
	PolicyVersion       string
	ActorID             string
	IdentityAlias       string
	Tool                string
	Request             []byte
	Response            []byte
	Command             string
	RequestExcerpt      string
	ResponseExcerpt     string
	Artifacts           []ArtifactRef
	PoCID               string
	Verification        VerificationStatus
}

func New(in Input) (Record, error) {
	if in.CampaignID == uuid.Nil {
		return Record{}, fmt.Errorf("campaign id is required")
	}
	if in.ActionID == "" || in.DecisionID == "" || in.PolicyVersion == "" || in.ActorID == "" {
		return Record{}, fmt.Errorf("action, decision, policy version and actor are required")
	}
	if in.Verification == "" {
		in.Verification = VerificationUnverified
	}
	reqExcerpt, reqRedactions := SanitizeText(in.RequestExcerpt)
	respExcerpt, respRedactions := SanitizeText(in.ResponseExcerpt)
	r := Record{
		ID:                  uuid.New(),
		CampaignID:          in.CampaignID,
		FindingID:           in.FindingID,
		ActionID:            in.ActionID,
		DecisionID:          in.DecisionID,
		PolicyVersion:       in.PolicyVersion,
		ActorID:             in.ActorID,
		IdentityAlias:       in.IdentityAlias,
		Tool:                in.Tool,
		RequestFingerprint:  Fingerprint(in.Request),
		ResponseFingerprint: Fingerprint(in.Response),
		CommandFingerprint:  Fingerprint([]byte(in.Command)),
		RequestExcerpt:      reqExcerpt,
		ResponseExcerpt:     respExcerpt,
		Artifacts:           append([]ArtifactRef(nil), in.Artifacts...),
		PoCID:               in.PoCID,
		Verification:        in.Verification,
		Redactions:          append(reqRedactions, respRedactions...),
		CreatedAt:           time.Now().UTC(),
	}
	r.IntegrityHash = r.computeIntegrity()
	return r, nil
}

func (r Record) VerifyIntegrity() bool {
	return r.IntegrityHash != "" && r.computeIntegrity() == r.IntegrityHash
}

func (r Record) computeIntegrity() string {
	cp := r
	cp.IntegrityHash = ""
	b, _ := json.Marshal(cp)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func Fingerprint(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
