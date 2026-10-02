package evidence

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestNewRecordRedactsSecretsAndLinksProvenance(t *testing.T) {
	campaignID := uuid.New()
	findingID := uuid.New()
	r, err := New(Input{
		CampaignID:    campaignID,
		FindingID:     findingID,
		ActionID:      "action-1",
		DecisionID:    "decision-1",
		PolicyVersion: "policy-v1",
		ActorID:       "user-a",
		IdentityAlias: "User A",
		Request:       []byte("GET /api/object/1"),
		Response:      []byte("200 object"),
		Command:       "httpreq --url https://example.test/api/object/1",
		RequestExcerpt: "Authorization: Bearer super-secret",
		ResponseExcerpt: `{"id":1,"token":"secret-value"}`,
		Verification: VerificationVerified,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !r.VerifyIntegrity() {
		t.Fatal("new record failed integrity verification")
	}
	if strings.Contains(r.RequestExcerpt, "super-secret") || strings.Contains(r.ResponseExcerpt, "secret-value") {
		t.Fatalf("secret leaked into evidence excerpts: req=%q resp=%q", r.RequestExcerpt, r.ResponseExcerpt)
	}
	if r.DecisionID != "decision-1" || r.ActorID != "user-a" || r.PolicyVersion != "policy-v1" {
		t.Fatalf("provenance linkage missing: %+v", r)
	}
	ref := PipelineRef(r, "verified authorization differential")
	if ref.RecordID != r.ID.String() || ref.IntegrityHash != r.IntegrityHash {
		t.Fatalf("pipeline reference missing provenance linkage: %+v", ref)
	}
}

func TestIntegrityDetectsMutation(t *testing.T) {
	r, err := New(Input{
		CampaignID: uuid.New(),
		ActionID: "a",
		DecisionID: "d",
		PolicyVersion: "p",
		ActorID: "i",
	})
	if err != nil {
		t.Fatal(err)
	}
	r.ActorID = "tampered"
	if r.VerifyIntegrity() {
		t.Fatal("mutated record must fail integrity verification")
	}
}

func TestSanitizeHeaders(t *testing.T) {
	h := http.Header{
		"Authorization": []string{"Bearer abc"},
		"Content-Type":  []string{"application/json"},
	}
	got, redactions := SanitizeHeaders(h)
	if got["Authorization"] != "[REDACTED]" || got["Content-Type"] != "application/json" {
		t.Fatalf("sanitized headers = %+v", got)
	}
	if len(redactions) != 1 {
		t.Fatalf("redactions = %+v", redactions)
	}
}
