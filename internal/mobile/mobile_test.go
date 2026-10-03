package mobile

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/evidence"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/identity"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope/programterms"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/workflow"
	"github.com/google/uuid"
)

func TestParseHARRedactsHeadersAndDecodesBoundedBody(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("{\"ok\":true}"))
	har := []byte(`{
		"log":{"entries":[{
			"request":{
				"method":"GET",
				"url":"https://api.example.test/api/invoices/42",
				"headers":[
					{"name":"Authorization","value":"Bearer secret-token"},
					{"name":"Accept","value":"application/json"}
				]
			},
			"response":{
				"status":200,
				"headers":[{"name":"Content-Type","value":"application/json"}],
				"content":{"text":"` + encoded + `","encoding":"base64"}
			}
		}]}
	}`)
	capture, err := ParseHAR(har, Metadata{
		Platform: PlatformAndroid, AppID: "com.example.app",
		IdentityAlias: "user-a", SessionRef: "vault:user-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(capture.Transactions) != 1 {
		t.Fatalf("transactions=%d", len(capture.Transactions))
	}
	tx := capture.Transactions[0]
	if tx.RequestHeaders["Authorization"] != "[REDACTED]" {
		t.Fatalf("authorization header=%q", tx.RequestHeaders["Authorization"])
	}
	if strings.Contains(strings.Join(mapValues(tx.RequestHeaders), " "), "secret-token") {
		t.Fatal("secret token survived HAR normalization")
	}
	if string(tx.ResponseBody) != "{\"ok\":true}" {
		t.Fatalf("response body=%q", string(tx.ResponseBody))
	}
	if capture.RedactionCount == 0 || capture.ID == "" {
		t.Fatalf("capture metadata=%+v", capture)
	}
}

func TestAnalyzeFeedsEvidenceWorkflowAndGuidance(t *testing.T) {
	har := []byte(`{
		"log":{"entries":[
			{
				"request":{
					"method":"POST",
					"url":"https://api.example.test/orders/42/refund",
					"headers":[{"name":"Authorization","value":"Bearer secret-token"}],
					"postData":{"text":"{\"previous_state\":\"paid\"}"}
				},
				"response":{
					"status":200,
					"headers":[{"name":"Content-Type","value":"application/json"}],
					"content":{"text":"{\"state\":\"refunded\",\"token\":\"response-secret\"}"}
				}
			},
			{
				"request":{"method":"GET","url":"https://api.example.test/admin/users"},
				"response":{"status":200,"content":{"text":"{}"}}
			},
			{
				"request":{"method":"GET","url":"https://analytics.other.test/track"},
				"response":{"status":204,"content":{"text":""}}
			}
		]}
	}`)
	capture, err := ParseHAR(har, Metadata{
		Platform: PlatformIOS, AppID: "com.example.app",
		IdentityAlias: "user-a", ActorRole: "user", SessionRef: "vault:user-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	store := evidence.NewMemoryStore()
	campaignID := uuid.New()
	analysis, err := Analyze(context.Background(), capture, AnalyzeOptions{
		Scope: scope.ScopeDefinition{AllowedDomains: []string{"example.test"}},
		Constraints: programterms.Constraints{DisallowedPaths: []string{"/admin"}},
		WorkflowRules: []workflow.Rule{{
			ID: "refund-precondition", Action: "refund", RequiredPrior: []string{"capture-payment"},
		}},
		CampaignID: campaignID,
		PolicyVersion: "mobile-policy-v1",
		EvidenceStore: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if analysis.InScopeCount != 1 || len(analysis.Skipped) != 2 {
		t.Fatalf("analysis counts=%+v", analysis)
	}
	if len(analysis.Workflow.Hypotheses) == 0 || len(analysis.Guidance) == 0 {
		t.Fatalf("workflow/guidance missing: %+v", analysis)
	}
	if len(analysis.EvidenceRefs) != 1 {
		t.Fatalf("evidence refs=%+v", analysis.EvidenceRefs)
	}
	id, err := uuid.Parse(analysis.EvidenceRefs[0].RecordID)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := store.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Verification != evidence.VerificationUnverified || !rec.VerifyIntegrity() {
		t.Fatalf("imported evidence=%+v", rec)
	}
	if strings.Contains(rec.RequestExcerpt, "secret-token") || strings.Contains(rec.ResponseExcerpt, "response-secret") {
		t.Fatalf("secret survived evidence redaction: req=%q resp=%q", rec.RequestExcerpt, rec.ResponseExcerpt)
	}
	if !analysis.SessionRefPresent {
		t.Fatal("session reference presence should be recorded without exposing its value")
	}
}

func TestCompareControlledFindsMobileObjectAuthorizationDifference(t *testing.T) {
	headers := map[string]string{"Content-Type": "application/json"}
	owner := Capture{
		Platform: PlatformAndroid, AppID: "com.example.app", IdentityAlias: "user-a",
		Transactions: []Transaction{{
			Method: "GET", URL: "https://api.example.test/api/invoices/42", StatusCode: 200,
			ResponseHeaders: headers, ResponseBody: []byte("{\"id\":\"42\",\"owner_id\":\"user-a\"}"),
		}},
	}
	actor := Capture{
		Platform: PlatformAndroid, AppID: "com.example.app", IdentityAlias: "user-b",
		Transactions: []Transaction{{
			Method: "GET", URL: "https://api.example.test/api/invoices/42", StatusCode: 200,
			ResponseHeaders: headers, ResponseBody: []byte("{\"id\":\"42\",\"owner_id\":\"user-a\"}"),
		}},
	}
	results := CompareControlled(owner, actor, scope.ScopeDefinition{AllowedDomains: []string{"example.test"}}, programterms.Constraints{})
	if len(results) != 1 || results[0].Kind != identity.DiffUnexpectedAccess {
		t.Fatalf("differential results=%+v", results)
	}

	actor.Transactions[0].StatusCode = 403
	actor.Transactions[0].ResponseBody = []byte("{\"error\":\"forbidden\"}")
	results = CompareControlled(owner, actor, scope.ScopeDefinition{AllowedDomains: []string{"example.test"}}, programterms.Constraints{})
	if len(results) != 1 || results[0].Kind != identity.DiffOwnerOnly {
		t.Fatalf("negative differential results=%+v", results)
	}
}

func mapValues(in map[string]string) []string {
	out := make([]string, 0, len(in))
	for _, value := range in {
		out = append(out, value)
	}
	return out
}
