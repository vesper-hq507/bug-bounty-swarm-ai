package acceptance_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/approval"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/bugbounty"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/evidence"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/guidance"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/identity"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/monitor"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/policygateway"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/recovery"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope/programterms"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/workflow"
	"github.com/google/uuid"
)

func TestControlledBugBountyAcceptanceChain(t *testing.T) {
	t.Parallel()

	const requiredHeaderValue = "acceptance-lab"
	var targetHits int
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits++
		if r.Header.Get("X-Bugbounty-User") != requiredHeaderValue {
			http.Error(w, "missing required program header", http.StatusBadRequest)
			return
		}
		if r.URL.Path == "/admin" {
			http.Error(w, "gateway should have blocked this path", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"42","owner_id":"user-a","state":"active","token":"lab-secret"}`)
	}))
	defer lab.Close()

	labURL, err := url.Parse(lab.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, _, err := net.SplitHostPort(labURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	cidrSuffix := "/128"
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		cidrSuffix = "/32"
	}

	constraints := programterms.Parse("5 requests per second\n`X-Bugbounty-User: acceptance-lab`\ndo not test /admin")
	if constraints.MaxRequestsPerSecond != 5 {
		t.Fatalf("parsed rate limit = %v, want 5", constraints.MaxRequestsPerSecond)
	}
	if constraints.RequiredHeaders["X-Bugbounty-User"] != requiredHeaderValue {
		t.Fatalf("required headers = %#v", constraints.RequiredHeaders)
	}

	gateway := policygateway.New(policygateway.Policy{
		Scope: scope.ScopeDefinition{AllowedCIDRs: []string{host + cidrSuffix}},
		RequiredHeaders:      constraints.RequiredHeaders,
		DisallowedPaths:      constraints.DisallowedPaths,
		RequestsPerSecond:    constraints.MaxRequestsPerSecond,
		Burst:                2,
		Version:              "acceptance-policy-v1",
	})

	campaignID := uuid.New()
	broker := approval.NewStaticBroker(nil, nil, false)
	readGrant, err := broker.Authorize(context.Background(), approval.Request{
		CampaignID: campaignID,
		ActionID:   "read-object",
		ActorID:    "user-a",
		Capability: approval.CapabilityObserve,
		Target:     lab.URL + "/objects/42",
		Reason:     "controlled read-only acceptance observation",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !readGrant.Granted || readGrant.Source != "automatic-read-only" {
		t.Fatalf("read-only grant = %+v", readGrant)
	}
	if _, err := broker.Authorize(context.Background(), approval.Request{
		CampaignID: campaignID,
		ActionID:   "mutate-object",
		ActorID:    "user-a",
		Capability: approval.CapabilityStateChange,
		Target:     lab.URL + "/objects/42",
		Reason:     "state-changing actions need explicit approval",
	}); !errors.Is(err, approval.ErrApprovalRequired) {
		t.Fatalf("state-changing action err = %v, want approval required", err)
	}

	store, err := evidence.NewFileStore(filepath.Join(t.TempDir(), "evidence"))
	if err != nil {
		t.Fatal(err)
	}
	obj := identity.ObjectRef{Type: "object", ID: "42"}
	owners := identity.NewOwnershipMap()
	if err := owners.SetOwner(obj, identity.ID("user-a")); err != nil {
		t.Fatal(err)
	}

	type observed struct {
		obs identity.Observation
		ref pipeline.Evidence
		body []byte
	}
	observe := func(actor string) observed {
		t.Helper()
		client := &http.Client{Transport: policygateway.NewHTTPTransport(gateway, http.DefaultTransport, func(r *http.Request) policygateway.Action {
			return policygateway.Action{
				ActionID:   "identity:" + obj.Key() + ":" + actor,
				CampaignID: campaignID.String(),
				ActorID:    actor,
				Kind:       policygateway.ActionHTTP,
				Method:     r.Method,
				URL:        r.URL.String(),
				Path:       r.URL.EscapedPath(),
				Tool:       "acceptance-identity-diff",
			}
		})}
		req, reqErr := http.NewRequestWithContext(context.Background(), http.MethodGet, lab.URL+"/objects/42", http.NoBody)
		if reqErr != nil {
			t.Fatal(reqErr)
		}
		resp, runErr := client.Do(req)
		if runErr != nil {
			t.Fatal(runErr)
		}
		defer func() { _ = resp.Body.Close() }()
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		decision, ok := policygateway.DecisionFromResponse(resp)
		if !ok || decision.ID == "" || decision.PolicyVersion == "" {
			t.Fatalf("missing policy decision: %+v ok=%v", decision, ok)
		}
		ref, evErr := evidence.RecordObservation(store, evidence.ObservationInput{
			CampaignID:      campaignID,
			ActionID:        decision.ActionID,
			DecisionID:      decision.ID,
			PolicyVersion:   decision.PolicyVersion,
			ActorID:         actor,
			IdentityAlias:   actor,
			Tool:            "identity-diff",
			Request:         []byte(http.MethodGet + " " + lab.URL + "/objects/42"),
			Response:        body,
			RequestExcerpt:  http.MethodGet + " " + lab.URL + "/objects/42",
			ResponseExcerpt: string(body),
			Verification:    evidence.VerificationVerified,
		})
		if evErr != nil {
			t.Fatal(evErr)
		}
		return observed{
			obs: identity.Snapshot(identity.ID(actor), obj, resp.StatusCode, resp.Header, body),
			ref: ref,
			body: body,
		}
	}

	owner := observe("user-a")
	actor := observe("user-b")
	diff := identity.CompareObjectAccess(owner.obs, actor.obs, owners)
	diff.EvidenceRefs = []string{owner.ref.Content, actor.ref.Content}
	if diff.Kind != identity.DiffUnexpectedAccess {
		t.Fatalf("differential result = %+v, want unexpected access", diff)
	}
	if len(diff.EvidenceRefs) != 2 {
		t.Fatalf("differential evidence refs = %#v", diff.EvidenceRefs)
	}

	records := store.ForCampaign(campaignID)
	if len(records) != 2 {
		t.Fatalf("campaign evidence records = %d, want 2", len(records))
	}
	for i := range records {
		if records[i].Verification != evidence.VerificationVerified || !records[i].VerifyIntegrity() {
			t.Fatalf("invalid verified evidence record: %+v", records[i])
		}
		if strings.Contains(records[i].ResponseExcerpt, "lab-secret") {
			t.Fatalf("secret leaked into persisted evidence excerpt: %q", records[i].ResponseExcerpt)
		}
	}

	collector := workflow.NewCollector()
	event := collector.Observe(workflow.Observation{
		Method:       http.MethodGet,
		URL:          lab.URL + "/objects/42",
		ActorID:      "user-b",
		ActorRole:    "user",
		StatusCode:   http.StatusOK,
		ResponseBody: actor.body,
		EvidenceRefs: diff.EvidenceRefs,
	})
	analysis := workflow.Analyze(collector.Events(), []workflow.Rule{{
		ID:            "owner-read-boundary",
		Action:        event.Action,
		RequiresOwner: true,
		Description:   "objects are readable only by their owner",
	}}, constraints.MaxRequestsPerSecond)
	if len(analysis.Hypotheses) == 0 || analysis.Hypotheses[0].Kind != workflow.HypothesisOwnership {
		t.Fatalf("workflow hypotheses = %+v, want ownership-boundary hypothesis", analysis.Hypotheses)
	}

	before := monitor.Snapshot{
		Target: lab.URL,
		Endpoints: []monitor.Endpoint{{
			Method: http.MethodGet, URL: lab.URL + "/health",
		}},
	}
	after := monitor.Snapshot{
		Target: lab.URL,
		Endpoints: []monitor.Endpoint{
			{Method: http.MethodGet, URL: lab.URL + "/health"},
			{Method: http.MethodGet, URL: lab.URL + "/objects/42", Parameters: []string{"id"}},
		},
	}
	monitorDiff := monitor.Diff(before, after)
	recs := guidance.Merge(10,
		guidance.FromWorkflow(analysis, constraints),
		guidance.FromMonitor(monitorDiff, constraints),
	)
	if len(recs) < 2 {
		t.Fatalf("guidance recommendations = %+v, want workflow + monitor guidance", recs)
	}
	if recs[0].Test != "workflow-ownership-boundary" {
		t.Fatalf("highest priority guidance = %+v", recs[0])
	}

	finding := pipeline.ReportFinding{
		ID:          uuid.New(),
		Title:       "Broken object-level authorization on /objects/42",
		Severity:    pipeline.SeverityHigh,
		CVSSScore:   8.1,
		Description: "Controlled user B received the same owner-A object representation as user A.",
		Evidence:    []pipeline.Evidence{owner.ref, actor.ref},
		AffectedComponents: []string{lab.URL + "/objects/42"},
		Remediation: "Enforce object ownership server-side on every object lookup.",
		CWE:         "CWE-639",
		Reproduce: &pipeline.Reproduction{
			HTTPRequest:      "GET /objects/42 HTTP/1.1\nHost: " + labURL.Host,
			ExpectedIndicator: "\"owner_id\":\"user-a\"",
			Tools:             []string{"identity-diff", "workflow"},
		},
	}
	fp := bugbounty.FingerprintReportFinding("acceptance-lab", finding)
	prior := bugbounty.Submission{
		ID:          "prior-acceptance-report",
		Title:       finding.Title,
		Fingerprint: &fp,
	}
	pkg := bugbounty.PrepareVerifiedSubmission("acceptance-lab", finding, []bugbounty.Submission{prior}, store)
	if pkg.State != bugbounty.StateDuplicateReview {
		t.Fatalf("submission state = %s, want duplicate-review", pkg.State)
	}
	if pkg.CanSubmit() {
		t.Fatal("submission must not be sendable before duplicate review and human approval")
	}
	pkg.MarkDuplicateReviewed()
	if pkg.State != bugbounty.StateSubmissionReady {
		t.Fatalf("submission state after duplicate review = %s, want submission-ready", pkg.State)
	}
	if pkg.CanSubmit() {
		t.Fatal("submission must still require explicit human approval")
	}
	if err := pkg.ApproveVerified("acceptance-operator", store); err != nil {
		t.Fatal(err)
	}
	if !pkg.CanSubmit() || pkg.State != bugbounty.StateApproved {
		t.Fatalf("approved package = %+v", pkg)
	}

	if targetHits != 2 {
		t.Fatalf("lab target hits = %d, want exactly 2 authorized observations", targetHits)
	}

	blockedClient := &http.Client{Transport: policygateway.NewHTTPTransport(gateway, http.DefaultTransport, nil)}
	blockedReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, lab.URL+"/admin", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	blockedResp, err := blockedClient.Do(blockedReq)
	if blockedResp != nil {
		_ = blockedResp.Body.Close()
	}
	if !errors.Is(err, policygateway.ErrDenied) {
		t.Fatalf("disallowed path err = %v, want policy denial", err)
	}
	if targetHits != 2 {
		t.Fatalf("disallowed request reached target; hits = %d", targetHits)
	}

	gateway.UpdateScope(scope.ScopeDefinition{AllowedCIDRs: []string{"192.0.2.0/24"}})
	scopeReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, lab.URL+"/objects/42", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	scopeResp, err := blockedClient.Do(scopeReq)
	if scopeResp != nil {
		_ = scopeResp.Body.Close()
	}
	if !errors.Is(err, policygateway.ErrDenied) {
		t.Fatalf("live scope removal err = %v, want policy denial", err)
	}
	if targetHits != 2 {
		t.Fatalf("request after live scope removal reached target; hits = %d", targetHits)
	}
}

func TestRecoveryCheckpointSurvivesProcessReopen(t *testing.T) {
	t.Parallel()

	root := filepath.Join(t.TempDir(), "recovery")
	store, err := recovery.NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	campaignID := uuid.New()
	cp, err := recovery.NewCheckpoint(recovery.Checkpoint{
		CampaignID:         campaignID,
		Phase:              "executing",
		PolicyVersion:      "acceptance-policy-v1",
		CompletedActionIDs: []string{"identity:object:42:user-a"},
		SkippedActionIDs:   []string{"blocked-admin"},
		CleanupActionIDs:   []uuid.UUID{uuid.New()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(cp); err != nil {
		t.Fatal(err)
	}

	reopened, err := recovery.NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.Load(campaignID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.VerifyIntegrity() || got.Phase != cp.Phase || got.PolicyVersion != cp.PolicyVersion {
		t.Fatalf("reopened checkpoint mismatch: %+v", got)
	}
	if len(got.CompletedActionIDs) != 1 || len(got.SkippedActionIDs) != 1 || len(got.CleanupActionIDs) != 1 {
		t.Fatalf("reopened checkpoint lost state: %+v", got)
	}
}
