package benchmark

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/approval"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/bugbounty"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/clientcode"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/evidence"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/guidance"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/identity"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/monitor"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/policygateway"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/recovery"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope/programterms"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/swarm"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/swarm/blackboard"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/swarm/provenance"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/workflow"
	"github.com/google/uuid"
)

// RunControlled executes a deterministic, offline benchmark against the real
// analysis/control modules. It never contacts an external target.
func RunControlled(ctx context.Context, stateParent string) (Report, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	root, err := benchmarkStateRoot(stateParent)
	if err != nil {
		return Report{}, err
	}
	defer func() { _ = os.RemoveAll(root) }()

	cases := make([]CaseResult, 0, 16)
	run := func(fn func(context.Context, string) CaseResult) {
		if err := ctx.Err(); err != nil {
			cases = append(cases, CaseResult{ID: "suite-context", Error: err.Error()})
			return
		}
		start := time.Now()
		result := fn(ctx, root)
		result.DurationMillis = time.Since(start).Milliseconds()
		cases = append(cases, result)
	}

	run(identityPositive)
	run(identityNegative)
	run(workflowPositive)
	run(workflowNegative)
	run(monitorPositive)
	run(monitorNegative)
	run(clientCodePositive)
	run(clientCodeNegative)
	run(dedupPositive)
	run(dedupNegative)
	run(policyBoundary)
	run(approvalBoundary)
	run(evidenceIntegrity)
	run(recoveryPersistence)
	run(schedulerQuiescence)
	run(schedulerCancellation)

	return Evaluate(cases, DefaultThresholds()), nil
}

func benchmarkStateRoot(parent string) (string, error) {
	if strings.TrimSpace(parent) == "" {
		return os.MkdirTemp("", "pentestswarm-benchmark-*")
	}
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", err
	}
	return os.MkdirTemp(parent, "controlled-*")
}

func identityPositive(_ context.Context, _ string) CaseResult {
	obj := identity.ObjectRef{Type: "invoice", ID: "42"}
	owners := identity.NewOwnershipMap()
	if err := owners.SetOwner(obj, identity.ID("user-a")); err != nil {
		return caseError("identity-bola-positive", CategoryAuthorization, true, err)
	}
	h := http.Header{"Content-Type": []string{"application/json"}}
	body := []byte("{\"id\":\"42\",\"owner_id\":\"user-a\",\"token\":\"secret-a\"}")
	owner := identity.Snapshot(identity.ID("user-a"), obj, http.StatusOK, h, body)
	actor := identity.Snapshot(identity.ID("user-b"), obj, http.StatusOK, h, body)
	diff := identity.CompareObjectAccess(owner, actor, owners)
	return CaseResult{
		ID: "identity-bola-positive", Category: CategoryAuthorization,
		DetectionCheck: true, ExpectedPositive: true,
		ObservedPositive: diff.Kind == identity.DiffUnexpectedAccess,
		Detail: string(diff.Kind),
	}
}

func identityNegative(_ context.Context, _ string) CaseResult {
	obj := identity.ObjectRef{Type: "invoice", ID: "42"}
	owners := identity.NewOwnershipMap()
	if err := owners.SetOwner(obj, identity.ID("user-a")); err != nil {
		return caseError("identity-owner-boundary-negative", CategoryAuthorization, false, err)
	}
	h := http.Header{"Content-Type": []string{"application/json"}}
	owner := identity.Snapshot(identity.ID("user-a"), obj, http.StatusOK, h, []byte("{\"id\":\"42\",\"owner_id\":\"user-a\"}"))
	actor := identity.Snapshot(identity.ID("user-b"), obj, http.StatusForbidden, h, []byte("{\"error\":\"forbidden\"}"))
	diff := identity.CompareObjectAccess(owner, actor, owners)
	return CaseResult{
		ID: "identity-owner-boundary-negative", Category: CategoryAuthorization,
		DetectionCheck: true, ExpectedPositive: false,
		ObservedPositive: diff.Kind == identity.DiffUnexpectedAccess,
		Detail: string(diff.Kind),
	}
}

func workflowPositive(_ context.Context, _ string) CaseResult {
	events := []workflow.Event{{
		WorkflowID: "order:1", Sequence: 1, StateBefore: "paid", StateAfter: "refunded",
		Action: "refund", Method: http.MethodPost, URL: "https://example.test/orders/1/refund",
		ActorID: "user-a", ActorRole: "user", StatusCode: http.StatusOK,
	}}
	rules := []workflow.Rule{{
		ID: "refund-precondition", Action: "refund", RequiredPrior: []string{"capture-payment"},
	}}
	a := workflow.Analyze(events, rules, 5)
	detected := false
	for i := range a.Hypotheses {
		if a.Hypotheses[i].Kind == workflow.HypothesisSequenceBypass {
			detected = true
		}
	}
	return CaseResult{
		ID: "workflow-sequence-positive", Category: CategoryWorkflow,
		DetectionCheck: true, ExpectedPositive: true, ObservedPositive: detected,
	}
}

func workflowNegative(_ context.Context, _ string) CaseResult {
	events := []workflow.Event{
		{WorkflowID: "order:1", Sequence: 1, StateBefore: "new", StateAfter: "paid", Action: "capture-payment", Method: http.MethodPost, StatusCode: http.StatusOK},
		{WorkflowID: "order:1", Sequence: 2, StateBefore: "paid", StateAfter: "refunded", Action: "refund", Method: http.MethodPost, StatusCode: http.StatusOK},
	}
	rules := []workflow.Rule{{
		ID: "refund-precondition", Action: "refund", RequiredPrior: []string{"capture-payment"},
	}}
	a := workflow.Analyze(events, rules, 5)
	detected := false
	for i := range a.Hypotheses {
		if a.Hypotheses[i].Kind == workflow.HypothesisSequenceBypass {
			detected = true
		}
	}
	return CaseResult{
		ID: "workflow-sequence-negative", Category: CategoryWorkflow,
		DetectionCheck: true, ExpectedPositive: false, ObservedPositive: detected,
	}
}

func monitorPositive(_ context.Context, _ string) CaseResult {
	before := monitor.Snapshot{Target: "https://example.test", Endpoints: []monitor.Endpoint{{Method: http.MethodGet, URL: "https://example.test/health"}}}
	after := monitor.Snapshot{Target: "https://example.test", Endpoints: []monitor.Endpoint{
		{Method: http.MethodGet, URL: "https://example.test/health"},
		{Method: http.MethodGet, URL: "https://example.test/api/invoices/42", Parameters: []string{"owner_id"}},
	}}
	diff := monitor.Diff(before, after)
	recs := guidance.FromMonitor(diff, programterms.Constraints{})
	return CaseResult{
		ID: "monitor-new-endpoint-positive", Category: CategoryMonitor,
		DetectionCheck: true, ExpectedPositive: true,
		ObservedPositive: len(diff.Changes) > 0 && len(recs) > 0,
	}
}

func monitorNegative(_ context.Context, _ string) CaseResult {
	snapshot := monitor.Snapshot{Target: "https://example.test", Endpoints: []monitor.Endpoint{{Method: http.MethodGet, URL: "https://example.test/health"}}}
	diff := monitor.Diff(snapshot, snapshot)
	recs := guidance.FromMonitor(diff, programterms.Constraints{})
	return CaseResult{
		ID: "monitor-no-change-negative", Category: CategoryMonitor,
		DetectionCheck: true, ExpectedPositive: false,
		ObservedPositive: len(diff.Changes) > 0 || len(recs) > 0,
	}
}

func clientCodePositive(_ context.Context, _ string) CaseResult {
	script := []byte("fetch(\"/api/invoices/42\"); new WebSocket(\"wss://example.test/ws\"); searchParams.get(\"owner_id\"); featureFlag(\"billing-v2\"); if (user.role === \"admin\") transitionTo(\"approved\");")
	a, err := clientcode.Analyze("https://example.test/assets/app.js", script, nil)
	if err != nil {
		return caseError("client-code-signals-positive", CategoryClientCode, true, err)
	}
	detected := len(a.Summary.Routes) > 0 &&
		len(a.Summary.RealtimeEndpoints) > 0 &&
		len(a.Summary.Parameters) > 0 &&
		len(a.Summary.FeatureFlags) > 0 &&
		len(a.Summary.RoleHints) > 0 &&
		len(a.Summary.WorkflowStates) > 0
	return CaseResult{
		ID: "client-code-signals-positive", Category: CategoryClientCode,
		DetectionCheck: true, ExpectedPositive: true, ObservedPositive: detected,
		Detail: "bounded static signal extraction",
	}
}

func clientCodeNegative(_ context.Context, _ string) CaseResult {
	a, err := clientcode.Analyze("https://example.test/assets/app.js", []byte("console.log(\"hello\"); const version = \"1.0.0\";"), nil)
	if err != nil {
		return caseError("client-code-benign-negative", CategoryClientCode, false, err)
	}
	return CaseResult{
		ID: "client-code-benign-negative", Category: CategoryClientCode,
		DetectionCheck: true, ExpectedPositive: false,
		ObservedPositive: len(a.Signals) > 0,
	}
}

func dedupPositive(_ context.Context, _ string) CaseResult {
	historical := bugbounty.FingerprintHistoricalReport(bugbounty.HistoricalReportFingerprintInput{
		Program: "acme",
		Title: "Object authorization weakness",
		VulnerabilityInformation: "GET https://api.example.test/api/invoices/123?invoice_id=123 HTTP/1.1",
		WeaknessName: "Authorization Bypass Through User-Controlled Key",
		WeaknessExternalID: "CWE-639",
		AssetIdentifier: "https://api.example.test",
	})
	candidate := bugbounty.FindingFingerprint{
		Program: "acme", Asset: "api.example.test", Endpoint: "/api/invoices/123",
		Method: http.MethodGet, CWE: "CWE-639", Parameter: "invoice_id",
	}
	match := bugbounty.CompareFingerprints(candidate, historical)
	return CaseResult{
		ID: "historical-dedup-positive", Category: CategoryDedup,
		DetectionCheck: true, ExpectedPositive: true, ObservedPositive: match.Score >= 0.75,
		Detail: strings.Join(match.Reasons, ", "),
	}
}

func dedupNegative(_ context.Context, _ string) CaseResult {
	historical := bugbounty.FingerprintHistoricalReport(bugbounty.HistoricalReportFingerprintInput{
		Program: "acme",
		Title: "Reflected XSS",
		VulnerabilityInformation: "GET https://web.example.test/search?q=test HTTP/1.1",
		WeaknessExternalID: "CWE-79",
		AssetIdentifier: "https://web.example.test",
	})
	candidate := bugbounty.FindingFingerprint{
		Program: "acme", Asset: "api.example.test", Endpoint: "/api/invoices/123",
		Method: http.MethodGet, CWE: "CWE-639", Parameter: "invoice_id",
	}
	match := bugbounty.CompareFingerprints(candidate, historical)
	return CaseResult{
		ID: "historical-dedup-negative", Category: CategoryDedup,
		DetectionCheck: true, ExpectedPositive: false, ObservedPositive: match.Score >= 0.75,
	}
}

func policyBoundary(ctx context.Context, _ string) CaseResult {
	g := policygateway.New(policygateway.Policy{
		Scope: scope.ScopeDefinition{AllowedDomains: []string{"example.test"}},
		DisallowedPaths: []string{"/admin"}, Version: "benchmark-policy-v1",
	})
	_, deniedErr := g.Decide(ctx, policygateway.Action{
		ActionID: "blocked-admin", CampaignID: uuid.NewString(), ActorID: "benchmark",
		Kind: policygateway.ActionHTTP, Method: http.MethodGet,
		URL: "https://example.test/admin/users", Path: "/admin/users",
	})
	decision, allowedErr := g.Decide(ctx, policygateway.Action{
		ActionID: "allowed-read", CampaignID: uuid.NewString(), ActorID: "benchmark",
		Kind: policygateway.ActionHTTP, Method: http.MethodGet,
		URL: "https://example.test/api/me", Path: "/api/me",
	})
	return CaseResult{
		ID: "policy-fail-closed-boundary", Category: CategoryPolicy,
		PolicyCheck: true,
		PolicyCompliant: errors.Is(deniedErr, policygateway.ErrDenied) &&
			allowedErr == nil && decision.ID != "" && decision.PolicyVersion == "benchmark-policy-v1",
	}
}

func approvalBoundary(ctx context.Context, _ string) CaseResult {
	b := approval.NewStaticBroker(nil, nil, false)
	read, readErr := b.Authorize(ctx, approval.Request{Capability: approval.CapabilityObserve})
	_, mutationErr := b.Authorize(ctx, approval.Request{
		Capability: approval.CapabilityStateChange, Reason: "benchmark mutation must require approval",
	})
	return CaseResult{
		ID: "approval-sensitive-action-boundary", Category: CategoryPolicy,
		PolicyCheck: true,
		PolicyCompliant: readErr == nil && read.Granted &&
			errors.Is(mutationErr, approval.ErrApprovalRequired),
	}
}

func evidenceIntegrity(_ context.Context, _ string) CaseResult {
	rec, err := evidence.New(evidence.Input{
		CampaignID: uuid.New(), ActionID: "benchmark-action", DecisionID: "benchmark-decision",
		PolicyVersion: "benchmark-policy-v1", ActorID: "benchmark",
		RequestExcerpt: "Authorization: Bearer request-secret",
		ResponseExcerpt: "{\"token\":\"response-secret\",\"ok\":true}",
		Verification: evidence.VerificationVerified,
	})
	if err != nil {
		return caseError("evidence-redaction-integrity", CategoryEvidence, false, err)
	}
	store := evidence.NewMemoryStore()
	addErr := store.Add(rec)
	redacted := !strings.Contains(rec.RequestExcerpt, "request-secret") &&
		!strings.Contains(rec.ResponseExcerpt, "response-secret")
	tampered := rec
	tampered.ActorID = "tampered"
	return CaseResult{
		ID: "evidence-redaction-integrity", Category: CategoryEvidence,
		EvidenceCheck: true,
		EvidenceValid: addErr == nil && redacted && rec.VerifyIntegrity() && !tampered.VerifyIntegrity(),
	}
}

func recoveryPersistence(_ context.Context, root string) CaseResult {
	dir := filepath.Join(root, "recovery")
	store, err := recovery.NewFileStore(dir)
	if err != nil {
		return caseError("recovery-process-reopen", CategoryRecovery, false, err)
	}
	campaignID := uuid.New()
	cp, err := recovery.NewCheckpoint(recovery.Checkpoint{
		CampaignID: campaignID, Phase: "executing", PolicyVersion: "benchmark-policy-v1",
		CompletedActionIDs: []string{"a1"}, SkippedActionIDs: []string{"a2"},
		CleanupActionIDs: []uuid.UUID{uuid.New()},
	})
	if err != nil {
		return caseError("recovery-process-reopen", CategoryRecovery, false, err)
	}
	if err := store.Save(cp); err != nil {
		return caseError("recovery-process-reopen", CategoryRecovery, false, err)
	}
	reopened, err := recovery.NewFileStore(dir)
	if err != nil {
		return caseError("recovery-process-reopen", CategoryRecovery, false, err)
	}
	got, err := reopened.Load(campaignID)
	if err != nil {
		return caseError("recovery-process-reopen", CategoryRecovery, false, err)
	}
	return CaseResult{
		ID: "recovery-process-reopen", Category: CategoryRecovery,
		RecoveryCheck: true,
		RecoveryValid: got.VerifyIntegrity() && got.IntegrityHash == cp.IntegrityHash &&
			len(got.CompletedActionIDs) == 1 && len(got.SkippedActionIDs) == 1 &&
			len(got.CleanupActionIDs) == 1,
	}
}

func schedulerQuiescence(ctx context.Context, root string) CaseResult {
	keyring, err := provenance.NewFileKeyring(filepath.Join(root, "scheduler-provenance"))
	if err != nil {
		return caseError("scheduler-quiescence-stop", CategoryTermination, false, err)
	}
	secure, err := blackboard.NewSecureBoard(blackboard.NewMemoryBoard(nil), keyring)
	if err != nil {
		return caseError("scheduler-quiescence-stop", CategoryTermination, false, err)
	}
	campaignID := uuid.New()
	var handled atomic.Int32
	scheduler := swarm.NewScheduler(
		secure, campaignID,
		swarm.WithIdleTimeout(75*time.Millisecond),
		swarm.WithBudgetCheckInterval(25*time.Millisecond),
	)
	scheduler.Register(swarm.NamedPredicate{
		AgentName: "benchmark-agent",
		Pred: blackboard.Predicate{Types: []blackboard.FindingType{blackboard.TypeTargetRegistered}},
		Fn: func(context.Context, blackboard.Finding, blackboard.Board) error {
			handled.Add(1)
			return nil
		},
	})
	if _, err := secure.Writer("benchmark-seed").Write(ctx, blackboard.Finding{
		CampaignID: campaignID, Type: blackboard.TypeTargetRegistered,
		Target: "benchmark.local", PheromoneBase: 1, HalfLifeSec: 60,
	}); err != nil {
		return caseError("scheduler-quiescence-stop", CategoryTermination, false, err)
	}
	runCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	err = scheduler.Run(runCtx)
	return CaseResult{
		ID: "scheduler-quiescence-stop", Category: CategoryTermination,
		TerminationCheck: true, TerminatedSafely: err == nil && handled.Load() == 1,
	}
}

func schedulerCancellation(ctx context.Context, root string) CaseResult {
	keyring, err := provenance.NewFileKeyring(filepath.Join(root, "cancel-provenance"))
	if err != nil {
		return caseError("scheduler-context-cancel", CategoryTermination, false, err)
	}
	secure, err := blackboard.NewSecureBoard(blackboard.NewMemoryBoard(nil), keyring)
	if err != nil {
		return caseError("scheduler-context-cancel", CategoryTermination, false, err)
	}
	scheduler := swarm.NewScheduler(secure, uuid.New(), swarm.WithIdleTimeout(0))
	scheduler.Register(swarm.NamedPredicate{
		AgentName: "idle-agent",
		Pred: blackboard.Predicate{Types: []blackboard.FindingType{blackboard.TypeTargetRegistered}},
	})
	runCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	err = scheduler.Run(runCtx)
	return CaseResult{
		ID: "scheduler-context-cancel", Category: CategoryTermination,
		TerminationCheck: true, TerminatedSafely: errors.Is(err, context.DeadlineExceeded),
	}
}

func caseError(id string, category Category, expectedPositive bool, err error) CaseResult {
	return CaseResult{
		ID: id, Category: category, DetectionCheck: category == CategoryAuthorization ||
			category == CategoryWorkflow || category == CategoryMonitor ||
			category == CategoryClientCode || category == CategoryDedup,
		ExpectedPositive: expectedPositive, Error: err.Error(),
	}
}
