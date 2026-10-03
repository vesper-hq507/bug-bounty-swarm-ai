package mobile

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/evidence"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/guidance"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/monitor"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope/programterms"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/workflow"
	"github.com/google/uuid"
)

type AnalyzeOptions struct {
	Scope         scope.ScopeDefinition
	Constraints   programterms.Constraints
	WorkflowRules []workflow.Rule
	CampaignID    uuid.UUID
	PolicyVersion string
	EvidenceStore evidence.Store
}

type SkippedTransaction struct {
	Sequence int    `json:"sequence"`
	Method   string `json:"method"`
	URL      string `json:"url"`
	Reason   string `json:"reason"`
}

type Analysis struct {
	CaptureID         string                    `json:"capture_id"`
	Platform          Platform                  `json:"platform"`
	AppID             string                    `json:"app_id"`
	IdentityAlias     string                    `json:"identity_alias"`
	ActorRole         string                    `json:"actor_role,omitempty"`
	SessionRefPresent bool                      `json:"session_ref_present"`
	TotalTransactions int                       `json:"total_transactions"`
	InScopeCount      int                       `json:"in_scope_count"`
	Skipped           []SkippedTransaction      `json:"skipped,omitempty"`
	Events            []workflow.Event          `json:"events,omitempty"`
	Workflow          workflow.Analysis         `json:"workflow"`
	Snapshot          monitor.Snapshot          `json:"snapshot"`
	Guidance          []guidance.Recommendation `json:"guidance,omitempty"`
	EvidenceRefs      []pipeline.Evidence       `json:"evidence_refs,omitempty"`
}

func Analyze(ctx context.Context, capture Capture, opts AnalyzeOptions) (Analysis, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(capture.Transactions) == 0 {
		return Analysis{}, fmt.Errorf("mobile capture contains no transactions")
	}
	if opts.EvidenceStore != nil {
		if opts.CampaignID == uuid.Nil {
			return Analysis{}, fmt.Errorf("campaign id is required when mobile evidence persistence is enabled")
		}
		if strings.TrimSpace(opts.PolicyVersion) == "" {
			return Analysis{}, fmt.Errorf("policy version is required when mobile evidence persistence is enabled")
		}
	}

	result := Analysis{
		CaptureID: capture.ID,
		Platform: capture.Platform,
		AppID: capture.AppID,
		IdentityAlias: capture.IdentityAlias,
		ActorRole: capture.ActorRole,
		SessionRefPresent: capture.SessionRef != "",
		TotalTransactions: len(capture.Transactions),
		Snapshot: monitor.Snapshot{
			Target: "mobile:" + string(capture.Platform) + ":" + capture.AppID,
			CapturedAt: time.Now().UTC(),
			JavaScript: map[string]string{},
			APISchemas: map[string]string{},
			Technologies: map[string]string{"mobile-platform": string(capture.Platform)},
		},
	}
	collector := workflow.NewCollector()
	endpointSeen := map[string]struct{}{}

	for i := range capture.Transactions {
		if err := ctx.Err(); err != nil {
			return Analysis{}, err
		}
		tx := &capture.Transactions[i]
		if err := scope.Validate(tx.URL, opts.Scope); err != nil {
			result.Skipped = append(result.Skipped, SkippedTransaction{
				Sequence: tx.Sequence, Method: tx.Method, URL: tx.URL,
				Reason: "out of program scope",
			})
			continue
		}
		if deniedPath(tx.URL, opts.Constraints.DisallowedPaths) {
			result.Skipped = append(result.Skipped, SkippedTransaction{
				Sequence: tx.Sequence, Method: tx.Method, URL: tx.URL,
				Reason: "program terms disallow this path",
			})
			continue
		}

		var refs []string
		if opts.EvidenceStore != nil {
			ref, err := persistTransaction(capture, *tx, opts)
			if err != nil {
				return Analysis{}, fmt.Errorf("persist mobile transaction %d: %w", tx.Sequence, err)
			}
			result.EvidenceRefs = append(result.EvidenceRefs, ref)
			refs = []string{ref.Content}
		}

		event := collector.Observe(workflow.Observation{
			Method: tx.Method,
			URL: tx.URL,
			ActorID: capture.IdentityAlias,
			ActorRole: capture.ActorRole,
			StatusCode: tx.StatusCode,
			RequestBody: tx.RequestBody,
			ResponseBody: tx.ResponseBody,
			EvidenceRefs: refs,
		})
		result.Events = append(result.Events, event)
		result.InScopeCount++

		key := strings.ToUpper(tx.Method) + " " + tx.URL
		if _, exists := endpointSeen[key]; !exists {
			endpointSeen[key] = struct{}{}
			result.Snapshot.Endpoints = append(result.Snapshot.Endpoints, monitor.Endpoint{
				Method: tx.Method, URL: tx.URL, StatusCode: tx.StatusCode,
			})
		}
	}

	sort.Slice(result.Snapshot.Endpoints, func(i, j int) bool {
		left := strings.ToUpper(result.Snapshot.Endpoints[i].Method) + " " + result.Snapshot.Endpoints[i].URL
		right := strings.ToUpper(result.Snapshot.Endpoints[j].Method) + " " + result.Snapshot.Endpoints[j].URL
		return left < right
	})
	result.Workflow = workflow.Analyze(result.Events, opts.WorkflowRules, opts.Constraints.MaxRequestsPerSecond)
	result.Guidance = guidance.FromWorkflow(result.Workflow, opts.Constraints)
	return result, nil
}

func persistTransaction(capture Capture, tx Transaction, opts AnalyzeOptions) (pipeline.Evidence, error) {
	actionID := fmt.Sprintf("mobile-import:%s:%d", capture.ID, tx.Sequence)
	requestExcerpt := strings.Join([]string{
		tx.Method + " " + tx.URL,
		formatHeaders(tx.RequestHeaders),
		string(tx.RequestBody),
	}, "\n")
	responseExcerpt := strings.Join([]string{
		fmt.Sprintf("HTTP %d", tx.StatusCode),
		formatHeaders(tx.ResponseHeaders),
		string(tx.ResponseBody),
	}, "\n")
	return evidence.RecordObservation(opts.EvidenceStore, evidence.ObservationInput{
		CampaignID: opts.CampaignID,
		ActionID: actionID,
		DecisionID: "offline-mobile-scope-validation:" + capture.ID,
		PolicyVersion: opts.PolicyVersion,
		ActorID: capture.IdentityAlias,
		IdentityAlias: capture.IdentityAlias,
		Tool: "mobile-capture-import",
		Request: []byte(tx.Method + " " + tx.URL),
		Response: tx.ResponseBody,
		RequestExcerpt: requestExcerpt,
		ResponseExcerpt: responseExcerpt,
		Verification: evidence.VerificationUnverified,
	})
}

func deniedPath(rawURL string, denied []string) bool {
	if len(denied) == 0 {
		return false
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return true
	}
	for _, item := range denied {
		prefix := strings.TrimSuffix(strings.TrimSpace(item), "*")
		if prefix != "" && strings.HasPrefix(u.Path, prefix) {
			return true
		}
	}
	return false
}

func formatHeaders(headers map[string]string) string {
	if len(headers) == 0 {
		return ""
	}
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	lines := make([]string, 0, len(keys))
	for _, key := range keys {
		lines = append(lines, key+": "+headers[key])
	}
	return strings.Join(lines, "\n")
}
