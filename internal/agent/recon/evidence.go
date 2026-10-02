package recon

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/evidence"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/policygateway"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/tools"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/workflow"
	"github.com/google/uuid"
)

type observationRecorder struct {
	store         evidence.Store
	campaignID    uuid.UUID
	identityID    string
	identityAlias string
	identityRole  string
	workflow      *workflow.Collector

	mu   sync.Mutex
	err  error
	refs []pipeline.Evidence
}

func newObservationRecorder(store evidence.Store, campaignID uuid.UUID) *observationRecorder {
	if store == nil {
		return nil
	}
	return &observationRecorder{store: store, campaignID: campaignID}
}

func (r *observationRecorder) setIdentity(id, alias string, role ...string) {
	if r == nil {
		return
	}
	r.identityID = strings.TrimSpace(id)
	r.identityAlias = strings.TrimSpace(alias)
	r.identityRole = ""
	if len(role) > 0 {
		r.identityRole = strings.TrimSpace(role[0])
	}
}

func (r *observationRecorder) setWorkflowCollector(c *workflow.Collector) {
	if r == nil {
		return
	}
	r.workflow = c
}

func (r *observationRecorder) identityActor(fallback string) (actorID, identityAlias string) {
	if r == nil || r.identityID == "" {
		return fallback, ""
	}
	return r.identityID, r.identityAlias
}

func (r *observationRecorder) setError(err error) {
	if r == nil || err == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err == nil {
		r.err = err
	}
}

func (r *observationRecorder) Err() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

func (r *observationRecorder) Refs() []pipeline.Evidence {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]pipeline.Evidence, len(r.refs))
	copy(out, r.refs)
	return out
}

func (r *observationRecorder) record(in evidence.ObservationInput) string {
	if r == nil || r.store == nil {
		return ""
	}
	if in.CampaignID == uuid.Nil {
		in.CampaignID = r.campaignID
	}
	ref, err := evidence.RecordObservation(r.store, in)
	if err != nil {
		r.setError(err)
		return ""
	}
	r.mu.Lock()
	r.refs = append(r.refs, ref)
	r.mu.Unlock()
	return ref.Content
}

func (r *observationRecorder) recordToolResult(result *tools.ToolResult, fallbackPolicyVersion string) {
	if r == nil || result == nil {
		return
	}
	actionID := result.ActionID
	if actionID == "" {
		actionID = "recon-tool:" + result.ToolName
	}
	decisionID := result.DecisionID
	if decisionID == "" {
		decisionID = "unavailable"
	}
	policyVersion := result.PolicyVersion
	if policyVersion == "" {
		policyVersion = fallbackPolicyVersion
	}
	actor := result.ActorID
	if actor == "" {
		actor = "tool-coordinator"
	}

	response := result.RawOutput
	if result.Error != nil {
		if response != "" {
			response += "\n"
		}
		response += "error: " + result.Error.Error()
	}

	r.record(evidence.ObservationInput{
		ActionID:        actionID,
		DecisionID:      decisionID,
		PolicyVersion:   policyVersion,
		ActorID:         actor,
		Tool:            result.ToolName,
		Request:         []byte(result.Target),
		Response:        []byte(response),
		RequestExcerpt:  result.Target,
		ResponseExcerpt: response,
		Verification:    evidence.VerificationUnverified,
	})
}

func (r *observationRecorder) recordHTTP(req *http.Request, resp *http.Response, runErr error, actor, tool string) {
	if r == nil || req == nil {
		return
	}
	decision, ok := policygateway.DecisionFromResponse(resp)
	if !ok {
		decision, ok = policygateway.DecisionFromError(runErr)
	}
	if !ok || decision.ID == "" || decision.PolicyVersion == "" {
		r.setError(fmt.Errorf("missing policy decision provenance for %s %s", req.Method, req.URL.String()))
		return
	}
	actionID := decision.ActionID
	if actionID == "" {
		actionID = actor + ":" + strings.ToUpper(req.Method) + ":" + req.URL.String()
	}
	responseExcerpt := ""
	if resp != nil {
		responseExcerpt = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	if runErr != nil {
		if responseExcerpt != "" {
			responseExcerpt += "\n"
		}
		responseExcerpt += "error: " + runErr.Error()
	}
	effectiveActor, alias := r.identityActor(actor)
	ref := r.record(evidence.ObservationInput{
		ActionID:        actionID,
		DecisionID:      decision.ID,
		PolicyVersion:   decision.PolicyVersion,
		ActorID:         effectiveActor,
		IdentityAlias:   alias,
		Tool:            tool,
		Request:         []byte(req.Method + " " + req.URL.String()),
		Response:        []byte(responseExcerpt),
		RequestExcerpt:  req.Method + " " + req.URL.String(),
		ResponseExcerpt: responseExcerpt,
		Verification:    evidence.VerificationUnverified,
	})
	if r.workflow != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		refs := []string(nil)
		if ref != "" {
			refs = []string{ref}
		}
		r.workflow.Observe(workflow.Observation{
			Method: req.Method, URL: req.URL.String(),
			ActorID: effectiveActor, ActorRole: r.identityRole,
			StatusCode: status, EvidenceRefs: refs,
		})
	}
}

func (r *observationRecorder) recordNetwork(method, rawURL string, status int, actionID, decisionID, policyVersion, actor, tool string) {
	if r == nil {
		return
	}
	if actionID == "" || decisionID == "" || policyVersion == "" {
		r.setError(fmt.Errorf("missing policy decision provenance for %s %s", method, rawURL))
		return
	}
	response := fmt.Sprintf("HTTP %d", status)
	effectiveActor, alias := r.identityActor(actor)
	ref := r.record(evidence.ObservationInput{
		ActionID:        actionID,
		DecisionID:      decisionID,
		PolicyVersion:   policyVersion,
		ActorID:         effectiveActor,
		IdentityAlias:   alias,
		Tool:            tool,
		Request:         []byte(method + " " + rawURL),
		Response:        []byte(response),
		RequestExcerpt:  method + " " + rawURL,
		ResponseExcerpt: response,
		Verification:    evidence.VerificationUnverified,
	})
	if r.workflow != nil {
		refs := []string(nil)
		if ref != "" {
			refs = []string{ref}
		}
		r.workflow.Observe(workflow.Observation{
			Method: method, URL: rawURL,
			ActorID: effectiveActor, ActorRole: r.identityRole,
			StatusCode: status, EvidenceRefs: refs,
		})
	}
}

type observationContextKey struct{}

func withObservationRecorder(ctx context.Context, recorder *observationRecorder) context.Context {
	if recorder == nil {
		return ctx
	}
	return context.WithValue(ctx, observationContextKey{}, recorder)
}

func observationRecorderFromContext(ctx context.Context) *observationRecorder {
	if ctx == nil {
		return nil
	}
	recorder, _ := ctx.Value(observationContextKey{}).(*observationRecorder)
	return recorder
}

type observingTransport struct {
	base  http.RoundTripper
	actor string
	tool  string
}

func (t *observingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	resp, err := base.RoundTrip(req)
	if recorder := observationRecorderFromContext(req.Context()); recorder != nil {
		recorder.recordHTTP(req, resp, err, t.actor, t.tool)
	}
	return resp, err
}
