package identity

import (
	"context"
	"fmt"
	"net/http"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/evidence"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/policygateway"
	"github.com/google/uuid"
)

type requestTrace struct {
	CampaignID uuid.UUID
	ActionID   string
}

type requestTraceKey struct{}

func withRequestTrace(ctx context.Context, campaignID uuid.UUID, actionID string) context.Context {
	return context.WithValue(ctx, requestTraceKey{}, requestTrace{CampaignID: campaignID, ActionID: actionID})
}

func requestTraceFromContext(ctx context.Context) requestTrace {
	if ctx == nil {
		return requestTrace{}
	}
	trace, _ := ctx.Value(requestTraceKey{}).(requestTrace)
	return trace
}

func recordIdentityObservation(
	store evidence.Store,
	campaignID uuid.UUID,
	ident Identity,
	obj ObjectRef,
	method, rawURL string,
	body []byte,
	status int,
	decision policygateway.Decision,
) (string, error) {
	if store == nil {
		return "", nil
	}
	if campaignID == uuid.Nil {
		return "", fmt.Errorf("campaign id is required for identity evidence")
	}
	if decision.ID == "" || decision.PolicyVersion == "" {
		return "", fmt.Errorf("missing policy decision provenance for identity %q", ident.ID)
	}
	actionID := decision.ActionID
	if actionID == "" {
		actionID = "identity:" + obj.Key() + ":" + string(ident.ID)
	}
	responseExcerpt := fmt.Sprintf("HTTP %d\n%s", status, string(body))
	ref, err := evidence.RecordObservation(store, evidence.ObservationInput{
		CampaignID:      campaignID,
		ActionID:        actionID,
		DecisionID:      decision.ID,
		PolicyVersion:   decision.PolicyVersion,
		ActorID:         string(ident.ID),
		IdentityAlias:   ident.Alias,
		Tool:            "identity-diff",
		Request:         []byte(method + " " + rawURL),
		Response:        body,
		RequestExcerpt:  method + " " + rawURL,
		ResponseExcerpt: responseExcerpt,
		Verification:    evidence.VerificationUnverified,
	})
	if err != nil {
		return "", err
	}
	return ref.Content, nil
}

func decisionFromIdentityResponse(resp *http.Response) (policygateway.Decision, error) {
	decision, ok := policygateway.DecisionFromResponse(resp)
	if !ok {
		return policygateway.Decision{}, fmt.Errorf("policy decision missing from identity response")
	}
	return decision, nil
}
