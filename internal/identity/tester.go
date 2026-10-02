package identity

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/evidence"
	"github.com/google/uuid"
)

const maxObservationBody = 1 << 20 // 1 MiB bounded comparison input

type RequestSpec struct {
	ActionID string
	Method  string
	URL     string
	Headers http.Header
	Body    []byte
	Object  ObjectRef
}

type DifferentialTester struct {
	Clients    *ClientFactory
	Ownership  *OwnershipMap
	CampaignID uuid.UUID
	Evidence   evidence.Store
}

func (t *DifferentialTester) TestObjectAccess(ctx context.Context, ownerID, actorID ID, spec RequestSpec) (DifferentialResult, error) {
	if t == nil || t.Clients == nil {
		return DifferentialResult{}, fmt.Errorf("differential tester is not configured")
	}
	method := spec.Method
	if method == "" {
		method = http.MethodGet
	}
	if method != http.MethodGet && method != http.MethodHead {
		return DifferentialResult{}, fmt.Errorf("differential object-access test is read-only; method %s requires a later stateful approval flow", method)
	}

	ownerObs, ownerRef, err := t.observe(ctx, ownerID, method, spec)
	if err != nil {
		return DifferentialResult{}, fmt.Errorf("owner observation: %w", err)
	}
	actorObs, actorRef, err := t.observe(ctx, actorID, method, spec)
	if err != nil {
		return DifferentialResult{}, fmt.Errorf("actor observation: %w", err)
	}
	result := CompareObjectAccess(ownerObs, actorObs, t.Ownership)
	if ownerRef != "" {
		result.EvidenceRefs = append(result.EvidenceRefs, ownerRef)
	}
	if actorRef != "" {
		result.EvidenceRefs = append(result.EvidenceRefs, actorRef)
	}
	return result, nil
}

func (t *DifferentialTester) observe(ctx context.Context, id ID, method string, spec RequestSpec) (Observation, string, error) {
	actionID := spec.ActionID
	if actionID == "" {
		actionID = "identity:" + spec.Object.Key() + ":" + string(id)
	}
	reqCtx := withRequestTrace(ctx, t.CampaignID, actionID)
	client, ident, err := t.Clients.ClientFor(reqCtx, id)
	if err != nil {
		return Observation{}, "", err
	}
	req, err := http.NewRequestWithContext(reqCtx, method, spec.URL, bytes.NewReader(spec.Body))
	if err != nil {
		return Observation{}, "", err
	}
	for k, values := range spec.Headers {
		for _, v := range values {
			req.Header.Add(k, v)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return Observation{}, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxObservationBody+1))
	if err != nil {
		return Observation{}, "", err
	}
	if len(body) > maxObservationBody {
		return Observation{}, "", fmt.Errorf("response exceeds %d-byte comparison limit", maxObservationBody)
	}
	decision, err := decisionFromIdentityResponse(resp)
	if err != nil {
		return Observation{}, "", err
	}
	ref, err := recordIdentityObservation(t.Evidence, t.CampaignID, ident, spec.Object, method, spec.URL, body, resp.StatusCode, decision)
	if err != nil {
		return Observation{}, "", err
	}
	return Snapshot(id, spec.Object, resp.StatusCode, resp.Header, body), ref, nil
}
