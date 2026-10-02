package identity

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
)

const maxObservationBody = 1 << 20 // 1 MiB bounded comparison input

type RequestSpec struct {
	Method  string
	URL     string
	Headers http.Header
	Body    []byte
	Object  ObjectRef
}

type DifferentialTester struct {
	Clients   *ClientFactory
	Ownership *OwnershipMap
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

	ownerObs, err := t.observe(ctx, ownerID, method, spec)
	if err != nil {
		return DifferentialResult{}, fmt.Errorf("owner observation: %w", err)
	}
	actorObs, err := t.observe(ctx, actorID, method, spec)
	if err != nil {
		return DifferentialResult{}, fmt.Errorf("actor observation: %w", err)
	}
	return CompareObjectAccess(ownerObs, actorObs, t.Ownership), nil
}

func (t *DifferentialTester) observe(ctx context.Context, id ID, method string, spec RequestSpec) (Observation, error) {
	client, _, err := t.Clients.ClientFor(ctx, id)
	if err != nil {
		return Observation{}, err
	}
	req, err := http.NewRequestWithContext(ctx, method, spec.URL, bytes.NewReader(spec.Body))
	if err != nil {
		return Observation{}, err
	}
	for k, values := range spec.Headers {
		for _, v := range values {
			req.Header.Add(k, v)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return Observation{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxObservationBody+1))
	if err != nil {
		return Observation{}, err
	}
	if len(body) > maxObservationBody {
		return Observation{}, fmt.Errorf("response exceeds %d-byte comparison limit", maxObservationBody)
	}
	return Snapshot(id, spec.Object, resp.StatusCode, resp.Header, body), nil
}
