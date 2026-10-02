package policygateway

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

func TestHTTPTransportCarriesDecisionOnResponse(t *testing.T) {
	g := New(Policy{Scope: scope.ScopeDefinition{AllowedDomains: []string{"example.com"}}})
	base := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader("ok")),
			Request: req,
		}, nil
	})
	client := &http.Client{Transport: NewHTTPTransport(g, base, func(r *http.Request) Action {
		return Action{ActionID: "step-1", CampaignID: "campaign-1", ActorID: "actor-1", URL: r.URL.String()}
	})}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com/me", http.NoBody)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	d, ok := DecisionFromResponse(resp)
	if !ok || d.ActionID != "step-1" || d.ID == "" || d.PolicyVersion == "" {
		t.Fatalf("decision context = %+v ok=%v", d, ok)
	}
}
