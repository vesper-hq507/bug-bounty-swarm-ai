package policygateway

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

func testPolicy() Policy {
	return Policy{
		Scope: scope.ScopeDefinition{
			AllowedDomains: []string{"example.com"},
			AllowedCIDRs:   []string{"127.0.0.0/8"},
		},
		RequiredHeaders:      map[string]string{"X-Bug-Bounty": "researcher"},
		DisallowedPaths:      []string{"/logout", "/billing/*"},
		DisallowedTechniques: []string{"destructive-*"},
		RequestsPerSecond:    1000,
		Burst:                1000,
	}
}

func TestGatewayFailsClosedOnEmptyScope(t *testing.T) {
	g := New(Policy{})
	d, err := g.Decide(context.Background(), Action{Kind: ActionHTTP, URL: "https://example.com"})
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("expected ErrDenied, got %v", err)
	}
	if d.Allowed {
		t.Fatal("empty scope must not allow an action")
	}
}

func TestGatewayAllowsInScopeAndReturnsRequiredHeaders(t *testing.T) {
	g := New(testPolicy())
	d, err := g.Decide(context.Background(), Action{
		Kind: ActionHTTP, Method: http.MethodGet, URL: "https://api.example.com/v1/me",
	})
	if err != nil {
		t.Fatalf("unexpected decision error: %v", err)
	}
	if !d.Allowed {
		t.Fatalf("expected allow, got %+v", d)
	}
	if d.RequiredHeaders["X-Bug-Bounty"] != "researcher" {
		t.Fatalf("required header missing: %+v", d.RequiredHeaders)
	}
	if d.PolicyVersion == "" || d.ID == "" {
		t.Fatalf("decision provenance missing: %+v", d)
	}
}

func TestGatewayBlocksPathAndTechnique(t *testing.T) {
	g := New(testPolicy())
	for _, tc := range []Action{
		{Kind: ActionHTTP, URL: "https://example.com/logout"},
		{Kind: ActionHTTP, URL: "https://example.com/billing/refund"},
		{Kind: ActionHTTP, URL: "https://example.com/api", Technique: "destructive-delete"},
	} {
		if _, err := g.Decide(context.Background(), tc); !errors.Is(err, ErrDenied) {
			t.Fatalf("expected policy denial for %+v, got %v", tc, err)
		}
	}
}

func TestMutatingActionRequiresApproval(t *testing.T) {
	g := New(testPolicy())
	d, err := g.Decide(context.Background(), Action{
		Kind: ActionHTTP, Method: http.MethodPost, URL: "https://example.com/api/profile",
		MutatesState: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !d.RequiresApproval {
		t.Fatal("mutating action should be marked as requiring approval")
	}
}

func TestTrafficGovernorHonorsContextCancellation(t *testing.T) {
	p := testPolicy()
	p.RequestsPerSecond = 0.01
	p.Burst = 1
	g := New(p)
	if _, err := g.Decide(context.Background(), Action{Kind: ActionHTTP, URL: "https://example.com/a"}); err != nil {
		t.Fatalf("first request should consume initial token: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := g.Decide(ctx, Action{Kind: ActionHTTP, URL: "https://example.com/b"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context deadline from governor, got %v", err)
	}
}

func TestHTTPTransportInjectsRequiredHeader(t *testing.T) {
	g := New(testPolicy())
	var got string
	base := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		got = req.Header.Get("X-Bug-Bounty")
		return &http.Response{
			StatusCode: http.StatusNoContent,
			Status:     "204 No Content",
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    req,
		}, nil
	})
	client := &http.Client{Transport: NewHTTPTransport(g, base, nil)}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com/ping", http.NoBody)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	_ = resp.Body.Close()
	if got != "researcher" {
		t.Fatalf("required header not injected, got %q", got)
	}
}

func TestHTTPTransportRevalidatesRedirectTargets(t *testing.T) {
	var hits int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		http.Redirect(w, r, "http://outside.invalid/next", http.StatusFound)
	}))
	defer srv.Close()

	p := testPolicy()
	p.Scope = scope.ScopeDefinition{AllowedCIDRs: []string{"127.0.0.0/8"}}
	g := New(p)
	client := &http.Client{Transport: NewHTTPTransport(g, http.DefaultTransport, nil)}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, http.NoBody)
	resp, err := client.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("expected redirect target to be denied, got %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if hits != 1 {
		t.Fatalf("unexpected local server hits: got %d want 1", hits)
	}
}

func TestUpdatePolicyTakesEffectImmediately(t *testing.T) {
	g := New(testPolicy())
	if _, err := g.Decide(context.Background(), Action{Kind: ActionHTTP, URL: "https://example.com/ok"}); err != nil {
		t.Fatalf("initial allow failed: %v", err)
	}
	p := testPolicy()
	p.Scope = scope.ScopeDefinition{AllowedDomains: []string{"other.example"}}
	g.UpdatePolicy(p)
	if _, err := g.Decide(context.Background(), Action{Kind: ActionHTTP, URL: "https://example.com/ok"}); !errors.Is(err, ErrDenied) {
		t.Fatalf("stale scope remained active: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }


func TestDecisionExposesPerRequestConstraints(t *testing.T) {
	p := testPolicy()
	p.RequestsPerSecond = 10
	p.Burst = 10
	p.DynamicScope = true
	g := New(p)
	d, err := g.Decide(context.Background(), Action{Kind: ActionHTTP, URL: "https://example.com/api"})
	if err != nil {
		t.Fatalf("decision failed: %v", err)
	}
	if !d.RateLimited || !d.DynamicScope {
		t.Fatalf("constraint flags missing: %+v", d)
	}
}
