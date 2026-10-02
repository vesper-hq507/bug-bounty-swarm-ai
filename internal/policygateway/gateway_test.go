package policygateway

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope/programterms"
)

func testGateway(c programterms.Constraints) *Gateway {
	return New(Policy{
		Scope: scope.ScopeDefinition{AllowedDomains: []string{"example.com"}},
		Constraints: c,
		Version: "test-v1",
	})
}

func TestDecideRejectsOutOfScope(t *testing.T) {
	g := testGateway(programterms.Constraints{})
	d := g.Decide(Action{Kind: ActionHTTP, URL: "https://evil.example.net/api"})
	if d.Allowed {
		t.Fatalf("expected out-of-scope action to be denied")
	}
}

func TestDecideRejectsDisallowedPathButNotPrefixCollision(t *testing.T) {
	g := testGateway(programterms.Constraints{DisallowedPaths: []string{"/admin"}})

	if d := g.Decide(Action{Kind: ActionHTTP, URL: "https://example.com/admin/users"}); d.Allowed {
		t.Fatalf("expected /admin subtree to be denied")
	}
	if d := g.Decide(Action{Kind: ActionHTTP, URL: "https://example.com/administrator"}); !d.Allowed {
		t.Fatalf("did not expect /administrator to match /admin: %s", d.Reason)
	}
}

func TestDecideRejectsAutomatedScanningWhenForbidden(t *testing.T) {
	g := testGateway(programterms.Constraints{NoAutomatedScanning: true})
	d := g.Decide(Action{Kind: ActionTool, Target: "example.com", Automated: true, Tool: "nuclei"})
	if d.Allowed {
		t.Fatalf("expected automated action to be denied")
	}
}

func TestDecideRejectsProhibitedTechnique(t *testing.T) {
	g := testGateway(programterms.Constraints{NoBruteForce: true})
	d := g.Decide(Action{Kind: ActionTool, Target: "example.com", Technique: "credential stuffing", Automated: true})
	if d.Allowed {
		t.Fatalf("expected credential stuffing to be denied")
	}
}

func TestMutatingHTTPRequiresApproval(t *testing.T) {
	g := testGateway(programterms.Constraints{})
	d := g.Decide(Action{Kind: ActionHTTP, URL: "https://example.com/api/profile", Method: http.MethodPatch, MutatesState: true})
	if !d.Allowed || !d.RequiresApproval {
		t.Fatalf("expected PATCH to be allowed but approval-gated: %#v", d)
	}
}

func TestApplyRequiredHeadersOverridesCallerValue(t *testing.T) {
	g := testGateway(programterms.Constraints{
		RequiredHeaders: map[string]string{"X-Bugbounty-User": "researcher"},
	})
	d := g.Decide(Action{Kind: ActionHTTP, URL: "https://example.com/"})
	req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Bugbounty-User", "wrong")
	ApplyRequiredHeaders(req, d)
	if got := req.Header.Get("X-Bugbounty-User"); got != "researcher" {
		t.Fatalf("required header = %q, want researcher", got)
	}
}

func TestAuthorizeRateLimiterHonorsContextCancellation(t *testing.T) {
	g := testGateway(programterms.Constraints{MaxRequestsPerSecond: 1})
	ctx := context.Background()
	if _, err := g.Authorize(ctx, Action{Kind: ActionHTTP, URL: "https://example.com/"}); err != nil {
		t.Fatalf("first authorize: %v", err)
	}

	cancelCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := g.Authorize(cancelCtx, Action{Kind: ActionHTTP, URL: "https://example.com/"}); err == nil {
		t.Fatalf("expected second authorization to be canceled while rate-limited")
	}
}
