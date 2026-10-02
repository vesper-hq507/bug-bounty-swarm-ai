package policygateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope/programterms"
)

func TestWrapHTTPClientEnforcesHeadersAndPaths(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Header.Get("X-Bugbounty-User") != "researcher" {
			t.Errorf("missing required policy header")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	g := New(Policy{
		Scope: scope.ScopeDefinition{AllowedCIDRs: []string{"127.0.0.1/32"}},
		Constraints: programterms.Constraints{
			RequiredHeaders: map[string]string{"X-Bugbounty-User": "researcher"},
			DisallowedPaths: []string{"/admin"},
		},
		Version: "test",
	})
	client := WrapHTTPClient(srv.Client(), g, Action{Automated: true})

	resp, err := client.Get(srv.URL + "/ok")
	if err != nil {
		t.Fatalf("allowed request failed: %v", err)
	}
	resp.Body.Close()

	_, err = client.Get(srv.URL + "/admin/users")
	if err == nil || !strings.Contains(err.Error(), "prohibited") {
		t.Fatalf("expected policy denial, got %v", err)
	}
	if hits != 1 {
		t.Fatalf("blocked request reached server; hits=%d", hits)
	}
}
