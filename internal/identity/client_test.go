package identity

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/policygateway"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/session"
)

func TestClientFactorySeparatesIdentitySessionsAndPolicyActor(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	reg := NewRegistry()
	if err := reg.Add(Identity{ID: "user-a", Alias: "User A", Role: RoleUser, SessionRef: "vault:user-a"}); err != nil {
		t.Fatal(err)
	}
	resolver := NewMemorySessionResolver()
	if err := resolver.Put("vault:user-a", session.New(map[string]string{"Authorization": "Bearer secret-a"})); err != nil {
		t.Fatal(err)
	}

	var actor string
	gateway := policygateway.New(policygateway.Policy{
		Scope: scope.ScopeDefinition{AllowedCIDRs: []string{"127.0.0.0/8"}},
	}, policygateway.WithAuditSink(func(rec policygateway.AuditRecord) {
		actor = rec.Action.ActorID
	}))

	factory := ClientFactory{Registry: reg, Resolver: resolver, Gateway: gateway}
	client, _, err := factory.ClientFor(context.Background(), "user-a")
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}

	if gotAuth != "Bearer secret-a" {
		t.Fatalf("authorization = %q", gotAuth)
	}
	if actor != "user-a" {
		t.Fatalf("policy actor = %q", actor)
	}
}

func TestClientFactoryAnonymousCarriesNoSessionSecret(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	reg := NewRegistry()
	if err := reg.Add(Identity{ID: "anon", Alias: "Anonymous", Role: RoleAnonymous}); err != nil {
		t.Fatal(err)
	}
	gateway := policygateway.New(policygateway.Policy{
		Scope: scope.ScopeDefinition{AllowedCIDRs: []string{"127.0.0.0/8"}},
	})
	client, _, err := (&ClientFactory{Registry: reg, Gateway: gateway}).ClientFor(context.Background(), "anon")
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "" {
		t.Fatalf("anonymous request leaked auth header %q", gotAuth)
	}
}
