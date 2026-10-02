package identity

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/policygateway"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/session"
)

func TestDifferentialTesterFindsControlledBOLACandidate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Authorization") {
		case "Bearer owner", "Bearer other":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"id":"acct-1","balance":42}`)
		default:
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		}
	}))
	defer srv.Close()

	reg := NewRegistry()
	if err := reg.Add(Identity{ID: "user-a", Alias: "User A", Role: RoleUser, SessionRef: "vault:a"}); err != nil {
		t.Fatal(err)
	}
	if err := reg.Add(Identity{ID: "user-b", Alias: "User B", Role: RoleUser, SessionRef: "vault:b"}); err != nil {
		t.Fatal(err)
	}
	resolver := NewMemorySessionResolver()
	_ = resolver.Put("vault:a", session.New(map[string]string{"Authorization": "Bearer owner"}))
	_ = resolver.Put("vault:b", session.New(map[string]string{"Authorization": "Bearer other"}))

	gateway := policygateway.New(policygateway.Policy{Scope: scope.ScopeDefinition{AllowedCIDRs: []string{"127.0.0.0/8"}}})
	owners := NewOwnershipMap()
	obj := ObjectRef{Type: "account", ID: "acct-1"}
	_ = owners.SetOwner(obj, "user-a")

	tester := DifferentialTester{
		Clients: &ClientFactory{Registry: reg, Resolver: resolver, Gateway: gateway},
		Ownership: owners,
	}
	got, err := tester.TestObjectAccess(context.Background(), "user-a", "user-b", RequestSpec{
		Method: http.MethodGet,
		URL: srv.URL + "/accounts/acct-1",
		Object: obj,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != DiffUnexpectedAccess || !got.SameBody {
		t.Fatalf("result = %+v", got)
	}
}

func TestDifferentialTesterRefusesStatefulMethod(t *testing.T) {
	tester := DifferentialTester{Clients: &ClientFactory{}}
	_, err := tester.TestObjectAccess(context.Background(), "a", "b", RequestSpec{Method: http.MethodPost})
	if err == nil {
		t.Fatal("stateful differential test must require later approval flow")
	}
}
