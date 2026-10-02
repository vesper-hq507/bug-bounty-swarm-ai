package identity

import (
	"errors"
	"testing"
	"time"
)

func TestRegistryRequiresReferenceForAuthenticatedIdentity(t *testing.T) {
	r := NewRegistry()
	err := r.Add(Identity{ID: "user-a", Alias: "User A", Role: RoleUser})
	if err == nil {
		t.Fatal("authenticated identity without session reference must fail")
	}
}

func TestRegistryAnonymousNeedsNoSecret(t *testing.T) {
	r := NewRegistry()
	if err := r.Add(Identity{ID: "anon", Alias: "Anonymous", Role: RoleAnonymous}); err != nil {
		t.Fatalf("anonymous add: %v", err)
	}
	got, err := r.Get("anon")
	if err != nil || got.SessionRef != "" {
		t.Fatalf("anonymous identity = %+v err=%v", got, err)
	}
}

func TestRegistryRejectsDuplicateIdentity(t *testing.T) {
	r := NewRegistry()
	i := Identity{ID: "user-a", Alias: "User A", Role: RoleUser, SessionRef: "vault:user-a"}
	if err := r.Add(i); err != nil {
		t.Fatal(err)
	}
	if err := r.Add(i); !errors.Is(err, ErrDuplicateIdentity) {
		t.Fatalf("duplicate error = %v", err)
	}
}

func TestIdentityFreshness(t *testing.T) {
	now := time.Now()
	i := Identity{ID: "user-a", Alias: "User A", Role: RoleUser, SessionRef: "vault:user-a", FreshUntil: now.Add(time.Minute)}
	if !i.AuthFresh(now) {
		t.Fatal("expected fresh auth")
	}
	if i.AuthFresh(now.Add(2 * time.Minute)) {
		t.Fatal("expired auth must be stale")
	}
}
