package engine

import (
	"context"
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/identity"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/policygateway"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/session"
)

func TestPrepareCampaignIdentitiesConvertsLegacySession(t *testing.T) {
	gateway := policygateway.New(policygateway.Policy{})
	runtime, err := prepareCampaignIdentities(context.Background(), CampaignConfig{
		AuthHeaders: map[string]string{"Authorization": "Bearer legacy-secret"},
	}, gateway)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.Primary().ID != "primary" || runtime.Primary().SessionRef != legacyPrimarySessionRef {
		t.Fatalf("primary = %+v", runtime.Primary())
	}
	sess := runtime.PrimarySession()
	if sess == nil || sess.Headers["Authorization"] != "Bearer legacy-secret" || sess.Headers["User-Agent"] == "" {
		t.Fatalf("primary session not normalized: %+v", sess)
	}
	refs := runtime.RecoveryRefs()
	if len(refs) != 1 || refs[0].SessionRef != legacyPrimarySessionRef {
		t.Fatalf("recovery refs = %+v", refs)
	}
}

func TestPrepareCampaignIdentitiesRequiresPrimaryForMultiple(t *testing.T) {
	gateway := policygateway.New(policygateway.Policy{})
	s1 := session.New(map[string]string{"Authorization": "Bearer one"})
	s2 := session.New(map[string]string{"Authorization": "Bearer two"})
	_, err := prepareCampaignIdentities(context.Background(), CampaignConfig{
		Identities: []identity.Identity{
			{ID: "user-a", Alias: "User A", Role: identity.RoleUser, SessionRef: "session-a"},
			{ID: "user-b", Alias: "User B", Role: identity.RoleUser, SessionRef: "session-b"},
		},
		IdentitySessions: map[identity.SessionRef]*session.Session{
			"session-a": s1,
			"session-b": s2,
		},
	}, gateway)
	if err == nil {
		t.Fatal("multiple identities without primary must fail")
	}
}

func TestPrepareCampaignIdentitiesUsesExplicitPrimaryAndReferencesOnly(t *testing.T) {
	gateway := policygateway.New(policygateway.Policy{})
	runtime, err := prepareCampaignIdentities(context.Background(), CampaignConfig{
		Identities: []identity.Identity{
			{ID: "anonymous", Alias: "Anonymous", Role: identity.RoleAnonymous},
			{ID: "user-a", Alias: "User A", Role: identity.RoleUser, SessionRef: "session-a"},
		},
		IdentitySessions: map[identity.SessionRef]*session.Session{
			"session-a": session.New(map[string]string{"Authorization": "Bearer do-not-persist"}),
		},
		PrimaryIdentity: "user-a",
	}, gateway)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.Primary().ID != "user-a" {
		t.Fatalf("primary = %+v", runtime.Primary())
	}
	refs := runtime.RecoveryRefs()
	if len(refs) != 2 {
		t.Fatalf("recovery refs = %+v", refs)
	}
	for _, ref := range refs {
		if string(ref.SessionRef) == "Bearer do-not-persist" {
			t.Fatal("raw credential leaked into recovery refs")
		}
	}
}
