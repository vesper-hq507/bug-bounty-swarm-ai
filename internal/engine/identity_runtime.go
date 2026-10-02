package engine

import (
	"context"
	"fmt"
	"sort"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/evidence"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/identity"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/policygateway"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/recovery"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/session"
	"github.com/google/uuid"
)

const legacyPrimarySessionRef identity.SessionRef = "runtime:legacy-primary"

type campaignIdentities struct {
	registry       *identity.Registry
	resolver       *identity.MemorySessionResolver
	clients        *identity.ClientFactory
	primary        identity.Identity
	primarySession *session.Session
}

func prepareCampaignIdentities(ctx context.Context, cc CampaignConfig, gateway *policygateway.Gateway) (*campaignIdentities, error) {
	if gateway == nil {
		return nil, fmt.Errorf("policy gateway is required for identity runtime")
	}

	idents := append([]identity.Identity(nil), cc.Identities...)
	sessions := make(map[identity.SessionRef]*session.Session, len(cc.IdentitySessions)+1)
	for ref, sess := range cc.IdentitySessions {
		sessions[ref] = sess
	}

	primaryID := cc.PrimaryIdentity
	if len(idents) == 0 {
		if len(cc.AuthHeaders) > 0 {
			idents = []identity.Identity{{
				ID: "primary", Alias: "Primary", Role: identity.RoleUser,
				SessionRef: legacyPrimarySessionRef,
			}}
			sessions[legacyPrimarySessionRef] = session.New(cc.AuthHeaders)
			primaryID = "primary"
		} else {
			idents = []identity.Identity{{ID: "anonymous", Alias: "Anonymous", Role: identity.RoleAnonymous}}
			primaryID = "anonymous"
		}
	}

	registry := identity.NewRegistry()
	resolver := identity.NewMemorySessionResolver()
	for ref, sess := range sessions {
		if err := resolver.Put(ref, sess); err != nil {
			return nil, fmt.Errorf("session %q: %w", ref, err)
		}
	}
	for i := range idents {
		if err := registry.Add(idents[i]); err != nil {
			return nil, err
		}
	}

	if primaryID == "" {
		if len(idents) != 1 {
			return nil, fmt.Errorf("primary identity is required when more than one identity is configured")
		}
		primaryID = idents[0].ID
	}
	primary, err := registry.Get(primaryID)
	if err != nil {
		return nil, fmt.Errorf("primary identity %q: %w", primaryID, err)
	}

	for _, ident := range registry.List() {
		if ident.Role == identity.RoleAnonymous {
			continue
		}
		if _, err := resolver.ResolveSession(ctx, ident.SessionRef); err != nil {
			return nil, fmt.Errorf("identity %q session: %w", ident.ID, err)
		}
	}

	var primarySession *session.Session
	if primary.Role == identity.RoleAnonymous {
		primarySession = session.New(session.BrowserHeaders())
	} else {
		resolved, err := resolver.ResolveSession(ctx, primary.SessionRef)
		if err != nil {
			return nil, fmt.Errorf("primary identity session: %w", err)
		}
		primarySession = session.New(session.WithBrowserDefaults(resolved.Headers))
	}

	return &campaignIdentities{
		registry: registry,
		resolver: resolver,
		clients: &identity.ClientFactory{
			Registry: registry,
			Resolver: resolver,
			Gateway:  gateway,
		},
		primary:        primary,
		primarySession: primarySession,
	}, nil
}

func (r *campaignIdentities) Primary() identity.Identity {
	if r == nil {
		return identity.Identity{}
	}
	return r.primary
}

func (r *campaignIdentities) PrimarySession() *session.Session {
	if r == nil {
		return nil
	}
	return r.primarySession
}

func (r *campaignIdentities) RecoveryRefs() []recovery.IdentityRef {
	if r == nil || r.registry == nil {
		return nil
	}
	idents := r.registry.List()
	out := make([]recovery.IdentityRef, 0, len(idents))
	for i := range idents {
		out = append(out, recovery.IdentityRef{ID: idents[i].ID, SessionRef: idents[i].SessionRef})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (r *campaignIdentities) DifferentialTester(campaignID uuid.UUID, store evidence.Store) *identity.DifferentialTester {
	if r == nil {
		return nil
	}
	return &identity.DifferentialTester{
		Clients:    r.clients,
		Ownership:  identity.NewOwnershipMap(),
		CampaignID: campaignID,
		Evidence:   store,
	}
}
