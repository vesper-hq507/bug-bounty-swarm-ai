package identity

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/policygateway"
)

type ClientFactory struct {
	Registry *Registry
	Resolver SessionResolver
	Gateway  *policygateway.Gateway
	Base     *http.Client
}

func (f *ClientFactory) ClientFor(ctx context.Context, id ID) (*http.Client, Identity, error) {
	if f == nil || f.Registry == nil || f.Gateway == nil {
		return nil, Identity{}, fmt.Errorf("identity client factory is not configured")
	}
	ident, err := f.Registry.Get(id)
	if err != nil {
		return nil, Identity{}, err
	}
	if !ident.AuthFresh(time.Now()) {
		return nil, Identity{}, fmt.Errorf("identity %q authentication is missing or stale", id)
	}

	base := f.Base
	if base == nil {
		base = &http.Client{Timeout: 30 * time.Second}
	}
	cp := *base
	cp.Transport = policygateway.NewHTTPTransport(f.Gateway, base.Transport, func(r *http.Request) policygateway.Action {
		return policygateway.Action{
			ActorID:      string(id),
			Kind:         policygateway.ActionHTTP,
			Method:       r.Method,
			URL:          r.URL.String(),
			Path:         r.URL.EscapedPath(),
			MutatesState: policygateway.IsMutatingMethod(r.Method),
			Metadata:     map[string]string{"identity_alias": ident.Alias},
		}
	})

	if ident.Role == RoleAnonymous {
		return &cp, ident, nil
	}
	if f.Resolver == nil {
		return nil, Identity{}, fmt.Errorf("session resolver unavailable for identity %q", id)
	}
	sess, err := f.Resolver.ResolveSession(ctx, ident.SessionRef)
	if err != nil {
		return nil, Identity{}, err
	}
	return sess.Wrap(&cp), ident, nil
}
