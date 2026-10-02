package policygateway

import (
	"fmt"
	"net/http"
)

// WrapHTTPClient returns a shallow copy whose transport authorizes every
// outbound request through the gateway. It is intended for in-process recon
// clients so redirects and helper probes cannot bypass policy by creating their
// own requests after the initial target check.
//
// Wrap session/auth transports first, then this wrapper last. The policy layer
// becomes outermost, so required program headers are set before a session
// decorator fills only missing headers.
func WrapHTTPClient(c *http.Client, g *Gateway, base Action) *http.Client {
	if c == nil || g == nil {
		return c
	}
	cp := *c
	under := c.Transport
	if under == nil {
		under = http.DefaultTransport
	}
	cp.Transport = &policyTransport{base: under, gateway: g, action: base}
	return &cp
}

type policyTransport struct {
	base    http.RoundTripper
	gateway *Gateway
	action  Action
}

func (t *policyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("policy transport: nil request")
	}
	action := t.action
	action.Method = req.Method
	action.URL = req.URL.String()
	if action.Kind == "" {
		action.Kind = ActionHTTP
	}
	decision, err := t.gateway.Authorize(req.Context(), action)
	if err != nil {
		return nil, fmt.Errorf("program policy: %s: %w", decision.Reason, err)
	}
	r2 := req.Clone(req.Context())
	r2.Header = req.Header.Clone()
	ApplyRequiredHeaders(r2, decision)
	return t.base.RoundTrip(r2)
}
