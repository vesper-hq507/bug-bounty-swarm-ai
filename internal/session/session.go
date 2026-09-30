// Package session carries a user-supplied authenticated session (Bearer token,
// cookies, arbitrary headers) and injects it into the swarm's outbound HTTP so
// authenticated surface — where the high-value bugs live (IDOR/BOLA, BFLA,
// account takeover, mass assignment) — is actually reachable.
//
// A bug-bounty hunter flagged that there was no way to hand the tool a real
// session, leaving authenticated endpoints out of reach. This closes that gap:
// one Session, set at campaign start, decorates every request the swarm makes
// through a wrapped http.Client.
package session

import (
	"net/http"
	"sort"
	"strings"
)

// Session holds the headers to attach to outbound requests.
type Session struct {
	Headers map[string]string
}

// New builds a Session from a header map (nil-safe).
func New(headers map[string]string) *Session {
	if len(headers) == 0 {
		return nil
	}
	return &Session{Headers: headers}
}

// Empty reports whether the session carries nothing.
func (s *Session) Empty() bool { return s == nil || len(s.Headers) == 0 }

// Apply sets the session's headers on a request, without clobbering a header
// the caller already set explicitly.
func (s *Session) Apply(r *http.Request) {
	if s.Empty() || r == nil {
		return
	}
	for _, k := range s.keys() {
		if r.Header.Get(k) == "" {
			r.Header.Set(k, s.Headers[k])
		}
	}
}

// Wrap returns a client whose transport injects the session headers on every
// request. The input client is not mutated; a nil/empty session returns it
// unchanged so call sites can wrap unconditionally.
func (s *Session) Wrap(c *http.Client) *http.Client {
	if s.Empty() || c == nil {
		return c
	}
	cp := *c
	base := c.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	cp.Transport = &authTransport{base: base, sess: s}
	return &cp
}

func (s *Session) keys() []string {
	ks := make([]string, 0, len(s.Headers))
	for k := range s.Headers {
		ks = append(ks, k)
	}
	sort.Strings(ks) // stable order (tests, and deterministic header emission)
	return ks
}

type authTransport struct {
	base http.RoundTripper
	sess *Session
}

func (t *authTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	// Clone so we never mutate the caller's request (RoundTripper contract).
	r2 := r.Clone(r.Context())
	t.sess.Apply(r2)
	return t.base.RoundTrip(r2)
}

// ParseHeaders builds a header map from CLI-style inputs: raw "Name: Value"
// strings, an optional Cookie value, and an optional bearer token (→
// "Authorization: Bearer <token>"). Later sources win over earlier ones for the
// same header. Blank/malformed entries are skipped.
func ParseHeaders(raw []string, cookie, bearer string) map[string]string {
	out := map[string]string{}
	for _, h := range raw {
		i := strings.IndexByte(h, ':')
		if i <= 0 {
			continue
		}
		name := strings.TrimSpace(h[:i])
		val := strings.TrimSpace(h[i+1:])
		if name == "" || val == "" {
			continue
		}
		out[http.CanonicalHeaderKey(name)] = val
	}
	if c := strings.TrimSpace(cookie); c != "" {
		out["Cookie"] = c
	}
	if b := strings.TrimSpace(bearer); b != "" {
		if !strings.HasPrefix(strings.ToLower(b), "bearer ") {
			b = "Bearer " + b
		}
		out["Authorization"] = b
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
