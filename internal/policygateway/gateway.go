// Package policygateway provides the authoritative policy decision point for
// target-directed actions. Lower-level scope and safe-mode checks remain in
// place as defense-in-depth, but outbound execution paths should route through
// this package before network I/O occurs.
package policygateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	pathpkg "path"
	"strings"
	"sync"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/swarm/ratelimit"
)

// ActionKind identifies the execution surface requesting authorization.
type ActionKind string

const (
	ActionHTTP    ActionKind = "http"
	ActionBrowser ActionKind = "browser"
	ActionTool    ActionKind = "tool"
	ActionMCP     ActionKind = "mcp"
)

// Action describes one target-directed operation.
type Action struct {
	CampaignID   string
	ActorID      string
	Kind         ActionKind
	Method       string
	URL          string
	Tool         string
	Technique    string
	Path         string
	MutatesState bool
	Metadata     map[string]string
}

// Policy is the normalized set of executable program constraints currently
// enforced by a Gateway.
type Policy struct {
	Scope                 scope.ScopeDefinition
	RequiredHeaders       map[string]string
	DisallowedPaths       []string
	DisallowedTechniques  []string
	RequestsPerSecond     float64
	Burst                 float64
	DynamicScope          bool
	Version               string
}

// Decision records the gateway result for one action.
type Decision struct {
	ID               string
	Allowed          bool
	RequiresApproval bool
	Reason           string
	RequiredHeaders  map[string]string
	RateClass        string
	RateLimited      bool
	DynamicScope     bool
	PolicyVersion    string
}

// AuditRecord is emitted after every completed decision, including denials.
type AuditRecord struct {
	Timestamp time.Time
	Action    Action
	Decision  Decision
}

// AuditSink receives decision records. Implementations must not log raw
// credentials from Action.Metadata.
type AuditSink func(AuditRecord)

// ErrDenied is the sentinel wrapped by DeniedError.
var ErrDenied = errors.New("policy gateway denied action")

// DeniedError carries the exact decision that blocked an action.
type DeniedError struct {
	Decision Decision
}

func (e *DeniedError) Error() string {
	if e == nil {
		return ErrDenied.Error()
	}
	if e.Decision.Reason == "" {
		return ErrDenied.Error()
	}
	return fmt.Sprintf("%s: %s", ErrDenied, e.Decision.Reason)
}

func (e *DeniedError) Unwrap() error { return ErrDenied }

// Gateway owns the current normalized policy and its global traffic limiter.
type Gateway struct {
	mu      sync.RWMutex
	policy  Policy
	limiter *ratelimit.Limiter
	audit   AuditSink
}

// Option customizes gateway construction.
type Option func(*Gateway)

// WithAuditSink installs a decision sink.
func WithAuditSink(sink AuditSink) Option {
	return func(g *Gateway) { g.audit = sink }
}

// New creates a fail-closed policy gateway.
func New(p Policy, opts ...Option) *Gateway {
	g := &Gateway{}
	for _, opt := range opts {
		opt(g)
	}
	g.UpdatePolicy(p)
	return g
}

// UpdatePolicy atomically replaces the active policy and traffic limiter.
func (g *Gateway) UpdatePolicy(p Policy) {
	if g == nil {
		return
	}
	p = normalizePolicy(p)
	g.mu.Lock()
	defer g.mu.Unlock()
	g.policy = p
	g.limiter = ratelimit.New(p.RequestsPerSecond, p.Burst)
}

// UpdateScope atomically replaces only the scope portion of the active policy.
 // The derived policy version is recomputed so evidence can distinguish decisions
 // made before and after a live scope change.
func (g *Gateway) UpdateScope(def scope.ScopeDefinition) {
	if g == nil {
		return
	}
	g.mu.RLock()
	p := g.policy
	g.mu.RUnlock()
	p.Scope = def
	p.Version = ""
	g.UpdatePolicy(p)
}

// PolicyVersion returns the active normalized policy version.
func (g *Gateway) PolicyVersion() string {
	if g == nil {
		return ""
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.policy.Version
}

// Decide evaluates one target-directed action. Scope, path and technique
// restrictions are checked before the global traffic token is consumed.
func (g *Gateway) Decide(ctx context.Context, action Action) (Decision, error) {
	if g == nil {
		d := Decision{Reason: "policy gateway unavailable"}
		return d, &DeniedError{Decision: d}
	}

	g.mu.RLock()
	p := g.policy
	lim := g.limiter
	audit := g.audit
	g.mu.RUnlock()

	decision := Decision{
		ID:               decisionID(p.Version, action),
		RequiresApproval: action.MutatesState,
		RequiredHeaders:  cloneHeaders(p.RequiredHeaders),
		RateClass:        "global-target",
		RateLimited:      p.RequestsPerSecond > 0,
		DynamicScope:     p.DynamicScope,
		PolicyVersion:    p.Version,
	}

	deny := func(reason string) (Decision, error) {
		decision.Allowed = false
		decision.Reason = reason
		if audit != nil {
			audit(AuditRecord{Timestamp: time.Now(), Action: action, Decision: decision})
		}
		return decision, &DeniedError{Decision: decision}
	}

	target := strings.TrimSpace(action.URL)
	if target == "" {
		target = strings.TrimSpace(action.Path)
	}
	if target == "" {
		return deny("target is empty")
	}
	if err := scope.Validate(target, p.Scope); err != nil {
		return deny("scope check failed: " + err.Error())
	}

	reqPath := strings.TrimSpace(action.Path)
	if reqPath == "" && action.URL != "" {
		if u, err := url.Parse(action.URL); err == nil {
			reqPath = u.EscapedPath()
			if reqPath == "" {
				reqPath = "/"
			}
		}
	}
	if pathBlocked(reqPath, p.DisallowedPaths) {
		return deny(fmt.Sprintf("path %q is disallowed by program policy", reqPath))
	}
	if techniqueBlocked(action.Technique, p.DisallowedTechniques) {
		return deny(fmt.Sprintf("technique %q is disallowed by program policy", action.Technique))
	}

	if lim != nil {
		if err := lim.Take(ctx); err != nil {
			decision.Reason = "traffic governor interrupted: " + err.Error()
			if audit != nil {
				audit(AuditRecord{Timestamp: time.Now(), Action: action, Decision: decision})
			}
			return decision, err
		}
	}

	decision.Allowed = true
	decision.Reason = "allowed"
	if audit != nil {
		audit(AuditRecord{Timestamp: time.Now(), Action: action, Decision: decision})
	}
	return decision, nil
}

// HTTPActionBuilder optionally enriches the default action derived from an
// outbound *http.Request.
type HTTPActionBuilder func(*http.Request) Action

// HTTPTransport is a fail-closed RoundTripper that authorizes every actual HTTP
// send. Because net/http invokes the transport again for redirects and each
// concurrent request, redirect targets and race bursts cannot bypass policy.
type HTTPTransport struct {
	Gateway *Gateway
	Base    http.RoundTripper
	Build   HTTPActionBuilder
}

// NewHTTPTransport wraps base with per-send policy enforcement.
func NewHTTPTransport(g *Gateway, base http.RoundTripper, build HTTPActionBuilder) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &HTTPTransport{Gateway: g, Base: base, Build: build}
}

func (t *HTTPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil {
		d := Decision{Reason: "nil HTTP request"}
		return nil, &DeniedError{Decision: d}
	}
	if t == nil || t.Gateway == nil {
		d := Decision{Reason: "policy gateway unavailable"}
		return nil, &DeniedError{Decision: d}
	}

	action := Action{
		Kind:         ActionHTTP,
		Method:       req.Method,
		URL:          req.URL.String(),
		Path:         req.URL.EscapedPath(),
		MutatesState: IsMutatingMethod(req.Method),
	}
	if t.Build != nil {
		custom := t.Build(req)
		if custom.Kind == "" {
			custom.Kind = ActionHTTP
		}
		if custom.Method == "" {
			custom.Method = req.Method
		}
		if custom.URL == "" {
			custom.URL = req.URL.String()
		}
		if custom.Path == "" {
			custom.Path = req.URL.EscapedPath()
		}
		action = custom
	}

	decision, err := t.Gateway.Decide(req.Context(), action)
	if err != nil {
		return nil, err
	}
	if !decision.Allowed {
		return nil, &DeniedError{Decision: decision}
	}

	r2 := req.Clone(req.Context())
	r2.Header = req.Header.Clone()
	for k, v := range decision.RequiredHeaders {
		r2.Header.Set(k, v)
	}

	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(r2)
}

// IsMutatingMethod classifies methods that can change server-side state.
func IsMutatingMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return false
	default:
		return true
	}
}

func normalizePolicy(p Policy) Policy {
	headers := make(map[string]string, len(p.RequiredHeaders))
	for k, v := range p.RequiredHeaders {
		k = http.CanonicalHeaderKey(strings.TrimSpace(k))
		if k == "" {
			continue
		}
		headers[k] = strings.TrimSpace(v)
	}
	p.RequiredHeaders = headers

	p.DisallowedPaths = normalizeStrings(p.DisallowedPaths, false)
	p.DisallowedTechniques = normalizeStrings(p.DisallowedTechniques, true)
	p.Version = strings.TrimSpace(p.Version)
	if p.Version == "" {
		wire := struct {
			Scope                scope.ScopeDefinition
			RequiredHeaders      map[string]string
			DisallowedPaths      []string
			DisallowedTechniques []string
			RequestsPerSecond    float64
			Burst                float64
			DynamicScope         bool
		}{
			Scope: p.Scope, RequiredHeaders: p.RequiredHeaders,
			DisallowedPaths: p.DisallowedPaths,
			DisallowedTechniques: p.DisallowedTechniques,
			RequestsPerSecond: p.RequestsPerSecond, Burst: p.Burst,
			DynamicScope: p.DynamicScope,
		}
		b, _ := json.Marshal(wire)
		sum := sha256.Sum256(b)
		p.Version = "sha256:" + hex.EncodeToString(sum[:8])
	}
	return p
}

func normalizeStrings(in []string, lower bool) []string {
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if lower {
			v = strings.ToLower(v)
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func cloneHeaders(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func pathBlocked(reqPath string, patterns []string) bool {
	if reqPath == "" {
		reqPath = "/"
	}
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if matched, err := pathpkg.Match(pattern, reqPath); err == nil && matched {
			return true
		}
		base := strings.TrimSuffix(pattern, "/")
		if !strings.ContainsAny(pattern, "*?[") &&
			(reqPath == base || strings.HasPrefix(reqPath, base+"/")) {
			return true
		}
	}
	return false
}

func techniqueBlocked(technique string, patterns []string) bool {
	technique = strings.ToLower(strings.TrimSpace(technique))
	if technique == "" {
		return false
	}
	for _, pattern := range patterns {
		if matched, err := pathpkg.Match(pattern, technique); err == nil && matched {
			return true
		}
		if technique == pattern {
			return true
		}
	}
	return false
}

func decisionID(version string, action Action) string {
	wire := struct {
		Version   string
		Campaign  string
		Actor     string
		Kind      ActionKind
		Method    string
		URL       string
		Tool      string
		Technique string
		Path      string
	}{
		Version: version, Campaign: action.CampaignID, Actor: action.ActorID,
		Kind: action.Kind, Method: action.Method, URL: action.URL, Tool: action.Tool,
		Technique: action.Technique, Path: action.Path,
	}
	b, _ := json.Marshal(wire)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:12])
}
