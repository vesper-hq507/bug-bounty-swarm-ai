// Package policygateway centralizes bug-bounty program policy decisions.
//
// It is intentionally deterministic: LLMs may propose actions, but they do not
// decide whether those actions are permitted. Callers must route target-directed
// actions through Gateway before execution.
package policygateway

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope/programterms"
)

// ActionKind identifies the execution path requesting authorization.
type ActionKind string

const (
	ActionHTTP    ActionKind = "http"
	ActionBrowser ActionKind = "browser"
	ActionTool    ActionKind = "tool"
	ActionMCP     ActionKind = "mcp"
)

// Action is the normalized description of one target-directed operation.
type Action struct {
	CampaignID   string
	ActorID      string
	Kind         ActionKind
	Method       string
	URL          string
	Target       string
	Path         string
	Tool         string
	Technique    string
	Automated    bool
	MutatesState bool
}

// Policy is the normalized subset of a program's rules needed at execution
// time. Version should identify the policy/scope snapshot used for auditing.
type Policy struct {
	Scope       scope.ScopeDefinition
	Constraints programterms.Constraints
	Version     string
}

// Decision is the deterministic result of evaluating one action.
type Decision struct {
	Allowed          bool
	RequiresApproval bool
	Reason           string
	RequiredHeaders  map[string]string
	PolicyVersion    string
}

// Gateway is the single policy decision point. Existing lower-level scope and
// safe-mode checks remain in place as defense-in-depth.
type Gateway struct {
	policy  Policy
	limiter *Limiter
}

// New constructs a Gateway. A parsed program RPS limit becomes a shared traffic
// governor for every caller using this Gateway instance.
func New(policy Policy) *Gateway {
	g := &Gateway{policy: policy}
	if policy.Constraints.MaxRequestsPerSecond > 0 {
		g.limiter = NewLimiter(policy.Constraints.MaxRequestsPerSecond)
	}
	return g
}

// Policy returns the immutable policy snapshot used by this gateway.
func (g *Gateway) Policy() Policy {
	return g.policy
}

// Authorize evaluates an action and, when permitted, applies the program's
// central request-rate governor. A denied action never consumes a rate slot.
func (g *Gateway) Authorize(ctx context.Context, action Action) (Decision, error) {
	d := g.Decide(action)
	if !d.Allowed {
		return d, fmt.Errorf("policy denied action: %s", d.Reason)
	}
	if g.limiter != nil {
		if err := g.limiter.Wait(ctx); err != nil {
			d.Allowed = false
			d.Reason = "rate-limit wait canceled"
			return d, err
		}
	}
	return d, nil
}

// Decide evaluates scope and program terms without blocking on rate limiting.
func (g *Gateway) Decide(action Action) Decision {
	d := Decision{
		Allowed:         true,
		Reason:          "allowed",
		RequiredHeaders: cloneHeaders(g.policy.Constraints.RequiredHeaders),
		PolicyVersion:   g.policy.Version,
	}

	target := strings.TrimSpace(action.URL)
	if target == "" {
		target = strings.TrimSpace(action.Target)
	}
	if target != "" && hasScope(g.policy.Scope) {
		if err := scope.Validate(target, g.policy.Scope); err != nil {
			return deny(d, "out of scope: "+err.Error())
		}
	}

	path := strings.TrimSpace(action.Path)
	if path == "" && action.URL != "" {
		if u, err := url.Parse(action.URL); err == nil {
			path = u.Path
			if path == "" {
				path = "/"
			}
		}
	}
	for _, blocked := range g.policy.Constraints.DisallowedPaths {
		if pathMatches(path, blocked) {
			return deny(d, fmt.Sprintf("path %q is prohibited by program policy", path))
		}
	}

	if action.Automated && g.policy.Constraints.NoAutomatedScanning {
		return deny(d, "program policy prohibits automated scanning")
	}

	haystack := strings.ToLower(strings.TrimSpace(action.Technique + " " + action.Tool))
	if g.policy.Constraints.NoBruteForce && containsAny(haystack,
		"brute", "password guess", "credential stuff", "credential spray") {
		return deny(d, "program policy prohibits brute force / credential attacks")
	}
	if g.policy.Constraints.NoDoS && containsAny(haystack,
		"denial of service", " dos ", "stress test", "load test", "flood") {
		return deny(d, "program policy prohibits denial-of-service testing")
	}
	if g.policy.Constraints.NoSocialEngineering && containsAny(haystack,
		"social engineering", "phish", "pretext") {
		return deny(d, "program policy prohibits social engineering")
	}
	if g.policy.Constraints.NoPhysical && containsAny(haystack,
		"physical security", "tailgat") {
		return deny(d, "program policy prohibits physical-security testing")
	}

	if action.MutatesState {
		d.RequiresApproval = true
		d.Reason = "allowed; state-changing action requires approval"
	}
	return d
}

// ApplyRequiredHeaders enforces the program's required request headers. Policy
// values win over caller values so an action cannot accidentally omit or alter a
// traffic-identification header required by the program.
func ApplyRequiredHeaders(req *http.Request, decision Decision) {
	if req == nil {
		return
	}
	for k, v := range decision.RequiredHeaders {
		k = strings.TrimSpace(k)
		if k == "" || strings.TrimSpace(v) == "" {
			continue
		}
		req.Header.Set(k, v)
	}
}

func deny(d Decision, reason string) Decision {
	d.Allowed = false
	d.RequiresApproval = false
	d.Reason = reason
	return d
}

func hasScope(s scope.ScopeDefinition) bool {
	return len(s.AllowedDomains) > 0 || len(s.AllowedCIDRs) > 0
}

func pathMatches(path, blocked string) bool {
	path = normalizePath(path)
	blocked = normalizePath(blocked)
	if blocked == "/" {
		return true
	}
	return path == blocked || strings.HasPrefix(path, strings.TrimSuffix(blocked, "/")+"/")
}

func normalizePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if len(p) > 1 {
		p = strings.TrimSuffix(p, "/")
	}
	return p
}

func containsAny(s string, needles ...string) bool {
	padded := " " + s + " "
	for _, n := range needles {
		if strings.Contains(padded, strings.ToLower(n)) {
			return true
		}
	}
	return false
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
