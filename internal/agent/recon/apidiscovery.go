package recon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/policygateway"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/session"
)

// DiscoverAPISurface actively probes a URL target for the API endpoints that
// passive recon cannot reach. Single-page apps serve their back-end API over
// JSON routes that appear in no crawlable link, so katana/gau never see them
// and the exploit agent — which turns endpoints into authenticated
// business-logic attacks (BOLA/IDOR, mass assignment) — gets nothing to work
// with. This closes that gap two ways:
//
//  1. Application fingerprinting: probe a small set of signature routes for
//     known apps; on a match, emit that app's documented API surface enriched
//     with concrete attack-hint notes the planner can build httpreq chains
//     from. A fingerprint that doesn't match contributes nothing, so a scan of
//     an unrelated target is unaffected.
//
// Every probe and every emitted endpoint is scope-validated against the target
// host, identical to the tool-adapter path. Discovery is best-effort: probe
// errors (host down, timeout) simply yield no endpoints rather than failing
// the recon phase.
func DiscoverAPISurface(ctx context.Context, target string, scopeDef *scope.ScopeDefinition, sess *session.Session) []pipeline.EndpointRecord {
	return DiscoverAPISurfaceWithPolicy(ctx, target, scopeDef, sess, nil)
}

// DiscoverAPISurfaceWithPolicy is the policy-enforced form used by campaign
// runners. A nil gateway falls back to a scope-only fail-closed gateway so
// existing direct callers remain safe.
func DiscoverAPISurfaceWithPolicy(ctx context.Context, target string, scopeDef *scope.ScopeDefinition, sess *session.Session, gateway *policygateway.Gateway) []pipeline.EndpointRecord {
	base := strings.TrimRight(target, "/")
	if base == "" {
		return nil
	}
	if scopeDef != nil {
		if err := scope.ValidateAndLog("api-discovery", base, *scopeDef); err != nil {
			return nil
		}
	}

	gateway = reconGatewayForTarget(base, scopeDef, gateway)
	client := newReconHTTPClient(gateway, "api-discovery", sess)

	var out []pipeline.EndpointRecord
	for _, p := range apiProfiles {
		if p.matches(ctx, base, client) {
			out = append(out, p.endpoints(base)...)
		}
	}

	// Generalize beyond the curated app profiles: any target that publishes
	// its own OpenAPI/Swagger spec yields a real endpoint surface, not just
	// the handful of named applications above.
	out = mergeEndpoints(out, DiscoverOpenAPIWithPolicy(ctx, base, scopeDef, sess, gateway))
	return out
}

// DiscoverPlaybooks returns the verified attack chains of every fingerprinted
// application at the target. Unlike endpoints (which the LLM turns into
// improvised chains), a playbook is a ready-to-run chain the exploit agent
// executes deterministically — so a known high-value finding (crAPI's BOLA)
// lands reliably instead of depending on the model reconstructing it. Probing
// and scope rules match DiscoverAPISurface.
func DiscoverPlaybooks(ctx context.Context, target string, scopeDef *scope.ScopeDefinition, sess *session.Session) []pipeline.AttackPath {
	return DiscoverPlaybooksWithPolicy(ctx, target, scopeDef, sess, nil)
}

// DiscoverPlaybooksWithPolicy fingerprints known applications through the same
// request-level gateway as the rest of campaign recon.
func DiscoverPlaybooksWithPolicy(ctx context.Context, target string, scopeDef *scope.ScopeDefinition, sess *session.Session, gateway *policygateway.Gateway) []pipeline.AttackPath {
	base := strings.TrimRight(target, "/")
	if base == "" {
		return nil
	}
	if scopeDef != nil {
		if err := scope.ValidateAndLog("api-discovery", base, *scopeDef); err != nil {
			return nil
		}
	}
	gateway = reconGatewayForTarget(base, scopeDef, gateway)
	client := newReconHTTPClient(gateway, "playbook-discovery", sess)
	var out []pipeline.AttackPath
	for _, p := range apiProfiles {
		if p.chains == nil {
			continue
		}
		if p.matches(ctx, base, client) {
			out = append(out, p.chains(base)...)
		}
	}
	return out
}


func reconGateway(scopeDef *scope.ScopeDefinition, gateway *policygateway.Gateway) *policygateway.Gateway {
	if gateway != nil {
		return gateway
	}
	policy := policygateway.Policy{}
	if scopeDef != nil {
		policy.Scope = *scopeDef
	}
	return policygateway.New(policy)
}

// reconGatewayForTarget preserves the package-level discovery helpers while
// remaining fail-closed: when the caller supplies no scope, only the exact
// target host is authorized. Campaign runners still pass their richer gateway.
func reconGatewayForTarget(target string, scopeDef *scope.ScopeDefinition, gateway *policygateway.Gateway) *policygateway.Gateway {
	if gateway != nil || scopeDef != nil {
		return reconGateway(scopeDef, gateway)
	}

	def := scope.ScopeDefinition{}
	host := strings.TrimSpace(target)
	if u, err := url.Parse(target); err == nil && u.Hostname() != "" {
		host = u.Hostname()
	}
	host = strings.TrimSpace(strings.TrimSuffix(host, "."))
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			def.AllowedCIDRs = []string{ip.String() + "/32"}
		} else {
			def.AllowedCIDRs = []string{ip.String() + "/128"}
		}
	} else if host != "" {
		def.AllowedDomains = []string{host}
	}
	return policygateway.New(policygateway.Policy{Scope: def})
}

func newReconHTTPClient(gateway *policygateway.Gateway, actor string, sess *session.Session) *http.Client {
	policyTransport := policygateway.NewHTTPTransport(gateway, http.DefaultTransport, func(r *http.Request) policygateway.Action {
		campaignID := ""
		actorID := actor
		metadata := map[string]string{}
		if recorder := observationRecorderFromContext(r.Context()); recorder != nil {
			campaignID = recorder.campaignID.String()
			if recorder.identityID != "" {
				actorID = recorder.identityID
				if recorder.identityAlias != "" {
					metadata["identity_alias"] = recorder.identityAlias
				}
				metadata["agent"] = actor
			}
		}
		return policygateway.Action{
			ActionID:     actor + ":" + strings.ToUpper(r.Method) + ":" + r.URL.String(),
			CampaignID:   campaignID,
			ActorID:      actorID,
			Kind:         policygateway.ActionHTTP,
			Method:       r.Method,
			URL:          r.URL.String(),
			Path:         r.URL.EscapedPath(),
			Tool:         actor,
			MutatesState: policygateway.IsMutatingMethod(r.Method),
			Metadata:     metadata,
		}
	})
	client := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &observingTransport{base: policyTransport, actor: actor, tool: actor},
	}
	return sess.Wrap(client)
}

// probeStatus issues a request and returns the response status code, or 0 on a
// transport error. A tiny JSON body is sent so routes that only accept POST
// with a content-type still route (a bad body yields 400, which — crucially —
// is not 404, i.e. the route exists).
func probeStatus(ctx context.Context, client *http.Client, method, url string) int {
	reqCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	var body *strings.Reader = strings.NewReader("{}")
	req, err := http.NewRequestWithContext(reqCtx, method, url, body)
	if err != nil {
		return 0
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// signatureRoute is one fingerprint probe: hitting method+path should return a
// status that proves the route exists (anything but 404 / a transport error).
type signatureRoute struct {
	method string
	path   string
}

// apiProfile is a curated API surface for a known application: a set of
// signature routes that fingerprint it, the endpoints to emit on a match, and
// (optionally) verified attack chains to run deterministically.
type apiProfile struct {
	name       string
	signatures []signatureRoute
	build      func(base string) []pipeline.EndpointRecord
	chains     func(base string) []pipeline.AttackPath
}

// matches reports whether the target is running this application. Every
// signature route must resolve to a non-404, non-5xx status — but only after a
// NEGATIVE CONTROL proves the app actually 404s on paths that cannot exist.
//
// Without that control, "signature route is non-404" identifies nothing: a
// catch-all router, a single-page app, or a WAF that answers 401/403/200 for
// EVERYTHING passes every profile's signatures and gets mis-fingerprinted (e.g.
// a 401 on /identity/ making an unrelated app look like crAPI, then getting
// crAPI-specific attack chains fired at it). So we first confirm the app
// distinguishes real routes from garbage; if it doesn't, we refuse to
// fingerprint. Reported by Vamsi (#6).
func (p apiProfile) matches(ctx context.Context, base string, client *http.Client) bool {
	if len(p.signatures) == 0 {
		return false
	}
	// Negative control: random paths that cannot exist must return 404. If the
	// app answers anything else (including a transport error → 0), its non-404s
	// carry no information and we can't fingerprint on them.
	tok := randomToken()
	for _, ctrl := range []string{"/" + tok, "/api/" + tok} {
		if code := probeStatus(ctx, client, "GET", base+ctrl); code != http.StatusNotFound {
			return false
		}
	}
	for _, s := range p.signatures {
		code := probeStatus(ctx, client, s.method, base+s.path)
		if code == 0 || code == http.StatusNotFound || code >= 500 {
			return false
		}
	}
	return true
}

// randomToken returns a short random hex string for negative-control probes.
func randomToken() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "zzq9xk3n7t2wq1"
	}
	return "nx-" + hex.EncodeToString(b)
}

// endpoints returns the profile's API surface for the given base URL.
func (p apiProfile) endpoints(base string) []pipeline.EndpointRecord {
	return p.build(base)
}

// apiProfiles is the registry of known-application fingerprints. Add a profile
// here to teach recon a new target's API surface.
var apiProfiles = []apiProfile{crapiProfile, vampiProfile, dvgaProfile}
