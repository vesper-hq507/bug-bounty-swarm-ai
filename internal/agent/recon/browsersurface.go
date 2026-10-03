package recon

import (
	"context"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/browser"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/policygateway"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/session"
)

// DiscoverBrowserSurface drives a real headless browser to render a URL target
// and returns the back-end API endpoints the page actually called — the XHR/
// fetch surface that a JS single-page app exposes but that appears in no
// crawlable link. This reaches applications a plain HTTP client cannot: JS-
// rendered frontends and sites behind a JS challenge. Returns nil when no
// browser is available (the caller falls back to HTTP-only discovery).
func DiscoverBrowserSurface(ctx context.Context, target string, scopeDef *scope.ScopeDefinition, sess *session.Session) []pipeline.EndpointRecord {
	return DiscoverBrowserSurfaceWithPolicy(ctx, target, scopeDef, sess, nil)
}

// BrowserSurface contains API endpoints and same-origin client scripts observed
// during one policy-governed browser render.
type BrowserSurface struct {
	Endpoints    []pipeline.EndpointRecord
	ClientAssets []pipeline.ClientAssetRecord
}

// DiscoverBrowserSurfaceWithPolicy uses CDP interception and returns only the
// API endpoint compatibility view.
func DiscoverBrowserSurfaceWithPolicy(ctx context.Context, target string, scopeDef *scope.ScopeDefinition, sess *session.Session, gateway *policygateway.Gateway) []pipeline.EndpointRecord {
	return DiscoverBrowserArtifactsWithPolicy(ctx, target, scopeDef, sess, gateway).Endpoints
}

// DiscoverBrowserArtifactsWithPolicy returns API endpoints plus same-origin
// script assets from one rendered page without downloading script bodies.
func DiscoverBrowserArtifactsWithPolicy(ctx context.Context, target string, scopeDef *scope.ScopeDefinition, sess *session.Session, gateway *policygateway.Gateway) BrowserSurface {
	if !isURLTarget(target) || !browser.Available() {
		return BrowserSurface{}
	}
	if scopeDef != nil {
		if err := scope.ValidateAndLog("browser-discovery", target, *scopeDef); err != nil {
			return BrowserSurface{}
		}
	}
	gateway = reconGatewayForTarget(target, scopeDef, gateway)
	actor := browser.ActorContext{ActorID: "browser"}
	if recorder := observationRecorderFromContext(ctx); recorder != nil {
		actor.CampaignID = recorder.campaignID.String()
		if recorder.identityID != "" {
			actor.ActorID = recorder.identityID
			actor.IdentityAlias = recorder.identityAlias
		}
	}
	res, err := browser.FetchWithPolicyAs(ctx, target, sess, 30*time.Second, gateway, actor)
	if err != nil || res == nil {
		return BrowserSurface{}
	}
	if recorder := observationRecorderFromContext(ctx); recorder != nil {
		if res.Navigation != nil {
			r := res.Navigation
			recorder.recordNetwork(r.Method, r.URL, r.Status, r.ActionID, r.DecisionID, r.PolicyVersion, "browser", "headless-browser")
		}
		for i := range res.APIRequests {
			r := &res.APIRequests[i]
			recorder.recordNetwork(r.Method, r.URL, r.Status, r.ActionID, r.DecisionID, r.PolicyVersion, "browser", "headless-browser")
		}
		for i := range res.ClientAssets {
			r := &res.ClientAssets[i]
			recorder.recordNetwork(r.Method, r.URL, r.Status, r.ActionID, r.DecisionID, r.PolicyVersion, "browser", "client-script")
		}
	}
	out := make([]pipeline.EndpointRecord, 0, len(res.APIRequests))
	for _, r := range res.APIRequests {
		protocol := "http"
		if strings.EqualFold(r.Type, "EventSource") {
			protocol = "sse"
		}
		out = append(out, pipeline.EndpointRecord{
			URL:         r.URL,
			Method:      r.Method,
			Protocol:    protocol,
			StatusCode:  r.Status,
			Interesting: true, // captured live from the app's own frontend
			Notes:       "discovered via headless browser (" + r.Type + " call made by the page) — real back-end application surface",
		})
	}
	assets := make([]pipeline.ClientAssetRecord, 0, len(res.ClientAssets))
	for _, r := range res.ClientAssets {
		assets = append(assets, pipeline.ClientAssetRecord{
			URL: r.URL, Kind: "javascript", StatusCode: r.Status,
		})
	}
	return BrowserSurface{Endpoints: out, ClientAssets: assets}
}
