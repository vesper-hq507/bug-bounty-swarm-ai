package recon

import (
	"context"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/browser"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
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
	if !isURLTarget(target) || !browser.Available() {
		return nil
	}
	if scopeDef != nil {
		if err := scope.ValidateAndLog("browser-discovery", target, *scopeDef); err != nil {
			return nil
		}
	}
	res, err := browser.Fetch(ctx, target, sess, 30*time.Second)
	if err != nil || res == nil {
		return nil
	}
	out := make([]pipeline.EndpointRecord, 0, len(res.APIRequests))
	for _, r := range res.APIRequests {
		out = append(out, pipeline.EndpointRecord{
			URL:         r.URL,
			Method:      r.Method,
			StatusCode:  r.Status,
			Interesting: true, // captured live from the app's own frontend
			Notes:       "discovered via headless browser (" + r.Type + " call made by the page) — real back-end API surface, not crawlable",
		})
	}
	return out
}
