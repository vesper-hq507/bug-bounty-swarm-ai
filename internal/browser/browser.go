// Package browser drives a real headless Chromium (Brave/Chrome/Chromium) to
// reach applications a plain HTTP client cannot: JavaScript-rendered single-page
// apps, sites behind a JS challenge (Cloudflare "just a moment"), and — most
// valuably — it CAPTURES THE UNDERLYING API CALLS the page makes, so the swarm
// discovers the real back-end surface (the XHR/fetch endpoints that appear in no
// crawlable link) the way a human proxying their browser would.
//
// A bug-bounty hunter flagged that a plain Go HTTP client gets fingerprinted and
// blocked and can't drive a modern frontend. This is the engine half of the fix
// (the header/fingerprint half lives in internal/session). It is optional and
// degrades gracefully: Available() reports whether a usable browser binary
// exists, and callers fall back to plain HTTP when it does not.
package browser

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	cdfetch "github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/policygateway"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/session"
)

// errNoBrowser is returned when no Chromium-family binary is available.
var errNoBrowser = errors.New("browser: no Chromium-family binary found (set PENTESTSWARM_BROWSER to a Chrome/Brave/Chromium path)")

// APIRequest is one back-end call the page made while rendering.
type APIRequest struct {
	Method string
	URL    string
	Type   string // "XHR" | "Fetch"
	Status int
}

// Result is a rendered page plus the API surface it exercised.
type Result struct {
	URL         string
	FinalURL    string
	Title       string
	HTML        string       // fully rendered DOM
	APIRequests []APIRequest // same-origin XHR/fetch calls, deduped
}

// browserCandidates are the Chromium-family binaries we can drive, in order.
var browserCandidates = []string{
	"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
	"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
	"/Applications/Chromium.app/Contents/MacOS/Chromium",
	"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
}

// findBrowser returns the path to a usable Chromium-family binary, or "".
func findBrowser() string {
	if env := os.Getenv("PENTESTSWARM_BROWSER"); env != "" {
		if isExec(env) {
			return env
		}
	}
	for _, c := range browserCandidates {
		if isExec(c) {
			return c
		}
	}
	for _, n := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "brave-browser", "chrome"} {
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}
	return ""
}

func isExec(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir() && info.Mode()&0o111 != 0
}

// Available reports whether a headless browser can be driven on this machine.
func Available() bool { return findBrowser() != "" }

// Fetch renders url in a real headless browser and returns the rendered DOM plus
// the same-origin API calls the page made. sess (optional) supplies auth headers
// so authenticated SPAs render as a logged-in user. It is safe to call only on
// authorized, in-scope targets.
func Fetch(ctx context.Context, target string, sess *session.Session, timeout time.Duration) (*Result, error) {
	return FetchWithPolicy(ctx, target, sess, timeout, gatewayForTarget(target))
}

// FetchWithPolicy renders a target while intercepting every HTTP(S) request at
// the Chrome DevTools Fetch domain. Each request is authorized independently,
// so redirects, subresources and frontend XHR/fetch calls cannot bypass scope,
// rate or mandatory-header policy.
func FetchWithPolicy(ctx context.Context, target string, sess *session.Session, timeout time.Duration, gateway *policygateway.Gateway) (*Result, error) {
	if gateway == nil {
		return nil, &policygateway.DeniedError{Decision: policygateway.Decision{Reason: "policy gateway unavailable"}}
	}
	if _, err := gateway.Decide(ctx, policygateway.Action{
		ActorID: "browser",
		Kind:    policygateway.ActionBrowser,
		Method:  http.MethodGet,
		URL:     target,
		Tool:    "browser-navigation",
	}); err != nil {
		return nil, err
	}

	bin := findBrowser()
	if bin == "" {
		return nil, errNoBrowser
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	ua := session.BrowserHeaders()["User-Agent"]
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(bin),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("headless", "new"),
		chromedp.UserAgent(ua),
	)
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx, opts...)
	defer cancelAlloc()
	runCtx, cancelRun := chromedp.NewContext(allocCtx)
	defer cancelRun()
	runCtx, cancelTimeout := context.WithTimeout(runCtx, timeout)
	defer cancelTimeout()

	// Capture network events and enforce policy on every paused request. CDP
	// callbacks must not synchronously issue commands back to the target, so the
	// continue/fail decision runs in a small goroutine with the target executor.
	var mu sync.Mutex
	reqs := map[network.RequestID]*APIRequest{}
	chromedp.ListenTarget(runCtx, func(ev interface{}) {
		switch e := ev.(type) {
		case *cdfetch.EventRequestPaused:
			go handlePausedRequest(runCtx, gateway, e)
		case *network.EventRequestWillBeSent:
			mu.Lock()
			reqs[e.RequestID] = &APIRequest{Method: e.Request.Method, URL: e.Request.URL, Type: e.Type.String()}
			mu.Unlock()
		case *network.EventResponseReceived:
			mu.Lock()
			if r, ok := reqs[e.RequestID]; ok {
				r.Status = int(e.Response.Status)
			}
			mu.Unlock()
		}
	})

	actions := []chromedp.Action{network.Enable(), cdfetch.Enable()}
	if !sess.Empty() {
		h := network.Headers{}
		for k, v := range sess.Headers {
			h[k] = v
		}
		actions = append(actions, network.SetExtraHTTPHeaders(h))
	}
	var html, title, finalURL string
	actions = append(actions,
		chromedp.Navigate(target),
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.Sleep(1500*time.Millisecond), // let post-load XHR/fetch fire
		chromedp.OuterHTML("html", &html, chromedp.ByQuery),
		chromedp.Title(&title),
		chromedp.Location(&finalURL),
	)
	if err := chromedp.Run(runCtx, actions...); err != nil {
		return nil, err
	}

	mu.Lock()
	collected := make([]APIRequest, 0, len(reqs))
	for _, r := range reqs {
		collected = append(collected, *r)
	}
	mu.Unlock()

	return &Result{
		URL:         target,
		FinalURL:    finalURL,
		Title:       title,
		HTML:        html,
		APIRequests: filterAPI(target, collected),
	}, nil
}

// filterAPI keeps only same-origin XHR/fetch calls (the app's own back-end API),
// deduped by method+path and sorted for stable output. Third-party analytics,
// fonts, and static assets are dropped.
func filterAPI(target string, in []APIRequest) []APIRequest {
	host := hostOf(target)
	seen := map[string]bool{}
	var out []APIRequest
	for _, r := range in {
		t := strings.ToLower(r.Type)
		if t != "xhr" && t != "fetch" {
			continue
		}
		if host != "" && hostOf(r.URL) != host {
			continue // same-origin only
		}
		key := r.Method + " " + stripQuery(r.URL)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

func stripQuery(raw string) string {
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		return raw[:i]
	}
	return raw
}


func handlePausedRequest(runCtx context.Context, gateway *policygateway.Gateway, e *cdfetch.EventRequestPaused) {
	if e == nil || e.Request == nil {
		return
	}
	exec := chromedp.FromContext(runCtx)
	if exec == nil || exec.Target == nil {
		return
	}
	cmdCtx := cdp.WithExecutor(runCtx, exec.Target)

	u, err := url.Parse(e.Request.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		_ = cdfetch.ContinueRequest(e.RequestID).Do(cmdCtx)
		return
	}

	decision, derr := gateway.Decide(runCtx, policygateway.Action{
		ActorID:      "browser",
		Kind:         policygateway.ActionBrowser,
		Method:       e.Request.Method,
		URL:          e.Request.URL,
		Path:         u.EscapedPath(),
		Tool:         "browser",
		MutatesState: policygateway.IsMutatingMethod(e.Request.Method),
	})
	if derr != nil || !decision.Allowed {
		_ = cdfetch.FailRequest(e.RequestID, network.ErrorReasonBlockedByClient).Do(cmdCtx)
		return
	}

	params := cdfetch.ContinueRequest(e.RequestID)
	if len(decision.RequiredHeaders) > 0 {
		params = params.WithHeaders(mergeBrowserHeaders(e.Request.Headers, decision.RequiredHeaders))
	}
	_ = params.Do(cmdCtx)
}

func mergeBrowserHeaders(existing network.Headers, required map[string]string) []*cdfetch.HeaderEntry {
	merged := make(map[string]string, len(existing)+len(required))
	for k, v := range existing {
		merged[http.CanonicalHeaderKey(k)] = fmt.Sprint(v)
	}
	for k, v := range required {
		merged[http.CanonicalHeaderKey(k)] = v
	}
	keys := make([]string, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]*cdfetch.HeaderEntry, 0, len(keys))
	for _, k := range keys {
		out = append(out, &cdfetch.HeaderEntry{Name: k, Value: merged[k]})
	}
	return out
}

func gatewayForTarget(target string) *policygateway.Gateway {
	def := scope.ScopeDefinition{}
	u, err := url.Parse(target)
	if err == nil {
		host := u.Hostname()
		if ip := net.ParseIP(host); ip != nil {
			if ip.To4() != nil {
				def.AllowedCIDRs = []string{host + "/32"}
			} else {
				def.AllowedCIDRs = []string{host + "/128"}
			}
		} else if host != "" {
			def.AllowedDomains = []string{host}
		}
	}
	return policygateway.New(policygateway.Policy{Scope: def})
}
