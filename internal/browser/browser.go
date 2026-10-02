// Package browser drives a real headless Chromium (Brave/Chrome/Chromium) to
// render JavaScript applications while keeping every network request behind the
// campaign policy gateway.
package browser

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/policygateway"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/session"
)

var errNoBrowser = errors.New("browser: no Chromium-family browser found (set PENTESTSWARM_BROWSER to a Chrome/Brave/Chromium path)")

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
	HTML        string
	APIRequests []APIRequest
}

var browserCandidates = []string{
	"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
	"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
	"/Applications/Chromium.app/Contents/MacOS/Chromium",
	"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
}

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

// Fetch is retained as a fail-closed compatibility entry point. Networked
// callers must use FetchWithPolicy with the campaign gateway.
func Fetch(ctx context.Context, target string, sess *session.Session, timeout time.Duration) (*Result, error) {
	return FetchWithPolicy(ctx, target, sess, timeout, policygateway.New(policygateway.Policy{}))
}

// FetchWithPolicy renders target while pausing every browser request before it
// reaches the network. Each actual request (including redirects and
// subresources) consumes exactly one gateway decision/rate token; denied
// requests are failed inside Chromium. Policy-required headers are applied to
// the exact request that was authorized.
func FetchWithPolicy(ctx context.Context, target string, sess *session.Session, timeout time.Duration, gateway *policygateway.Gateway) (*Result, error) {
	if gateway == nil {
		return nil, &policygateway.DeniedError{Decision: policygateway.Decision{Reason: "policy gateway unavailable"}}
	}
	bin := findBrowser()
	if bin == "" {
		return nil, errNoBrowser
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	ua := session.BrowserHeaders()["User-Agent"]
	startupTimeout := 45 * time.Second
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(bin),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("headless", "new"),
		chromedp.UserAgent(ua),
		chromedp.WSURLReadTimeout(startupTimeout),
	)
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx, opts...)
	defer cancelAlloc()
	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	defer cancelBrowser()

	startupCtx, cancelStartup := context.WithTimeout(browserCtx, startupTimeout)
	if err := chromedp.Run(startupCtx); err != nil {
		cancelStartup()
		return nil, err
	}
	cancelStartup()

	runCtx, cancelTimeout := context.WithTimeout(browserCtx, timeout)
	defer cancelTimeout()

	var mu sync.Mutex
	reqs := map[network.RequestID]*APIRequest{}
	allowed := map[string]bool{}

	chromedp.ListenTarget(runCtx, func(ev interface{}) {
		switch e := ev.(type) {
		case *fetch.EventRequestPaused:
			// CDP listeners are synchronous; protocol commands from inside the
			// callback must run asynchronously or Chromium can deadlock.
			go handlePausedRequest(runCtx, e, gateway, &mu, allowed)
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

	actions := []chromedp.Action{
		network.Enable(),
		fetch.Enable(),
	}
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
		chromedp.Sleep(1500*time.Millisecond),
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
		if allowed[requestKey(r.Method, r.URL)] {
			collected = append(collected, *r)
		}
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

func handlePausedRequest(ctx context.Context, e *fetch.EventRequestPaused, gateway *policygateway.Gateway, mu *sync.Mutex, allowed map[string]bool) {
	if e == nil || e.Request == nil {
		return
	}

	execCtx := ctx
	if c := chromedp.FromContext(ctx); c != nil && c.Target != nil {
		execCtx = cdp.WithExecutor(ctx, c.Target)
	}

	raw := e.Request.URL
	if browserLocalURL(raw) {
		_ = fetch.ContinueRequest(e.RequestID).Do(execCtx)
		return
	}

	decision, err := gateway.Decide(ctx, policygateway.Action{
		ActorID:      "browser",
		Kind:         policygateway.ActionBrowser,
		Method:       e.Request.Method,
		URL:          raw,
		Path:         urlPath(raw),
		Tool:         "headless-browser",
		MutatesState: policygateway.IsMutatingMethod(e.Request.Method),
	})
	if err != nil || !decision.Allowed {
		_ = fetch.FailRequest(e.RequestID, network.ErrorReasonBlockedByClient).Do(execCtx)
		return
	}

	mu.Lock()
	allowed[requestKey(e.Request.Method, raw)] = true
	mu.Unlock()

	entries := mergeBrowserHeaders(e.Request.Headers, decision.RequiredHeaders)
	_ = fetch.ContinueRequest(e.RequestID).WithHeaders(entries).Do(execCtx)
}

func mergeBrowserHeaders(current map[string]any, required map[string]string) []*fetch.HeaderEntry {
	headers := make(map[string]string, len(current)+len(required))
	for k, v := range current {
		headers[k] = fmt.Sprint(v)
	}
	for k, v := range required {
		headers[k] = v
	}
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	entries := make([]*fetch.HeaderEntry, 0, len(keys))
	for _, k := range keys {
		entries = append(entries, &fetch.HeaderEntry{Name: k, Value: headers[k]})
	}
	return entries
}

func browserLocalURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "about", "blob", "data":
		return true
	default:
		return false
	}
}

func urlPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.EscapedPath() == "" {
		return "/"
	}
	return u.EscapedPath()
}

func requestKey(method, raw string) string {
	return strings.ToUpper(strings.TrimSpace(method)) + " " + raw
}

// filterAPI keeps only same-origin XHR/fetch calls, deduped by method+path and
// sorted for stable output.
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
			continue
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
