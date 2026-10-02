package browser

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/policygateway"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

func TestFilterAPI(t *testing.T) {
	in := []APIRequest{
		{Method: "GET", URL: "https://app.example.com/api/orders", Type: "XHR", Status: 200},
		{Method: "POST", URL: "https://app.example.com/api/login", Type: "Fetch", Status: 200},
		{Method: "GET", URL: "https://app.example.com/api/orders?page=2", Type: "XHR"}, // dup of orders (query stripped)
		{Method: "GET", URL: "https://cdn.thirdparty.com/analytics.js", Type: "Fetch"}, // third-party → drop
		{Method: "GET", URL: "https://app.example.com/styles.css", Type: "Stylesheet"}, // not xhr/fetch → drop
		{Method: "GET", URL: "https://app.example.com/logo.png", Type: "Image"},        // drop
	}
	out := filterAPI("https://app.example.com/", in)
	if len(out) != 2 {
		t.Fatalf("expected 2 same-origin API calls, got %d: %+v", len(out), out)
	}
	for _, r := range out {
		if hostOf(r.URL) != "app.example.com" {
			t.Errorf("third-party leaked: %s", r.URL)
		}
	}
}

// End-to-end: render a page that fires an XHR and a fetch, and confirm the
// engine captured them as the app's API surface. Skips where no browser exists.
func TestFetch_CapturesAPICalls(t *testing.T) {
	if !Available() {
		t.Skip("no Chromium-family browser available")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!doctype html><html><body><h1>hi</h1>
<script>
  fetch('/api/profile');
  var x = new XMLHttpRequest(); x.open('GET','/api/orders'); x.send();
</script></body></html>`)
	})
	mux.HandleFunc("/api/profile", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("{}")) })
	mux.HandleFunc("/api/orders", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("[]")) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	res, err := Fetch(ctx, srv.URL, nil, 30*time.Second)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	got := map[string]bool{}
	for _, r := range res.APIRequests {
		got[stripQuery(r.URL)] = true
	}
	if !got[srv.URL+"/api/profile"] {
		t.Errorf("fetch() call /api/profile not captured; got %+v", res.APIRequests)
	}
	if !got[srv.URL+"/api/orders"] {
		t.Errorf("XHR /api/orders not captured; got %+v", res.APIRequests)
	}
	if res.HTML == "" {
		t.Error("expected rendered HTML")
	}
}


func TestMergeBrowserHeaders_PolicyWins(t *testing.T) {
	got := mergeBrowserHeaders(
		map[string]any{"X-Bug-Bounty": "caller", "Accept": "text/html"},
		map[string]string{"X-Bug-Bounty": "program-required"},
	)
	values := map[string]string{}
	for _, h := range got {
		values[h.Name] = h.Value
	}
	if values["X-Bug-Bounty"] != "program-required" {
		t.Fatalf("mandatory policy header did not win: %+v", values)
	}
	if values["Accept"] != "text/html" {
		t.Fatalf("existing browser header lost: %+v", values)
	}
}

func TestGatewayForTarget_LoopbackIsScoped(t *testing.T) {
	g := gatewayForTarget("http://127.0.0.1:8080/app")
	if _, err := g.Decide(context.Background(), policygateway.Action{
		Kind: policygateway.ActionBrowser,
		URL:  "http://127.0.0.1:9999/other",
	}); err != nil {
		t.Fatalf("same loopback host should remain in scope: %v", err)
	}
	if _, err := g.Decide(context.Background(), policygateway.Action{
		Kind: policygateway.ActionBrowser,
		URL:  "http://192.0.2.1/outside",
	}); err == nil {
		t.Fatal("different IP must be out of scope")
	}
}

func TestFetchWithPolicy_InjectsRequiredHeader(t *testing.T) {
	if !Available() {
		t.Skip("no Chromium-family browser available")
	}
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Bug-Bounty")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body>ok</body></html>")
	}))
	defer srv.Close()

	g := policygateway.New(policygateway.Policy{
		Scope:           scope.ScopeDefinition{AllowedCIDRs: []string{"127.0.0.0/8"}},
		RequiredHeaders: map[string]string{"X-Bug-Bounty": "authorized-research"},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	if _, err := FetchWithPolicy(ctx, srv.URL, nil, 30*time.Second, g); err != nil {
		t.Fatalf("FetchWithPolicy: %v", err)
	}
	if got != "authorized-research" {
		t.Fatalf("required header = %q, want authorized-research", got)
	}
}
