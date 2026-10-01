package browser

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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
