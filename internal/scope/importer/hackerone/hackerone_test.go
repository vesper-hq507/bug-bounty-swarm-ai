package hackerone

import (
	"context"
	"fmt"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeH1 stands up a minimal server that answers GET
// /v1/hackers/programs/<slug>/structured_scopes with canned JSON.
func fakeH1(t *testing.T, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/structured_scopes") {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, body)
	}))
}

func TestImport_MapsAssetTypes(t *testing.T) {
	srv := fakeH1(t, `{
		"data": [
			{"attributes": {"asset_identifier": "*.acme.corp",  "asset_type": "WILDCARD",   "eligible_for_submission": true}},
			{"attributes": {"asset_identifier": "api.acme.corp","asset_type": "URL",        "eligible_for_submission": true}},
			{"attributes": {"asset_identifier": "10.0.0.0/24",  "asset_type": "CIDR",       "eligible_for_submission": true}},
			{"attributes": {"asset_identifier": "1.2.3.4",      "asset_type": "IP_ADDRESS", "eligible_for_submission": true}},
			{"attributes": {"asset_identifier": "not-in-scope.corp","asset_type": "DOMAIN", "eligible_for_submission": false}},
			{"attributes": {"asset_identifier": "ios-app",      "asset_type": "IOS_APP",    "eligible_for_submission": true}}
		]
	}`)
	defer srv.Close()

	c := NewClient(Config{})
	c.baseURL = srv.URL + "/v1" // point at fake

	def, err := c.Import(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	// WILDCARD + URL land in AllowedDomains, ineligible item dropped, unsupported type dropped.
	wantDomains := map[string]bool{"*.acme.corp": true, "api.acme.corp": true}
	if len(def.AllowedDomains) != len(wantDomains) {
		t.Fatalf("domains: want 2, got %v", def.AllowedDomains)
	}
	for _, d := range def.AllowedDomains {
		if !wantDomains[d] {
			t.Errorf("unexpected domain %q", d)
		}
	}
	// CIDR passes through; bare IP becomes /32.
	wantCIDRs := map[string]bool{"10.0.0.0/24": true, "1.2.3.4/32": true}
	for _, c := range def.AllowedCIDRs {
		if !wantCIDRs[c] {
			t.Errorf("unexpected cidr %q", c)
		}
	}
	if len(def.AllowedCIDRs) != 2 {
		t.Fatalf("cidrs: want 2, got %v", def.AllowedCIDRs)
	}
}

func TestImport_AuthHeaderWhenCredentialsProvided(t *testing.T) {
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{}})
	}))
	defer srv.Close()

	c := NewClient(Config{APIUser: "akhil", APIToken: "tkn"})
	c.baseURL = srv.URL + "/v1"
	_, _ = c.Import(context.Background(), "acme")

	if !strings.HasPrefix(seen, "Basic ") {
		t.Fatalf("expected Basic auth header; got %q", seen)
	}
}

func TestPublicReports_ParsesHacktivityFeed(t *testing.T) {
	body := `{
		"data": [
			{"id":"r1","attributes":{"title":"Reflected XSS in /search","state":"resolved"}},
			{"id":"r2","attributes":{"title":"SSRF via image fetch","state":"triaged"}}
		]
	}`
	var sawSlug bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.RawQuery, "team_handle:acme") {
			http.NotFound(w, r)
			return
		}
		sawSlug = true
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()

	c := NewClient(Config{})
	c.baseURL = srv.URL + "/v1"
	got, err := c.PublicReports(context.Background(), "acme", 50)
	if err != nil {
		t.Fatal(err)
	}
	if !sawSlug {
		t.Error("query string did not include team_handle filter")
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 reports, got %d", len(got))
	}
	if got[0].Title != "Reflected XSS in /search" || got[0].Program != "acme" {
		t.Errorf("first report wrong: %+v", got[0])
	}
}

func TestPublicReports_HTTPErrorSurfaced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer srv.Close()
	c := NewClient(Config{})
	c.baseURL = srv.URL + "/v1"
	if _, err := c.PublicReports(context.Background(), "acme", 10); err == nil {
		t.Error("want error on 429")
	}
}

func TestImport_SurfacesHTTPErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":["not found"]}`, http.StatusNotFound)
	}))
	defer srv.Close()

	c := NewClient(Config{})
	c.baseURL = srv.URL + "/v1"
	_, err := c.Import(context.Background(), "unknown")
	if err == nil {
		t.Fatal("want error on 404")
	}
}


func TestReportsParsesRichHistoryAndPaginates(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/hackers/me/reports" {
			http.NotFound(w, r)
			return
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
			http.Error(w, "missing auth", http.StatusUnauthorized)
			return
		}
		calls++
		page := r.URL.Query().Get("page[number]")
		var data []map[string]any
		switch page {
		case "1":
			data = make([]map[string]any, 0, 100)
			for i := 1; i <= 100; i++ {
				item := map[string]any{
					"id": fmt.Sprintf("r%d", i),
					"attributes": map[string]any{
						"title": fmt.Sprintf("Report %d", i),
						"state": "resolved",
						"created_at": "2026-09-01T12:00:00Z",
					},
				}
				if i == 1 {
					item["attributes"] = map[string]any{
						"title": "Object authorization weakness",
						"state": "resolved",
						"created_at": "2026-09-01T12:00:00Z",
						"vulnerability_information": "GET https://api.example.test/api/invoices/123?invoice_id=123 HTTP/1.1",
					}
					item["relationships"] = map[string]any{
						"program": map[string]any{"data": map[string]any{"attributes": map[string]any{"handle": "acme"}}},
						"severity": map[string]any{"data": map[string]any{"attributes": map[string]any{"rating": "high"}}},
						"weakness": map[string]any{"data": map[string]any{"attributes": map[string]any{
							"name": "Authorization Bypass Through User-Controlled Key",
							"external_id": "CWE-639",
						}}},
						"structured_scope": map[string]any{"data": map[string]any{"attributes": map[string]any{
							"asset_identifier": "https://api.example.test",
							"asset_type": "URL",
						}}},
					}
				}
				data = append(data, item)
			}
		case "2":
			data = []map[string]any{{
				"id": "r101",
				"attributes": map[string]any{"title": "Report 101", "state": "triaged"},
			}}
		}
		if err := json.NewEncoder(w).Encode(map[string]any{"data": data}); err != nil {
			t.Fatal(err)
		}
	}))
	defer srv.Close()

	client := NewClient(Config{APIUser: "researcher", APIToken: "token"})
	client.baseURL = srv.URL + "/v1"
	got, err := client.Reports(context.Background(), 101)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(got) != 101 {
		t.Fatalf("calls=%d reports=%d", calls, len(got))
	}
	first := got[0]
	if first.Program != "acme" || first.Severity != "high" ||
		first.WeaknessExternalID != "CWE-639" || first.AssetIdentifier != "https://api.example.test" {
		t.Fatalf("rich report metadata = %+v", first)
	}
	if first.CreatedAt.IsZero() || first.VulnerabilityInformation == "" {
		t.Fatalf("rich report timestamps/narrative missing: %+v", first)
	}
	if got[100].ID != "r101" {
		t.Fatalf("second page not retained: %+v", got[100])
	}
}
