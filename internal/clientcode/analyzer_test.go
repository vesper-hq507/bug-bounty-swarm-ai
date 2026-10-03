package clientcode

import (
	"strings"
	"testing"
)

func TestAnalyzeExtractsBoundedSignals(t *testing.T) {
	js := []byte(strings.Join([]string{
		`fetch('/api/orders?owner_id=42')`,
		`const ws = new WebSocket('wss://app.example.test/ws')`,
		`const events = new EventSource('/events')`,
		`params.get('owner_id')`,
		`isFeatureEnabled('new-billing')`,
		`if (user.role === 'admin') { transitionTo('approved') }`,
		`//# sourceMappingURL=app.js.map`,
	}, "\n"))

	got, err := Analyze("https://app.example.test/assets/app.js", js, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Summary.SourceMapURL != "app.js.map" {
		t.Fatalf("source map URL = %q", got.Summary.SourceMapURL)
	}
	assertContains(t, got.Summary.Routes, "https://app.example.test/api/orders?owner_id=42")
	assertContains(t, got.Summary.RealtimeEndpoints, "wss://app.example.test/ws")
	assertContains(t, got.Summary.RealtimeEndpoints, "https://app.example.test/events")
	assertContains(t, got.Summary.Parameters, "owner_id")
	assertContains(t, got.Summary.FeatureFlags, "new-billing")
	assertContains(t, got.Summary.RoleHints, "admin")
	assertContains(t, got.Summary.WorkflowStates, "approved")
}

func TestAnalyzeSourceMapSourcesContent(t *testing.T) {
	js := []byte(`console.log('bundle')`)
	sm := []byte(`{"version":3,"sources":["src/api.ts","src/auth.ts"],"sourcesContent":["fetch('/api/private')","roles.includes('manager')"]}`)

	got, err := Analyze("https://app.example.test/app.js", js, sm)
	if err != nil {
		t.Fatal(err)
	}
	if got.Summary.SourceMapHash == "" || len(got.Summary.SourceFiles) != 2 {
		t.Fatalf("source-map summary = %+v", got.Summary)
	}
	assertContains(t, got.Summary.Routes, "https://app.example.test/api/private")
	assertContains(t, got.Summary.RoleHints, "manager")
}

func TestAnalyzeRejectsOversizedAsset(t *testing.T) {
	_, err := Analyze("https://example.test/app.js", make([]byte, MaxAssetBytes+1), nil)
	if err == nil {
		t.Fatal("oversized asset must fail")
	}
}

func TestAnalyzeDoesNotPromoteStaticAssetsToRoutes(t *testing.T) {
	got, err := Analyze("https://example.test/app.js", []byte(`const x='/assets/logo.svg'; const y='/api/me'`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if contains(got.Summary.Routes, "https://example.test/assets/logo.svg") {
		t.Fatalf("static asset leaked into routes: %+v", got.Summary.Routes)
	}
	assertContains(t, got.Summary.Routes, "https://example.test/api/me")
}

func assertContains(t *testing.T, got []string, want string) {
	t.Helper()
	if !contains(got, want) {
		t.Fatalf("%q not found in %#v", want, got)
	}
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
