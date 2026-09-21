package plugins

import (
	"reflect"
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/google/uuid"
)

func TestBuildPlaybookScope(t *testing.T) {
	cases := []struct {
		target      string
		vars        map[string]string
		wantDomains []string
		wantCIDRs   []string
	}{
		{"https://shop.example.com/path", nil, []string{"shop.example.com"}, nil},
		{"example.com", nil, []string{"example.com"}, nil},
		{"10.0.0.5", nil, nil, []string{"10.0.0.5/32"}},
		{"https://shop.example.com", map[string]string{"scope": "api.example.com,10.0.0.0/24"},
			[]string{"shop.example.com", "api.example.com"}, []string{"10.0.0.0/24"}},
	}
	for _, c := range cases {
		def, err := buildPlaybookScope(c.target, c.vars)
		if err != nil {
			t.Fatalf("%s: %v", c.target, err)
		}
		if !reflect.DeepEqual(def.AllowedDomains, c.wantDomains) {
			t.Errorf("%s domains = %v, want %v", c.target, def.AllowedDomains, c.wantDomains)
		}
		if !reflect.DeepEqual(def.AllowedCIDRs, c.wantCIDRs) {
			t.Errorf("%s cidrs = %v, want %v", c.target, def.AllowedCIDRs, c.wantCIDRs)
		}
	}
}

func TestSubstituteOptions(t *testing.T) {
	vars := map[string]string{"store_path": "/shop", "unused": "x"}
	opts := map[string]any{
		"paths":     []any{"${store_path}/rest", "/static"},
		"templates": []string{"cves/${store_path}"},
		"threads":   25,
		"flag":      true,
	}
	got := substituteOptions(opts, vars)
	if p := got["paths"].([]any); p[0] != "/shop/rest" || p[1] != "/static" {
		t.Errorf("paths not substituted: %v", p)
	}
	if tpl := got["templates"].([]string); tpl[0] != "cves//shop" {
		t.Errorf("templates not substituted: %v", tpl)
	}
	if got["threads"] != 25 || got["flag"] != true {
		t.Errorf("non-string options mutated: %v", got)
	}
}

func TestPromoteFinding(t *testing.T) {
	cid := uuid.New()
	f := promoteFinding(cid, pipeline.VulnerabilityRecord{
		Tool: "nuclei", Title: "StyleSmuggler", Severity: "Critical",
		URL: "https://shop.test", Reference: "CVE-2026-75650",
	})
	if f.Severity != pipeline.SeverityCritical {
		t.Errorf("severity = %q", f.Severity)
	}
	if f.CVSSScore != 9.5 {
		t.Errorf("cvss = %v", f.CVSSScore)
	}
	if len(f.CVEIDs) != 1 || f.CVEIDs[0] != "CVE-2026-75650" {
		t.Errorf("cve ids = %v", f.CVEIDs)
	}
	// "info" normalizes to informational
	if promoteFinding(cid, pipeline.VulnerabilityRecord{Severity: "info"}).Severity != pipeline.SeverityInformational {
		t.Error("info should normalize to informational")
	}
}

func TestSafeSlug(t *testing.T) {
	cases := map[string]string{
		`CVE-2026-75650 — Magento "StyleSmuggler" RCE Hunt`: "cve-2026-75650-magento-stylesmuggler-rce-hunt",
		"":         "run",
		"  / . _ ": "run",
	}
	for in, want := range cases {
		if got := safeSlug(in); got != want {
			t.Errorf("safeSlug(%q) = %q, want %q", in, got, want)
		}
	}
}

// A phase whose tools aren't installed must not panic and must return no
// results (the coordinator skips missing binaries).
func TestRunPhase_MissingToolsNoPanic(t *testing.T) {
	e := NewExecutor(nil)
	def, _ := buildPlaybookScope("https://shop.test", nil)
	phase := Phase{Name: "x", Tools: []ToolConfig{{Name: "definitely-not-a-real-tool"}, {Name: ""}}}
	var events int
	res := e.runPhase(t.Context(), phase, "https://shop.test", def,
		nil, func(pipeline.EventType, string, string) { events++ })
	if len(res) != 0 {
		t.Errorf("expected 0 results, got %d", len(res))
	}
	if events == 0 {
		t.Error("expected at least a tool_call + skipped event")
	}
}
