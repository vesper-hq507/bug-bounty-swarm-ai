package tools

import (
	"strings"
	"testing"
)

func joinArgs(a []string) string { return strings.Join(a, " ") }

func TestBuildNucleiArgs_Defaults(t *testing.T) {
	got := joinArgs(buildNucleiArgs("https://x.test", Options{}))
	if !strings.Contains(got, "-severity critical,high,medium") {
		t.Errorf("default severity missing: %s", got)
	}
	if strings.Contains(got, "-t ") || strings.Contains(got, "-tags") {
		t.Errorf("no templates/tags expected by default: %s", got)
	}
}

func TestBuildNucleiArgs_TemplatesTagsSeverity(t *testing.T) {
	opts := Options{
		"severity":  []string{"critical"},
		"templates": []string{"cves/2026/", "http/cves/2026/CVE-2026-75650.yaml"},
		"tags":      []string{"cve-2026-75650", "magento"},
	}
	got := joinArgs(buildNucleiArgs("https://shop.test", opts))
	for _, want := range []string{
		"-severity critical",
		"-t cves/2026/",
		"-t http/cves/2026/CVE-2026-75650.yaml",
		"-tags cve-2026-75650,magento",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in: %s", want, got)
		}
	}
}

func TestBuildHttpxArgs_PathsThreads(t *testing.T) {
	opts := Options{
		"paths":            []string{"/magento_version", "/rest/V1/"},
		"threads":          25,
		"follow_redirects": false,
	}
	got := joinArgs(buildHttpxArgs("https://shop.test", opts))
	if !strings.Contains(got, "-path /magento_version,/rest/V1/") {
		t.Errorf("paths not mapped: %s", got)
	}
	if !strings.Contains(got, "-threads 25") {
		t.Errorf("threads not mapped: %s", got)
	}
	if strings.Contains(got, "-follow-redirects") {
		t.Errorf("follow_redirects=false should omit the flag: %s", got)
	}
}

// options arriving from YAML unmarshal as []any, not []string — the accessors
// must still resolve them (this is the real playbook path).
func TestBuildNucleiArgs_FromYAMLShapedOptions(t *testing.T) {
	opts := Options{
		"templates": []any{"cves/2026/"},
		"tags":      []any{"cve-2026-75650"},
	}
	got := joinArgs(buildNucleiArgs("https://shop.test", opts))
	if !strings.Contains(got, "-t cves/2026/") || !strings.Contains(got, "-tags cve-2026-75650") {
		t.Errorf("[]any options not handled: %s", got)
	}
}
