package tools

import "testing"

func TestWafw00fTool_Name(t *testing.T) {
	if n := NewWafw00fTool().Name(); n != "wafw00f" {
		t.Errorf("Name() = %q, want \"wafw00f\"", n)
	}
}

func TestWafw00fTool_IsAvailable(t *testing.T) { _ = NewWafw00fTool().IsAvailable() }

// TestParseWafw00fJSON_Detected — a detected WAF carries the firewall
// name, manufacturer and trigger url through as an "info" finding.
func TestParseWafw00fJSON_Detected(t *testing.T) {
	input := []byte(`[
		{
			"url": "https://target.example.com",
			"detected": true,
			"trigger_url": "https://target.example.com/?a=<script>",
			"firewall": "Cloudflare",
			"manufacturer": "Cloudflare Inc."
		}
	]`)
	findings := parseWafw00fJSON(input)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f["tool"] != "wafw00f" {
		t.Errorf("tool = %v", f["tool"])
	}
	if f["severity"] != "info" {
		t.Errorf("severity = %v, want \"info\"", f["severity"])
	}
	if f["firewall"] != "Cloudflare" || f["manufacturer"] != "Cloudflare Inc." {
		t.Errorf("firewall/manufacturer not carried through: %+v", f)
	}
	if f["trigger_url"] != "https://target.example.com/?a=<script>" {
		t.Errorf("trigger_url wrong: %+v", f)
	}
	if f["url"] != "https://target.example.com" {
		t.Errorf("url wrong: %+v", f)
	}
}

// TestParseWafw00fJSON_NotDetected — a clean result still emits one
// finding recording that no WAF was found.
func TestParseWafw00fJSON_NotDetected(t *testing.T) {
	input := []byte(`[
		{
			"url": "https://target.example.com",
			"detected": false,
			"trigger_url": null,
			"firewall": "None",
			"manufacturer": "None"
		}
	]`)
	findings := parseWafw00fJSON(input)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0]["firewall"] != "None" || findings[0]["title"] != "No WAF detected" {
		t.Errorf("not-detected shape wrong: %+v", findings[0])
	}
	if findings[0]["severity"] != "info" {
		t.Errorf("severity = %v, want \"info\"", findings[0]["severity"])
	}
}

// TestParseWafw00fJSON_MultipleFindAll — with --findall wafw00f emits
// one record per matching WAF; each becomes its own finding.
func TestParseWafw00fJSON_MultipleFindAll(t *testing.T) {
	input := []byte(`[
		{"url": "https://x.example.com", "detected": true, "firewall": "Cloudflare", "manufacturer": "Cloudflare Inc."},
		{"url": "https://x.example.com", "detected": true, "firewall": "ModSecurity", "manufacturer": "SpiderLabs"}
	]`)
	findings := parseWafw00fJSON(input)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[1]["firewall"] != "ModSecurity" {
		t.Errorf("second finding firewall wrong: %+v", findings[1])
	}
}

func TestParseWafw00fJSON_MalformedReturnsNil(t *testing.T) {
	for _, c := range [][]byte{nil, []byte(""), []byte("{not json"), []byte("garbage")} {
		if got := parseWafw00fJSON(c); got != nil {
			t.Errorf("input %q should produce nil, got %v", c, got)
		}
	}
}
