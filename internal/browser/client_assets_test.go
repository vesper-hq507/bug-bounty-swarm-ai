package browser

import "testing"

func TestFilterClientAssetsKeepsSameOriginScriptsOnly(t *testing.T) {
	in := []APIRequest{
		{Method: "GET", URL: "https://example.test/assets/app.js?v=1", Type: "Script", Status: 200},
		{Method: "GET", URL: "https://example.test/assets/app.js?v=2", Type: "Script", Status: 200},
		{Method: "GET", URL: "https://cdn.example.net/vendor.js", Type: "Script", Status: 200},
		{Method: "GET", URL: "https://example.test/api/me", Type: "Fetch", Status: 200},
	}
	got := filterClientAssets("https://example.test/", in)
	if len(got) != 1 {
		t.Fatalf("assets = %+v, want one same-origin deduplicated script", got)
	}
	if got[0].URL != "https://example.test/assets/app.js?v=1" {
		t.Fatalf("asset URL = %q", got[0].URL)
	}
}
