package cli

import "testing"

func TestRealtimeProtocolAuto(t *testing.T) {
	cases := map[string]string{
		"https://example.test/events": "sse",
		"http://example.test/events":  "sse",
		"wss://example.test/ws":       "websocket",
		"ws://example.test/ws":        "websocket",
	}
	for rawURL, want := range cases {
		got, err := realtimeProtocol("auto", rawURL)
		if err != nil {
			t.Fatalf("%s: %v", rawURL, err)
		}
		if got != want {
			t.Fatalf("%s: got %q want %q", rawURL, got, want)
		}
	}
}

func TestRealtimeScopeSeparatesDomainsAndCIDRs(t *testing.T) {
	got, err := realtimeScope([]string{"example.test,192.0.2.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.AllowedDomains) != 1 || got.AllowedDomains[0] != "example.test" {
		t.Fatalf("domains = %#v", got.AllowedDomains)
	}
	if len(got.AllowedCIDRs) != 1 || got.AllowedCIDRs[0] != "192.0.2.0/24" {
		t.Fatalf("cidrs = %#v", got.AllowedCIDRs)
	}
}

func TestRealtimeScopeExtractsURLHostname(t *testing.T) {
	got, err := realtimeScope([]string{"https://api.example.test:8443/path"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.AllowedDomains) != 1 || got.AllowedDomains[0] != "api.example.test" {
		t.Fatalf("domains = %#v", got.AllowedDomains)
	}
}
