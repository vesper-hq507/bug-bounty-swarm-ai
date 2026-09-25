package chains

import (
	"testing"
	"testing/fstest"
)

const validChain = `id: demo-ssrf-rce
name: Demo SSRF to RCE
cves: [CVE-2026-0001, CVE-2026-0002]
product: DemoApp
links:
  - name: pre-auth SSRF
    cve: CVE-2026-0001
    verify: benign canary
  - name: SSRF to RCE
    cve: CVE-2026-0002
    verify: safe check
`

func TestParseChain(t *testing.T) {
	c, err := parseChain([]byte(validChain), "demo")
	if err != nil {
		t.Fatal(err)
	}
	if c.ID != "demo-ssrf-rce" || len(c.Links) != 2 || len(c.CVEs) != 2 {
		t.Fatalf("bad parse: %+v", c)
	}
	// invalid: no links
	if _, err := parseChain([]byte("id: x\nname: y\n"), "x"); err == nil {
		t.Error("chain with no links should fail validation")
	}
	// invalid: no id
	if _, err := parseChain([]byte("name: y\nlinks:\n  - name: a\n    verify: b\n"), "x"); err == nil {
		t.Error("chain with no id should fail validation")
	}
}

func TestDiscoverAndLoadChainFS(t *testing.T) {
	fsys := fstest.MapFS{
		"demo-ssrf-rce.yaml": {Data: []byte(validChain)},
		"broken.yaml":        {Data: []byte("id:\nlinks: []\n")},
		"notes.txt":          {Data: []byte("ignore")},
	}
	found := DiscoverChainsFS(fsys)
	if len(found) != 1 || found[0].ID != "demo-ssrf-rce" {
		t.Fatalf("expected 1 valid chain, got %+v", found)
	}
	if _, err := LoadChainFS(fsys, "demo-ssrf-rce"); err != nil {
		t.Errorf("load by id: %v", err)
	}
	if _, err := LoadChainFS(fsys, "missing"); err == nil {
		t.Error("missing chain should error")
	}
}
