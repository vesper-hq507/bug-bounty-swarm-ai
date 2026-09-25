package pentestswarm

import (
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/chains"
)

// Every bundled exploit chain must parse + validate, and we expect the core set.
func TestBundledChainsParse(t *testing.T) {
	found := chains.DiscoverChainsFS(BundledChains())
	if len(found) < 12 {
		t.Fatalf("expected >=12 bundled chains, got %d", len(found))
	}
	for _, want := range []string{
		"sonicwall-sma1000-ssrf-rce", "ivanti-connect-secure-authbypass-rce",
		"exchange-proxyshell-rce", "moveit-transfer-sqli-rce", "magento-stylesmuggler-rce",
	} {
		if _, err := chains.LoadChainFS(BundledChains(), want); err != nil {
			t.Errorf("bundled chain %q missing/invalid: %v", want, err)
		}
	}
	// each must carry at least one CVE and one link
	for _, c := range found {
		if len(c.CVEs) == 0 || len(c.Links) == 0 {
			t.Errorf("chain %q missing CVEs or links", c.ID)
		}
	}
}
