package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMobileCampaignIDGeneratedAndValidated(t *testing.T) {
	generated, err := mobileCampaignID("")
	if err != nil {
		t.Fatal(err)
	}
	if generated.String() == "" {
		t.Fatal("generated campaign id is empty")
	}
	if _, err := mobileCampaignID("not-a-uuid"); err == nil {
		t.Fatal("invalid campaign id must fail")
	}
}

func TestMobilePolicyVersionTracksScopeAndPolicyInputs(t *testing.T) {
	dir := t.TempDir()
	scopePath := filepath.Join(dir, "scope.yaml")
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(scopePath, []byte("allowed_domains:\n  - example.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, []byte("max_requests_per_second: 5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := mobilePolicyVersion(scopePath, policyPath)
	if err != nil {
		t.Fatal(err)
	}
	second, err := mobilePolicyVersion(scopePath, policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || first == "" {
		t.Fatalf("versions first=%q second=%q", first, second)
	}
	if err := os.WriteFile(policyPath, []byte("max_requests_per_second: 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, err := mobilePolicyVersion(scopePath, policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if changed == first {
		t.Fatal("policy version did not change after policy input changed")
	}
}
