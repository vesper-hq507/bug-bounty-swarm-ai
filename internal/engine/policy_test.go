package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/policygateway"
)

func TestWithCampaignDeadlineAddsDefault(t *testing.T) {
	ctx, cancel := withCampaignDeadline(context.Background(), 0)
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("campaign context must have a hard deadline")
	}
	remaining := time.Until(deadline)
	if remaining <= 0 || remaining > DefaultCampaignTimeout {
		t.Fatalf("unexpected campaign deadline: %v", remaining)
	}
}

func TestWithCampaignDeadlineParentStillWins(t *testing.T) {
	parent, parentCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer parentCancel()
	parentDeadline, _ := parent.Deadline()

	ctx, cancel := withCampaignDeadline(parent, time.Hour)
	defer cancel()
	got, ok := ctx.Deadline()
	if !ok {
		t.Fatal("expected inherited parent deadline")
	}
	if got.Sub(parentDeadline) > time.Millisecond || parentDeadline.Sub(got) > time.Millisecond {
		t.Fatalf("campaign wrapper extended parent deadline: got %v want %v", got, parentDeadline)
	}
}

func TestPrepareCampaignPolicyRejectsUnreadableScopeFile(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := prepareCampaignPolicy(ctx, CampaignConfig{
		ScopeFile: filepath.Join(t.TempDir(), "missing.yaml"),
	})
	if err == nil {
		t.Fatal("missing live scope file must fail closed")
	}
}

func TestPrepareCampaignPolicyLoadsExecutableConstraints(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scope.yaml")
	if err := os.WriteFile(path, []byte("allowed_domains:\n  - example.com\nallowed_cidrs: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rt, err := prepareCampaignPolicy(ctx, CampaignConfig{
		ScopeFile:            path,
		RequiredHeaders:      map[string]string{"X-Bug-Bounty": "researcher"},
		DisallowedPaths:      []string{"/logout"},
		MaxRequestsPerSecond: 50,
	})
	if err != nil {
		t.Fatalf("prepareCampaignPolicy: %v", err)
	}
	defer rt.close()

	d, err := rt.gateway.Decide(context.Background(), policygateway.Action{
		Kind: policygateway.ActionHTTP,
		URL:  "https://example.com/api",
	})
	if err != nil {
		t.Fatalf("in-scope decision failed: %v", err)
	}
	if d.RequiredHeaders["X-Bug-Bounty"] != "researcher" {
		t.Fatalf("required header missing from decision: %+v", d)
	}
	if _, err := rt.gateway.Decide(context.Background(), policygateway.Action{
		Kind: policygateway.ActionHTTP,
		URL:  "https://example.com/logout",
	}); err == nil {
		t.Fatal("disallowed path should be denied")
	}
}
