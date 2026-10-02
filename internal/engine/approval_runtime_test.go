package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/approval"
)

func TestPrepareApprovalBrokerRejectsUnknownCapability(t *testing.T) {
	r := NewRunner(nil)
	if _, err := r.prepareApprovalBroker(CampaignConfig{
		ApprovedCapabilities: []string{"not-a-capability"},
	}); err == nil {
		t.Fatal("unknown capability must fail")
	}
}

func TestPrepareApprovalBrokerAllowsExplicitStateChangeGrant(t *testing.T) {
	r := NewRunner(nil)
	b, err := r.prepareApprovalBroker(CampaignConfig{
		ApprovedCapabilities: []string{"state-change"},
	})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := b.Authorize(context.Background(), approval.Request{
		Capability: approval.CapabilityStateChange,
	})
	if err != nil || !grant.Granted || grant.Source != "campaign-grant" {
		t.Fatalf("grant=%+v err=%v", grant, err)
	}
}

func TestPrepareApprovalBrokerDeniesSensitiveByDefault(t *testing.T) {
	r := NewRunner(nil)
	b, err := r.prepareApprovalBroker(CampaignConfig{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = b.Authorize(context.Background(), approval.Request{
		Capability: approval.CapabilityConcurrency,
		Reason: "race test",
	})
	if !errors.Is(err, approval.ErrApprovalRequired) {
		t.Fatalf("err=%v", err)
	}
}

func TestPrepareApprovalBrokerRequiresPromptForAssist(t *testing.T) {
	r := NewRunner(nil)
	if _, err := r.prepareApprovalBroker(CampaignConfig{Assist: true}); err == nil {
		t.Fatal("assist without approval prompt must fail closed")
	}
}
