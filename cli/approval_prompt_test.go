package cli

import (
	"bufio"
	"context"
	"strings"
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/approval"
)

func TestAssistApprovalSensitiveDoesNotUseApproveAll(t *testing.T) {
	oldReader, oldAuto := assistReader, assistAutoApprove
	defer func() {
		assistReader = oldReader
		assistAutoApprove = oldAuto
	}()

	assistAutoApprove = true
	assistReader = bufio.NewReader(strings.NewReader("n\n"))
	ok, err := assistApprovalPrompt(context.Background(), approval.Request{
		Capability: approval.CapabilityStateChange,
		StepName: "mutate",
		Command: "httpreq --method POST --url https://example.test/item",
		Reason: "state change",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("sensitive capability inherited read-only approve-all state")
	}
}

func TestAssistApprovalReadOnlyCanUseApproveAll(t *testing.T) {
	oldReader, oldAuto := assistReader, assistAutoApprove
	defer func() {
		assistReader = oldReader
		assistAutoApprove = oldAuto
	}()

	assistAutoApprove = true
	ok, err := assistApprovalPrompt(context.Background(), approval.Request{
		Capability: approval.CapabilityObserve,
		StepName: "observe",
	})
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}
