package engine

import (
	"fmt"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/approval"
)

func (r *Runner) prepareApprovalBroker(cc CampaignConfig) (approval.Broker, error) {
	caps := make([]approval.Capability, 0, len(cc.ApprovedCapabilities)+1)
	seen := map[approval.Capability]struct{}{}
	for _, raw := range cc.ApprovedCapabilities {
		capability, err := approval.ParseCapability(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid approved capability: %w", err)
		}
		if capability == approval.CapabilityObserve {
			continue
		}
		if _, ok := seen[capability]; ok {
			continue
		}
		seen[capability] = struct{}{}
		caps = append(caps, capability)
	}

	// --verify-poc is itself an explicit operator decision to execute generated
	// proof material, so it grants only the proof-impact capability.
	if cc.VerifyPoC {
		if _, ok := seen[approval.CapabilityProofImpact]; !ok {
			caps = append(caps, approval.CapabilityProofImpact)
		}
	}

	if cc.Assist && r.approvalPrompt == nil {
		return nil, fmt.Errorf("assist mode requires an approval prompt")
	}
	return approval.NewStaticBroker(caps, r.approvalPrompt, cc.Assist), nil
}
