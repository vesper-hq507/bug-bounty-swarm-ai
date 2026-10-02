package engine

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/guidance"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/identity"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/monitor"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope/programterms"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/workflow"
	"github.com/google/uuid"
)

type runtimeHunter struct {
	runtime     *runtimePersistence
	campaignID  uuid.UUID
	collector   *workflow.Collector
	constraints programterms.Constraints
	base        []guidance.Recommendation
	changed     []guidance.Recommendation
}

func newRuntimeHunter(
	runtime *runtimePersistence,
	campaignID uuid.UUID,
	surface *pipeline.AttackSurface,
	collector *workflow.Collector,
	cc CampaignConfig,
	identities []identity.Identity,
) (*runtimeHunter, error) {
	if runtime == nil || runtime.monitor == nil {
		return nil, fmt.Errorf("runtime monitor unavailable")
	}
	if surface == nil {
		return nil, fmt.Errorf("attack surface is required")
	}
	constraints := campaignGuidanceConstraints(cc)
	current := monitor.FromAttackSurface(*surface)
	previous, ok, err := runtime.monitor.Load(current.Target)
	if err != nil {
		return nil, err
	}
	var diff monitor.DiffResult
	if ok {
		diff = monitor.Diff(previous, current)
	}
	if err := runtime.monitor.Save(current); err != nil {
		return nil, err
	}
	h := &runtimeHunter{
		runtime: runtime,
		campaignID: campaignID,
		collector: collector,
		constraints: constraints,
		base: guidance.Recommend(guidance.Input{
			Surface: *surface,
			Constraints: constraints,
			Identities: append([]identity.Identity(nil), identities...),
		}, 6),
		changed: guidance.FromMonitor(diff, constraints),
	}
	return h, nil
}

func (h *runtimeHunter) Refresh() ([]guidance.Recommendation, workflow.Analysis, error) {
	if h == nil {
		return nil, workflow.Analysis{}, fmt.Errorf("runtime hunter unavailable")
	}
	analysis := workflow.Analyze(h.collector.Events(), nil, h.constraints.MaxRequestsPerSecond)
	recs := guidance.Merge(12, guidance.FromWorkflow(analysis, h.constraints), h.changed, h.base)
	if err := h.runtime.saveWorkflow(h.campaignID, analysis); err != nil {
		return nil, analysis, err
	}
	if err := h.runtime.saveGuidance(h.campaignID, recs); err != nil {
		return nil, analysis, err
	}
	return recs, analysis, nil
}

func campaignGuidanceConstraints(cc CampaignConfig) programterms.Constraints {
	c := programterms.Constraints{
		MaxRequestsPerSecond: cc.MaxRequestsPerSecond,
		DisallowedPaths: append([]string(nil), cc.DisallowedPaths...),
		RequiredHeaders: cloneStringMap(cc.RequiredHeaders),
	}
	for _, technique := range cc.DisallowedTechniques {
		lower := strings.ToLower(technique)
		if strings.Contains(lower, "brute") {
			c.NoBruteForce = true
		}
		if strings.Contains(lower, "dos") || strings.Contains(lower, "denial") || strings.Contains(lower, "stress") {
			c.NoDoS = true
		}
	}
	return c
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func emitHunterGuidance(onEvent EventCallback, campaignID uuid.UUID, recs []guidance.Recommendation, analysis workflow.Analysis) {
	if onEvent == nil {
		return
	}
	data, _ := json.Marshal(struct {
		Recommendations []guidance.Recommendation `json:"recommendations"`
		Workflow       workflow.Analysis         `json:"workflow"`
	}{
		Recommendations: recs,
		Workflow: analysis,
	})
	detail := fmt.Sprintf("%d bounded recommendations from live surface/workflow state", len(recs))
	if len(recs) > 0 {
		detail += "; next: " + recs[0].Test
	}
	onEvent(pipeline.CampaignEvent{
		ID: uuid.New(), CampaignID: campaignID, Timestamp: time.Now(),
		EventType: pipeline.EventToolResult, AgentName: "hunter-guidance",
		Detail: detail, Data: data,
	})
}
