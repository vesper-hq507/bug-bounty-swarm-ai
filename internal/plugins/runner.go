package plugins

import (
	"context"
	"fmt"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/config"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
)

// PlaybookRunner executes a playbook by running its declared phases/tools
// deterministically through the Executor, rather than flattening the playbook
// into a single free-text objective and hoping the model picks the right tools.
type PlaybookRunner struct {
	cfg *config.Config
}

// NewPlaybookRunner creates a playbook runner.
func NewPlaybookRunner(cfg *config.Config) *PlaybookRunner {
	return &PlaybookRunner{cfg: cfg}
}

// Run executes a playbook against a target: it resolves variables, then hands
// off to the Executor which runs each phase's tools (scope-enforced), extracts
// findings, runs the per-phase LLM analysis, and writes the report.
func (r *PlaybookRunner) Run(ctx context.Context, pb *Playbook, target string, variables map[string]string, onEvent func(pipeline.CampaignEvent)) error {
	resolved, err := resolveVariables(pb, target, variables)
	if err != nil {
		return err
	}

	if onEvent != nil {
		onEvent(pipeline.CampaignEvent{
			EventType: pipeline.EventThought,
			AgentName: "playbook",
			Detail:    fmt.Sprintf("Running playbook: %s by %s (%d phases)", pb.Name, pb.Author.Name, len(pb.Phases)),
		})
	}

	_, err = NewExecutor(r.cfg).Execute(ctx, pb, target, resolved, onEvent)
	return err
}

// targetAliases are the conventional variable names a playbook uses for "the
// thing being tested". The CLI --target flag binds to whichever of these the
// playbook declares, so a playbook can call it target_url, target, host, etc.
// and still be satisfied by --target without the author wiring anything.
var targetAliases = []string{"target_domain", "target_url", "target", "url", "host"}

// resolveVariables seeds the target-alias bindings from the CLI --target flag,
// then validates that every required playbook variable has either a
// caller-supplied value or a declared default.
func resolveVariables(pb *Playbook, target string, vars map[string]string) (map[string]string, error) {
	if vars == nil {
		vars = make(map[string]string)
	}
	if target != "" {
		for _, alias := range targetAliases {
			if _, ok := vars[alias]; !ok {
				vars[alias] = target
			}
		}
	}
	for key, v := range pb.Variables {
		if _, ok := vars[key]; !ok && v.Required {
			if v.Default != "" {
				vars[key] = v.Default
				continue
			}
			return nil, fmt.Errorf("required variable %q not provided (pass it or set a default)", key)
		}
	}
	return vars, nil
}
