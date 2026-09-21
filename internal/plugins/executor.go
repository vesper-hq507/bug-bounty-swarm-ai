package plugins

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/agent/prompts"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/agent/recon"
	reportpkg "github.com/Armur-Ai/Pentest-Swarm-AI/internal/agent/report"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/config"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/llm"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/tools"
	"github.com/google/uuid"
)

// Executor runs a playbook deterministically: it executes each phase's declared
// tools (with their options, scope-enforced) in order, turns the tool output
// into findings, lets the LLM reason over each phase's post_analysis, and
// renders a report. This replaces the old behaviour of flattening phases into a
// single free-text objective and hoping the model ran the right tools.
type Executor struct {
	cfg         *config.Config
	coordinator *tools.Coordinator
	outputDir   string
	format      string
}

// NewExecutor builds a playbook executor from campaign config.
func NewExecutor(cfg *config.Config) *Executor {
	return &Executor{
		cfg:         cfg,
		coordinator: tools.NewCoordinator(),
		outputDir:   "./reports",
		format:      "md",
	}
}

// WithFormat sets the report format(s): "md", "json", "html", a comma-separated
// list, or "all". Empty keeps the default. Returns the executor for chaining.
func (e *Executor) WithFormat(f string) *Executor {
	if f != "" {
		e.format = f
	}
	return e
}

// WithOutputDir sets where reports are written. Empty keeps the default.
func (e *Executor) WithOutputDir(dir string) *Executor {
	if dir != "" {
		e.outputDir = dir
	}
	return e
}

// Execute runs the playbook against target with resolved variables, streaming
// progress through onEvent. It returns the findings it produced.
func (e *Executor) Execute(ctx context.Context, pb *Playbook, target string, vars map[string]string, onEvent func(pipeline.CampaignEvent)) ([]pipeline.ClassifiedFinding, error) {
	campaignID := uuid.New()
	emit := func(t pipeline.EventType, agent, detail string) {
		if onEvent != nil {
			onEvent(pipeline.CampaignEvent{
				ID:         uuid.New(),
				CampaignID: campaignID,
				Timestamp:  time.Now(),
				EventType:  t,
				AgentName:  agent,
				Detail:     detail,
			})
		}
	}

	scopeDef, err := buildPlaybookScope(target, vars)
	if err != nil {
		return nil, fmt.Errorf("scope: %w", err)
	}

	// Best-effort LLM provider for per-phase analysis + report synthesis. A
	// playbook still runs and produces deterministic findings without a key;
	// only the narrative reasoning/report degrade gracefully.
	var provider llm.Provider
	if p, perr := prompts.NewProviderWithRetry(e.cfg.Orchestrator); perr == nil {
		provider = p
	} else {
		emit(pipeline.EventMilestone, "playbook", "no LLM provider — running tools only, skipping AI analysis")
	}

	var allResults []*tools.ToolResult
	for _, phase := range pb.Phases {
		emit(pipeline.EventMilestone, "playbook", "phase: "+phase.Name)
		phaseResults := e.runPhase(ctx, phase, target, scopeDef, vars, emit)
		allResults = append(allResults, phaseResults...)

		if provider != nil && strings.TrimSpace(phase.PostAnalysis) != "" {
			if txt := analyzePhase(ctx, provider, phase, phaseResults); txt != "" {
				emit(pipeline.EventThought, "playbook", txt)
			}
		}
	}

	// Deterministic tool-output → findings, reusing the same extractor the
	// recon agent uses so playbook findings look identical to swarm findings.
	findings := make([]pipeline.ClassifiedFinding, 0)
	for _, v := range recon.ExtractVulnerabilities(allResults) {
		f := promoteFinding(campaignID, v)
		findings = append(findings, f)
		emit(pipeline.EventFindingDiscovered, "playbook", fmt.Sprintf("%s [%s]", f.Title, f.Severity))
	}

	if err := e.report(ctx, pb, target, campaignID, scopeDef, findings, provider, emit); err != nil {
		emit(pipeline.EventError, "report", err.Error())
	}
	return findings, nil
}

// runPhase executes every tool in a phase and returns their results. Each tool
// is run with its own options (RunSelected shares one option set per call, so
// we call it once per tool). Scope is enforced inside the tool layer.
func (e *Executor) runPhase(ctx context.Context, phase Phase, target string, scopeDef *scope.ScopeDefinition, vars map[string]string, emit func(pipeline.EventType, string, string)) []*tools.ToolResult {
	var results []*tools.ToolResult
	for _, tc := range phase.Tools {
		if tc.Name == "" {
			continue
		}
		emit(pipeline.EventToolCall, tc.Name, "phase "+phase.Name)
		opts := tools.Options(substituteOptions(tc.Options, vars))
		_, ch := e.coordinator.RunSelected(ctx, []string{tc.Name}, target, scopeDef, opts)
		got := false
		for res := range ch {
			got = true
			results = append(results, res)
			if res.Error != nil {
				emit(pipeline.EventError, tc.Name, res.Error.Error())
			} else {
				emit(pipeline.EventToolResult, tc.Name, fmt.Sprintf("%d raw findings", len(res.ParsedFindings)))
			}
		}
		if !got {
			// Tool not registered or its binary isn't installed — the
			// coordinator skips it silently, so surface that in the stream.
			emit(pipeline.EventMilestone, tc.Name, "skipped (not installed) — run: pentestswarm install-tools")
		}
	}
	return results
}

// report synthesises and writes the campaign report. With a provider it uses
// the LLM report agent (executive summary, etc.); without one it writes a
// deterministic findings summary so a run always leaves an artifact.
func (e *Executor) report(ctx context.Context, pb *Playbook, target string, campaignID uuid.UUID, scopeDef *scope.ScopeDefinition, findings []pipeline.ClassifiedFinding, provider llm.Provider, emit func(pipeline.EventType, string, string)) error {
	campaign := pipeline.Campaign{
		ID:        campaignID,
		Name:      fmt.Sprintf("playbook-%s-%s", safeSlug(pb.Name), time.Now().Format("20060102-150405")),
		Target:    target,
		Objective: objectiveFromPlaybook(pb),
		Status:    pipeline.StatusReporting,
		Scope: pipeline.ScopeDefinition{
			AllowedDomains: scopeDef.AllowedDomains,
			AllowedCIDRs:   scopeDef.AllowedCIDRs,
		},
		CreatedAt: time.Now(),
	}

	if provider == nil {
		return e.writeFallbackReport(campaign, findings, emit)
	}

	rep, err := reportpkg.NewReportAgent(provider).Generate(ctx, campaign, findings, nil, nil)
	if err != nil {
		emit(pipeline.EventError, "report", "LLM report failed, writing summary: "+err.Error())
		return e.writeFallbackReport(campaign, findings, emit)
	}

	renderer := reportpkg.NewRenderer()
	writers := map[string]func() ([]byte, error){
		"md":   func() ([]byte, error) { return renderer.ToMarkdown(rep) },
		"json": func() ([]byte, error) { return renderer.ToJSON(rep) },
		"html": func() ([]byte, error) { return renderer.ToHTML(rep) },
	}
	for _, f := range e.selectedFormats() {
		w, ok := writers[f]
		if !ok {
			continue
		}
		data, werr := w()
		if werr != nil {
			emit(pipeline.EventError, "report", werr.Error())
			continue
		}
		path, perr := e.writeArtifact(campaign.Name, f, data)
		if perr != nil {
			emit(pipeline.EventError, "report", perr.Error())
			continue
		}
		emit(pipeline.EventToolResult, "report", fmt.Sprintf("%s report: %s", f, path))
	}
	return nil
}

// writeFallbackReport emits a deterministic markdown findings list when no LLM
// is available (or LLM generation failed), so `playbook run` never ends empty.
func (e *Executor) writeFallbackReport(campaign pipeline.Campaign, findings []pipeline.ClassifiedFinding, emit func(pipeline.EventType, string, string)) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\nTarget: %s\n\nFindings: %d\n\n", campaign.Name, campaign.Target, len(findings))
	for _, f := range findings {
		fmt.Fprintf(&b, "## [%s] %s\n\n%s\n\n- Target: %s\n- CVSS: %.1f\n", strings.ToUpper(string(f.Severity)), f.Title, f.Description, f.Target, f.CVSSScore)
		if len(f.CVEIDs) > 0 {
			fmt.Fprintf(&b, "- CVE: %s\n", strings.Join(f.CVEIDs, ", "))
		}
		b.WriteString("\n")
	}
	path, err := e.writeArtifact(campaign.Name, "md", []byte(b.String()))
	if err != nil {
		return err
	}
	emit(pipeline.EventToolResult, "report", "md report: "+path)
	return nil
}

func (e *Executor) writeArtifact(name, ext string, data []byte) (string, error) {
	if err := os.MkdirAll(e.outputDir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(e.outputDir, name+"."+ext)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func (e *Executor) selectedFormats() []string {
	if e.format == "" || e.format == "all" {
		return []string{"md", "json", "html"}
	}
	var out []string
	for _, f := range strings.Split(e.format, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// analyzePhase asks the LLM to reason over a phase's tool output using the
// phase's post_analysis instructions. Returns a short summary for the event
// stream, or "" on any error (analysis is advisory, never fatal).
func analyzePhase(ctx context.Context, provider llm.Provider, phase Phase, results []*tools.ToolResult) string {
	var ev strings.Builder
	for _, r := range results {
		fmt.Fprintf(&ev, "\n[%s] %d findings\n", r.ToolName, len(r.ParsedFindings))
		if out := strings.TrimSpace(r.RawOutput); out != "" {
			ev.WriteString(truncate(out, 2000))
			ev.WriteByte('\n')
		}
	}
	prompt := fmt.Sprintf("You are a penetration-test analyst. Phase %q produced this tool output:\n%s\n\nInstructions:\n%s\n\nIn 1-2 sentences, state what this means for the finding. Be concrete; do not include exploit payloads.",
		phase.Name, ev.String(), strings.TrimSpace(phase.PostAnalysis))
	resp, err := provider.Complete(ctx, llm.CompletionRequest{
		Messages: []llm.Message{{Role: "user", Content: prompt}},
	})
	if err != nil || resp == nil {
		return ""
	}
	return strings.TrimSpace(resp.Content)
}

// promoteFinding turns a tool VulnerabilityRecord into a ClassifiedFinding,
// mirroring the swarm recon agent so playbook findings are identical in shape.
func promoteFinding(campaignID uuid.UUID, v pipeline.VulnerabilityRecord) pipeline.ClassifiedFinding {
	sev := pipeline.Severity(strings.ToLower(v.Severity))
	switch sev {
	case "informational", "", "info":
		sev = pipeline.SeverityInformational
	}
	var cves []string
	if strings.HasPrefix(strings.ToUpper(v.Reference), "CVE-") {
		cves = []string{strings.ToUpper(v.Reference)}
	}
	desc := v.Description
	if desc == "" {
		desc = v.Title
	}
	if v.Reference != "" {
		desc = fmt.Sprintf("%s\n\nReported by %s (ref: %s).", desc, v.Tool, v.Reference)
	} else {
		desc = fmt.Sprintf("%s\n\nReported by %s.", desc, v.Tool)
	}
	return pipeline.ClassifiedFinding{
		ID:             uuid.New(),
		CampaignID:     campaignID,
		Title:          v.Title,
		Description:    desc,
		CVEIDs:         cves,
		CVSSScore:      cvssForSeverity(sev),
		Severity:       sev,
		AttackCategory: v.Tool,
		Confidence:     pipeline.Confidence("medium"),
		Target:         v.URL,
		ClassifiedAt:   time.Now(),
	}
}

func cvssForSeverity(s pipeline.Severity) float64 {
	switch s {
	case pipeline.SeverityCritical:
		return 9.5
	case pipeline.SeverityHigh:
		return 8.0
	case pipeline.SeverityMedium:
		return 5.5
	case pipeline.SeverityLow:
		return 3.0
	default:
		return 0.0
	}
}

// buildPlaybookScope derives the authorized scope from the target (and an
// optional `scope` variable). A URL is reduced to its host; an IP becomes a
// single-host CIDR; anything else is treated as a domain.
func buildPlaybookScope(target string, vars map[string]string) (*scope.ScopeDefinition, error) {
	def := &scope.ScopeDefinition{}
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		if strings.Contains(raw, "/") && !strings.Contains(raw, "://") {
			def.AllowedCIDRs = append(def.AllowedCIDRs, raw)
			return
		}
		host := raw
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			host = u.Hostname()
		}
		if ip := net.ParseIP(host); ip != nil {
			if ip.To4() != nil {
				def.AllowedCIDRs = append(def.AllowedCIDRs, host+"/32")
			} else {
				def.AllowedCIDRs = append(def.AllowedCIDRs, host+"/128")
			}
			return
		}
		def.AllowedDomains = append(def.AllowedDomains, host)
	}

	add(target)
	if s, ok := vars["scope"]; ok {
		for _, part := range strings.Split(s, ",") {
			add(part)
		}
	}
	if len(def.AllowedCIDRs) == 0 && len(def.AllowedDomains) == 0 {
		return nil, fmt.Errorf("could not derive a scope from target %q", target)
	}
	return def, nil
}

// substituteOptions replaces ${var} / $var references in string option values
// (and inside string slices) with resolved variables. Non-string values pass
// through unchanged.
func substituteOptions(opts map[string]any, vars map[string]string) map[string]any {
	if len(opts) == 0 {
		return opts
	}
	expand := func(s string) string {
		return os.Expand(s, func(k string) string {
			if v, ok := vars[k]; ok {
				return v
			}
			return "${" + k + "}"
		})
	}
	out := make(map[string]any, len(opts))
	for k, v := range opts {
		switch val := v.(type) {
		case string:
			out[k] = expand(val)
		case []any:
			ns := make([]any, len(val))
			for i, item := range val {
				if s, ok := item.(string); ok {
					ns[i] = expand(s)
				} else {
					ns[i] = item
				}
			}
			out[k] = ns
		case []string:
			ns := make([]string, len(val))
			for i, s := range val {
				ns[i] = expand(s)
			}
			out[k] = ns
		default:
			out[k] = v
		}
	}
	return out
}

func objectiveFromPlaybook(pb *Playbook) string {
	if strings.TrimSpace(pb.Description) != "" {
		return strings.TrimSpace(pb.Description)
	}
	names := make([]string, 0, len(pb.Phases))
	for _, p := range pb.Phases {
		names = append(names, p.Name)
	}
	return fmt.Sprintf("Execute playbook %q: %s", pb.Name, strings.Join(names, " → "))
}

func safeSlug(s string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		default:
			// Any separator or non-alphanumeric collapses to a single hyphen.
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	slug := strings.Trim(b.String(), "-")
	if slug == "" {
		return "run"
	}
	return slug
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
