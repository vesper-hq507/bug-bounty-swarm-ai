package agents

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	reportpkg "github.com/Armur-Ai/Pentest-Swarm-AI/internal/agent/report"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/agent/report/bounty"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/agent/report/roi"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/attackgraph"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/jev"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/llm"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/poc"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/swarm/blackboard"
	"github.com/google/uuid"
)

// ReportAgent wakes on CAMPAIGN_COMPLETE, queries the blackboard for
// everything the swarm discovered, reconstructs the classical
// Campaign / Findings / Plan / Results shape, and hands it to the
// existing report agent for rendering.
type ReportAgent struct {
	reportAgent      *reportpkg.ReportAgent
	renderer         *reportpkg.Renderer
	campaign         pipeline.Campaign
	outputDir        string
	format           string
	publishThreshold float64 // findings below this pheromone are excluded from the report
	onRendered       func(paths map[string]string)
	// spendSnapshot returns the current LLM dollar spend, or 0 if no
	// metered provider is wired. Optional — when nil, the ROI footer
	// is omitted from the report.
	spendSnapshot func() float64
	// programStats is the per-program bounty stats used to refine the
	// ROI estimate. Optional — nil falls back to industry-average
	// public-market numbers in `internal/agent/report/bounty`.
	programStats *bounty.ProgramStats

	// Jev false-positive filter (optional). When jev is set, findings are
	// scored by TypeSafe's Jev model just before rendering and those below
	// jevThreshold P(true-positive) are dropped. Fails open on any error.
	jev          *jev.Client
	jevThreshold float64
	jevEmit      func(detail string) // surfaces the kept/dropped summary as an event

	// pocProvider, when set, generates a safe proof-of-concept script per
	// confirmed high-value finding and drops it alongside the report. Optional.
	pocProvider llm.Provider
	// pocRunner, when set, closes the loop — each PoC is run and marked VERIFIED
	// only if it actually fires. Opt-in (executes generated code); nil generates
	// without running.
	pocRunner poc.Runner
}

// NewReportAgent wires the existing report agent into the swarm.
// publishThreshold gates which findings appear in the report:
//
//	0.5 (default) — 'bugbounty' mode: verified PoCs only.
//	                ConfirmationAgent's superseded findings (pheromone
//	                0.1) are automatically excluded.
//	0.1 ('aggressive') — include everything including suspected-but-
//	                not-reproduced findings (with a banner in the report).
func NewReportAgent(inner *reportpkg.ReportAgent, renderer *reportpkg.Renderer, campaign pipeline.Campaign, outputDir, format string, publishThreshold float64, onRendered func(map[string]string)) *ReportAgent {
	if outputDir == "" {
		outputDir = "./reports"
	}
	if format == "" {
		format = "md"
	}
	if publishThreshold <= 0 {
		publishThreshold = 0.5
	}
	return &ReportAgent{
		reportAgent:      inner,
		renderer:         renderer,
		campaign:         campaign,
		outputDir:        outputDir,
		format:           format,
		publishThreshold: publishThreshold,
		onRendered:       onRendered,
	}
}

// WithROI attaches a spend-snapshot closure and (optionally) per-program
// bounty stats so the agent can render an ROI footer at the bottom of
// the campaign report. Closure form means the snapshot stays fresh —
// we read it at render time, not at agent construction time.
func (a *ReportAgent) WithROI(spend func() float64, stats *bounty.ProgramStats) *ReportAgent {
	a.spendSnapshot = spend
	a.programStats = stats
	return a
}

// WithJev enables a final Jev false-positive filter over the graded findings.
// threshold is the minimum P(true-positive) to keep a finding (default 0.5);
// emit surfaces the kept/dropped summary as a campaign event. Optional.
func (a *ReportAgent) WithJev(client *jev.Client, threshold float64, emit func(string)) *ReportAgent {
	a.jev = client
	a.jevThreshold = threshold
	if a.jevThreshold <= 0 {
		a.jevThreshold = 0.5
	}
	a.jevEmit = emit
	return a
}

// WithPoC enables proof-of-concept generation: for each confirmed high-value
// finding, a safe, self-contained verification script is generated and written
// next to the report. provider is the (typically cheap) model used to author
// the scripts. Optional — nil leaves the report unchanged.
func (a *ReportAgent) WithPoC(provider llm.Provider) *ReportAgent {
	a.pocProvider = provider
	return a
}

// WithPoCVerify wires a runner so generated PoCs are executed and marked
// VERIFIED only when they actually fire. Opt-in — it runs LLM-authored code, so
// callers pass this only for authorized targets outside dry-run/safe-mode.
func (a *ReportAgent) WithPoCVerify(runner poc.Runner) *ReportAgent {
	a.pocRunner = runner
	return a
}

// filterFalsePositives asks Jev whether each finding is a real vulnerability and
// drops those it's confident are false positives. Fails OPEN: on any error it
// keeps every finding (a scoring hiccup must never silently discard real bugs).
func (a *ReportAgent) filterFalsePositives(ctx context.Context, findings []pipeline.ClassifiedFinding) []pipeline.ClassifiedFinding {
	if a.jev == nil || len(findings) == 0 {
		return findings
	}
	emit := a.jevEmit
	if emit == nil {
		emit = func(string) {}
	}
	texts := make(map[string]string, len(findings))
	for i, f := range findings {
		id := fmt.Sprintf("f%d", i)
		ev := ""
		if len(f.Evidence) > 0 {
			ev = "\nEvidence: " + truncate(f.Evidence[0].Content, 800)
		}
		texts[id] = fmt.Sprintf("Title: %s\nSeverity: %s\nCategory: %s\nTarget: %s\nDescription: %s%s",
			f.Title, f.Severity, f.AttackCategory, f.Target, truncate(f.Description, 1200), ev)
	}
	state := "Target: " + a.campaign.Target + ". Findings from an autonomous penetration-testing swarm; judge each strictly on whether it is a genuine, exploitable vulnerability."
	probs, err := a.jev.TruePositiveProbabilities(ctx, state, texts)
	if err != nil {
		emit(fmt.Sprintf("Jev false-positive filter skipped (%v) — keeping all %d findings", err, len(findings)))
		return findings
	}
	kept := make([]pipeline.ClassifiedFinding, 0, len(findings))
	dropped := 0
	for i, f := range findings {
		p, ok := probs[fmt.Sprintf("f%d", i)]
		if ok && p < a.jevThreshold {
			dropped++
			continue
		}
		kept = append(kept, f)
	}
	emit(fmt.Sprintf("Jev false-positive filter: kept %d, dropped %d (P(real) < %.2f)", len(kept), dropped, a.jevThreshold))
	return kept
}

// Name implements swarm.Agent.
func (a *ReportAgent) Name() string { return "report" }

// Trigger implements swarm.Agent.
func (a *ReportAgent) Trigger() blackboard.Predicate {
	return blackboard.Predicate{Types: []blackboard.FindingType{blackboard.TypeCampaignComplete}}
}

// MaxConcurrency implements swarm.Agent — exactly one report per campaign.
func (a *ReportAgent) MaxConcurrency() int { return 1 }

// Handle queries the board, generates, renders, and writes the report.
func (a *ReportAgent) Handle(ctx context.Context, f blackboard.Finding, board blackboard.Board) error {
	// The report agent fires on CAMPAIGN_COMPLETE — the very signal the
	// scheduler uses to cancel the swarm's run context. Generating on that
	// context races the cancellation: the report's LLM calls (executive
	// summary, remediation, narrative) return context.Canceled and those
	// sections silently blank out, while the deterministic parts still render.
	// Detach from the campaign cancellation and give report generation its own
	// budget so it always completes.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
	defer cancel()

	// Reconstruct findings. publishThreshold excludes low-pheromone findings
	// (those superseded by the ConfirmationAgent, or agent-error noise).
	matches, _ := board.Query(ctx, blackboard.Predicate{
		Types:        []blackboard.FindingType{blackboard.TypeCVEMatch, blackboard.TypeMisconfig},
		MinPheromone: a.publishThreshold,
		Limit:        500,
	})
	findings := make([]pipeline.ClassifiedFinding, 0, len(matches))
	for _, m := range matches {
		var cf pipeline.ClassifiedFinding
		if err := json.Unmarshal(m.Data, &cf); err == nil {
			findings = append(findings, cf)
		}
	}
	findings = collapseDuplicateFindings(findings)
	// Final false-positive pass (opt-in): let Jev drop findings it's confident
	// are noise before they reach the report.
	findings = a.filterFalsePositives(ctx, findings)

	// Reconstruct plan
	var plan *pipeline.AttackPlan
	chains, _ := board.Query(ctx, blackboard.Predicate{
		Types: []blackboard.FindingType{blackboard.TypeExploitChain},
		Limit: 100,
	})
	if len(chains) > 0 {
		plan = &pipeline.AttackPlan{
			ID:         uuid.New(),
			CampaignID: a.campaign.ID,
			CreatedAt:  a.campaign.CreatedAt,
		}
		for _, c := range chains {
			var p pipeline.AttackPath
			if err := json.Unmarshal(c.Data, &p); err == nil {
				plan.Paths = append(plan.Paths, p)
			}
		}
	}

	// Reconstruct execution results
	resultFinds, _ := board.Query(ctx, blackboard.Predicate{
		Types: []blackboard.FindingType{blackboard.TypeExploitResult},
		Limit: 500,
	})
	results := make([]pipeline.ExecutionResult, 0, len(resultFinds))
	for _, r := range resultFinds {
		var wrapped struct {
			Result pipeline.ExecutionResult `json:"result"`
		}
		if err := json.Unmarshal(r.Data, &wrapped); err == nil {
			results = append(results, wrapped.Result)
		}
	}

	rep, err := a.reportAgent.Generate(ctx, a.campaign, findings, plan, results)
	if err != nil {
		return fmt.Errorf("generate report: %w", err)
	}

	// Phase 4.5.7: ROI footer. Only renders when a metered provider was
	// wired into the swarm — otherwise we'd be dividing by an unknown
	// spend and the verdict would be meaningless.
	if a.spendSnapshot != nil {
		rep.ROIFooter = roi.Calculate(a.spendSnapshot(), findings, a.programStats).Footer()
	}

	if err := os.MkdirAll(a.outputDir, 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	// campaign.Name embeds the raw target (e.g. "swarm-http://localhost:3000-…").
	// Left untouched, the "://" turns filepath.Join into a nested path whose
	// parent dir does not exist, so every WriteFile below silently fails and
	// the reports dir comes up empty. Sanitize the filename component so it is
	// a single safe path segment.
	name := fmt.Sprintf("%s-%s", a.campaign.Name, a.campaign.ID.String()[:8])
	base := filepath.Join(a.outputDir, sanitizeFilename(name))
	rendered := map[string]string{}

	// writeReport renders one format and writes it, surfacing the first error
	// rather than discarding it — a failed write must not look like success.
	var writeErr error
	writeReport := func(kind, ext string, render func() ([]byte, error)) {
		b, err := render()
		if err != nil {
			if writeErr == nil {
				writeErr = fmt.Errorf("render %s: %w", kind, err)
			}
			return
		}
		p := base + ext
		if err := os.WriteFile(p, b, 0o644); err != nil {
			if writeErr == nil {
				writeErr = fmt.Errorf("write %s report %q: %w", kind, p, err)
			}
			return
		}
		rendered[kind] = p
	}

	want := func(kind string) bool {
		return a.format == "all" || a.format == kind
	}
	if a.format == "" || want("md") {
		writeReport("md", ".md", func() ([]byte, error) { return a.renderer.ToMarkdown(rep) })
	}
	if want("html") {
		writeReport("html", ".html", func() ([]byte, error) { return a.renderer.ToHTML(rep) })
	}
	if want("json") {
		writeReport("json", ".json", func() ([]byte, error) { return a.renderer.ToJSON(rep) })
	}
	if want("sarif") {
		writeReport("sarif", ".sarif", func() ([]byte, error) { return a.renderer.ToSARIF(rep) })
	}
	// Self-contained, shareable HTML (offline, on-brand). PDF is intentionally
	// not produced mid-run (it needs a headless browser) — use
	// `pentestswarm report --format pdf` on the finished run for that.
	if want("shareable") {
		writeReport("shareable", "-shareable.html", func() ([]byte, error) { return a.renderer.ToShareableHTML(rep) })
	}

	// Attack map — the flagship: an interactive graph of the most-likely path to
	// the objective, plus the graph as JSON for the dashboard. Produced by
	// default (it's the headline output), skipped only for narrow single-format
	// requests like sarif/json-only.
	if a.format == "" || want("md") || want("html") || want("all") || want("graph") {
		objLabel := strings.TrimSpace(a.campaign.Objective)
		if objLabel == "" {
			objLabel = "full compromise"
		}
		g := attackgraph.BuildFromFindings(findings, a.campaign.Objective)
		writeReport("attackmap", "-attackmap.html", func() ([]byte, error) { return g.RenderHTML(objLabel), nil })
		writeReport("attackgraph", "-attackgraph.json", func() ([]byte, error) { return g.ToJSON(), nil })
	}

	// Proof-of-concept scripts — turn confirmed findings into runnable, safe
	// verification artifacts a triager (or a bounty program) can re-run.
	if a.pocProvider != nil && (a.format == "" || want("md") || want("html") || want("all") || want("poc")) {
		a.writePoCs(ctx, base, findings, rendered)
	}

	if a.onRendered != nil {
		a.onRendered(rendered)
	}
	return writeErr
}

// writePoCs generates a safe proof-of-concept script for each confirmed
// high-value finding and writes it beside the report. It is best-effort: a PoC
// that fails to generate or trips the safety scan is skipped, never fatal — a
// missing PoC must never sink a real report. Capped so a huge finding set can't
// blow the LLM budget at report time.
func (a *ReportAgent) writePoCs(ctx context.Context, base string, findings []pipeline.ClassifiedFinding, rendered map[string]string) {
	const maxPoCs = 8
	seen := map[string]int{}
	made := 0
	for _, f := range findings {
		if made >= maxPoCs {
			break
		}
		if !pocWorthy(f.Severity) {
			continue
		}
		var p *poc.PoC
		var err error
		if a.pocRunner != nil {
			p, err = poc.GenerateAndVerify(ctx, a.pocProvider, a.pocRunner, f, poc.Options{})
		} else {
			p, err = poc.Generate(ctx, a.pocProvider, f)
		}
		if err != nil || p == nil {
			continue
		}
		fname := p.Filename
		if n := seen[p.Filename]; n > 0 { // several findings can share a class slug
			fname = strings.TrimSuffix(fname, ".py") + fmt.Sprintf("-%d.py", n+1)
		}
		seen[p.Filename]++
		path := base + "-" + fname
		if err := os.WriteFile(path, []byte(p.Script), 0o644); err != nil {
			continue
		}
		key := "poc:" + fname
		if p.Verified {
			key = "poc(verified):" + fname
		}
		rendered[key] = path
		made++
	}
}

// pocWorthy reports whether a finding's severity justifies spending an LLM call
// to author a proof-of-concept. Informational/low findings are skipped.
func pocWorthy(s pipeline.Severity) bool {
	switch s {
	case pipeline.SeverityCritical, pipeline.SeverityHigh, pipeline.SeverityMedium:
		return true
	}
	return false
}

// collapseDuplicateFindings merges findings that describe the same issue on
// the same target — most visibly the several nuclei templates that all flag a
// single readable /.env (generic-env, laravel-env, codeigniter-env), which
// would otherwise render as three separate HIGH findings and read as padding.
//
// Two findings collapse when they share the same target URL, severity, and
// attack category (the tool/class). The kept entry kills the highest CVSS and
// gains a one-line note listing the other detectors, so no signal is lost.
// Findings with no target are never collapsed — an empty target is not an
// identity — so distinct business-logic findings stay separate.
func collapseDuplicateFindings(in []pipeline.ClassifiedFinding) []pipeline.ClassifiedFinding {
	type key struct{ target, sev, cat string }
	idx := make(map[key]int)         // key -> position in out
	extras := make(map[key][]string) // key -> merged finding titles
	out := make([]pipeline.ClassifiedFinding, 0, len(in))

	for _, f := range in {
		if strings.TrimSpace(f.Target) == "" {
			out = append(out, f) // no identity to dedup on
			continue
		}
		k := key{
			target: normalizeFindingTarget(f.Target),
			sev:    string(f.Severity),
			cat:    strings.ToLower(f.AttackCategory),
		}
		pos, seen := idx[k]
		if !seen {
			idx[k] = len(out)
			out = append(out, f)
			continue
		}
		// Duplicate: keep the higher-CVSS representative, record the other's title.
		extras[k] = append(extras[k], f.Title)
		if f.CVSSScore > out[pos].CVSSScore {
			title := out[pos].Title
			out[pos] = f
			extras[k] = append(extras[k], title)
		}
	}

	// Fold the merged-detector note into each collapsed finding's description.
	for k, titles := range extras {
		if len(titles) == 0 {
			continue
		}
		pos := idx[k]
		uniq := dedupeStrings(titles, out[pos].Title)
		if len(uniq) > 0 {
			out[pos].Description += "\n\nAlso reported by: " + strings.Join(uniq, ", ") + "."
		}
	}
	return out
}

// idSegmentRe matches a path segment that's an object id — a UUID, a 2+ digit
// number, or a template placeholder ({id} / {{var}}) — so the same endpoint
// addressed with different ids collapses in the dedup key. This makes the
// deterministic BOLA playbook and an adaptive BOLA hit on the same endpoint
// (one targets …/vehicle/{{victim}}/location, the other …/vehicle/<uuid>/…)
// read as one finding instead of two.
var idSegmentRe = regexp.MustCompile(`(?i)(/)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|\d{2,}|\{\{[^}]+\}\}|\{[^}]+\})(/|$)`)

// normalizeFindingTarget lowercases/trims a finding target and collapses its
// object-id path segments to ":id" for dedup keying.
func normalizeFindingTarget(target string) string {
	t := strings.ToLower(strings.TrimSpace(target))
	// Apply twice to catch adjacent id segments separated by a shared slash.
	for i := 0; i < 2; i++ {
		t = idSegmentRe.ReplaceAllString(t, "$1:id$3")
	}
	return t
}

// dedupeStrings returns the unique entries of in, excluding `exclude` and
// preserving first-seen order.
func dedupeStrings(in []string, exclude string) []string {
	seen := map[string]struct{}{strings.ToLower(exclude): {}}
	var out []string
	for _, s := range in {
		l := strings.ToLower(s)
		if _, dup := seen[l]; dup {
			continue
		}
		seen[l] = struct{}{}
		out = append(out, s)
	}
	return out
}

// unsafeFilenameChars matches every character that is not safe in a single
// path segment across the platforms we support (path separators, the Windows
// reserved set, and control chars). Runs of them collapse to one dash.
var unsafeFilenameChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// sanitizeFilename turns an arbitrary label (which may contain a URL scheme,
// slashes, or colons) into a single safe filename segment.
func sanitizeFilename(s string) string {
	out := unsafeFilenameChars.ReplaceAllString(s, "-")
	out = strings.Trim(out, "-.")
	if out == "" {
		return "report"
	}
	return out
}
