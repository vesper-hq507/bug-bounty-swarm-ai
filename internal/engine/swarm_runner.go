package engine

import (
	"context"
	"encoding/json"
	"fmt"
	neturl "net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	classifierpkg "github.com/Armur-Ai/Pentest-Swarm-AI/internal/agent/classifier"
	exploitpkg "github.com/Armur-Ai/Pentest-Swarm-AI/internal/agent/exploit"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/agent/prompts"
	reconpkg "github.com/Armur-Ai/Pentest-Swarm-AI/internal/agent/recon"
	reportpkg "github.com/Armur-Ai/Pentest-Swarm-AI/internal/agent/report"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/config"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/jev"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/llm"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/policygateway"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/poc"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/session"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/swarm"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/swarm/agents"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/swarm/blackboard"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/swarm/quality"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/swarm/tuning"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/swarm/verify"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/tools"
	"github.com/google/uuid"
)

// togetherModelFor picks a sensible Together AI model for an agent role so a
// run uses a *mixture* of open models by task: a cheap/fast one for bulk work
// (recon parsing, report formatting) and a stronger reasoner for the hard
// exploit/classify steps.
//
// The reasoning roles run on Z.ai's GLM-5.3-Flash — the top-ranked open-weight
// model on the agentic leaderboard as of Sept 2026, with near-frontier
// exploitation reasoning at a fraction of the cost. It's both *stronger* and
// *cheaper* than the DeepSeek-V3 / Qwen2.5 it replaces, so the swarm got
// sharper and its per-run cost went down at the same time.
//
// Prices (per Mtok, integration-time snapshot): Llama-3.3-70B ~$0.88 flat,
// GLM-5.3-Flash $0.15 in / $0.50 out ($0.03 cached). Keeping bulk work on
// Llama holds a full run near the single-model baseline.
func togetherModelFor(role string) string {
	switch role {
	case "classifier", "exploit":
		return "zai-org/GLM-5.3-Flash"
	default: // recon, report — bulk work, cheapest capable model
		return "meta-llama/Llama-3.3-70B-Instruct-Turbo"
	}
}

// openrouterModelFor picks a model per agent role for the OpenRouter gateway —
// the same "mixture by task" idea as togetherModelFor, but drawing on
// OpenRouter's 400+ model catalog through a single key. Bulk roles (recon,
// report) run on DeepSeek V4.1 Flash — cheap, fast, 1M-token context; the
// reasoning-heavy roles (classify, exploit) run on GLM-5.3-Flash, the
// top-ranked open-weight agentic reasoner. Both are a fraction of frontier
// cost, so a full run stays in pennies, and OpenRouter adds automatic
// provider-level fallback so a backend outage mid-campaign doesn't stall the
// swarm. An explicit per-agent model in config always wins over this default.
func openrouterModelFor(role string) string {
	switch role {
	case "classifier", "exploit":
		return "z-ai/glm-5.3-flash"
	default: // recon, report — bulk work, cheapest capable model
		return "deepseek/deepseek-v4.1-flash"
	}
}

// mixtureMeterModel returns the costliest model across all agent roles for a
// per-role routing function, so the aggregate cost meter prices conservatively
// — the budget cap then errs toward stopping a run slightly early rather than
// overspending. Derived from the pricing table rather than hardcoded, so it
// stays correct whenever the per-role routing changes (e.g. a bulk model that's
// pricier per token than the reasoning one).
func mixtureMeterModel(modelFor func(string) string) string {
	best := modelFor("recon")
	var bestHi float64 = -1
	for _, role := range []string{"recon", "classifier", "exploit", "report"} {
		m := modelFor(role)
		p := llm.PricingFor(m)
		hi := p.InputPerMillion
		if p.OutputPerMillion > hi {
			hi = p.OutputPerMillion
		}
		if hi > bestHi {
			bestHi, best = hi, m
		}
	}
	return best
}

// RunSwarm executes a campaign using the stigmergic swarm (blackboard +
// scheduler) rather than the sequential 5-phase runner.
//
// It is intentionally API-compatible with Run so the CLI can flip between
// them via --swarm. The swarm path terminates via two conditions:
//
//   - the campaign context is canceled (SIGINT, deadline, etc.), OR
//   - the per-campaign time budget elapses, after which the runner writes
//     CAMPAIGN_COMPLETE and waits for the report agent to finish.
//
// Budget is currently time-based: DefaultSwarmTimeBudget below. A future
// revision will watch for blackboard quiescence instead.
func (r *Runner) RunSwarm(ctx context.Context, cc CampaignConfig, onEvent EventCallback) error {
	start := time.Now()
	campaignID := uuid.New()

	scopeDef, err := buildScope(cc.Scope)
	if err != nil {
		return fmt.Errorf("invalid scope: %w", err)
	}

	policyGate := policygateway.New(policygateway.Policy{
		Scope:       *scopeDef,
		Constraints: cc.ProgramConstraints,
		Version:     cc.PolicyVersion,
	})

	campaign := pipeline.Campaign{
		ID:        campaignID,
		Name:      fmt.Sprintf("swarm-%s-%s", cc.Target, time.Now().Format("20060102-150405")),
		Target:    cc.Target,
		Objective: cc.Objective,
		Status:    pipeline.StatusPlanned,
		Mode:      pipeline.CampaignMode(cc.Mode),
		Scope: pipeline.ScopeDefinition{
			AllowedDomains: scopeDef.AllowedDomains,
			AllowedCIDRs:   scopeDef.AllowedCIDRs,
		},
		CreatedAt: time.Now(),
	}

	emit := func(eventType pipeline.EventType, agent, detail string) {
		if onEvent != nil {
			onEvent(pipeline.CampaignEvent{
				ID:         uuid.New(),
				CampaignID: campaignID,
				Timestamp:  time.Now(),
				EventType:  eventType,
				AgentName:  agent,
				Detail:     detail,
			})
		}
	}

	orchestratorCfg := r.cfg.Orchestrator
	if cc.Provider != "" {
		orchestratorCfg.Provider = cc.Provider
	}
	if cc.APIKey != "" {
		orchestratorCfg.APIKey = cc.APIKey
	}

	// One cost meter aggregates spend across every agent's provider so the
	// budget cap sees the true total. On Together (a mixture of models) it's
	// priced at the priciest model in the mix, so the cap errs on the side of
	// stopping slightly early rather than overspending.
	meterModel := orchestratorCfg.Model
	switch orchestratorCfg.Provider {
	case "together":
		meterModel = mixtureMeterModel(togetherModelFor) // costliest model across the role mix
	case "openrouter":
		meterModel = mixtureMeterModel(openrouterModelFor)
	}
	meter := llm.NewMeter(meterModel)

	// Per-task model routing: each specialist agent gets its own metered
	// provider. On Together we route cheap/bulk work (recon, report) to a fast
	// low-cost model and reserve stronger models for the reasoning-heavy
	// exploit/classify steps — a real "mixture by task" that keeps a run near
	// the single-model baseline (~$1) rather than multiplying it. An explicit
	// per-agent model in config always wins.
	buildAgent := func(role string, agentCfg config.AgentModelConfig) (llm.Provider, error) {
		cfg := orchestratorCfg
		if agentCfg.Provider != "" {
			cfg.Provider = agentCfg.Provider
		}
		if agentCfg.APIKey != "" {
			cfg.APIKey = agentCfg.APIKey
		}
		if agentCfg.Endpoint != "" {
			cfg.Endpoint = agentCfg.Endpoint
		}
		switch {
		case agentCfg.Model != "":
			cfg.Model = agentCfg.Model // explicit config wins
		case cfg.Provider == "together" && (cfg.Model == "" || strings.HasPrefix(cfg.Model, "claude")):
			cfg.Model = togetherModelFor(role) // smart cheap default per task
		case cfg.Provider == "openrouter" && (cfg.Model == "" || strings.HasPrefix(cfg.Model, "claude")):
			cfg.Model = openrouterModelFor(role) // per-role mixture over OpenRouter's catalog
		}
		p, err := prompts.NewProviderWithRetry(cfg)
		if err != nil {
			return nil, err
		}
		return meter.Wrap(p), nil
	}

	reconProvider, err := buildAgent("recon", r.cfg.Agents.Recon)
	if err != nil {
		return fmt.Errorf("failed to create recon LLM provider: %w", err)
	}
	classifierProvider, err := buildAgent("classifier", r.cfg.Agents.Classifier)
	if err != nil {
		return fmt.Errorf("failed to create classifier LLM provider: %w", err)
	}
	exploitProvider, err := buildAgent("exploit", r.cfg.Agents.Exploit)
	if err != nil {
		return fmt.Errorf("failed to create exploit LLM provider: %w", err)
	}
	reportProvider, err := buildAgent("report", r.cfg.Agents.Report)
	if err != nil {
		return fmt.Errorf("failed to create report LLM provider: %w", err)
	}

	emit(pipeline.EventStateChange, "engine", "Swarm campaign initialized")

	// Live cost meter: on a ticker, emit current $ spend so --follow
	// surfaces it without each agent having to self-report.
	meterCtx, meterCancel := context.WithCancel(ctx)
	defer meterCancel()
	// runStopped is closed when a hard limit (cost cap) or a manual killswitch
	// fires, so the scheduler-driver goroutine below can wind the campaign
	// down gracefully (CAMPAIGN_COMPLETE → report on partial state).
	runStopped := make(chan struct{})
	var stopOnce sync.Once
	stop := func(reason string) {
		stopOnce.Do(func() {
			emit(pipeline.EventMilestone, "scheduler", reason)
			close(runStopped)
		})
	}
	// Manual killswitch (e.g. the dashboard "Stop" button).
	if cc.StopRequested != nil {
		go func() {
			select {
			case <-meterCtx.Done():
			case <-cc.StopRequested:
				stop("killswitch engaged — stopping the swarm")
			}
		}()
	}
	go func() {
		// Poll fast enough that the cost cap is honored promptly, but only
		// emit the human-facing spend line every ~15s to avoid log spam.
		t := time.NewTicker(3 * time.Second)
		defer t.Stop()
		lastReport := time.Now()
		for {
			select {
			case <-meterCtx.Done():
				return
			case <-t.C:
			}
			u, spent := meter.Snapshot()
			if time.Since(lastReport) >= 15*time.Second {
				emit(pipeline.EventMilestone, "cost",
					fmt.Sprintf("spent $%.3f so far (%d in / %d cached / %d out)",
						spent, u.InputTokens, u.CacheReadInputTokens, u.OutputTokens))
				lastReport = time.Now()
			}
			if cc.MaxCostUSD > 0 && spent >= cc.MaxCostUSD {
				stop(fmt.Sprintf("cost cap $%.2f reached (spent $%.3f) — winding down", cc.MaxCostUSD, spent))
				return
			}
		}
	}()

	// Always run cleanup on exit, including SIGINT/budget cancellation.
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cleanupCancel()
		if rep := r.cleanup.RunCleanup(cleanupCtx, campaignID); rep != nil && rep.TotalCount > 0 {
			emit(pipeline.EventMilestone, "cleanup",
				fmt.Sprintf("Cleanup ran %d actions (%d executed, %d failed)",
					rep.TotalCount, len(rep.Executed), len(rep.Failed)))
		}
	}()

	// Build the blackboard. Memory-backed for now — Postgres variant is
	// selected in the CLI when a DB pool is available.
	board := blackboard.NewMemoryBoard(nil)

	// Live finding stream: surface each report-worthy finding to the event
	// sink the moment it lands on the board, so the terminal and the live
	// dashboard grade vulnerabilities in real time instead of only at the end.
	if onEvent != nil {
		findCtx, findCancel := context.WithCancel(ctx)
		defer findCancel()
		go func() {
			ch, err := board.Subscribe(findCtx, blackboard.Predicate{
				Types: []blackboard.FindingType{blackboard.TypeMisconfig, blackboard.TypeCVEMatch},
			})
			if err != nil {
				return
			}
			seen := make(map[string]struct{})
			for f := range ch {
				var cf pipeline.ClassifiedFinding
				if json.Unmarshal(f.Data, &cf) != nil {
					continue
				}
				sev := strings.ToLower(string(cf.Severity))
				if sev == "" || sev == "informational" || sev == "info" {
					continue // keep the live stream to real signal
				}
				key := strings.ToLower(strings.TrimSpace(cf.Title))
				if key == "" {
					continue
				}
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}
				desc := cf.Description
				if len(desc) > 600 {
					desc = desc[:600]
				}
				data, _ := json.Marshal(map[string]any{
					"severity": string(cf.Severity), "title": cf.Title, "category": cf.AttackCategory,
					"cvss": cf.CVSSScore, "confidence": string(cf.Confidence), "description": desc,
				})
				onEvent(pipeline.CampaignEvent{
					ID:         uuid.New(),
					CampaignID: campaignID,
					Timestamp:  time.Now(),
					EventType:  pipeline.EventFindingDiscovered,
					AgentName:  f.AgentName,
					Detail:     cf.Title,
					Data:       data,
				})
			}
		}()

		// Attack-surface stream: emit each discovered API endpoint (capped and
		// deduped) so the dashboard can draw the surface as it's mapped. Purely
		// a read-only board subscription, like the finding stream above.
		epCtx, epCancel := context.WithCancel(ctx)
		defer epCancel()
		go func() {
			ch, err := board.Subscribe(epCtx, blackboard.Predicate{
				Types: []blackboard.FindingType{blackboard.TypeHTTPEndpoint},
			})
			if err != nil {
				return
			}
			seen := make(map[string]struct{})
			const maxEP = 16
			for f := range ch {
				var ep pipeline.EndpointRecord
				if json.Unmarshal(f.Data, &ep) != nil || ep.URL == "" {
					continue
				}
				path := ep.URL
				if u, uerr := neturl.Parse(ep.URL); uerr == nil && u.Path != "" {
					path = u.Path
				}
				low := strings.ToLower(path)
				if !strings.Contains(low, "/api/") && !strings.Contains(low, "/identity/") &&
					!strings.Contains(low, "/workshop/") && !strings.Contains(low, "/community/") {
					continue // API surface only — skip static/asset noise
				}
				if _, dup := seen[low]; dup || len(seen) >= maxEP {
					continue
				}
				seen[low] = struct{}{}
				onEvent(pipeline.CampaignEvent{
					ID:         uuid.New(),
					CampaignID: campaignID,
					Timestamp:  time.Now(),
					EventType:  pipeline.EventEndpointDiscovered,
					AgentName:  "recon",
					Detail:     path,
				})
			}
		}()

		// Attack-chain stream: the chain skeleton (EXPLOIT_CHAIN → name + steps
		// + MITRE technique per step) and each step's result (EXPLOIT_RESULT),
		// so the dashboard can render a multi-step exploit executing move by
		// move. The chain finding's own ID correlates the two on the wire.
		chainCtx, chainCancel := context.WithCancel(ctx)
		defer chainCancel()
		go func() {
			ch, err := board.Subscribe(chainCtx, blackboard.Predicate{
				Types: []blackboard.FindingType{blackboard.TypeExploitChain, blackboard.TypeExploitResult},
			})
			if err != nil {
				return
			}
			for f := range ch {
				if f.Type == blackboard.TypeExploitChain {
					var path pipeline.AttackPath
					if json.Unmarshal(f.Data, &path) != nil {
						continue
					}
					steps := make([]map[string]string, 0, len(path.Steps))
					for _, s := range path.Steps {
						if s.Command == "" {
							continue
						}
						steps = append(steps, map[string]string{"name": s.Name, "technique": s.TechniqueID})
					}
					if len(steps) == 0 {
						continue
					}
					data, _ := json.Marshal(map[string]any{"id": f.ID.String(), "name": path.Name, "steps": steps})
					onEvent(pipeline.CampaignEvent{ID: uuid.New(), CampaignID: campaignID, Timestamp: time.Now(),
						EventType: pipeline.EventChainStarted, AgentName: "exploit", Data: data})
					continue
				}
				var w struct {
					ChainID string                   `json:"chain_id"`
					Step    string                   `json:"step"`
					Result  pipeline.ExecutionResult `json:"result"`
				}
				if json.Unmarshal(f.Data, &w) != nil || w.Step == "" {
					continue
				}
				data, _ := json.Marshal(map[string]any{"chain_id": w.ChainID, "step": w.Step, "success": w.Result.Success})
				onEvent(pipeline.CampaignEvent{ID: uuid.New(), CampaignID: campaignID, Timestamp: time.Now(),
					EventType: pipeline.EventChainStep, AgentName: "exploit", Data: data})
			}
		}()
	}

	// Build specialist agents (reusing the existing stack).
	coordinator := tools.NewCoordinator()
	coordinator.SetPolicyGateway(policyGate)
	// Surface missing tool binaries loudly. Without this the coordinator
	// silently skips any tool whose binary isn't on PATH, so recon quietly
	// reports zero findings — the single most confusing failure mode on a
	// fresh install. Point the operator at `pentestswarm doctor`.
	coordinator.SetHooks(&tools.ToolHooks{
		OnSkip: func(name, _, reason string) {
			emit(pipeline.EventError, "recon",
				fmt.Sprintf("skipped %s — %s (run 'pentestswarm doctor' for install commands)", name, reason))
		},
	})
	reconOpts := []reconpkg.Option{
		reconpkg.WithErrorSink(func(err error) { emit(pipeline.EventError, "recon", err.Error()) }),
	}
	classifierOpts := []classifierpkg.Option{
		classifierpkg.WithErrorSink(func(err error) { emit(pipeline.EventError, "classifier", err.Error()) }),
	}
	if r.strict {
		reconOpts = append(reconOpts, reconpkg.WithStrict())
		classifierOpts = append(classifierOpts, classifierpkg.WithStrict())
	}
	if len(cc.NucleiSeverity) > 0 {
		reconOpts = append(reconOpts, reconpkg.WithNucleiSeverity(cc.NucleiSeverity))
	}
	reconOpts = append(reconOpts, reconpkg.WithActiveScan(cc.ActiveScan))
	// Always send a realistic browser fingerprint (plus any user auth) so the
	// swarm isn't blocked as "Go-http-client" before it reaches the app.
	authSession := session.New(session.WithBrowserDefaults(cc.AuthHeaders))
	reconOpts = append(reconOpts, reconpkg.WithSession(authSession))
	reconOpts = append(reconOpts, reconpkg.WithPolicyGateway(policyGate))
	if cc.Browser {
		reconOpts = append(reconOpts, reconpkg.WithBrowser(true))
		emit(pipeline.EventMilestone, "recon", "headless-browser recon enabled (--browser)")
	}
	reconInner := reconpkg.NewReconAgent(reconProvider, coordinator, reconOpts...)
	classifierInner := classifierpkg.NewClassifierAgent(classifierProvider, classifierOpts...)
	exploitInner := exploitpkg.NewExploitAgent(exploitProvider)
	reportInner := reportpkg.NewReportAgent(reportProvider)
	renderer := reportpkg.NewRenderer()

	executor := exploitpkg.NewExecutor(
		&scope.ScopeDefinition{AllowedDomains: scopeDef.AllowedDomains, AllowedCIDRs: scopeDef.AllowedCIDRs},
		r.cleanup,
		cc.DryRun,
	).WithSafeMode(cc.SafeMode).
		WithAllowedExecutables(coordinator.RegisteredToolNames()).
		WithPolicyGateway(policyGate).
		WithSession(authSession)
	if cc.Assist {
		executor = executor.WithConfirm(r.assist)
	}

	// Pheromone tuning: config file if present, else embedded defaults.
	// --exploration-bias on the CLI applies a multiplier at lookup time.
	tuningSettings, _ := tuning.Load("config/pheromones.yaml")
	tuningSettings = tuningSettings.WithBias(tuning.Bias(cc.ExplorationBias))

	// The exploit agent's adaptive BOLA sweep fans out into many concurrent
	// probe work-units (real HTTP replays, not LLM calls). Wire a probe sink so
	// each reports itself as a cheap EventProbe — the dashboard and TUI render
	// this as a live decentralized mesh branching off the exploit node. Capped
	// defensively so a huge attack surface can't flood the event stream.
	exploitSwarm := agents.NewExploitAgent(exploitInner, executor, cc.Objective, campaignID, 2, cc.DryRun, tuningSettings)
	if onEvent != nil {
		var probeCount int64
		exploitSwarm.SetProbeSink(func(target string, ok bool) {
			if atomic.AddInt64(&probeCount, 1) > 200 {
				return
			}
			data, _ := json.Marshal(map[string]any{"target": target, "ok": ok})
			onEvent(pipeline.CampaignEvent{
				ID:         uuid.New(),
				CampaignID: campaignID,
				Timestamp:  time.Now(),
				EventType:  pipeline.EventProbe,
				AgentName:  "exploit",
				Detail:     target,
				Data:       data,
			})
		})
	}

	// Adaptive attack-path scoring via Jev (opt-in): the exploit agent scores its
	// candidate strategies against live state and pursues the best first, grading
	// pheromone by the score. Reuses the Jev key; fails open to a heuristic rank.
	if cc.JevAdaptive && cc.JevAPIKey != "" {
		exploitSwarm.SetPathScorer(exploitpkg.NewJevScorer(jev.New(cc.JevAPIKey)))
		exploitSwarm.SetScoreSink(func(scored []exploitpkg.ScoredPath) {
			// Stream the full ranked scoreboard (not just the winner) so the TUI
			// and web dashboard show which strategies were considered and why.
			for _, line := range exploitpkg.FormatScoreboard(scored) {
				emit(pipeline.EventMilestone, "jev-adaptive", line)
			}
		})
		emit(pipeline.EventMilestone, "jev-adaptive", "adaptive attack-path scoring enabled")
	}

	reportSwarm := agents.NewReportAgent(reportInner, renderer, campaign, cc.OutputDir, cc.Format, cc.PublishThreshold,
		func(paths map[string]string) {
			for k, p := range paths {
				emit(pipeline.EventToolResult, "report", fmt.Sprintf("%s report: %s", k, p))
			}
		}).WithROI(func() float64 { _, s := meter.Snapshot(); return s }, nil).
		WithPoC(reportProvider)
	// Opt-in PoC self-verification: run each generated PoC and mark it VERIFIED
	// only if it fires. Executes LLM-authored code, so it's gated to an explicit
	// --verify-poc outside dry-run/safe-mode, and needs python3 on PATH.
	if cc.VerifyPoC && !cc.DryRun && !cc.SafeMode {
		if runner := poc.NewLocalRunner(); runner.Available() {
			reportSwarm = reportSwarm.WithPoCVerify(runner)
			emit(pipeline.EventMilestone, "report", "PoC self-verification enabled (--verify-poc)")
		} else {
			emit(pipeline.EventMilestone, "report", "--verify-poc set but python3 not found on PATH; generating PoCs without running them")
		}
	}
	// Opt-in final false-positive filter via TypeSafe's Jev model.
	if cc.JevEnabled && cc.JevAPIKey != "" {
		reportSwarm.WithJev(jev.New(cc.JevAPIKey), cc.JevThreshold,
			func(d string) { emit(pipeline.EventMilestone, "jev", d) })
	}

	// Active corroboration at the classifier→exploit handoff (the heterogeneous-
	// swarm guard). Free corroboration + the passive tier gate always run; a
	// bounded paid verification is enabled only when a strictly stronger model
	// than the classifier's is configured and buildable (the orchestrator brain),
	// so a cheap classifier's cost win is never traded away for verification.
	var verifier verify.Verifier
	classifierModel := classifierProvider.ModelName()
	if quality.TierFor(orchestratorCfg.Model).Factor > quality.TierFor(classifierModel).Factor {
		if vp, verr := prompts.NewProviderWithRetry(orchestratorCfg); verr == nil {
			verifier = verify.NewLLMVerifier(meter.Wrap(vp))
			emit(pipeline.EventMilestone, "classifier", "active corroboration enabled (stronger verifier available)")
		}
	}
	corroborator := verify.New(verify.Policy{MaxVerifications: 20}, verifier)

	swarmAgents := []swarm.Agent{
		agents.NewReconAgent(reconInner, &scope.ScopeDefinition{
			AllowedDomains: scopeDef.AllowedDomains,
			AllowedCIDRs:   scopeDef.AllowedCIDRs,
		}, campaignID, 1, tuningSettings),
		agents.NewClassifierAgent(classifierInner, campaignID, 3).WithCorroborator(corroborator),
		exploitSwarm,
		reportSwarm,
	}

	sched := swarm.NewScheduler(board, campaignID,
		swarm.WithEventSink(func(e swarm.Event) {
			switch e.Type {
			case "agent_started":
				emit(pipeline.EventToolCall, e.AgentName, fmt.Sprintf("handling %s", e.FindingID))
			case "agent_finished":
				emit(pipeline.EventToolResult, e.AgentName, fmt.Sprintf("done in %s", e.Detail))
			case "agent_error":
				emit(pipeline.EventError, e.AgentName, e.Detail)
			case "budget_exceeded":
				emit(pipeline.EventMilestone, "scheduler", "budget exceeded — winding down")
			case "campaign_complete":
				emit(pipeline.EventMilestone, "scheduler", "campaign complete signal received")
			}
		}),
	)
	for _, a := range swarmAgents {
		sched.Register(a)
	}

	// Seed the swarm. Without this nothing triggers.
	if err := agents.Seed(ctx, board, campaignID, cc.Target, cc.Objective, tuningSettings); err != nil {
		return fmt.Errorf("seed swarm: %w", err)
	}
	emit(pipeline.EventThought, "orchestrator", fmt.Sprintf("Swarm deployed against %s", cc.Target))

	// Drive the swarm. A separate goroutine writes CAMPAIGN_COMPLETE after
	// the time budget expires, so the report agent fires and the scheduler
	// exits cleanly.
	schedCtx, schedCancel := context.WithCancel(ctx)
	defer schedCancel()

	budget := DefaultSwarmTimeBudget
	windDown := func() {
		_, _ = board.Write(schedCtx, blackboard.Finding{
			CampaignID:    campaignID,
			AgentName:     "engine",
			Type:          blackboard.TypeCampaignComplete,
			Target:        cc.Target,
			PheromoneBase: 1.0,
			HalfLifeSec:   300,
		})
	}
	go func() {
		select {
		case <-schedCtx.Done():
			return
		case <-time.After(budget):
			windDown()
		case <-runStopped:
			// Cost cap hit or killswitch engaged: wind down gracefully so the
			// report agent still fires on whatever the swarm has found so far.
			windDown()
		}
	}()

	if err := sched.Run(schedCtx); err != nil && err != context.Canceled {
		return fmt.Errorf("swarm scheduler: %w", err)
	}

	elapsed := time.Since(start).Round(time.Second)

	// Final cost summary. The ROI verdict (bounty value vs. spend) lands
	// at the bottom of the rendered report itself — see report.WithROI.
	u, spent := meter.Snapshot()
	emit(pipeline.EventMilestone, "cost",
		fmt.Sprintf("total spent $%.3f  (input %d, cached %d, output %d)",
			spent, u.InputTokens, u.CacheReadInputTokens, u.OutputTokens))

	emit(pipeline.EventMilestone, "orchestrator",
		fmt.Sprintf("Swarm campaign complete in %s — see ./reports", elapsed))
	return nil
}

// DefaultSwarmTimeBudget is the default wall-clock cap for a swarm campaign.
// Can be overridden at runtime via CampaignConfig / config later.
const DefaultSwarmTimeBudget = 20 * time.Minute
