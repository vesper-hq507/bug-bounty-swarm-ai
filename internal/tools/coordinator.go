package tools

import (
	"context"
	"sync"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/policygateway"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// ToolRunSummary aggregates results from running multiple tools.
type ToolRunSummary struct {
	Results   []*ToolResult `json:"results"`
	TotalTime time.Duration `json:"total_time"`
	Succeeded int           `json:"succeeded"`
	Failed    int           `json:"failed"`
}

// ToolHooks is an optional set of per-tool lifecycle callbacks the
// coordinator fires during dispatch. All hooks are nil-safe — callers
// supply only the ones they care about.
//
// Useful for streaming progress to the campaign event stream so the
// operator (or chat client) sees each tool start, finish, or get
// skipped as it happens, rather than just a final batch summary.
type ToolHooks struct {
	// OnStart fires immediately before tool.Run() is called.
	OnStart func(name, target string)
	// OnDone fires after tool.Run() returns. err will be non-nil for
	// failures (binary missing returns no error here — that path goes
	// through OnSkip).
	OnDone func(name, target string, result *ToolResult, err error)
	// OnSkip fires when tool.IsAvailable() returns false. Useful for
	// surfacing missing binaries in the event stream.
	OnSkip func(name, target, reason string)
}

func (h *ToolHooks) start(name, target string) {
	if h != nil && h.OnStart != nil {
		h.OnStart(name, target)
	}
}
func (h *ToolHooks) done(name, target string, result *ToolResult, err error) {
	if h != nil && h.OnDone != nil {
		h.OnDone(name, target, result, err)
	}
}
func (h *ToolHooks) skip(name, target, reason string) {
	if h != nil && h.OnSkip != nil {
		h.OnSkip(name, target, reason)
	}
}

// Coordinator manages parallel tool execution.
type Coordinator struct {
	tools   map[string]Tool
	hooks   *ToolHooks
	gateway *policygateway.Gateway
}

// NewCoordinator creates a coordinator with all registered tools.
func NewCoordinator() *Coordinator {
	c := &Coordinator{
		tools: make(map[string]Tool),
	}

	// Register all built-in tools. Tools that rely on external binaries
	// (nmap) are advertised here but filtered at dispatch time via
	// IsAvailable() — `pentestswarm doctor` flags missing binaries so
	// users aren't surprised at scan time.
	allTools := []Tool{
		NewSubfinderTool(),
		NewHttpxTool(),
		NewNucleiTool(),
		NewNaabuTool(),
		NewKatanaTool(),
		NewDnsxTool(),
		NewGauTool(),
		NewNmapTool(),
		NewSqlmapTool(),
		NewFfufTool(),
		NewGobusterTool(),
		NewFeroxbusterTool(),
		NewTrufflehogTool(),
		NewGitleaksTool(),
		NewSemgrepTool(),
		NewAmassTool(),
		NewDalfoxTool(),
		NewJWTTool(),
		NewArjunTool(),
		NewYsoserialTool(),
		NewInteractshTool(),
		NewTestSSLTool(),
		NewCRLFuzzTool(),
		NewWPScanTool(),
		NewCheckovTool(),
		NewGXSSTool(),
		NewProwlerTool(),
		NewPacuTool(),
		NewScoutSuiteTool(),
		NewCloudsplainingTool(),
		NewKubeHunterTool(),
		NewDroopescanTool(),
		NewNiktoTool(),
		NewWafw00fTool(),
		NewDotDotPwnTool(),
		NewCrackMapExecTool(),
		NewBloodHoundTool(),
	}

	for _, t := range allTools {
		c.tools[t.Name()] = t
	}

	return c
}

// SetHooks installs lifecycle callbacks. Call this immediately after
// NewCoordinator(); not safe to mutate concurrently with RunAll/RunSelected.
func (c *Coordinator) SetHooks(h *ToolHooks) {
	c.hooks = h
}

// SetPolicyGateway attaches the campaign's authoritative program-policy
// decision point. Tool launches are denied here when scope/automation/technique
// policy forbids them. Adapter-level per-request RPS/header propagation is a
// separate enforcement layer; one tool launch is not treated as one request.
func (c *Coordinator) SetPolicyGateway(g *policygateway.Gateway) {
	c.gateway = g
}

func (c *Coordinator) policyCompatible(t Tool, target string) bool {
	if c.gateway == nil {
		return true
	}
	p := c.gateway.Policy()
	needsRate := p.Constraints.MaxRequestsPerSecond > 0
	needsHeaders := len(p.Constraints.RequiredHeaders) > 0
	if !needsRate && !needsHeaders {
		return true
	}

	aware, ok := t.(ProgramPolicyAware)
	if !ok {
		c.hooks.skip(t.Name(), target, "blocked by program policy: adapter has not declared constrained-traffic support")
		return false
	}
	caps := aware.ProgramPolicyCapabilities()
	if !caps.TargetTraffic {
		return true
	}
	if needsRate && !caps.RateLimit {
		c.hooks.skip(t.Name(), target, "blocked by program policy: adapter cannot enforce the imported request-rate limit")
		return false
	}
	if needsRate && p.Constraints.MaxRequestsPerSecond < 1 && !caps.SubRPS {
		c.hooks.skip(t.Name(), target, "blocked by program policy: adapter cannot safely enforce a sub-1 req/s rate limit")
		return false
	}
	if needsHeaders && caps.HTTP && !caps.RequiredHeaders {
		c.hooks.skip(t.Name(), target, "blocked by program policy: adapter cannot inject required program headers")
		return false
	}
	return true
}

func (c *Coordinator) toolAllowed(name, target string) bool {
	if c.gateway == nil {
		return true
	}
	d := c.gateway.Decide(policygateway.Action{
		Kind:      policygateway.ActionTool,
		Target:    target,
		Tool:      name,
		Automated: true,
	})
	if !d.Allowed {
		c.hooks.skip(name, target, "blocked by program policy: "+d.Reason)
		return false
	}
	return true
}

func (c *Coordinator) policyOptions(opts Options) Options {
	if c.gateway == nil {
		return opts
	}
	out := make(Options, len(opts)+2)
	for k, v := range opts {
		out[k] = v
	}
	p := c.gateway.Policy()
	if p.Constraints.MaxRequestsPerSecond > 0 {
		out["program_max_rps"] = p.Constraints.MaxRequestsPerSecond
	}
	if len(p.Constraints.RequiredHeaders) > 0 {
		headers := make(map[string]string, len(p.Constraints.RequiredHeaders))
		for k, v := range p.Constraints.RequiredHeaders {
			headers[k] = v
		}
		out["program_required_headers"] = headers
	}
	return out
}

// RunAll executes all tools concurrently against the target.
// Results are streamed to the results channel as each tool completes.
func (c *Coordinator) RunAll(ctx context.Context, target string, scopeDef *scope.ScopeDefinition, opts Options) (*ToolRunSummary, <-chan *ToolResult) {
	resultCh := make(chan *ToolResult, len(c.tools))
	summary := &ToolRunSummary{}

	// Attach scope to context for tool validation
	toolCtx := WithScope(ctx, scopeDef)
	start := time.Now()

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, tool := range c.tools {
		if !tool.IsAvailable() {
			c.hooks.skip(tool.Name(), target, "binary not found in PATH")
			continue
		}
		if !c.toolAllowed(tool.Name(), target) || !c.policyCompatible(tool, target) {
			continue
		}

		wg.Add(1)
		go func(t Tool) {
			defer wg.Done()

			c.hooks.start(t.Name(), target)
			result, err := t.Run(toolCtx, target, c.policyOptions(opts))
			if err != nil {
				result = &ToolResult{
					ToolName: t.Name(),
					Target:   target,
					Error:    err,
				}
				mu.Lock()
				summary.Failed++
				mu.Unlock()
			} else {
				mu.Lock()
				summary.Succeeded++
				mu.Unlock()
			}

			mu.Lock()
			summary.Results = append(summary.Results, result)
			mu.Unlock()

			c.hooks.done(t.Name(), target, result, err)

			// Stream result as it completes
			select {
			case resultCh <- result:
			case <-ctx.Done():
			}
		}(tool)
	}

	// Close channel when all tools complete
	go func() {
		wg.Wait()
		summary.TotalTime = time.Since(start)
		close(resultCh)
	}()

	return summary, resultCh
}

// RunSelected executes only the specified tools.
func (c *Coordinator) RunSelected(ctx context.Context, toolNames []string, target string, scopeDef *scope.ScopeDefinition, opts Options) (*ToolRunSummary, <-chan *ToolResult) {
	resultCh := make(chan *ToolResult, len(toolNames))
	summary := &ToolRunSummary{}

	toolCtx := WithScope(ctx, scopeDef)
	start := time.Now()

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, name := range toolNames {
		t, ok := c.tools[name]
		if !ok {
			c.hooks.skip(name, target, "tool not registered")
			continue
		}
		if !t.IsAvailable() {
			c.hooks.skip(name, target, "binary not found in PATH")
			continue
		}
		if !c.toolAllowed(name, target) || !c.policyCompatible(t, target) {
			continue
		}

		wg.Add(1)
		go func(tool Tool) {
			defer wg.Done()

			c.hooks.start(tool.Name(), target)
			result, err := tool.Run(toolCtx, target, c.policyOptions(opts))
			if err != nil {
				result = &ToolResult{
					ToolName: tool.Name(),
					Target:   target,
					Error:    err,
				}
				mu.Lock()
				summary.Failed++
				mu.Unlock()
			} else {
				mu.Lock()
				summary.Succeeded++
				mu.Unlock()
			}

			mu.Lock()
			summary.Results = append(summary.Results, result)
			mu.Unlock()

			c.hooks.done(tool.Name(), target, result, err)

			select {
			case resultCh <- result:
			case <-ctx.Done():
			}
		}(t)
	}

	go func() {
		wg.Wait()
		summary.TotalTime = time.Since(start)
		close(resultCh)
	}()

	return summary, resultCh
}

// AvailableTools returns names of all registered and available tools.
func (c *Coordinator) AvailableTools() []string {
	var names []string
	for name, t := range c.tools {
		if t.IsAvailable() {
			names = append(names, name)
		}
	}
	return names
}

// RegisteredToolNames returns the names of all registered tools,
// regardless of whether their binary is currently installed. The exploit
// executor uses this to derive its executable allowlist (#43): if a tool
// is on this list, the LLM is allowed to ask the executor to invoke it.
// Availability gating still happens separately at dispatch time.
func (c *Coordinator) RegisteredToolNames() []string {
	names := make([]string, 0, len(c.tools))
	for name := range c.tools {
		names = append(names, name)
	}
	return names
}
