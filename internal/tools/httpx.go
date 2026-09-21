package tools

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

type HttpxTool struct{}

func NewHttpxTool() *HttpxTool         { return &HttpxTool{} }
func (h *HttpxTool) Name() string      { return "httpx" }
func (h *HttpxTool) IsAvailable() bool { return IsCommandAvailable("httpx") }

func (h *HttpxTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	scopeDef := getScopeFromContext(ctx)
	if scopeDef != nil {
		if err := scope.ValidateAndLog("httpx", target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in httpx: %w", err)
		}
	}

	timeout := time.Duration(opts.GetInt("timeout", 30)) * time.Second
	args := buildHttpxArgs(target, opts)

	result := RunToolCommand(ctx, "httpx", target, timeout, "httpx", args...)
	return result, result.Error
}

// buildHttpxArgs assembles the httpx command line from playbook options. Pure so
// the option→flag mapping is unit-testable without the httpx binary. Recognised:
//   - follow_redirects bool     → -follow-redirects        (default true)
//   - paths            []string → -path /a,/b              (probe extra paths)
//   - threads          int      → -threads N
// The probe flags (-tech-detect/-status-code/-title/-server) are always on so a
// playbook always gets the fingerprint data the analysis step relies on.
func buildHttpxArgs(target string, opts Options) []string {
	args := []string{"-u", target, "-json", "-tech-detect", "-status-code", "-title", "-server", "-silent"}

	if opts.GetBool("follow_redirects", true) {
		args = append(args, "-follow-redirects")
	}

	if paths := opts.GetStringSlice("paths"); len(paths) > 0 {
		args = append(args, "-path", strings.Join(paths, ","))
	}

	if threads := opts.GetInt("threads", 0); threads > 0 {
		args = append(args, "-threads", fmt.Sprintf("%d", threads))
	}

	return args
}
