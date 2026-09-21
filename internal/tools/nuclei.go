package tools

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// NucleiTool wraps nuclei for template-based vulnerability scanning.
type NucleiTool struct{}

func NewNucleiTool() *NucleiTool { return &NucleiTool{} }

func (n *NucleiTool) Name() string { return "nuclei" }

func (n *NucleiTool) IsAvailable() bool { return IsCommandAvailable("nuclei") }

func (n *NucleiTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	scopeDef := getScopeFromContext(ctx)
	if scopeDef != nil {
		if err := scope.ValidateAndLog("nuclei", target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in nuclei: %w", err)
		}
	}

	timeout := time.Duration(opts.GetInt("timeout", 120)) * time.Second
	args := buildNucleiArgs(target, opts)

	result := RunToolCommand(ctx, "nuclei", target, timeout, "nuclei", args...)
	return result, result.Error
}

// buildNucleiArgs assembles the nuclei command line from playbook options. It's
// a pure function so a playbook can select specific templates/tags/severity and
// we can unit-test the mapping without the nuclei binary. Recognised options:
//   - severity   []string  → -severity a,b   (default critical,high,medium)
//   - templates  []string  → -t t1 -t t2     (template dirs/files/ids)
//   - tags       []string  → -tags a,b       (template tags, e.g. a CVE id)
//   - rate_limit int        → -rate-limit N
func buildNucleiArgs(target string, opts Options) []string {
	severity := opts.GetStringSlice("severity")
	if severity == nil {
		severity = []string{"critical", "high", "medium"}
	}

	// Nuclei v3 replaced the legacy `-json` flag with `-jsonl` (JSON-Lines).
	// Passing the old flag makes the binary exit immediately with
	// "flag provided but not defined: -json", killing the recon pipeline.
	args := []string{"-u", target, "-jsonl", "-silent", "-severity", strings.Join(severity, ",")}

	// -t may be repeated; one flag per template keeps dirs, files and ids
	// (e.g. "cves/2026/", "http/cves/2026/CVE-2026-75650.yaml") unambiguous.
	for _, tpl := range opts.GetStringSlice("templates") {
		if tpl != "" {
			args = append(args, "-t", tpl)
		}
	}

	if tags := opts.GetStringSlice("tags"); len(tags) > 0 {
		args = append(args, "-tags", strings.Join(tags, ","))
	}

	if rl := opts.GetInt("rate_limit", 0); rl > 0 {
		args = append(args, "-rate-limit", fmt.Sprintf("%d", rl))
	}

	return args
}
