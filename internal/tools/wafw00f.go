package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// Wafw00fTool wraps EnableSecurity/wafw00f (https://github.com/EnableSecurity/wafw00f)
// for Web Application Firewall fingerprinting. It sends a handful of
// benign and malicious probes and matches the responses against a
// signature library to name the WAF/CDN sitting in front of a target.
//
// Knowing a WAF is present changes how the rest of the swarm should
// probe a host, so every result is surfaced at "info" severity: a
// detection is a routing signal for the classifier, not a vulnerability
// in itself.
type Wafw00fTool struct{}

// NewWafw00fTool constructs the adapter.
func NewWafw00fTool() *Wafw00fTool { return &Wafw00fTool{} }

// Name implements Tool.
func (w *Wafw00fTool) Name() string { return "wafw00f" }

// IsAvailable checks for `wafw00f` on PATH.
func (w *Wafw00fTool) IsAvailable() bool { return IsCommandAvailable("wafw00f") }

// Run executes wafw00f against a target URL.
//
// Supported options:
//
//	timeout     int    — per-invocation timeout in seconds (default 120).
//	find_all    bool   — keep testing past the first match (-a). Default
//	                     false — stop on the first detected WAF.
//	no_redirect bool   — do not follow 3xx redirects (-r). Default false.
//	proxy       string — route requests through an HTTP/SOCKS proxy (-p).
//	req_timeout int    — wafw00f's own per-request timeout (-T). Separate
//	                     from the process timeout above, which is a hard kill.
func (w *Wafw00fTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	if scopeDef := getScopeFromContext(ctx); scopeDef != nil {
		if err := scope.ValidateAndLog("wafw00f", target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in wafw00f: %w", err)
		}
	}

	timeout := time.Duration(opts.GetInt("timeout", 120)) * time.Second

	tmp, err := os.CreateTemp("", "wafw00f-*.json")
	if err != nil {
		return &ToolResult{ToolName: "wafw00f", Target: target, Error: err}, err
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(tmpPath)

	args := []string{
		target,
		"-o", tmpPath,
		"-f", "json",
		"--no-colors",
	}
	if opts.GetBool("find_all", false) {
		args = append(args, "-a")
	}
	if opts.GetBool("no_redirect", false) {
		args = append(args, "-r")
	}
	if proxy := opts.GetString("proxy", ""); proxy != "" {
		args = append(args, "-p", proxy)
	}
	if reqTimeout := opts.GetInt("req_timeout", 0); reqTimeout > 0 {
		args = append(args, "-T", fmt.Sprintf("%d", reqTimeout))
	}

	result := RunToolCommand(ctx, "wafw00f", target, timeout, "wafw00f", args...)
	if result.Error != nil && !strings.Contains(result.Error.Error(), "exit status") {
		return result, result.Error
	}
	result.Error = nil

	body, readErr := os.ReadFile(tmpPath)
	if readErr != nil || len(body) == 0 {
		body = []byte(result.RawOutput)
	}
	result.ParsedFindings = parseWafw00fJSON(body)
	return result, nil
}

// wafw00fResult mirrors one record of wafw00f's `-f json` output: a
// flat array of per-URL results. `detected` is false (with firewall
// "None") when nothing matched.
type wafw00fResult struct {
	URL          string `json:"url"`
	Detected     bool   `json:"detected"`
	TriggerURL   string `json:"trigger_url"`
	Firewall     string `json:"firewall"`
	Manufacturer string `json:"manufacturer"`
}

// parseWafw00fJSON turns the result array into findings. A detected WAF
// yields one finding naming the product and vendor; a clean result
// yields a single "no WAF detected" finding so the classifier can record
// that the target is unprotected. All findings are "info" severity.
func parseWafw00fJSON(body []byte) []map[string]any {
	if len(body) == 0 {
		return nil
	}
	var results []wafw00fResult
	if err := json.Unmarshal(body, &results); err != nil {
		return nil
	}
	var findings []map[string]any
	for _, r := range results {
		if r.Detected {
			findings = append(findings, map[string]any{
				"tool":         "wafw00f",
				"url":          r.URL,
				"title":        fmt.Sprintf("WAF detected: %s", r.Firewall),
				"firewall":     r.Firewall,
				"manufacturer": r.Manufacturer,
				"trigger_url":  r.TriggerURL,
				"severity":     "info",
			})
			continue
		}
		findings = append(findings, map[string]any{
			"tool":     "wafw00f",
			"url":      r.URL,
			"title":    "No WAF detected",
			"firewall": "None",
			"severity": "info",
		})
	}
	return findings
}
