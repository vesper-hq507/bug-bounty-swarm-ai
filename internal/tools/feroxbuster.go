package tools

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// FeroxbusterTool wraps epi052/feroxbuster (https://github.com/epi052/feroxbuster),
// a fast, recursive content-discovery scanner (an alternative to
// gobuster/ffuf). Discovered paths become endpoints on the blackboard
// for the classifier and exploit agents to work.
//
// feroxbuster's `--json` mode emits NDJSON — one JSON object per line —
// interleaving a config header, per-response records, and a trailing
// statistics summary. We keep only the `response` records and surface
// each discovered path at "info" severity; content discovery reports
// existence, not risk, so the classifier promotes individual paths
// after correlating against context.
type FeroxbusterTool struct{}

// NewFeroxbusterTool constructs the adapter.
func NewFeroxbusterTool() *FeroxbusterTool { return &FeroxbusterTool{} }

// Name implements Tool.
func (f *FeroxbusterTool) Name() string { return "feroxbuster" }

// IsAvailable checks for `feroxbuster` on PATH.
func (f *FeroxbusterTool) IsAvailable() bool { return IsCommandAvailable("feroxbuster") }

// Run executes feroxbuster against a target URL.
//
// Supported options:
//
//	wordlist string — wordlist path (-w). Defaults to the common SecLists path.
//	threads  int    — concurrent threads (-t). Default 40.
//	depth    int    — maximum recursion depth (-d); 0 is infinite. Default 4.
//	timeout  int    — per-invocation process timeout in seconds. Default 300.
func (f *FeroxbusterTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	if scopeDef := getScopeFromContext(ctx); scopeDef != nil {
		if err := scope.ValidateAndLog("feroxbuster", target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in feroxbuster: %w", err)
		}
	}

	wordlist := opts.GetString("wordlist", "/usr/share/seclists/Discovery/Web-Content/common.txt")
	threads := opts.GetInt("threads", 40)
	depth := opts.GetInt("depth", 4)
	timeout := time.Duration(opts.GetInt("timeout", 300)) * time.Second

	outFile, err := os.CreateTemp("", "feroxbuster-*.json")
	if err != nil {
		return &ToolResult{ToolName: "feroxbuster", Target: target, Error: err}, err
	}
	outPath := outFile.Name()
	_ = outFile.Close()
	defer os.Remove(outPath)

	args := []string{
		"--url", target,
		"--wordlist", wordlist,
		"--threads", fmt.Sprintf("%d", threads),
		"--depth", fmt.Sprintf("%d", depth),
		"--json",
		"--output", outPath,
		"--silent",
	}

	result := RunToolCommand(ctx, f.Name(), target, timeout, "feroxbuster", args...)
	if result.Error != nil && !strings.Contains(result.Error.Error(), "exit status") {
		return result, result.Error
	}
	result.Error = nil

	body, readErr := os.ReadFile(outPath)
	if readErr != nil || len(body) == 0 {
		body = []byte(result.RawOutput)
	}
	result.ParsedFindings = parseFeroxbusterJSON(body)
	return result, nil
}

// feroxbusterResponse mirrors the `response`-typed NDJSON records
// feroxbuster writes under `--json`: a discovered path with its status
// code and response size counters.
type feroxbusterResponse struct {
	Type          string `json:"type"`
	URL           string `json:"url"`
	Path          string `json:"path"`
	Method        string `json:"method"`
	Status        int    `json:"status"`
	ContentLength int64  `json:"content_length"`
	LineCount     int64  `json:"line_count"`
	WordCount     int64  `json:"word_count"`
}

// parseFeroxbusterJSON walks the NDJSON stream and emits one finding
// per `response` record. Config and statistics records are skipped.
func parseFeroxbusterJSON(body []byte) []map[string]any {
	if len(body) == 0 {
		return nil
	}
	var findings []map[string]any
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var r feroxbusterResponse
		if err := json.Unmarshal(line, &r); err != nil {
			continue
		}
		if r.Type != "response" || r.URL == "" {
			continue
		}
		findings = append(findings, map[string]any{
			"tool":           "feroxbuster",
			"url":            r.URL,
			"path":           r.Path,
			"method":         r.Method,
			"status":         r.Status,
			"content_length": r.ContentLength,
			"line_count":     r.LineCount,
			"word_count":     r.WordCount,
			"title":          fmt.Sprintf("%s (status %d)", r.URL, r.Status),
			"severity":       "info",
		})
	}
	return findings
}
