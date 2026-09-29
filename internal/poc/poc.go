// Package poc generates proof-of-concept scripts that VERIFY a finding — the
// difference between "this looks vulnerable" and "run this and watch it prove
// it." For a confirmed finding it synthesises a self-contained Python script
// (standard library only, so it runs anywhere with python3 and no pip install)
// that reproduces the vulnerability and prints a clear VULNERABLE / NOT
// CONFIRMED verdict.
//
// Safety is the whole point of this package, enforced in depth:
//
//   - The system prompt demands a NON-WEAPONISED proof: a benign demonstration
//     (read a version string, run `id`, fetch ONE other object to show an ID
//     mismatch), never a destructive or disruptive payload, never mass
//     exfiltration, never denial of service.
//   - Every generated script is run through a safety scan that rejects
//     destructive content (rm -rf, DROP/TRUNCATE, rmtree, fork bombs, shutdown,
//     …). A script that fails gets one repair attempt; if it still fails, no PoC
//     is returned rather than a dangerous one.
//   - Generation is NOT execution. This package only writes the script; it never
//     runs LLM-authored code. Running a PoC stays a deliberate, separate act
//     under the scope/dry-run/safe-mode executor.
package poc

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/llm"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
)

// completer is the minimal LLM surface this package needs (provider-agnostic,
// same shape as the Chain Forge generator).
type completer interface {
	Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error)
}

// PoC is a generated proof-of-concept script for a single finding.
type PoC struct {
	Title    string // the finding it proves
	Target   string
	Language string // always "python" in v1
	Filename string // suggested artifact name, e.g. poc-bola-orders.py
	Script   string // the self-contained script
}

const pocSystemPrompt = `You are a senior penetration tester writing a SAFE, non-weaponised proof-of-concept
that VERIFIES a single vulnerability for a report a human will read and re-run.

Output rules:
- Output ONLY a single self-contained Python 3 script. No prose, no markdown outside one code block.
- Use the Python STANDARD LIBRARY ONLY (urllib, http.client, json, ssl, sys, argparse). No pip installs, no requests.
- Read the target base URL from argv (default to the target given). Never hardcode secrets.
- Print a clear final verdict line: "VULNERABLE: <one line why>" on success, or "NOT CONFIRMED: <why>" otherwise.
- Exit 0 only when the vulnerability is demonstrated, non-zero otherwise.

Safety rules (MANDATORY — this is a PROOF, not an attack):
- Demonstrate reachability/impact with a BENIGN signal only: read a version banner, run "id" or "whoami" for RCE,
  fetch exactly ONE other object to show a BOLA/IDOR id mismatch, reflect a harmless marker for XSS,
  extract a single harmless value (e.g. current_user/version) for SQLi.
- NEVER destroy, modify, or bulk-extract data. No DROP/DELETE/TRUNCATE, no rm, no file writes on the target,
  no shutdown/reboot, no loops that flood the target, no lateral movement, no persistence.
- Stay on the single in-scope target host. Do not scan or reach any other host.
- Add a top-of-file comment block: the finding title, the target, "SAFE / non-destructive proof-of-concept",
  and one line on exactly what it proves and how to run it.`

// Generate synthesises a safe PoC script for a finding using the given LLM. It
// validates the result with a safety scan and makes one repair attempt before
// giving up. Returns (nil, nil) with no error only if the model produced nothing
// usable; a script that cannot be made safe returns an error rather than an
// unsafe PoC.
func Generate(ctx context.Context, c completer, f pipeline.ClassifiedFinding) (*PoC, error) {
	if strings.TrimSpace(f.Target) == "" {
		return nil, fmt.Errorf("finding has no target to prove against")
	}
	user := promptFor(f)

	script, err := ask(ctx, c, user)
	if err != nil {
		return nil, err
	}
	if bad := safetyScan(script); len(bad) > 0 {
		// One repair attempt: tell the model exactly what tripped the scan.
		repair := fmt.Sprintf("Your script was rejected by the safety scan for containing: %s.\n"+
			"Rewrite it as a SAFE, non-destructive proof. Output ONLY the corrected Python script.",
			strings.Join(bad, ", "))
		script2, err2 := ask(ctx, c, user+"\n\n"+repair)
		if err2 != nil {
			return nil, err2
		}
		if bad2 := safetyScan(script2); len(bad2) > 0 {
			return nil, fmt.Errorf("refusing to emit PoC: unsafe content after repair (%s)", strings.Join(bad2, ", "))
		}
		script = script2
	}
	if strings.TrimSpace(script) == "" {
		return nil, nil
	}
	return &PoC{
		Title:    f.Title,
		Target:   f.Target,
		Language: "python",
		Filename: filename(f),
		Script:   script,
	}, nil
}

func promptFor(f pipeline.ClassifiedFinding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Write a safe proof-of-concept for this finding.\n\n")
	fmt.Fprintf(&b, "Title: %s\n", f.Title)
	fmt.Fprintf(&b, "Target: %s\n", f.Target)
	fmt.Fprintf(&b, "Severity: %s\n", f.Severity)
	if f.AttackCategory != "" {
		fmt.Fprintf(&b, "Class: %s\n", f.AttackCategory)
	}
	if len(f.CVEIDs) > 0 {
		fmt.Fprintf(&b, "CVEs: %s\n", strings.Join(f.CVEIDs, ", "))
	}
	if d := strings.TrimSpace(f.Description); d != "" {
		fmt.Fprintf(&b, "Description: %s\n", d)
	}
	// The reproduction, when present, is the seed the PoC should robustly codify.
	if f.Reproduce != nil {
		if f.Reproduce.Command != "" {
			fmt.Fprintf(&b, "Known reproduction command: %s\n", f.Reproduce.Command)
		}
		if f.Reproduce.HTTPRequest != "" {
			fmt.Fprintf(&b, "Known reproduction HTTP request:\n%s\n", f.Reproduce.HTTPRequest)
		}
		if f.Reproduce.ExpectedIndicator != "" {
			fmt.Fprintf(&b, "Success indicator to check for: %s\n", f.Reproduce.ExpectedIndicator)
		}
	}
	return b.String()
}

func ask(ctx context.Context, c completer, user string) (string, error) {
	resp, err := c.Complete(ctx, llm.CompletionRequest{
		SystemPrompt: pocSystemPrompt,
		Messages:     []llm.Message{{Role: "user", Content: user}},
		MaxTokens:    3000,
		Temperature:  0.1,
	})
	if err != nil {
		return "", fmt.Errorf("provider call failed: %w", err)
	}
	if resp == nil || strings.TrimSpace(resp.Content) == "" {
		return "", fmt.Errorf("empty response from provider")
	}
	return extractCode(resp.Content), nil
}

// extractCode strips a ```python / ``` fence if the model wrapped its output.
func extractCode(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "```"); i >= 0 {
		rest := s[i+3:]
		rest = strings.TrimPrefix(rest, "python")
		rest = strings.TrimPrefix(rest, "py")
		if j := strings.Index(rest, "```"); j >= 0 {
			return strings.TrimSpace(rest[:j])
		}
		return strings.TrimSpace(rest)
	}
	return s
}

// dangerous matches destructive / disruptive constructs that must never appear
// in a proof-of-concept. Case-insensitive.
var dangerous = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\brm\s+-rf\b`),
	regexp.MustCompile(`(?i)\brmdir\b`),
	regexp.MustCompile(`(?i)shutil\.rmtree`),
	regexp.MustCompile(`(?i)os\.remove|os\.unlink`),
	regexp.MustCompile(`(?i)\b(DROP|TRUNCATE)\s+TABLE\b`),
	regexp.MustCompile(`(?i)\bDELETE\s+FROM\b`),
	regexp.MustCompile(`(?i)\bmkfs\b|\bdd\s+if=`),
	regexp.MustCompile(`(?i)\b(shutdown|reboot|halt|poweroff)\b`),
	regexp.MustCompile(`:\(\)\s*\{`), // fork bomb :(){ :|:& };:
	regexp.MustCompile(`(?i)fork\s*bomb`),
	regexp.MustCompile(`(?i)while\s+true\s*:\s*$`), // bare infinite loop (DoS)
}

// safetyScan returns the list of dangerous patterns found in a script. Empty
// means the script passed. This is a defence-in-depth net behind the prompt —
// generated code is never trusted on the model's word alone.
func safetyScan(script string) []string {
	var hits []string
	for _, re := range dangerous {
		if re.MatchString(script) {
			hits = append(hits, re.String())
		}
	}
	return hits
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

func filename(f pipeline.ClassifiedFinding) string {
	base := f.AttackCategory
	if base == "" {
		base = f.Title
	}
	slug := strings.Trim(slugRe.ReplaceAllString(strings.ToLower(base), "-"), "-")
	if slug == "" {
		slug = "finding"
	}
	if len(slug) > 40 {
		slug = strings.Trim(slug[:40], "-")
	}
	return "poc-" + slug + ".py"
}
