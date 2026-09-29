// Package poc generates — and optionally self-verifies — proof-of-concept
// scripts that PROVE a finding, the difference between "this looks vulnerable"
// and "run this and watch it prove it."
//
// For a confirmed finding it produces a class-aware, multi-artifact PoC: a
// self-contained Python 3 script (standard library only), a raw HTTP request a
// human can drop into Burp, a Markdown "steps to reproduce," and an explicit
// success indicator. With a Runner wired (opt-in), it closes the loop —
// running the script safely, observing whether it actually triggered, and
// repairing it until it does or a cap is hit — and marks the PoC VERIFIED only
// when it genuinely fired.
//
// Safety is enforced in depth:
//   - Per-class recipes (recipes.go) constrain proof to a benign signal (read a
//     version, run `id`, fetch ONE other object) — never destructive, never
//     bulk exfiltration, never DoS.
//   - Every generated script passes a safety scan (safety.go); failures get a
//     repair attempt and are withheld rather than emitted unsafe.
//   - Generation is not execution. Running the script is opt-in, sandboxed
//     (runner.go), scope-locked, and off in dry-run/safe-mode.
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

// PoC is a generated proof-of-concept for a single finding.
type PoC struct {
	Title     string // the finding it proves
	Target    string
	Class     string // attack class the recipe matched
	Language  string // always "python" in v1
	Filename  string // suggested artifact name, e.g. poc-bola.py
	Script    string // self-contained Python (stdlib only)
	HTTP      string // raw HTTP/1.1 request for manual replay (may be empty)
	Steps     string // Markdown "steps to reproduce"
	Indicator string // what a successful run prints / proves

	// Verified is set by the self-verification loop: true only when the script
	// was actually run and its success indicator observed. RunOutput carries the
	// captured proof output; Attempts is how many generate/repair rounds it took.
	Verified  bool
	RunOutput string
	Attempts  int
}

const pocSystemPrompt = `You are a senior penetration tester writing a SAFE, non-weaponised proof-of-concept
that VERIFIES one vulnerability for a report a human will read and re-run.

Return EXACTLY these four sections, each introduced by its marker on its own line:

===SCRIPT===
A single self-contained Python 3 script. Standard library ONLY (urllib, http.client, json, ssl, socket, sys, argparse, base64, secrets) — no pip, no requests. Read the target base URL from argv[1], defaulting to the given target. Print a final verdict line: "VULNERABLE: <why>" on success or "NOT CONFIRMED: <why>" otherwise, and sys.exit(0) only when proven. Start with a comment block: finding title, target, "SAFE / non-destructive proof-of-concept", and how to run it.
===HTTP===
The single most important raw HTTP/1.1 request that triggers it (Burp-ready), or "none".
===STEPS===
Short Markdown "steps to reproduce" (3-6 bullet steps) a triager can follow by hand.
===INDICATOR===
One line: exactly what a successful, safe proof looks like.

MANDATORY safety rules — this is a PROOF, not an attack:
- Prove impact with a BENIGN signal only, per the technique given below.
- NEVER destroy, modify, or bulk-extract data. No DROP/DELETE/UPDATE/INSERT, no rm/rmtree/file writes, no shutdown, no flooding loops, no lateral movement, no persistence, no reading credentials or secret files.
- Stay on the single in-scope target host. Reach no other host.`

// Generate synthesises a class-aware, multi-artifact PoC for a finding, without
// running it (Verified stays false). It validates the script with the safety
// scan and makes one repair attempt before giving up; a script that cannot be
// made safe returns an error rather than an unsafe PoC. (nil, nil) means the
// model produced nothing usable.
func Generate(ctx context.Context, c completer, f pipeline.ClassifiedFinding) (*PoC, error) {
	if strings.TrimSpace(f.Target) == "" {
		return nil, fmt.Errorf("finding has no target to prove against")
	}
	recipe := recipeFor(f.AttackCategory, f.Title, f.Description)
	user := promptFor(f, recipe)

	raw, err := ask(ctx, c, user)
	if err != nil {
		return nil, err
	}
	p := parseSections(raw)
	if bad := safetyScan(p.Script); len(bad) > 0 {
		repair := fmt.Sprintf("Your script was rejected by the safety scan for containing: %s.\n"+
			"Rewrite it as a SAFE, non-destructive proof using the same section format. Return all four sections.",
			strings.Join(bad, ", "))
		raw2, err2 := ask(ctx, c, user+"\n\n"+repair)
		if err2 != nil {
			return nil, err2
		}
		p = parseSections(raw2)
		if bad2 := safetyScan(p.Script); len(bad2) > 0 {
			return nil, fmt.Errorf("refusing to emit PoC: unsafe content after repair (%s)", strings.Join(bad2, ", "))
		}
	}
	if strings.TrimSpace(p.Script) == "" {
		return nil, nil
	}
	p.Title, p.Target, p.Class, p.Language, p.Filename = f.Title, f.Target, recipe.Class, "python", filename(f)
	if p.Indicator == "" {
		p.Indicator = recipe.Indicator
	}
	return p, nil
}

func promptFor(f pipeline.ClassifiedFinding, r Recipe) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Write a safe proof-of-concept for this finding.\n\n")
	fmt.Fprintf(&b, "Title: %s\n", f.Title)
	fmt.Fprintf(&b, "Target: %s\n", f.Target)
	fmt.Fprintf(&b, "Severity: %s\n", f.Severity)
	fmt.Fprintf(&b, "Attack class: %s\n", r.Class)
	if len(f.CVEIDs) > 0 {
		fmt.Fprintf(&b, "CVEs: %s\n", strings.Join(f.CVEIDs, ", "))
	}
	if d := strings.TrimSpace(f.Description); d != "" {
		fmt.Fprintf(&b, "Description: %s\n", d)
	}
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
	fmt.Fprintf(&b, "\nProof technique for this class (%s): %s\n", r.Class, r.SafeProof)
	fmt.Fprintf(&b, "A successful proof looks like: %s\n", r.Indicator)
	if r.Hints != "" {
		fmt.Fprintf(&b, "Guidance: %s\n", r.Hints)
	}
	return b.String()
}

func ask(ctx context.Context, c completer, user string) (string, error) {
	resp, err := c.Complete(ctx, llm.CompletionRequest{
		SystemPrompt: pocSystemPrompt,
		Messages:     []llm.Message{{Role: "user", Content: user}},
		MaxTokens:    3500,
		Temperature:  0.1,
	})
	if err != nil {
		return "", fmt.Errorf("provider call failed: %w", err)
	}
	if resp == nil || strings.TrimSpace(resp.Content) == "" {
		return "", fmt.Errorf("empty response from provider")
	}
	return resp.Content, nil
}

var sectionRe = regexp.MustCompile(`(?m)^===(SCRIPT|HTTP|STEPS|INDICATOR)===\s*$`)

// parseSections splits the model's delimited response into a PoC's parts. It is
// forgiving: if no markers are present it treats the whole thing as the script
// (stripping a code fence), so a model that ignores the format still yields a
// usable script.
func parseSections(raw string) *PoC {
	raw = strings.TrimSpace(raw)
	locs := sectionRe.FindAllStringSubmatchIndex(raw, -1)
	if len(locs) == 0 {
		return &PoC{Script: stripFence(raw, "python", "py")}
	}
	p := &PoC{}
	for i, loc := range locs {
		name := raw[loc[2]:loc[3]]
		start := loc[1]
		end := len(raw)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		body := strings.TrimSpace(raw[start:end])
		switch name {
		case "SCRIPT":
			p.Script = stripFence(body, "python", "py")
		case "HTTP":
			h := stripFence(body, "http", "")
			if !strings.EqualFold(strings.TrimSpace(h), "none") {
				p.HTTP = h
			}
		case "STEPS":
			p.Steps = stripFence(body, "markdown", "md")
		case "INDICATOR":
			p.Indicator = strings.TrimSpace(body)
		}
	}
	return p
}

// stripFence removes a leading ```lang / trailing ``` fence if present.
func stripFence(s string, langs ...string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "```"); i == 0 {
		rest := s[3:]
		for _, l := range langs {
			rest = strings.TrimPrefix(rest, l)
		}
		if j := strings.Index(rest, "```"); j >= 0 {
			return strings.TrimSpace(rest[:j])
		}
		return strings.TrimSpace(rest)
	}
	return s
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
