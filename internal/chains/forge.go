package chains

import (
	"context"
	"fmt"
	"strings"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/llm"
)

// ParseChainBytes validates raw YAML as an exploit chain (used by the forge to
// check a drafted chain before it's shown for review).
func ParseChainBytes(data []byte) (*ExploitChain, error) { return parseChain(data, "forged") }

// completer is the minimal LLM surface the forge needs — any configured
// provider (Ollama, Together, GLM, Claude, Gemini, Muse Spark…) satisfies it.
// Kept as an interface so it's testable with a fake and provider-agnostic.
type completer interface {
	Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error)
}

const forgeSystemPrompt = `You are a security engineer authoring an EXPLOIT CHAIN definition for the
Pentest Swarm library from a vulnerability advisory. Output ONLY a valid YAML
document — no prose, no markdown fences — matching exactly this schema:

id: <kebab-case-slug>            # unique, e.g. vendor-product-shortname
name: <human title, e.g. "Vendor Product — SSRF → unauth RCE">
description: >
  2-4 sentences: what the chain is and its real-world impact.
cves: [CVE-XXXX-YYYY, ...]       # every CVE involved
product: <affected product>
affected: <affected versions>
cvss: <number>
severity: critical|high|medium|low
tags: [<lowercase tags>]
references: [<authoritative URLs from the advisory>]
fingerprint:
  paths: [<paths to probe to identify the product/version>]
  signals: [<response cues that confirm the product/version>]
  notes: <how to recover the version and gate the chain>
links:                          # ORDERED — each link enables the next
  - name: "<step name> (<CVE if any>)"
    cve: <CVE or omit>
    enables: <what this link unlocks>
    verify: >
      SAFE, NON-WEAPONIZED verification: how to CONFIRM this link is
      present/reachable WITHOUT exploiting it — a benign canary, a read-only
      unauthorized response, an out-of-band callback. Never a working payload,
      never code execution, never a destructive/state-changing action.
remediation: >
  How to fix, and any post-compromise triage.

HARD RULES:
- Every 'verify' must be non-weaponized (confirm reachability/impact, never detonate).
- Do NOT invent CVEs or details not supported by the advisory; if unsure, say so in notes.
- Ship no working exploit payload.
Output the YAML and nothing else.`

// Forge drafts an exploit chain from an advisory using the given provider,
// validating the result against the schema (with one repair attempt). Returns
// the parsed chain and the raw YAML for human review. It NEVER writes anything —
// the caller decides whether to save after review.
func Forge(ctx context.Context, c completer, advisory, cveHint string) (*ExploitChain, string, error) {
	if strings.TrimSpace(advisory) == "" {
		return nil, "", fmt.Errorf("no advisory text provided")
	}
	user := advisory
	if cveHint != "" {
		user = "CVEs: " + cveHint + "\n\nAdvisory:\n" + advisory
	}

	raw, err := ask(ctx, c, user)
	if err != nil {
		return nil, "", err
	}
	ch, perr := ParseChainBytes([]byte(raw))
	if perr != nil {
		// One repair attempt: hand the model its validation error.
		repair := fmt.Sprintf("Your previous YAML failed validation: %v\nReturn ONLY corrected YAML.\n\nPrevious:\n%s", perr, raw)
		raw2, err2 := ask(ctx, c, user+"\n\n"+repair)
		if err2 == nil {
			if ch2, perr2 := ParseChainBytes([]byte(raw2)); perr2 == nil {
				return ch2, raw2, nil
			}
		}
		return nil, raw, fmt.Errorf("drafted chain failed validation: %w", perr)
	}
	return ch, raw, nil
}

func ask(ctx context.Context, c completer, user string) (string, error) {
	resp, err := c.Complete(ctx, llm.CompletionRequest{
		SystemPrompt: forgeSystemPrompt,
		Messages:     []llm.Message{{Role: "user", Content: user}},
		MaxTokens:    4096,
		Temperature:  0.2,
	})
	if err != nil {
		return "", fmt.Errorf("provider call failed: %w", err)
	}
	if resp == nil || strings.TrimSpace(resp.Content) == "" {
		return "", fmt.Errorf("empty response from provider")
	}
	return extractYAML(resp.Content), nil
}

// extractYAML strips a ```yaml / ``` code fence if the model wrapped its output.
func extractYAML(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "```"); i >= 0 {
		rest := s[i+3:]
		rest = strings.TrimPrefix(rest, "yaml")
		rest = strings.TrimPrefix(rest, "yml")
		if j := strings.Index(rest, "```"); j >= 0 {
			return strings.TrimSpace(rest[:j])
		}
		return strings.TrimSpace(rest)
	}
	return s
}
