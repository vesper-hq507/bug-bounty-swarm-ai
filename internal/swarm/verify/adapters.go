package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/llm"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/swarm/blackboard"
)

// boardEvidence corroborates a candidate against what is already on the
// blackboard for the same target — free, deterministic support that avoids a
// paid verification. Only signals that independently bear on a *vulnerability*
// count (recon context like an open port or a crawled URL is attack surface,
// not corroboration of a judgment). A tool-confirmed exploitation for the
// target (an EXPLOIT_RESULT / session / playbook) is treated as ground truth.
type boardEvidence struct {
	board blackboard.Board
}

// NewBoardEvidence wraps a blackboard as an Evidence source.
func NewBoardEvidence(board blackboard.Board) Evidence { return boardEvidence{board: board} }

func (e boardEvidence) SupportingSignals(ctx context.Context, target string) (int, bool) {
	if e.board == nil || target == "" {
		return 0, false
	}
	fs, err := e.board.Query(ctx, blackboard.Predicate{TargetPrefix: target})
	if err != nil {
		return 0, false
	}
	count := 0
	toolGrounded := false
	for _, f := range fs {
		switch f.Type {
		case blackboard.TypeExploitResult, blackboard.TypeExploitPlaybook, blackboard.TypeSession:
			// A tool actually confirmed exploitation here — ground truth.
			toolGrounded = true
			count++
		case blackboard.TypeCVEMatch, blackboard.TypeMisconfig, blackboard.TypePotentialSQLI,
			blackboard.TypeSecretLeak, blackboard.TypeExploitChain:
			// Independent vulnerability signals for the same target.
			count++
		}
	}
	return count, toolGrounded
}

// llmVerifier re-derives a judgment with a (stronger) model. The prompt asks
// for a strict yes/no plus a confidence, kept short so a verification is a cheap
// single call — not a full re-analysis.
type llmVerifier struct {
	provider llm.Provider
}

// NewLLMVerifier wraps a provider (meant to be a stronger model than the one
// that produced the candidate) as a Verifier.
func NewLLMVerifier(provider llm.Provider) Verifier { return llmVerifier{provider: provider} }

const verifySystemPrompt = `You are a senior penetration tester verifying a finding produced by a cheaper, less reliable model before an exploitation agent spends effort on it.
Decide whether it is a REAL, plausibly exploitable vulnerability or a likely false positive / low-quality guess.
Respond with STRICT JSON only, no prose: {"real": true|false, "confidence": 0.0-1.0}.
Be skeptical: if the evidence is thin or generic, mark it not real.`

func (v llmVerifier) Verify(ctx context.Context, c Candidate) (bool, float64, error) {
	if v.provider == nil {
		return false, 0, fmt.Errorf("verify: nil provider")
	}
	user := fmt.Sprintf("Target: %s\nType: %s\nSeverity: %s\nFinding: %s",
		c.Target, c.Type, c.Severity, strings.TrimSpace(c.Detail))
	resp, err := v.provider.Complete(ctx, llm.CompletionRequest{
		SystemPrompt: verifySystemPrompt,
		Messages:     []llm.Message{{Role: "user", Content: user}},
		MaxTokens:    120,
		Temperature:  0,
	})
	if err != nil {
		return false, 0, err
	}
	real, conf, ok := parseVerdict(resp.Content)
	if !ok {
		return false, 0, fmt.Errorf("verify: could not parse verdict from %q", clip(resp.Content, 120))
	}
	return real, conf, nil
}

// verdict is the strict JSON shape the verifier model must return.
type verdict struct {
	Real       bool    `json:"real"`
	Confidence float64 `json:"confidence"`
}

// parseVerdict extracts the {"real":..,"confidence":..} object even if the model
// wrapped it in prose or a code fence. Returns ok=false if no object parses.
func parseVerdict(s string) (real bool, conf float64, ok bool) {
	start := strings.Index(s, "{")
	end := strings.LastIndex(s, "}")
	if start < 0 || end <= start {
		return false, 0, false
	}
	var v verdict
	if err := json.Unmarshal([]byte(s[start:end+1]), &v); err != nil {
		return false, 0, false
	}
	if v.Confidence < 0 {
		v.Confidence = 0
	}
	if v.Confidence > 1 {
		v.Confidence = 1
	}
	return v.Real, v.Confidence, true
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
