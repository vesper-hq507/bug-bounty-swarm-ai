package poc

import (
	"context"
	"strings"
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/llm"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
)

// fakeLLM returns scripted responses in order, one per Complete call.
type fakeLLM struct {
	responses []string
	calls     int
}

func (f *fakeLLM) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	i := f.calls
	if i >= len(f.responses) {
		i = len(f.responses) - 1
	}
	f.calls++
	return &llm.CompletionResponse{Content: f.responses[i]}, nil
}

func finding() pipeline.ClassifiedFinding {
	return pipeline.ClassifiedFinding{
		Title:          "BOLA on /api/orders/{id}",
		Target:         "https://app.example.com",
		Severity:       pipeline.SeverityHigh,
		AttackCategory: "bola",
		Description:    "Any authenticated user can read another user's order by changing the id.",
	}
}

const safeScript = "```python\n# SAFE / non-destructive proof-of-concept\nimport urllib.request, sys\nprint('VULNERABLE: fetched another user\\'s order')\n```"

func TestGenerate_SafeScriptPasses(t *testing.T) {
	llmc := &fakeLLM{responses: []string{safeScript}}
	p, err := Generate(context.Background(), llmc, finding())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if p == nil {
		t.Fatal("expected a PoC, got nil")
	}
	if strings.Contains(p.Script, "```") {
		t.Errorf("code fence not stripped: %q", p.Script)
	}
	if p.Language != "python" || !strings.HasPrefix(p.Filename, "poc-") || !strings.HasSuffix(p.Filename, ".py") {
		t.Errorf("unexpected metadata: %+v", p)
	}
	if llmc.calls != 1 {
		t.Errorf("expected 1 LLM call for a clean script, got %d", llmc.calls)
	}
}

func TestGenerate_UnsafeThenRepaired(t *testing.T) {
	unsafe := "```python\nimport os\nos.system('rm -rf /')\n```"
	llmc := &fakeLLM{responses: []string{unsafe, safeScript}}
	p, err := Generate(context.Background(), llmc, finding())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if p == nil {
		t.Fatal("expected a repaired PoC, got nil")
	}
	if llmc.calls != 2 {
		t.Errorf("expected a repair call (2 total), got %d", llmc.calls)
	}
}

func TestGenerate_RefusesWhenUnsafeAfterRepair(t *testing.T) {
	unsafe := "```python\n# still bad\nq = 'DROP TABLE users'\n```"
	llmc := &fakeLLM{responses: []string{unsafe, unsafe}}
	if _, err := Generate(context.Background(), llmc, finding()); err == nil {
		t.Fatal("expected refusal when script stays unsafe after repair")
	}
}

func TestGenerate_RequiresTarget(t *testing.T) {
	f := finding()
	f.Target = ""
	if _, err := Generate(context.Background(), &fakeLLM{responses: []string{safeScript}}, f); err == nil {
		t.Fatal("expected error when finding has no target")
	}
}

func TestSafetyScan_CatchesDestructive(t *testing.T) {
	cases := []string{
		"os.system('rm -rf /tmp/x')",
		"cur.execute('DROP TABLE users')",
		"DELETE FROM accounts",
		"shutil.rmtree(path)",
		"subprocess.run(['shutdown','-h','now'])",
		":(){ :|:& };:",
	}
	for _, c := range cases {
		if hits := safetyScan(c); len(hits) == 0 {
			t.Errorf("safetyScan(%q) = clean, want a hit", c)
		}
	}
	// A benign proof must pass.
	benign := "import urllib.request\nr = urllib.request.urlopen(base)\nprint('VULNERABLE' if 'root' in r.read().decode() else 'NOT CONFIRMED')"
	if hits := safetyScan(benign); len(hits) != 0 {
		t.Errorf("safetyScan flagged a benign proof: %v", hits)
	}
}

func TestFilename_Slugifies(t *testing.T) {
	f := finding()
	if got := filename(f); got != "poc-bola.py" {
		t.Errorf("filename = %q, want poc-bola.py", got)
	}
}
