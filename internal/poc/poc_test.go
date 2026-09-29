package poc

import (
	"context"
	"strings"
	"testing"
	"time"

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

// a well-formed multi-section response
const fullResponse = `===SCRIPT===
` + "```python" + `
# SAFE / non-destructive proof-of-concept
import urllib.request, sys
base = sys.argv[1] if len(sys.argv) > 1 else "https://app.example.com"
print("VULNERABLE: fetched another user's order")
sys.exit(0)
` + "```" + `
===HTTP===
GET /api/orders/1002 HTTP/1.1
Host: app.example.com

===STEPS===
- Log in as user A
- Request /api/orders/1002 (owned by B)
- Observe B's order returned
===INDICATOR===
A 200 with another user's order fields`

func TestGenerate_ParsesAllSections(t *testing.T) {
	llmc := &fakeLLM{responses: []string{fullResponse}}
	p, err := Generate(context.Background(), llmc, finding())
	if err != nil || p == nil {
		t.Fatalf("Generate: %v (p=%v)", err, p)
	}
	if strings.Contains(p.Script, "```") {
		t.Errorf("fence not stripped: %q", p.Script)
	}
	if !strings.Contains(p.Script, "VULNERABLE") {
		t.Errorf("script missing verdict: %q", p.Script)
	}
	if p.HTTP == "" || !strings.HasPrefix(p.HTTP, "GET /api/orders/1002") {
		t.Errorf("HTTP section wrong: %q", p.HTTP)
	}
	if !strings.Contains(p.Steps, "Log in as user A") {
		t.Errorf("steps wrong: %q", p.Steps)
	}
	if p.Indicator == "" {
		t.Errorf("indicator empty")
	}
	if p.Class != "bola" || p.Filename != "poc-bola.py" || p.Language != "python" {
		t.Errorf("metadata wrong: %+v", p)
	}
	if p.Verified {
		t.Errorf("Generate must not mark Verified (no run happened)")
	}
}

// A response with no section markers is treated as a bare script.
func TestGenerate_BareScriptFallback(t *testing.T) {
	llmc := &fakeLLM{responses: []string{"```python\nprint('VULNERABLE: x')\n```"}}
	p, err := Generate(context.Background(), llmc, finding())
	if err != nil || p == nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.Contains(p.Script, "VULNERABLE") {
		t.Errorf("bare script not captured: %q", p.Script)
	}
}

func TestGenerate_UnsafeRefusedAfterRepair(t *testing.T) {
	unsafe := "===SCRIPT===\nimport os\nos.system('rm -rf /')\n===INDICATOR===\nx"
	llmc := &fakeLLM{responses: []string{unsafe, unsafe}}
	if _, err := Generate(context.Background(), llmc, finding()); err == nil {
		t.Fatal("expected refusal when script stays unsafe after repair")
	}
}

func TestGenerate_RequiresTarget(t *testing.T) {
	f := finding()
	f.Target = ""
	if _, err := Generate(context.Background(), &fakeLLM{responses: []string{fullResponse}}, f); err == nil {
		t.Fatal("expected error when finding has no target")
	}
}

// --- self-verification loop ---

type fakeRunner struct {
	outputs []string // one per Run call
	exits   []int
	calls   int
}

func (r *fakeRunner) Run(ctx context.Context, script, target string, timeout time.Duration) (string, int, error) {
	i := r.calls
	if i >= len(r.outputs) {
		i = len(r.outputs) - 1
	}
	r.calls++
	return r.outputs[i], r.exits[i], nil
}

// A run that prints VULNERABLE + exit 0 marks the PoC verified on the first try.
func TestGenerateAndVerify_VerifiesOnSuccessfulRun(t *testing.T) {
	llmc := &fakeLLM{responses: []string{fullResponse}}
	r := &fakeRunner{outputs: []string{"VULNERABLE: fetched another user's order"}, exits: []int{0}}
	p, err := GenerateAndVerify(context.Background(), llmc, r, finding(), Options{})
	if err != nil {
		t.Fatalf("GenerateAndVerify: %v", err)
	}
	if !p.Verified {
		t.Errorf("expected Verified after a successful run")
	}
	if r.calls != 1 {
		t.Errorf("expected 1 run, got %d", r.calls)
	}
}

// A failing run triggers a repair; the second run succeeds → verified.
func TestGenerateAndVerify_RepairsThenVerifies(t *testing.T) {
	llmc := &fakeLLM{responses: []string{fullResponse, fullResponse}}
	r := &fakeRunner{
		outputs: []string{"NOT CONFIRMED: got 403", "VULNERABLE: worked"},
		exits:   []int{1, 0},
	}
	p, err := GenerateAndVerify(context.Background(), llmc, r, finding(), Options{MaxAttempts: 2})
	if err != nil {
		t.Fatalf("GenerateAndVerify: %v", err)
	}
	if !p.Verified {
		t.Errorf("expected verified after repair")
	}
	if r.calls != 2 || p.Attempts != 2 {
		t.Errorf("expected 2 runs/attempts, got runs=%d attempts=%d", r.calls, p.Attempts)
	}
}

// If it never fires within the cap, it's returned UNVERIFIED — never faked.
func TestGenerateAndVerify_UnverifiedNeverFaked(t *testing.T) {
	llmc := &fakeLLM{responses: []string{fullResponse, fullResponse}}
	r := &fakeRunner{outputs: []string{"NOT CONFIRMED", "NOT CONFIRMED"}, exits: []int{1, 1}}
	p, err := GenerateAndVerify(context.Background(), llmc, r, finding(), Options{MaxAttempts: 2})
	if err != nil {
		t.Fatalf("GenerateAndVerify: %v", err)
	}
	if p.Verified {
		t.Errorf("must not be marked verified when the run never fired")
	}
}

// A nil Runner is generate-only.
func TestGenerateAndVerify_NilRunnerGenerateOnly(t *testing.T) {
	llmc := &fakeLLM{responses: []string{fullResponse}}
	p, err := GenerateAndVerify(context.Background(), llmc, nil, finding(), Options{})
	if err != nil || p == nil {
		t.Fatalf("GenerateAndVerify: %v", err)
	}
	if p.Verified {
		t.Errorf("nil runner must not verify")
	}
}

func TestVerifiedContract(t *testing.T) {
	if !verified("VULNERABLE: proof", 0) {
		t.Error("exit 0 + VULNERABLE should verify")
	}
	if verified("VULNERABLE but NOT CONFIRMED", 0) {
		t.Error("NOT CONFIRMED must not verify even with the word VULNERABLE")
	}
	if verified("VULNERABLE", 1) {
		t.Error("non-zero exit must not verify")
	}
}

func TestRecipeFor_Selects(t *testing.T) {
	if recipeFor("bola", "", "").Class != "bola" {
		t.Error("bola recipe")
	}
	if recipeFor("", "SQL injection in search", "").Class != "sqli" {
		t.Error("sqli recipe")
	}
	if recipeFor("", "", "server-side request forgery").Class != "ssrf" {
		t.Error("ssrf recipe")
	}
	if recipeFor("weirdclass", "", "").Class != "generic" {
		t.Error("generic fallback")
	}
}

func TestSafetyScan_CatchesDestructive(t *testing.T) {
	for _, c := range []string{
		"os.system('rm -rf /tmp/x')", "cur.execute('DROP TABLE users')",
		"DELETE FROM accounts", "shutil.rmtree(path)",
		"subprocess.run(['shutdown','-h','now'])", ":(){ :|:& };:",
		"open('/etc/passwd','w')", "requests.get('http://169.254.169.254/latest/meta-data/iam/x')",
	} {
		if len(safetyScan(c)) == 0 {
			t.Errorf("safetyScan(%q) = clean, want a hit", c)
		}
	}
	benign := "import urllib.request\nr = urllib.request.urlopen(base)\nprint('VULNERABLE' if 'root' in r.read().decode() else 'NOT CONFIRMED')"
	if hits := safetyScan(benign); len(hits) != 0 {
		t.Errorf("flagged a benign proof: %v", hits)
	}
}
