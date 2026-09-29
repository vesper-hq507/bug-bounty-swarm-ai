package poc

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
)

// Runner executes a PoC script against a target and reports what happened. It is
// the boundary that lets self-verification stay testable (fake it in tests) and
// optional (nil Runner ⇒ generate-only). Implementations MUST be safe to call
// only on authorized, in-scope targets.
type Runner interface {
	Run(ctx context.Context, script, target string, timeout time.Duration) (output string, exit int, err error)
}

// Options tune the self-verification loop.
type Options struct {
	MaxAttempts int           // generate + repair rounds (default 2)
	Timeout     time.Duration // per script run (default 30s)
}

func (o Options) withDefaults() Options {
	if o.MaxAttempts <= 0 {
		o.MaxAttempts = 2
	}
	if o.Timeout <= 0 {
		o.Timeout = 30 * time.Second
	}
	return o
}

// GenerateAndVerify generates a PoC and, when a Runner is supplied, closes the
// loop: run it, observe whether it actually triggered, and on failure feed the
// output back and repair — up to MaxAttempts. The PoC is marked Verified only
// when a run genuinely fired (exit 0 with a VULNERABLE verdict). A nil Runner
// (dry-run / safe-mode / execution disabled) yields a generated-but-unverified
// PoC. Repaired scripts are re-scanned for safety before ever being run.
func GenerateAndVerify(ctx context.Context, c completer, r Runner, f pipeline.ClassifiedFinding, opts Options) (*PoC, error) {
	opts = opts.withDefaults()
	p, err := Generate(ctx, c, f)
	if err != nil || p == nil {
		return p, err
	}
	if r == nil {
		return p, nil // generate-only: no execution of LLM-authored code
	}

	user := promptFor(f, recipeFor(f.AttackCategory, f.Title, f.Description))
	for i := 1; i <= opts.MaxAttempts; i++ {
		p.Attempts = i
		out, exit, runErr := r.Run(ctx, p.Script, f.Target, opts.Timeout)
		p.RunOutput = out
		if runErr == nil && verified(out, exit) {
			p.Verified = true
			return p, nil
		}
		if i == opts.MaxAttempts {
			break
		}
		// Repair using what actually happened when we ran it.
		raw, aerr := ask(ctx, c, user+"\n\n"+repairPrompt(p, out, exit, runErr))
		if aerr != nil {
			break
		}
		np := parseSections(raw)
		if strings.TrimSpace(np.Script) == "" || len(safetyScan(np.Script)) > 0 {
			break // never run an unsafe or empty repair
		}
		p.Script = np.Script
		if np.HTTP != "" {
			p.HTTP = np.HTTP
		}
		if np.Steps != "" {
			p.Steps = np.Steps
		}
		if np.Indicator != "" {
			p.Indicator = np.Indicator
		}
	}
	return p, nil // returned unverified — never faked
}

// verified encodes the success contract the prompt establishes: the script
// exits 0 and prints a VULNERABLE verdict (and not a NOT CONFIRMED one).
func verified(output string, exit int) bool {
	if exit != 0 {
		return false
	}
	up := strings.ToUpper(output)
	return strings.Contains(up, "VULNERABLE") && !strings.Contains(up, "NOT CONFIRMED")
}

func repairPrompt(p *PoC, out string, exit int, runErr error) string {
	var b strings.Builder
	b.WriteString("Your PoC ran but did NOT prove the vulnerability. Fix it and return all four sections.\n")
	fmt.Fprintf(&b, "Exit code: %d\n", exit)
	if runErr != nil {
		fmt.Fprintf(&b, "Runner error: %v\n", runErr)
	}
	fmt.Fprintf(&b, "Expected proof: %s\n", p.Indicator)
	o := strings.TrimSpace(out)
	if len(o) > 1500 {
		o = o[:1500] + "…(truncated)"
	}
	fmt.Fprintf(&b, "Script output was:\n%s\n", o)
	b.WriteString("Keep it SAFE and non-destructive. Adjust the request/parsing so the proof actually triggers.")
	return b.String()
}

// LocalRunner runs a PoC as a local python3 subprocess with process isolation:
// a throwaway temp working directory, a stripped environment, no shell, and a
// hard timeout. It does NOT sandbox network egress (that is OS-specific), so it
// must only ever be enabled against an authorized, in-scope target — the swarm's
// scope validation and the safety scan are the guardrails around it. Off by
// default; callers opt in.
type LocalRunner struct {
	Python string // interpreter, default "python3"
}

// NewLocalRunner returns a LocalRunner, defaulting to python3.
func NewLocalRunner() *LocalRunner { return &LocalRunner{Python: "python3"} }

// Available reports whether the interpreter is on PATH.
func (lr *LocalRunner) Available() bool {
	py := lr.Python
	if py == "" {
		py = "python3"
	}
	_, err := exec.LookPath(py)
	return err == nil
}

func (lr *LocalRunner) Run(ctx context.Context, script, target string, timeout time.Duration) (string, int, error) {
	py := lr.Python
	if py == "" {
		py = "python3"
	}
	dir, err := os.MkdirTemp("", "poc-")
	if err != nil {
		return "", -1, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "poc.py")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		return "", -1, err
	}

	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(rctx, py, path, target)
	cmd.Dir = dir
	// Stripped environment: no inherited creds/tokens, minimal PATH.
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/local/bin", "HOME=" + dir, "PYTHONDONTWRITEBYTECODE=1"}
	out, err := cmd.CombinedOutput()
	exit := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exit = ee.ExitCode()
			err = nil // a non-zero exit is data, not a runner failure
		} else {
			exit = -1
		}
	}
	if rctx.Err() == context.DeadlineExceeded {
		return string(out), -1, fmt.Errorf("poc run timed out after %s", timeout)
	}
	return string(out), exit, err
}
