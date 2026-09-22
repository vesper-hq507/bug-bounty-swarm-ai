package agents

import (
	"strings"
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
)

func TestClamp01(t *testing.T) {
	for _, c := range []struct{ in, want float64 }{
		{-0.5, 0}, {0, 0}, {0.42, 0.42}, {1, 1}, {1.5, 1},
	} {
		if got := clamp01(c.in); got != c.want {
			t.Errorf("clamp01(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestExecutablePaths(t *testing.T) {
	runnable := pipeline.AttackPath{Name: "real", Steps: []pipeline.AttackStep{
		{Name: "s1", Command: ""}, {Name: "s2", Command: "httpreq --url x"},
	}}
	conceptual := pipeline.AttackPath{Name: "rule", Steps: []pipeline.AttackStep{
		{Name: "Exploit X"}, {Name: "Achieve Y"}, // no commands
	}}
	got := executablePaths([]pipeline.AttackPath{conceptual, runnable})
	if len(got) != 1 || got[0].Name != "real" {
		t.Fatalf("expected only the runnable path, got %+v", got)
	}
	if len(executablePaths([]pipeline.AttackPath{conceptual})) != 0 {
		t.Error("a command-less path is not executable")
	}
}

func TestLiveStateWithResults(t *testing.T) {
	a := &ExploitAgent{objective: "take over an account"}
	cf := pipeline.ClassifiedFinding{Title: "BOLA on /orders", Severity: pipeline.SeverityHigh, Target: "shop.test", AttackCategory: "bola"}
	results := []*pipeline.ExecutionResult{
		{CommandExecuted: "httpreq GET /api/v2/order/1", Success: true},
		{CommandExecuted: "httpreq GET /api/v2/order/2", Success: false},
	}
	s := a.liveStateWithResults(cf, results)
	if !strings.Contains(s, "BOLA on /orders") {
		t.Error("state should carry the finding under exploitation")
	}
	if !strings.Contains(s, "succeeded") || !strings.Contains(s, "failed") {
		t.Errorf("state should report per-step outcomes:\n%s", s)
	}
	if !strings.Contains(s, "take over an account") {
		t.Error("state should carry the objective")
	}
}
