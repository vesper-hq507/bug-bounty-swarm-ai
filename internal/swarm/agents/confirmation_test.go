package agents

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/swarm/blackboard"
	"github.com/google/uuid"
)

func writeFindingForTest(t *testing.T, board blackboard.Board, cid uuid.UUID, cf pipeline.ClassifiedFinding) blackboard.Finding {
	t.Helper()
	data, _ := json.Marshal(cf)
	id, err := board.Write(context.Background(), blackboard.Finding{
		CampaignID: cid, AgentName: "test", Type: blackboard.TypeCVEMatch,
		Target: cf.Target, Data: data, PheromoneBase: 0.9, HalfLifeSec: 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	return blackboard.Finding{ID: id, Type: blackboard.TypeCVEMatch, Target: cf.Target, Data: data}
}

// indicator-matching command reproduces a "pass" case cleanly.
func TestConfirmation_CommandPassKeepsFinding(t *testing.T) {
	board := blackboard.NewMemoryBoard(nil)
	cid := uuid.New()

	cf := pipeline.ClassifiedFinding{
		ID: uuid.New(), Target: "example.com",
		Title: "SQLi", Severity: pipeline.SeverityCritical,
		Reproduce: &pipeline.Reproduction{
			Command:           "echo vuln-triggered",
			ExpectedIndicator: "vuln-triggered",
		},
	}
	f := writeFindingForTest(t, board, cid, cf)

	agent := NewConfirmationAgent(nil, cid, 1)
	if err := agent.Handle(context.Background(), f, board); err != nil {
		t.Fatal(err)
	}

	// Only the original finding should still be on the board.
	all, _ := board.Query(context.Background(), blackboard.Predicate{})
	if len(all) != 1 {
		t.Fatalf("want 1 finding (no supersede); got %d", len(all))
	}
}

// indicator-missing command reproduces a "fail" — supersede publishes a
// low-pheromone finding that hides the original.
func TestConfirmation_CommandFailSupersedes(t *testing.T) {
	board := blackboard.NewMemoryBoard(nil)
	cid := uuid.New()

	cf := pipeline.ClassifiedFinding{
		ID: uuid.New(), Target: "example.com",
		Title: "SQLi", Severity: pipeline.SeverityCritical,
		Reproduce: &pipeline.Reproduction{
			Command:           "echo all-clean",
			ExpectedIndicator: "never-going-to-appear",
		},
	}
	f := writeFindingForTest(t, board, cid, cf)

	agent := NewConfirmationAgent(nil, cid, 1)
	if err := agent.Handle(context.Background(), f, board); err != nil {
		t.Fatal(err)
	}

	// Only the superseding finding should be visible; Query filters
	// superseded_by entries.
	all, _ := board.Query(context.Background(), blackboard.Predicate{})
	if len(all) != 1 {
		t.Fatalf("want 1 visible finding (superseding only); got %d", len(all))
	}
	if all[0].PheromoneBase > 0.2 {
		t.Fatalf("superseding finding should have low pheromone, got %f", all[0].PheromoneBase)
	}
}

// HTTP reproduction round-trip through httptest.
func TestConfirmation_HTTPReproduction(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("sql syntax error at line 1"))
	}))
	defer srv.Close()

	board := blackboard.NewMemoryBoard(nil)
	cid := uuid.New()

	cf := pipeline.ClassifiedFinding{
		ID: uuid.New(), Target: srv.URL,
		Title: "SQLi", Severity: pipeline.SeverityHigh,
		Reproduce: &pipeline.Reproduction{
			// Absolute URL on the request line so the parser keeps the
			// http:// scheme httptest actually serves.
			HTTPRequest:       "GET " + srv.URL + "/ HTTP/1.1\nHost: " + stripScheme(srv.URL) + "\n\n",
			ExpectedIndicator: "syntax error",
		},
	}
	f := writeFindingForTest(t, board, cid, cf)

	// httptest binds 127.0.0.1:<ephemeral>, so whitelist the loopback CIDR.
	agent := NewConfirmationAgent(&scope.ScopeDefinition{
		AllowedDomains: []string{stripScheme(srv.URL)},
		AllowedCIDRs:   []string{"127.0.0.0/8"},
	}, cid, 1)
	agent.httpClient = &http.Client{Timeout: 2 * time.Second}

	if err := agent.Handle(context.Background(), f, board); err != nil {
		t.Fatal(err)
	}
	all, _ := board.Query(context.Background(), blackboard.Predicate{})
	if len(all) != 1 {
		t.Fatalf("HTTP indicator matched — want single finding, got %d", len(all))
	}
}

// Stripping the scheme off an httptest URL gives us a hostname:port the
// scope validator recognizes.
func stripScheme(u string) string {
	for _, prefix := range []string{"https://", "http://"} {
		if len(u) > len(prefix) && u[:len(prefix)] == prefix {
			return u[len(prefix):]
		}
	}
	return u
}

// #8 fix: confirmation must not be gated by a decaying recency weight — a real
// finding found early should still be confirmable much later. The floor is a
// tiny anti-noise value, not the old 0.5 that findings decay below in ~1 hour.
func TestConfirmation_TriggerNotGatedByDecay(t *testing.T) {
	a := NewConfirmationAgent(&scope.ScopeDefinition{}, uuid.New(), 1)
	if got := a.Trigger().MinPheromone; got > 0.1 {
		t.Errorf("confirmation MinPheromone = %.2f; must be a low floor so decayed real findings still confirm (was 0.5, the #8 bug)", got)
	}
}

// The self-write guard stops the agent re-processing its own superseding
// false-positive writes (which sit just above the new low floor).
func TestConfirmation_SkipsOwnWrites(t *testing.T) {
	a := NewConfirmationAgent(&scope.ScopeDefinition{}, uuid.New(), 1)
	board := blackboard.NewMemoryBoard(time.Now)
	cf := pipeline.ClassifiedFinding{Target: "http://x", Reproduce: &pipeline.Reproduction{Command: "echo hi", ExpectedIndicator: "nope"}}
	data, _ := json.Marshal(cf)
	// A finding authored by the confirm agent itself must be ignored (no panic,
	// no re-run, no error) regardless of its content.
	self := blackboard.Finding{AgentName: a.Name(), Type: blackboard.TypeCVEMatch, Target: cf.Target, Data: data}
	if err := a.Handle(context.Background(), self, board); err != nil {
		t.Errorf("Handle on own write should be a no-op, got %v", err)
	}
}
