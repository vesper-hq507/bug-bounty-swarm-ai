package verify

import (
	"context"
	"testing"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/swarm/blackboard"
	"github.com/google/uuid"
)

func TestParseVerdict(t *testing.T) {
	cases := []struct {
		in       string
		wantReal bool
		wantOK   bool
	}{
		{`{"real": true, "confidence": 0.9}`, true, true},
		{"here is my answer:\n```json\n{\"real\": false, \"confidence\": 0.2}\n```", false, true},
		{`prose {"real":true,"confidence":1.5} trailing`, true, true}, // confidence clamps
		{`no json here`, false, false},
		{``, false, false},
	}
	for _, c := range cases {
		real, conf, ok := parseVerdict(c.in)
		if ok != c.wantOK {
			t.Errorf("parseVerdict(%q) ok = %v, want %v", c.in, ok, c.wantOK)
			continue
		}
		if ok {
			if real != c.wantReal {
				t.Errorf("parseVerdict(%q) real = %v, want %v", c.in, real, c.wantReal)
			}
			if conf < 0 || conf > 1 {
				t.Errorf("parseVerdict(%q) confidence %.2f out of [0,1]", c.in, conf)
			}
		}
	}
}

// boardEvidence must count independent vulnerability signals for a target and
// flag tool-grounding when a tool confirmed exploitation — but ignore pure
// recon context (open ports, crawled URLs).
func TestBoardEvidence_SupportingSignals(t *testing.T) {
	board := blackboard.NewMemoryBoard(time.Now)
	ctx := context.Background()
	cid := uuid.New()
	target := "https://app.example.com/api/orders"

	write := func(tp blackboard.FindingType) {
		_, _ = board.Write(ctx, blackboard.Finding{CampaignID: cid, AgentName: "x", Type: tp, Target: target})
	}
	// recon context — must NOT count as corroboration
	write(blackboard.TypeHTTPEndpoint)
	write(blackboard.TypePortOpen)
	// one independent vuln signal
	write(blackboard.TypeCVEMatch)

	ev := NewBoardEvidence(board)
	n, tool := ev.SupportingSignals(ctx, target)
	if n != 1 {
		t.Errorf("count = %d, want 1 (only the CVE match, not recon context)", n)
	}
	if tool {
		t.Errorf("toolGrounded = true, want false (no exploit confirmation yet)")
	}

	// a tool-confirmed exploitation flips tool-grounding
	write(blackboard.TypeExploitResult)
	if _, tool := ev.SupportingSignals(ctx, target); !tool {
		t.Errorf("toolGrounded = false after EXPLOIT_RESULT, want true")
	}
}

// A nil board is safe.
func TestBoardEvidence_NilSafe(t *testing.T) {
	ev := NewBoardEvidence(nil)
	if n, tool := ev.SupportingSignals(context.Background(), "x"); n != 0 || tool {
		t.Errorf("nil board = (%d,%v), want (0,false)", n, tool)
	}
}
