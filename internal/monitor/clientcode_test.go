package monitor

import (
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/clientcode"
)

func TestAttachClientAnalysisFeedsDetailedDiff(t *testing.T) {
	before := Snapshot{
		Target:     "https://example.test",
		JavaScript: map[string]string{},
		ClientCode: map[string]clientcode.Summary{},
	}
	after := before
	after.JavaScript = map[string]string{}
	after.ClientCode = map[string]clientcode.Summary{}

	analysis, err := clientcode.Analyze(
		"https://example.test/assets/app.js",
		[]byte(`fetch('/api/orders'); new WebSocket('wss://example.test/ws'); params.get('owner_id'); user.role === 'admin'; transitionTo('approved'); featureFlag('billing-v2')`),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := AttachClientAnalysis(&after, analysis); err != nil {
		t.Fatal(err)
	}

	got := Diff(before, after)
	tests := map[string]bool{}
	for i := range got.Suggestions {
		tests[got.Suggestions[i].Test] = true
		if got.Suggestions[i].Scope != "targeted-change-only" {
			t.Fatalf("non-targeted suggestion: %+v", got.Suggestions[i])
		}
	}
	for _, name := range []string{
		"review-client-route",
		"observe-client-realtime-endpoint",
		"review-client-parameter",
		"review-client-role-boundary",
		"review-client-workflow-state",
		"review-client-feature-gate",
	} {
		if !tests[name] {
			t.Fatalf("missing %s in %+v", name, got.Suggestions)
		}
	}
}

func TestAttachClientAnalysisRequiresAssetURL(t *testing.T) {
	s := Snapshot{}
	a, err := clientcode.Analyze("", []byte(`fetch('/api/me')`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := AttachClientAnalysis(&s, a); err == nil {
		t.Fatal("analysis without canonical asset URL must not attach to monitor state")
	}
}
