package ui

import (
	"strings"
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
)

// A probe event must bump the probes tally, light the exploit fan, and surface
// a "probes N" counter in the live counters row — the terminal echo of the
// dashboard's fan-out mesh.
func TestProbeEventsRenderFanAndCounter(t *testing.T) {
	m := NewModel("cid", "target.example", "find bugs")
	m.width = 100 // wide enough for the full counters row + fan

	const n = 7
	for i := 0; i < n; i++ {
		m.handleEvent(pipeline.CampaignEvent{
			EventType: pipeline.EventProbe,
			AgentName: "exploit",
			Detail:    "http://target.example/vehicle/42/location",
		})
	}

	if m.probes != n {
		t.Fatalf("expected probes tally %d, got %d", n, m.probes)
	}

	view := stripANSI(m.View())
	if !strings.Contains(view, "probes 7") {
		t.Fatalf("counters row should show 'probes 7', got:\n%s", view)
	}
	if !strings.Contains(view, "EXPLOIT") {
		t.Fatalf("view should render the EXPLOIT node/fan, got:\n%s", view)
	}
}

// ExploitFan is empty before any probe and non-empty once probes exist, so the
// idle view is unchanged.
func TestExploitFan(t *testing.T) {
	if got := ExploitFan(0, 0, 80); got != "" {
		t.Errorf("no probes: expected empty fan, got %q", got)
	}
	fan := stripANSI(ExploitFan(4, 12, 80))
	if !strings.Contains(fan, "EXPLOIT") || !strings.Contains(fan, "12 probes") {
		t.Errorf("active fan should label the EXPLOIT node and probe count, got %q", fan)
	}
}
