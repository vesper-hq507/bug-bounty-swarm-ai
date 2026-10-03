package memorygraft

import (
	"context"
	"fmt"
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/swarm/blackboard"
	"github.com/google/uuid"
)

func TestScan_FlagsBurstWrites(t *testing.T) {
	b := blackboard.NewMemoryBoard(nil)
	camp := uuid.New()
	for i := 0; i < 60; i++ {
		_, _ = b.Write(context.Background(), blackboard.Finding{
			CampaignID: camp,
			AgentName:  "recon",
			Type:       blackboard.TypeSubdomain,
			Target:     fmt.Sprintf("a%d.example.com", i),
			Data:       []byte(fmt.Sprintf(`{"sub":"a%d"}`, i)),
		})
	}
	alerts, err := Scan(context.Background(), b, Config{BurstThreshold: 50})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range alerts {
		if a.Kind == "burst" && a.AgentName == "recon" {
			found = true
		}
	}
	if !found {
		t.Errorf("burst not detected; got %+v", alerts)
	}
}

func TestScan_FlagsDuplicateDataPayloads(t *testing.T) {
	b := blackboard.NewMemoryBoard(nil)
	camp := uuid.New()
	payload := []byte(`{"identical":"injected"}`)
	for i := 0; i < 5; i++ {
		_, _ = b.Write(context.Background(), blackboard.Finding{
			CampaignID: camp,
			AgentName:  "classifier",
			Type:       blackboard.TypeCVEMatch,
			Target:     fmt.Sprintf("t%d", i),
			Data:       payload,
		})
	}
	alerts, _ := Scan(context.Background(), b, Config{})
	found := false
	for _, a := range alerts {
		if a.Kind == "duplicate-data" {
			found = true
		}
	}
	if !found {
		t.Errorf("duplicate-data not flagged; got %+v", alerts)
	}
}

func TestScan_FlagsTypeMismatch(t *testing.T) {
	b := blackboard.NewMemoryBoard(nil)
	camp := uuid.New()
	// Recon is writing CVE_MATCH — that's the classifier's territory.
	_, _ = b.Write(context.Background(), blackboard.Finding{
		CampaignID: camp,
		AgentName:  "recon",
		Type:       blackboard.TypeCVEMatch,
		Target:     "t",
		Data:       []byte(`{}`),
	})
	alerts, _ := Scan(context.Background(), b, Config{})
	found := false
	for _, a := range alerts {
		if a.Kind == "type-mismatch" && a.AgentName == "recon" {
			found = true
		}
	}
	if !found {
		t.Errorf("type-mismatch not flagged; got %+v", alerts)
	}
}

func TestScan_QuietBoardProducesNoAlerts(t *testing.T) {
	b := blackboard.NewMemoryBoard(nil)
	camp := uuid.New()
	// One legit finding from each expected agent.
	_, _ = b.Write(context.Background(), blackboard.Finding{
		CampaignID: camp, AgentName: "recon", Type: blackboard.TypeSubdomain,
		Target: "a.com", Data: []byte(`{"x":1}`),
	})
	_, _ = b.Write(context.Background(), blackboard.Finding{
		CampaignID: camp, AgentName: "classifier", Type: blackboard.TypeCVEMatch,
		Target: "a.com", Data: []byte(`{"x":2}`),
	})
	alerts, _ := Scan(context.Background(), b, Config{})
	if len(alerts) != 0 {
		t.Errorf("quiet board should not raise alerts; got %+v", alerts)
	}
}


func TestScan_FlagsCrossAgentReinforcement(t *testing.T) {
	b := blackboard.NewMemoryBoard(nil)
	camp := uuid.New()
	payload := []byte(`{"claim":"same-high-confidence-signal"}`)
	for _, agent := range []string{"recon-a", "recon-b", "recon-a", "recon-b"} {
		_, _ = b.Write(context.Background(), blackboard.Finding{
			CampaignID: camp,
			AgentName:  agent,
			Type:       blackboard.TypeTechnology,
			Target:     "victim.example.test",
			Data:       payload,
		})
	}
	alerts, err := Scan(context.Background(), b, Config{
		BurstThreshold:         100,
		RepeatTitleThreshold:   100,
		DuplicateDataThreshold: 100,
		CollusionThreshold:     4,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range alerts {
		if a.Kind == "cross-agent-reinforcement" && a.Count == 4 {
			return
		}
	}
	t.Fatalf("cross-agent reinforcement not detected; got %+v", alerts)
}

func TestScan_DoesNotFlagIndependentCrossAgentSignal(t *testing.T) {
	b := blackboard.NewMemoryBoard(nil)
	camp := uuid.New()
	for i, agent := range []string{"recon-a", "recon-b", "recon-a", "recon-b"} {
		_, _ = b.Write(context.Background(), blackboard.Finding{
			CampaignID: camp,
			AgentName:  agent,
			Type:       blackboard.TypeTechnology,
			Target:     "victim.example.test",
			Data:       []byte(fmt.Sprintf(`{"signal":%d}`, i)),
		})
	}
	alerts, err := Scan(context.Background(), b, Config{
		BurstThreshold:         100,
		RepeatTitleThreshold:   100,
		DuplicateDataThreshold: 100,
		CollusionThreshold:     4,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range alerts {
		if a.Kind == "cross-agent-reinforcement" {
			t.Fatalf("independent signals should not trigger collusion alert: %+v", a)
		}
	}
}
