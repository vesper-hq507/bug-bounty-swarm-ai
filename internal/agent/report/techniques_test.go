package report

import (
	"strings"
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/google/uuid"
)

func TestCollectTechniques_DistinctFirstSeen(t *testing.T) {
	plan := &pipeline.AttackPlan{Paths: []pipeline.AttackPath{
		{Steps: []pipeline.AttackStep{{TechniqueID: "T1190"}, {TechniqueID: ""}, {TechniqueID: "T1078"}}},
		{Steps: []pipeline.AttackStep{{TechniqueID: "T1190"}, {TechniqueID: "T1552"}}}, // T1190 dup
	}}
	got := collectTechniques(plan)
	want := []string{"T1190", "T1078", "T1552"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v want %v", got, want)
	}
	if collectTechniques(nil) != nil {
		t.Error("nil plan should yield nil")
	}
}

func TestRenderer_MITRESection(t *testing.T) {
	rep := &pipeline.PentestReport{ID: uuid.New(), Target: "x", Techniques: []string{"T1190", "T1078"}}
	md, err := NewRenderer().ToMarkdown(rep)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(md), "MITRE ATT&CK Techniques") || !strings.Contains(string(md), "`T1190`") {
		t.Errorf("MITRE section missing from report:\n%s", md)
	}
}
