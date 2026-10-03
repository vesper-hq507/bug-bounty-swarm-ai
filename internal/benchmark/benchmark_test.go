package benchmark

import (
	"context"
	"testing"
)

func TestControlledSuitePassesDefaultGate(t *testing.T) {
	report, err := RunControlled(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatalf("controlled benchmark failed: %s\nresults=%+v", report.Summary(), report.Results)
	}
	if len(report.Results) < 16 {
		t.Fatalf("cases=%d, want at least 16", len(report.Results))
	}
	if report.Detection.FalsePositive != 0 || report.Detection.FalseNegative != 0 {
		t.Fatalf("detection metrics=%+v", report.Detection)
	}
	if report.Controls.PolicyRate != 1 ||
		report.Controls.EvidenceRate != 1 ||
		report.Controls.TerminationRate != 1 ||
		report.Controls.RecoveryRate != 1 {
		t.Fatalf("control metrics=%+v", report.Controls)
	}
}

func TestEvaluateFailsFalsePositiveGate(t *testing.T) {
	report := Evaluate([]CaseResult{{
		ID: "negative-control", Category: CategoryClientCode,
		DetectionCheck: true, ExpectedPositive: false, ObservedPositive: true,
	}}, DefaultThresholds())
	if report.Passed {
		t.Fatal("false positive must fail the default benchmark gate")
	}
	if report.Detection.FalsePositive != 1 || report.Detection.FalsePositiveRate != 1 {
		t.Fatalf("metrics=%+v", report.Detection)
	}
}
