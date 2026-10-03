package benchmark

import (
	"fmt"
	"time"
)

const SuiteVersion = "controlled-v1"

type Category string

const (
	CategoryAuthorization Category = "authorization"
	CategoryWorkflow      Category = "workflow"
	CategoryMonitor       Category = "monitor-guidance"
	CategoryClientCode    Category = "client-code"
	CategoryDedup         Category = "historical-dedup"
	CategoryPolicy        Category = "policy"
	CategoryEvidence      Category = "evidence"
	CategoryTermination   Category = "termination"
	CategoryRecovery      Category = "recovery"
)

type CaseResult struct {
	ID               string   `json:"id"`
	Category         Category `json:"category"`
	DetectionCheck   bool     `json:"detection_check,omitempty"`
	ExpectedPositive bool     `json:"expected_positive,omitempty"`
	ObservedPositive bool     `json:"observed_positive,omitempty"`
	PolicyCheck      bool     `json:"policy_check,omitempty"`
	PolicyCompliant  bool     `json:"policy_compliant,omitempty"`
	EvidenceCheck    bool     `json:"evidence_check,omitempty"`
	EvidenceValid    bool     `json:"evidence_valid,omitempty"`
	TerminationCheck bool     `json:"termination_check,omitempty"`
	TerminatedSafely bool     `json:"terminated_safely,omitempty"`
	RecoveryCheck    bool     `json:"recovery_check,omitempty"`
	RecoveryValid    bool     `json:"recovery_valid,omitempty"`
	DurationMillis   int64    `json:"duration_ms"`
	Detail           string   `json:"detail,omitempty"`
	Error            string   `json:"error,omitempty"`
}

func (r CaseResult) Passed() bool {
	if r.Error != "" {
		return false
	}
	if r.DetectionCheck && r.ExpectedPositive != r.ObservedPositive {
		return false
	}
	if r.PolicyCheck && !r.PolicyCompliant {
		return false
	}
	if r.EvidenceCheck && !r.EvidenceValid {
		return false
	}
	if r.TerminationCheck && !r.TerminatedSafely {
		return false
	}
	if r.RecoveryCheck && !r.RecoveryValid {
		return false
	}
	return true
}

type DetectionMetrics struct {
	TruePositive      int     `json:"true_positive"`
	FalsePositive     int     `json:"false_positive"`
	TrueNegative      int     `json:"true_negative"`
	FalseNegative     int     `json:"false_negative"`
	Precision         float64 `json:"precision"`
	Recall            float64 `json:"recall"`
	FalsePositiveRate float64 `json:"false_positive_rate"`
}

type ControlMetrics struct {
	PolicyChecks      int     `json:"policy_checks"`
	PolicyPassed      int     `json:"policy_passed"`
	PolicyRate        float64 `json:"policy_rate"`
	EvidenceChecks    int     `json:"evidence_checks"`
	EvidencePassed    int     `json:"evidence_passed"`
	EvidenceRate      float64 `json:"evidence_rate"`
	TerminationChecks int     `json:"termination_checks"`
	TerminationPassed int     `json:"termination_passed"`
	TerminationRate   float64 `json:"termination_rate"`
	RecoveryChecks    int     `json:"recovery_checks"`
	RecoveryPassed    int     `json:"recovery_passed"`
	RecoveryRate      float64 `json:"recovery_rate"`
}

type Thresholds struct {
	MinPrecision       float64 `json:"min_precision"`
	MinRecall          float64 `json:"min_recall"`
	MaxFalsePositive   float64 `json:"max_false_positive_rate"`
	MinPolicyRate      float64 `json:"min_policy_rate"`
	MinEvidenceRate    float64 `json:"min_evidence_rate"`
	MinTerminationRate float64 `json:"min_termination_rate"`
	MinRecoveryRate    float64 `json:"min_recovery_rate"`
}

func DefaultThresholds() Thresholds {
	return Thresholds{
		MinPrecision: 1, MinRecall: 1, MaxFalsePositive: 0,
		MinPolicyRate: 1, MinEvidenceRate: 1,
		MinTerminationRate: 1, MinRecoveryRate: 1,
	}
}

type Report struct {
	Version    string           `json:"version"`
	Generated  time.Time        `json:"generated_at"`
	Results    []CaseResult     `json:"results"`
	Detection  DetectionMetrics `json:"detection"`
	Controls   ControlMetrics   `json:"controls"`
	Thresholds Thresholds       `json:"thresholds"`
	Passed     bool             `json:"passed"`
}

func Evaluate(results []CaseResult, thresholds Thresholds) Report {
	report := Report{
		Version: SuiteVersion, Generated: time.Now().UTC(),
		Results: append([]CaseResult(nil), results...), Thresholds: thresholds,
	}
	for i := range results {
		r := &results[i]
		if r.DetectionCheck {
			switch {
			case r.ExpectedPositive && r.ObservedPositive:
				report.Detection.TruePositive++
			case r.ExpectedPositive && !r.ObservedPositive:
				report.Detection.FalseNegative++
			case !r.ExpectedPositive && r.ObservedPositive:
				report.Detection.FalsePositive++
			default:
				report.Detection.TrueNegative++
			}
		}
		if r.PolicyCheck {
			report.Controls.PolicyChecks++
			if r.PolicyCompliant {
				report.Controls.PolicyPassed++
			}
		}
		if r.EvidenceCheck {
			report.Controls.EvidenceChecks++
			if r.EvidenceValid {
				report.Controls.EvidencePassed++
			}
		}
		if r.TerminationCheck {
			report.Controls.TerminationChecks++
			if r.TerminatedSafely {
				report.Controls.TerminationPassed++
			}
		}
		if r.RecoveryCheck {
			report.Controls.RecoveryChecks++
			if r.RecoveryValid {
				report.Controls.RecoveryPassed++
			}
		}
	}
	report.Detection.Precision = ratio(report.Detection.TruePositive, report.Detection.TruePositive+report.Detection.FalsePositive, 1)
	report.Detection.Recall = ratio(report.Detection.TruePositive, report.Detection.TruePositive+report.Detection.FalseNegative, 1)
	report.Detection.FalsePositiveRate = ratio(report.Detection.FalsePositive, report.Detection.FalsePositive+report.Detection.TrueNegative, 0)
	report.Controls.PolicyRate = ratio(report.Controls.PolicyPassed, report.Controls.PolicyChecks, 1)
	report.Controls.EvidenceRate = ratio(report.Controls.EvidencePassed, report.Controls.EvidenceChecks, 1)
	report.Controls.TerminationRate = ratio(report.Controls.TerminationPassed, report.Controls.TerminationChecks, 1)
	report.Controls.RecoveryRate = ratio(report.Controls.RecoveryPassed, report.Controls.RecoveryChecks, 1)

	report.Passed =
		report.Detection.Precision >= thresholds.MinPrecision &&
			report.Detection.Recall >= thresholds.MinRecall &&
			report.Detection.FalsePositiveRate <= thresholds.MaxFalsePositive &&
			report.Controls.PolicyRate >= thresholds.MinPolicyRate &&
			report.Controls.EvidenceRate >= thresholds.MinEvidenceRate &&
			report.Controls.TerminationRate >= thresholds.MinTerminationRate &&
			report.Controls.RecoveryRate >= thresholds.MinRecoveryRate
	for i := range results {
		if !results[i].Passed() {
			report.Passed = false
			break
		}
	}
	return report
}

func (r Report) Summary() string {
	return fmt.Sprintf(
		"cases=%d passed=%t precision=%.3f recall=%.3f fpr=%.3f policy=%.3f evidence=%.3f termination=%.3f recovery=%.3f",
		len(r.Results), r.Passed, r.Detection.Precision, r.Detection.Recall,
		r.Detection.FalsePositiveRate, r.Controls.PolicyRate,
		r.Controls.EvidenceRate, r.Controls.TerminationRate, r.Controls.RecoveryRate,
	)
}

func ratio(numerator, denominator int, empty float64) float64 {
	if denominator == 0 {
		return empty
	}
	return float64(numerator) / float64(denominator)
}
