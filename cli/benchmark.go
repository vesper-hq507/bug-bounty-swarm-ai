package cli

import (
	"encoding/json"
	"fmt"
	"os"

	bbh "github.com/Armur-Ai/Pentest-Swarm-AI/internal/benchmark"
	"github.com/spf13/cobra"
)

var benchmarkCmd = &cobra.Command{
	Use:   "benchmark",
	Short: "Run deterministic local bug-bounty capability benchmarks",
}

var benchmarkControlledCmd = &cobra.Command{
	Use:   "controlled",
	Short: "Run the offline controlled benchmark suite",
	Long: "Runs deterministic local scenarios against the real analysis and control modules. " +
		"The suite does not contact an external target. It measures detection quality, " +
		"false-positive control, policy adherence, evidence integrity, safe termination, and recovery persistence.",
	RunE: runBenchmarkControlled,
}

func runBenchmarkControlled(cmd *cobra.Command, _ []string) error {
	stateParent, _ := cmd.Flags().GetString("state-parent")
	report, err := bbh.RunControlled(cmd.Context(), stateParent)
	if err != nil {
		return err
	}
	if OutputIsJSON() {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return err
		}
	} else {
		renderBenchmarkReport(report)
	}
	if !report.Passed {
		ExitCode = 1
	}
	return nil
}

func renderBenchmarkReport(report bbh.Report) {
	fmt.Println()
	status := colorGreen("PASS")
	if !report.Passed {
		status = colorYellow("FAIL")
	}
	fmt.Printf("  %s Controlled bug-bounty benchmark %s\n", colorCyan("[benchmark]"), status)
	fmt.Printf("  version: %s | cases: %d\n", report.Version, len(report.Results))
	fmt.Printf("  detection: precision %.3f | recall %.3f | false-positive rate %.3f\n",
		report.Detection.Precision, report.Detection.Recall, report.Detection.FalsePositiveRate)
	fmt.Printf("  controls: policy %.3f | evidence %.3f | termination %.3f | recovery %.3f\n",
		report.Controls.PolicyRate, report.Controls.EvidenceRate,
		report.Controls.TerminationRate, report.Controls.RecoveryRate)
	for i := range report.Results {
		r := &report.Results[i]
		caseStatus := colorGreen("pass")
		if !r.Passed() {
			caseStatus = colorYellow("fail")
		}
		fmt.Printf("    - %-34s %s\n", r.ID, caseStatus)
		if r.Error != "" {
			fmt.Printf("      error: %s\n", r.Error)
		}
	}
	fmt.Println()
}

func init() {
	benchmarkControlledCmd.Flags().String("state-parent", "", "optional parent directory for temporary benchmark state")
	benchmarkCmd.AddCommand(benchmarkControlledCmd)
	rootCmd.AddCommand(benchmarkCmd)
}
