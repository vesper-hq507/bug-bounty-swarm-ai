package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/monitor"
	"github.com/spf13/cobra"
)

var monitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "Create and compare target-surface snapshots",
}

var monitorSnapshotCmd = &cobra.Command{
	Use:   "snapshot <attack-surface.json>",
	Short: "Create a baseline snapshot from an existing attack surface",
	Args:  cobra.ExactArgs(1),
	RunE:  runMonitorSnapshot,
}

var monitorDiffCmd = &cobra.Command{
	Use:   "diff <before.json> <after.json>",
	Short: "Diff snapshots and produce targeted re-test suggestions",
	Args:  cobra.ExactArgs(2),
	RunE:  runMonitorDiff,
}

func runMonitorSnapshot(cmd *cobra.Command, args []string) error {
	surface, err := readAttackSurface(args[0])
	if err != nil {
		return err
	}
	snapshot := monitor.FromAttackSurface(surface)
	outPath, _ := cmd.Flags().GetString("out")
	if outPath != "" {
		return writeJSONFile(outPath, snapshot)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(snapshot)
}

func runMonitorDiff(_ *cobra.Command, args []string) error {
	before, err := readMonitorSnapshot(args[0])
	if err != nil {
		return err
	}
	after, err := readMonitorSnapshot(args[1])
	if err != nil {
		return err
	}
	result := monitor.Diff(before, after)
	if OutputIsJSON() {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}
	renderMonitorDiff(result)
	return nil
}

func readMonitorSnapshot(path string) (monitor.Snapshot, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return monitor.Snapshot{}, fmt.Errorf("reading monitor snapshot: %w", err)
	}
	var snapshot monitor.Snapshot
	if err := json.Unmarshal(b, &snapshot); err != nil {
		return monitor.Snapshot{}, fmt.Errorf("parsing monitor snapshot JSON: %w", err)
	}
	return snapshot, nil
}

func writeJSONFile(path string, value any) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding JSON: %w", err)
	}
	b = append(b, '\n')
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

func renderMonitorDiff(result monitor.DiffResult) {
	fmt.Println()
	fmt.Printf("  %s Target-change diff - no automatic rescan\n", colorCyan("[monitor]"))
	fmt.Printf("  changes: %d | targeted suggestions: %d\n", len(result.Changes), len(result.Suggestions))
	for i := range result.Changes {
		change := &result.Changes[i]
		fmt.Printf("\n  %d. %s %s\n", i+1, colorBold(string(change.Kind)), change.Asset)
		fmt.Printf("     priority: %d | %s\n", change.Priority, change.Reason)
	}
	if len(result.Suggestions) > 0 {
		fmt.Println("\n  Suggested bounded re-tests:")
		for i := range result.Suggestions {
			s := &result.Suggestions[i]
			fmt.Printf("    - %s -> %s\n", s.Test, s.Target)
			fmt.Printf("      %s\n", s.Why)
			fmt.Printf("      stop: %s\n", s.StopCondition)
		}
	}
	fmt.Println()
}

func init() {
	monitorSnapshotCmd.Flags().String("out", "", "write snapshot JSON to this file")
	monitorCmd.AddCommand(monitorSnapshotCmd, monitorDiffCmd)
	rootCmd.AddCommand(monitorCmd)
}
