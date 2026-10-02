package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/workflow"
	"github.com/spf13/cobra"
)

var workflowCmd = &cobra.Command{
	Use:   "workflow",
	Short: "Analyze observed workflows for business-logic weaknesses",
}

var workflowAnalyzeCmd = &cobra.Command{
	Use:   "analyze <trace.json>",
	Short: "Analyze a workflow trace without sending target traffic",
	Args:  cobra.ExactArgs(1),
	RunE:  runWorkflowAnalyze,
}

var workflowReplayPlanCmd = &cobra.Command{
	Use:   "replay-plan <trace.json>",
	Short: "Build a replay plan; never executes the plan",
	Args:  cobra.ExactArgs(1),
	RunE:  runWorkflowReplayPlan,
}

func runWorkflowAnalyze(cmd *cobra.Command, args []string) error {
	events, err := readWorkflowEvents(args[0])
	if err != nil {
		return err
	}
	rulesPath, _ := cmd.Flags().GetString("rules")
	rules, err := readWorkflowRules(rulesPath)
	if err != nil {
		return err
	}
	maxRPS, _ := cmd.Flags().GetFloat64("max-rps")
	analysis := workflow.Analyze(events, rules, maxRPS)

	if OutputIsJSON() {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(analysis)
	}
	renderWorkflowAnalysis(analysis)
	return nil
}

func runWorkflowReplayPlan(cmd *cobra.Command, args []string) error {
	events, err := readWorkflowEvents(args[0])
	if err != nil {
		return err
	}
	from, _ := cmd.Flags().GetString("from")
	to, _ := cmd.Flags().GetString("to")
	allowStateful, _ := cmd.Flags().GetBool("allow-stateful-plan")
	steps, err := workflow.PlanReplay(workflow.BuildGraph(events), from, to, allowStateful)
	if err != nil {
		return err
	}
	if OutputIsJSON() {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(steps)
	}
	fmt.Println()
	fmt.Printf("  %s Replay plan - no target actions executed\n", colorCyan("[workflow]"))
	for i := range steps {
		step := &steps[i]
		status := colorGreen("eligible")
		if !step.Executable {
			status = colorYellow("approval required")
		}
		fmt.Printf("  %d. %s %s %s\n", i+1, step.Method, step.URL, status)
		fmt.Printf("     action: %s | approval: %s\n", step.Action, step.ApprovalClass)
		if step.Reason != "" {
			fmt.Printf("     reason: %s\n", step.Reason)
		}
	}
	fmt.Println()
	return nil
}

func readWorkflowEvents(path string) ([]workflow.Event, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading workflow trace: %w", err)
	}
	var events []workflow.Event
	if err := json.Unmarshal(b, &events); err != nil {
		return nil, fmt.Errorf("parsing workflow trace JSON: %w", err)
	}
	if len(events) == 0 {
		return nil, fmt.Errorf("workflow trace contains no events")
	}
	return events, nil
}

func readWorkflowRules(path string) ([]workflow.Rule, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading workflow rules: %w", err)
	}
	var rules []workflow.Rule
	if err := json.Unmarshal(b, &rules); err != nil {
		return nil, fmt.Errorf("parsing workflow rules JSON: %w", err)
	}
	return rules, nil
}

func renderWorkflowAnalysis(a workflow.Analysis) {
	fmt.Println()
	fmt.Printf("  %s Business-logic analysis - no target actions executed\n", colorCyan("[workflow]"))
	fmt.Printf("  states: %d | transitions: %d | hypotheses: %d\n", len(a.Graph.States), len(a.Graph.Transitions), len(a.Hypotheses))
	for i := range a.Hypotheses {
		h := &a.Hypotheses[i]
		fmt.Printf("\n  %d. %s\n", i+1, colorBold(string(h.Kind)))
		fmt.Printf("     action: %s | actor: %s | approval: %s\n", h.Action, h.ActorID, h.ApprovalClass)
		fmt.Printf("     reason: %s\n", h.Reason)
		fmt.Printf("     expected safe behavior: %s\n", h.ExpectedSafe)
	}
	if len(a.RaceCandidates) > 0 {
		fmt.Println("\n  Race candidates (planning only):")
		for i := range a.RaceCandidates {
			r := &a.RaceCandidates[i]
			status := colorYellow("blocked/policy review")
			if r.PolicyCompatible {
				status = colorYellow("explicit approval required")
			}
			fmt.Printf("    - %s %s %s\n", r.Action, r.URL, status)
			fmt.Printf("      %s\n", r.Reason)
		}
	}
	fmt.Println()
}

func init() {
	workflowAnalyzeCmd.Flags().String("rules", "", "JSON workflow invariant rules")
	workflowAnalyzeCmd.Flags().Float64("max-rps", 0, "program request-rate allowance used only to assess race-test eligibility")
	workflowReplayPlanCmd.Flags().String("from", "", "starting workflow state")
	workflowReplayPlanCmd.Flags().String("to", "", "target workflow state")
	workflowReplayPlanCmd.Flags().Bool("allow-stateful-plan", false, "mark state-changing replay steps eligible for a later approved executor; does not execute them")
	_ = workflowReplayPlanCmd.MarkFlagRequired("from")
	_ = workflowReplayPlanCmd.MarkFlagRequired("to")
	workflowCmd.AddCommand(workflowAnalyzeCmd, workflowReplayPlanCmd)
	rootCmd.AddCommand(workflowCmd)
}
