package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/guidance"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/identity"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope/programterms"
	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"
)

var guideCmd = &cobra.Command{
	Use:   "guide <attack-surface.json>",
	Short: "Explain the highest-value policy-compatible tests to run next",
	Long:  "Reads an existing attack-surface snapshot and produces a bounded hunter plan. The guide does not execute target traffic. It explains the hypothesis, recommended tool/test, expected signal, identity requirement, approval class, and stop condition.",
	Args:  cobra.ExactArgs(1),
	RunE:  runGuide,
}

func runGuide(cmd *cobra.Command, args []string) error {
	surface, err := readAttackSurface(args[0])
	if err != nil {
		return err
	}

	policyPath, _ := cmd.Flags().GetString("policy")
	constraints, err := readGuidePolicy(policyPath)
	if err != nil {
		return err
	}
	identityArgs, _ := cmd.Flags().GetStringArray("identity")
	identities, err := parseGuideIdentities(identityArgs)
	if err != nil {
		return err
	}
	completed, _ := cmd.Flags().GetStringArray("completed")
	failedArgs, _ := cmd.Flags().GetStringArray("failed")
	failed := parseGuideFailures(failedArgs)
	limit, _ := cmd.Flags().GetInt("limit")

	recs := guidance.Recommend(guidance.Input{
		Surface:     surface,
		Constraints: constraints,
		Completed:   completed,
		Failed:      failed,
		Identities:  identities,
	}, limit)

	if OutputIsJSON() {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(recs)
	}
	renderGuidance(recs)
	return nil
}

func readAttackSurface(path string) (pipeline.AttackSurface, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return pipeline.AttackSurface{}, fmt.Errorf("reading attack surface: %w", err)
	}
	var surface pipeline.AttackSurface
	if err := json.Unmarshal(b, &surface); err != nil {
		return pipeline.AttackSurface{}, fmt.Errorf("parsing attack surface JSON: %w", err)
	}
	if strings.TrimSpace(surface.Target) == "" {
		return pipeline.AttackSurface{}, fmt.Errorf("attack surface target is required")
	}
	return surface, nil
}

func readGuidePolicy(path string) (programterms.Constraints, error) {
	if strings.TrimSpace(path) == "" {
		return programterms.Constraints{}, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return programterms.Constraints{}, fmt.Errorf("reading policy constraints: %w", err)
	}
	var c programterms.Constraints
	if err := yaml.Unmarshal(b, &c); err != nil {
		return programterms.Constraints{}, fmt.Errorf("parsing policy constraints YAML: %w", err)
	}
	return c, nil
}

func parseGuideIdentities(raw []string) ([]identity.Identity, error) {
	out := make([]identity.Identity, 0, len(raw))
	for _, item := range raw {
		parts := strings.SplitN(item, ":", 3)
		if len(parts) < 2 {
			return nil, fmt.Errorf("invalid --identity %q; expected id:role[:session-ref]", item)
		}
		ident := identity.Identity{
			ID:    identity.ID(strings.TrimSpace(parts[0])),
			Alias: strings.TrimSpace(parts[0]),
			Role:  identity.Role(strings.TrimSpace(parts[1])),
		}
		if len(parts) == 3 {
			ident.SessionRef = identity.SessionRef(strings.TrimSpace(parts[2]))
		}
		if ident.ID == "" || ident.Role == "" {
			return nil, fmt.Errorf("invalid --identity %q", item)
		}
		if ident.Role != identity.RoleAnonymous && ident.SessionRef == "" {
			return nil, fmt.Errorf("authenticated --identity %q requires a session reference", item)
		}
		out = append(out, ident)
	}
	return out, nil
}

func parseGuideFailures(raw []string) []guidance.Attempt {
	out := make([]guidance.Attempt, 0, len(raw))
	for _, item := range raw {
		name, reason, ok := strings.Cut(item, "=")
		if !ok {
			name, reason = item, "failure reason not supplied"
		}
		if strings.TrimSpace(name) == "" {
			continue
		}
		out = append(out, guidance.Attempt{Name: strings.TrimSpace(name), Reason: strings.TrimSpace(reason)})
	}
	return out
}

func renderGuidance(recs []guidance.Recommendation) {
	fmt.Println()
	fmt.Printf("  %s Hunter guidance - no target actions executed\n", colorCyan("[guide]"))
	if len(recs) == 0 {
		fmt.Printf("  %s No bounded next test could be derived from the supplied surface.\n\n", colorDim("-"))
		return
	}
	for i := range recs {
		r := &recs[i]
		status := colorGreen("allowed")
		if !r.PolicyCompatible {
			status = colorYellow("manual/policy review")
		}
		fmt.Printf("\n  %d. %s  %s\n", i+1, colorBold(r.Test), status)
		fmt.Printf("     hypothesis: %s\n", r.Hypothesis)
		fmt.Printf("     tool: %s\n", r.Tool)
		if r.Target != "" {
			fmt.Printf("     target: %s\n", r.Target)
		}
		fmt.Printf("     identity: %s | approval: %s\n", r.RequiredIdentity, r.ApprovalClass)
		fmt.Printf("     expected signal: %s\n", r.ExpectedSignal)
		fmt.Printf("     why: %s\n", r.Why)
		fmt.Printf("     stop: %s\n", r.StopCondition)
		if r.PolicyReason != "" {
			fmt.Printf("     policy: %s\n", r.PolicyReason)
		}
	}
	fmt.Println()
}

func init() {
	guideCmd.Flags().String("policy", "", "YAML constraints from 'program inspect --yaml'")
	guideCmd.Flags().StringArray("identity", nil, "controlled identity as id:role[:session-ref] (repeatable)")
	guideCmd.Flags().StringArray("completed", nil, "completed test name to avoid recommending again (repeatable)")
	guideCmd.Flags().StringArray("failed", nil, "failed test as name=reason (repeatable)")
	guideCmd.Flags().Int("limit", 5, "maximum recommendations to display")
	rootCmd.AddCommand(guideCmd)
}
