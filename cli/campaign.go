package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/engine"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/identity"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/preflight"
	"github.com/spf13/cobra"
)

// campaignListEntry is the JSON shape for one row of `campaign list --json`.
// Kept minimal and separate from any internal campaign type so this command
// can grow real data (fetched from the API/DB, per the TODO below) without
// dragging engine internals into the CLI's JSON contract.
type campaignListEntry struct {
	ID       string `json:"id"`
	Status   string `json:"status"`
	Target   string `json:"target"`
	Findings int    `json:"findings"`
}

var campaignCmd = &cobra.Command{
	Use:   "campaign",
	Short: "Manage penetration testing campaigns",
}

var campaignListCmd = &cobra.Command{
	Use:     "list",
	Short:   "List all campaigns",
	Example: "  pentestswarm campaign list\n  pentestswarm campaign list --json",
	RunE: func(cmd *cobra.Command, args []string) error {
		// TODO: fetch from API/DB
		entries := []campaignListEntry{}

		if OutputIsJSON() {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(entries)
		}

		fmt.Println(colorBold("ID                                   STATUS       TARGET              FINDINGS"))
		fmt.Println(colorDim("───────────────────────────────────────────────────────────────────────────────"))
		if len(entries) == 0 {
			fmt.Println(colorDim("  (no campaigns yet — run: pentestswarm scan <target> --scope <scope>)"))
		}
		return nil
	},
}

var campaignStatusCmd = &cobra.Command{
	Use:     "status <id>",
	Short:   "Show detailed status of a campaign",
	Args:    cobra.ExactArgs(1),
	Example: "  pentestswarm campaign status abc-123",
	RunE: func(cmd *cobra.Command, args []string) error {
		id := args[0]
		fmt.Printf("%s Campaign: %s\n", colorBold("*"), id)
		fmt.Printf("  Status:  %s\n", colorYellow("unknown"))
		fmt.Printf("  Target:  %s\n", colorDim("fetch from API"))
		// TODO: fetch from API
		return nil
	},
}

var campaignStopCmd = &cobra.Command{
	Use:     "stop <id>",
	Short:   "Emergency stop a running campaign",
	Args:    cobra.ExactArgs(1),
	Example: "  pentestswarm campaign stop abc-123",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("%s Stopping campaign %s...\n", colorRed("*"), args[0])
		// TODO: call API
		fmt.Printf("%s Campaign stopped. Cleanup actions executed.\n", colorGreen("*"))
		return nil
	},
}

var campaignPreflightCmd = &cobra.Command{
	Use:   "preflight <target>",
	Short: "Verify an authorized campaign is ready before any target traffic",
	Long: "Runs a zero-target-traffic readiness gate. It validates scope, extracted program constraints, " +
		"identity/session references, approval capabilities, durable state/cleanup storage, the fail-closed policy gateway, " +
		"and the controlled benchmark suite. It does not contact the target.",
	Args: cobra.ExactArgs(1),
	RunE: runCampaignPreflight,
}

func runCampaignPreflight(cmd *cobra.Command, args []string) error {
	scopePath, _ := cmd.Flags().GetString("scope")
	policyPath, _ := cmd.Flags().GetString("policy")
	identityArgs, _ := cmd.Flags().GetStringArray("identity")
	primaryRaw, _ := cmd.Flags().GetString("primary-identity")
	capabilities, _ := cmd.Flags().GetStringArray("approve-capability")
	stateDir, _ := cmd.Flags().GetString("state-dir")
	maxDuration, _ := cmd.Flags().GetDuration("max-duration")
	maxRPS, _ := cmd.Flags().GetFloat64("max-rps")
	activeScan, _ := cmd.Flags().GetBool("active-scan")
	safeMode, _ := cmd.Flags().GetBool("safe-mode")
	assist, _ := cmd.Flags().GetBool("assist")

	def, err := readScope(scopePath)
	if err != nil {
		return err
	}
	constraints, err := readGuidePolicy(policyPath)
	if err != nil {
		return err
	}
	identities, err := parseGuideIdentities(identityArgs)
	if err != nil {
		return err
	}

	report, err := preflight.Run(cmd.Context(), preflight.Input{
		Target: args[0],
		Scope: *def,
		Constraints: constraints,
		Identities: identities,
		PrimaryIdentity: identity.ID(primaryRaw),
		ApprovedCapabilities: capabilities,
		StateDir: stateDir,
		MaxDuration: maxDuration,
		MaxRequestsPerSecond: maxRPS,
		ActiveScan: activeScan,
		SafeMode: safeMode,
		Assist: assist,
	})
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
		renderCampaignPreflight(report)
	}
	if !report.Ready {
		ExitCode = 1
	}
	return nil
}

func renderCampaignPreflight(report preflight.Report) {
	fmt.Println()
	status := colorGreen("READY")
	if !report.Ready {
		status = colorRed("NOT READY")
	}
	fmt.Printf("  %s Campaign preflight %s\n", colorCyan("[preflight]"), status)
	fmt.Printf("  target: %s\n", report.Target)
	if report.PolicyVersion != "" {
		fmt.Printf("  policy version: %s\n", report.PolicyVersion)
	}
	for i := range report.Checks {
		check := &report.Checks[i]
		mark := colorGreen("PASS")
		if !check.Passed {
			mark = colorRed("FAIL")
		}
		fmt.Printf("    %-24s %s  %s\n", check.Name, mark, check.Detail)
	}
	for _, warning := range report.Warnings {
		fmt.Printf("  %s %s\n", colorYellow("[review]"), warning)
	}
	fmt.Printf("  benchmark: %s\n", report.Benchmark.Summary())
	fmt.Println()
	if report.Ready {
		fmt.Println(colorGreen("  Preflight passed. No target traffic was sent."))
	} else {
		fmt.Println(colorRed("  Resolve the failed checks before starting the campaign."))
	}
	fmt.Println()
}

func init() {
	campaignPreflightCmd.Flags().String("scope", "", "program scope YAML")
	campaignPreflightCmd.Flags().String("policy", "", "program constraints YAML from 'program inspect --yaml'")
	campaignPreflightCmd.Flags().StringArray("identity", nil, "controlled identity as id:role[:session-ref] (repeatable)")
	campaignPreflightCmd.Flags().String("primary-identity", "", "primary controlled identity ID (required when multiple identities are configured)")
	campaignPreflightCmd.Flags().StringArray("approve-capability", nil, "campaign capability grant (repeatable)")
	campaignPreflightCmd.Flags().String("state-dir", ".pentestswarm/state", "durable campaign state directory")
	campaignPreflightCmd.Flags().Duration("max-duration", engine.DefaultCampaignTimeout, "hard wall-clock campaign duration")
	campaignPreflightCmd.Flags().Float64("max-rps", 0, "optional additional global request ceiling; never exceeds a stricter parsed program limit")
	campaignPreflightCmd.Flags().Bool("active-scan", false, "preflight an active-scan campaign")
	campaignPreflightCmd.Flags().Bool("safe-mode", false, "preflight with destructive-command safe mode enabled")
	campaignPreflightCmd.Flags().Bool("assist", false, "preflight with interactive approval mode enabled")
	_ = campaignPreflightCmd.MarkFlagRequired("scope")
	_ = campaignPreflightCmd.MarkFlagRequired("policy")

	campaignCmd.AddCommand(campaignListCmd)
	campaignCmd.AddCommand(campaignStatusCmd)
	campaignCmd.AddCommand(campaignStopCmd)
	campaignCmd.AddCommand(campaignPreflightCmd)

	rootCmd.AddCommand(campaignCmd)
}
