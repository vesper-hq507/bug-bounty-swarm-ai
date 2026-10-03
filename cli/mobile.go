package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/evidence"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/identity"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/mobile"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

var mobileCmd = &cobra.Command{
	Use:   "mobile",
	Short: "Analyze controlled mobile traffic captures without replaying them",
}

var mobileAnalyzeCmd = &cobra.Command{
	Use:   "analyze <capture.har>",
	Short: "Import a mobile HAR into scope, evidence, workflow and guidance",
	Args:  cobra.ExactArgs(1),
	RunE:  runMobileAnalyze,
}

var mobileDiffCmd = &cobra.Command{
	Use:   "diff <owner.har> <actor.har>",
	Short: "Compare the same mobile object traffic across two controlled identities",
	Args:  cobra.ExactArgs(2),
	RunE:  runMobileDiff,
}

func runMobileAnalyze(cmd *cobra.Command, args []string) error {
	platformRaw, _ := cmd.Flags().GetString("platform")
	appID, _ := cmd.Flags().GetString("app-id")
	identityAlias, _ := cmd.Flags().GetString("identity")
	role, _ := cmd.Flags().GetString("role")
	sessionRef, _ := cmd.Flags().GetString("session-ref")
	scopePath, _ := cmd.Flags().GetString("scope")
	policyPath, _ := cmd.Flags().GetString("policy")
	rulesPath, _ := cmd.Flags().GetString("rules")
	stateDir, _ := cmd.Flags().GetString("state-dir")
	campaignRaw, _ := cmd.Flags().GetString("campaign-id")

	def, err := readScope(scopePath)
	if err != nil {
		return err
	}
	constraints, err := readGuidePolicy(policyPath)
	if err != nil {
		return err
	}
	rules, err := readWorkflowRules(rulesPath)
	if err != nil {
		return err
	}
	capture, err := readMobileHAR(args[0], mobile.Metadata{
		Platform: mobile.Platform(strings.ToLower(platformRaw)),
		AppID: appID, IdentityAlias: identityAlias, ActorRole: role, SessionRef: sessionRef,
	})
	if err != nil {
		return err
	}
	campaignID, err := mobileCampaignID(campaignRaw)
	if err != nil {
		return err
	}
	store, err := evidence.NewFileStore(filepath.Join(stateDir, "evidence"))
	if err != nil {
		return err
	}
	policyVersion, err := mobilePolicyVersion(scopePath, policyPath)
	if err != nil {
		return err
	}
	analysis, err := mobile.Analyze(cmd.Context(), capture, mobile.AnalyzeOptions{
		Scope: *def, Constraints: constraints, WorkflowRules: rules,
		CampaignID: campaignID, PolicyVersion: policyVersion, EvidenceStore: store,
	})
	if err != nil {
		return err
	}
	if OutputIsJSON() {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(analysis)
	}
	renderMobileAnalysis(analysis, campaignID)
	return nil
}

func runMobileDiff(cmd *cobra.Command, args []string) error {
	platformRaw, _ := cmd.Flags().GetString("platform")
	appID, _ := cmd.Flags().GetString("app-id")
	ownerIdentity, _ := cmd.Flags().GetString("owner-identity")
	actorIdentity, _ := cmd.Flags().GetString("actor-identity")
	scopePath, _ := cmd.Flags().GetString("scope")
	policyPath, _ := cmd.Flags().GetString("policy")

	def, err := readScope(scopePath)
	if err != nil {
		return err
	}
	constraints, err := readGuidePolicy(policyPath)
	if err != nil {
		return err
	}
	platform := mobile.Platform(strings.ToLower(platformRaw))
	owner, err := readMobileHAR(args[0], mobile.Metadata{Platform: platform, AppID: appID, IdentityAlias: ownerIdentity})
	if err != nil {
		return err
	}
	actor, err := readMobileHAR(args[1], mobile.Metadata{Platform: platform, AppID: appID, IdentityAlias: actorIdentity})
	if err != nil {
		return err
	}
	results := mobile.CompareControlled(owner, actor, *def, constraints)
	if OutputIsJSON() {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	}
	fmt.Println()
	fmt.Printf("  %s Mobile controlled-identity differential — offline only\n", colorCyan("[mobile]"))
	unexpected := 0
	for i := range results {
		r := &results[i]
		if r.Kind == identity.DiffUnexpectedAccess {
			unexpected++
		}
		fmt.Printf("    - %-24s object=%s owner=%s actor=%s\n", r.Kind, r.Object.Key(), r.Owner, r.Actor)
	}
	fmt.Printf("\n  compared objects: %d | unexpected access: %d\n\n", len(results), unexpected)
	return nil
}

func readMobileHAR(path string, meta mobile.Metadata) (mobile.Capture, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return mobile.Capture{}, fmt.Errorf("read mobile HAR: %w", err)
	}
	return mobile.ParseHAR(data, meta)
}

func mobileCampaignID(raw string) (uuid.UUID, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return uuid.New(), nil
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid campaign id: %w", err)
	}
	return id, nil
}

func mobilePolicyVersion(scopePath, policyPath string) (string, error) {
	h := sha256.New()
	for _, path := range []string{scopePath, policyPath} {
		if strings.TrimSpace(path) == "" {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read policy input %s: %w", path, err)
		}
		_, _ = h.Write(data)
	}
	sum := h.Sum(nil)
	return "mobile-import-" + hex.EncodeToString(sum[:8]), nil
}

func renderMobileAnalysis(a mobile.Analysis, campaignID uuid.UUID) {
	fmt.Println()
	fmt.Printf("  %s Mobile workflow analysis — no request replay\n", colorCyan("[mobile]"))
	fmt.Printf("  app: %s | platform: %s | identity: %s\n", a.AppID, a.Platform, a.IdentityAlias)
	fmt.Printf("  campaign: %s\n", campaignID)
	fmt.Printf("  transactions: %d | in-scope: %d | skipped: %d | evidence refs: %d\n",
		a.TotalTransactions, a.InScopeCount, len(a.Skipped), len(a.EvidenceRefs))
	fmt.Printf("  workflow hypotheses: %d | guidance items: %d\n", len(a.Workflow.Hypotheses), len(a.Guidance))
	for i := range a.Guidance {
		g := &a.Guidance[i]
		fmt.Printf("    - %s -> %s\n", g.Test, g.Target)
		fmt.Printf("      %s\n", g.Hypothesis)
	}
	if len(a.Skipped) > 0 {
		fmt.Println("  skipped observations:")
		for i := range a.Skipped {
			s := &a.Skipped[i]
			fmt.Printf("    - %s %s: %s\n", s.Method, s.URL, s.Reason)
		}
	}
	fmt.Println()
}

func init() {
	for _, cmd := range []*cobra.Command{mobileAnalyzeCmd, mobileDiffCmd} {
		cmd.Flags().String("platform", "", "mobile platform: android or ios")
		cmd.Flags().String("app-id", "", "application/package identifier")
		cmd.Flags().String("scope", "scope.yaml", "program scope YAML")
		cmd.Flags().String("policy", "", "optional program-constraint YAML")
		_ = cmd.MarkFlagRequired("platform")
		_ = cmd.MarkFlagRequired("app-id")
	}

	mobileAnalyzeCmd.Flags().String("identity", "", "controlled identity alias for this capture")
	mobileAnalyzeCmd.Flags().String("role", "", "role for workflow analysis")
	mobileAnalyzeCmd.Flags().String("session-ref", "", "opaque session/vault reference; raw credentials must not be supplied")
	mobileAnalyzeCmd.Flags().String("rules", "", "optional workflow invariant rules JSON")
	mobileAnalyzeCmd.Flags().String("state-dir", ".pentestswarm/state", "durable evidence state directory")
	mobileAnalyzeCmd.Flags().String("campaign-id", "", "existing campaign UUID; generated when omitted")
	_ = mobileAnalyzeCmd.MarkFlagRequired("identity")

	mobileDiffCmd.Flags().String("owner-identity", "", "controlled owner identity alias")
	mobileDiffCmd.Flags().String("actor-identity", "", "controlled comparison identity alias")
	_ = mobileDiffCmd.MarkFlagRequired("owner-identity")
	_ = mobileDiffCmd.MarkFlagRequired("actor-identity")

	mobileCmd.AddCommand(mobileAnalyzeCmd, mobileDiffCmd)
	rootCmd.AddCommand(mobileCmd)
}
