package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/agent/prompts"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/config"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/poc"
	"github.com/spf13/cobra"
)

var pocCmd = &cobra.Command{
	Use:   "poc <finding-description>",
	Short: "Generate a safe proof-of-concept script that verifies a vulnerability",
	Long: `Generate a self-contained, SAFE proof-of-concept that proves a finding —
a Python script (standard library only), a Burp-ready HTTP request, and steps
to reproduce. With --run, it executes the PoC against the target and marks it
VERIFIED only if it actually fires (proof, not probability).

Safety: PoCs are non-weaponised (benign proof only) and pass a destructive-
content scan. --run executes generated code — only ever point it at a target
you are AUTHORIZED to test.`,
	Args: cobra.MinimumNArgs(1),
	Example: `  pentestswarm poc "BOLA on /api/orders/{id}" --target https://app.example.com
  pentestswarm poc "reflected XSS in q param" --target https://app.local --class xss --out poc.py
  pentestswarm poc "SQLi in search" --target https://app.local --run   # generate AND self-verify`,
	RunE: runPoC,
}

func runPoC(cmd *cobra.Command, args []string) error {
	desc := strings.Join(args, " ")
	target, _ := cmd.Flags().GetString("target")
	class, _ := cmd.Flags().GetString("class")
	severity, _ := cmd.Flags().GetString("severity")
	out, _ := cmd.Flags().GetString("out")
	run, _ := cmd.Flags().GetBool("run")

	if strings.TrimSpace(target) == "" {
		return fmt.Errorf("--target is required (the in-scope host to prove against)")
	}

	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	if cfg.Orchestrator.APIKey == "" {
		if key := os.Getenv("PENTESTSWARM_ORCHESTRATOR_API_KEY"); key != "" {
			cfg.Orchestrator.APIKey = key
		} else if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
			cfg.Orchestrator.APIKey = key
		}
	}
	provider, err := prompts.NewProviderWithRetry(cfg.Orchestrator)
	if err != nil {
		return fmt.Errorf("creating LLM provider: %w", err)
	}

	finding := pipeline.ClassifiedFinding{
		Title:          desc,
		Description:    desc,
		Target:         target,
		Severity:       pipeline.Severity(strings.ToLower(severity)),
		AttackCategory: class,
	}

	ctx := context.Background()
	var p *poc.PoC
	if run {
		runner := poc.NewLocalRunner()
		if !runner.Available() {
			return fmt.Errorf("--run needs python3 on PATH to execute the PoC")
		}
		timeout, _ := cmd.Flags().GetDuration("timeout")
		fmt.Printf("  generating and self-verifying against %s (authorized targets only)…\n\n", target)
		p, err = poc.GenerateAndVerify(ctx, provider, runner, finding, poc.Options{Timeout: timeout})
	} else {
		fmt.Printf("  generating proof-of-concept for: %s\n\n", desc)
		p, err = poc.Generate(ctx, provider, finding)
	}
	if err != nil {
		return fmt.Errorf("generating PoC: %w", err)
	}
	if p == nil {
		return fmt.Errorf("no PoC could be generated for this finding")
	}

	if run {
		status := "UNVERIFIED (did not fire within attempts)"
		if p.Verified {
			status = "VERIFIED ✓ (the PoC actually triggered)"
		}
		fmt.Printf("  status: %s\n", status)
		if strings.TrimSpace(p.RunOutput) != "" {
			fmt.Printf("  run output:\n%s\n\n", indent(p.RunOutput))
		}
	}
	if p.Indicator != "" {
		fmt.Printf("  proof indicator: %s\n", p.Indicator)
	}
	if p.HTTP != "" {
		fmt.Printf("\n  --- HTTP request ---\n%s\n", indent(p.HTTP))
	}
	if p.Steps != "" {
		fmt.Printf("\n  --- steps to reproduce ---\n%s\n", indent(p.Steps))
	}

	if out != "" {
		if err := os.WriteFile(out, []byte(p.Script), 0o644); err != nil {
			return fmt.Errorf("saving PoC: %w", err)
		}
		fmt.Printf("\n  saved script → %s\n", out)
	} else {
		fmt.Printf("\n  --- %s ---\n%s\n", p.Filename, p.Script)
	}
	return nil
}

func indent(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		b.WriteString("    " + line + "\n")
	}
	return b.String()
}

func init() {
	pocCmd.Flags().String("target", "", "in-scope target URL/host to prove against (required)")
	pocCmd.Flags().String("class", "", "attack class hint (bola|sqli|xss|ssrf|rce|auth-bypass|…); inferred if omitted")
	pocCmd.Flags().String("severity", "high", "finding severity (critical|high|medium|low)")
	pocCmd.Flags().String("out", "", "write the PoC script to this file instead of stdout")
	pocCmd.Flags().Bool("run", false, "execute the PoC to self-verify (authorized targets only; needs python3)")
	pocCmd.Flags().Duration("timeout", 30*time.Second, "per-run timeout when --run is set")
	rootCmd.AddCommand(pocCmd)
}
