package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"syscall"

	pentestswarm "github.com/Armur-Ai/Pentest-Swarm-AI"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/chains"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/config"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/plugins"
	"github.com/spf13/cobra"
)

// localChainsDir is where on-demand-fetched exploit chains live (see `chains
// update`). The binary ships a small embedded default set; this dir extends it.
func localChainsDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "chains"
	}
	return filepath.Join(home, ".pentestswarm", "chains")
}

// allChains returns the merged library: embedded defaults + locally-fetched,
// with a local file overriding an embedded chain of the same id.
func allChains() []*chains.ExploitChain {
	byID := map[string]*chains.ExploitChain{}
	for _, c := range chains.DiscoverChainsFS(pentestswarm.BundledChains()) {
		byID[c.ID] = c
	}
	for _, c := range chains.DiscoverChainsDir(localChainsDir()) {
		byID[c.ID] = c
	}
	out := make([]*chains.ExploitChain, 0, len(byID))
	for _, c := range byID {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// resolveChain finds a chain by id or path: explicit file → local dir →
// embedded default set.
func resolveChain(idOrPath string) (*chains.ExploitChain, error) {
	if c, err := chains.LoadChain(idOrPath); err == nil {
		return c, nil
	}
	if c, err := chains.LoadChain(filepath.Join(localChainsDir(), idOrPath+".yaml")); err == nil {
		return c, nil
	}
	if c, err := chains.LoadChainFS(pentestswarm.BundledChains(), idOrPath); err == nil {
		return c, nil
	}
	return nil, fmt.Errorf("exploit chain not found: %s (try 'pentestswarm chain list')", idOrPath)
}

var chainCmd = &cobra.Command{
	Use:   "chain",
	Short: "Run and manage exploit chains (named, CVE-tied attack chains)",
	Long: `Exploit chains are named, versioned attacks where one vulnerability enables
the next (e.g. SSRF → unauthenticated RCE). The swarm fingerprints the target,
safely verifies each link (non-weaponized), and reports the full path with CVEs
and remediation. Distinct from playbooks (workflows).`,
}

var chainListCmd = &cobra.Command{
	Use:     "list",
	Short:   "List available exploit chains",
	Example: "  pentestswarm chain list",
	RunE: func(cmd *cobra.Command, args []string) error {
		cs := allChains()
		if len(cs) == 0 {
			fmt.Println(colorDim("  No exploit chains found."))
			return nil
		}
		fmt.Println(colorBold("  ID                                     CVSS  CVEs"))
		fmt.Println(colorDim("  ────────────────────────────────────────────────────────────"))
		for _, c := range cs {
			fmt.Printf("  %-38s %-5.1f %s\n", c.ID, c.CVSS, joinStr(c.CVEs, ", "))
		}
		fmt.Printf("\n  %s\n", colorDim(fmt.Sprintf("%d chains · run: pentestswarm chain run <id> --target <t>", len(cs))))
		return nil
	},
}

var chainInfoCmd = &cobra.Command{
	Use:     "info <id>",
	Short:   "Show details for an exploit chain",
	Args:    cobra.ExactArgs(1),
	Example: "  pentestswarm chain info ivanti-connect-secure-authbypass-rce",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := resolveChain(args[0])
		if err != nil {
			return err
		}
		fmt.Printf("\n  %s\n", colorBold(c.Name))
		fmt.Printf("  %s\n\n", colorDim(c.Description))
		fmt.Printf("  %s %s\n", colorCyan("Product:"), c.Product)
		if c.Affected != "" {
			fmt.Printf("  %s %s\n", colorCyan("Affected:"), c.Affected)
		}
		fmt.Printf("  %s %s (CVSS %.1f)\n", colorCyan("CVEs:"), joinStr(c.CVEs, ", "), c.CVSS)
		fmt.Printf("\n  %s\n", colorCyan("Chain:"))
		for i, l := range c.Links {
			fmt.Printf("    %d. %s\n", i+1, l.Name)
		}
		if len(c.References) > 0 {
			fmt.Printf("\n  %s\n", colorCyan("References:"))
			for _, r := range c.References {
				fmt.Printf("    - %s\n", r)
			}
		}
		return nil
	},
}

var chainRunCmd = &cobra.Command{
	Use:   "run <id-or-path>",
	Short: "Run an exploit chain against a target",
	Args:  cobra.ExactArgs(1),
	Example: `  pentestswarm chain run sonicwall-sma1000-ssrf-rce --target https://vpn.example.com
  pentestswarm chain run ivanti-connect-secure-authbypass-rce --target https://ics.example.com`,
	RunE: func(cmd *cobra.Command, args []string) error {
		target, _ := cmd.Flags().GetString("target")
		scopeArg, _ := cmd.Flags().GetString("scope")
		format, _ := cmd.Flags().GetString("format")
		reportDir, _ := cmd.Flags().GetString("report-dir")
		if target == "" {
			return fmt.Errorf("--target is required")
		}

		c, err := resolveChain(args[0])
		if err != nil {
			return err
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

		if !quiet {
			fmt.Printf("\n  %s Exploit chain: %s\n", colorCyan("*"), colorBold(c.Name))
			fmt.Printf("  %s CVEs: %s\n", colorDim("*"), joinStr(c.CVEs, ", "))
			fmt.Printf("  %s Target: %s\n", colorDim("*"), target)
			fmt.Printf("  %s Links: %d (safe verification, non-weaponized)\n\n", colorDim("*"), len(c.Links))
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() { <-sigCh; cancel() }()

		vars := map[string]string{}
		if scopeArg != "" {
			vars["scope"] = scopeArg
		}
		_, err = plugins.NewExecutor(cfg).WithFormat(format).WithOutputDir(reportDir).
			Execute(ctx, c.ToPlaybook(), target, vars, func(e pipeline.CampaignEvent) { printEvent(e) })
		if err != nil {
			return fmt.Errorf("exploit chain failed: %w", err)
		}
		fmt.Println(colorGreen("\n  Exploit chain complete."))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(chainCmd)
	chainCmd.AddCommand(chainListCmd, chainInfoCmd, chainRunCmd)
	chainRunCmd.Flags().String("target", "", "target URL / host (required)")
	chainRunCmd.Flags().String("scope", "", "extra authorized scope — CIDRs/domains, comma-separated")
	chainRunCmd.Flags().String("format", "md", "report format: md | json | html | all")
	chainRunCmd.Flags().String("report-dir", "./reports", "directory to write the report into")
}
