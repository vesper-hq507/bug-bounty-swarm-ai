package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	pentestswarm "github.com/Armur-Ai/Pentest-Swarm-AI"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/agent/prompts"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/chains"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/config"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/plugins"
	"github.com/spf13/cobra"
)

// readAdvisory gathers the advisory text for `chain forge` from (in order):
// --from <file>, --url <url>, positional args, or piped stdin.
func readAdvisory(args []string, fromFile, url string) (string, error) {
	if fromFile != "" {
		b, err := os.ReadFile(fromFile)
		return string(b), err
	}
	if url != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 200<<10)) // 200KB cap
		return string(b), nil
	}
	if len(args) > 0 {
		return strings.Join(args, " "), nil
	}
	if fi, _ := os.Stdin.Stat(); fi != nil && (fi.Mode()&os.ModeCharDevice) == 0 {
		b, _ := io.ReadAll(io.LimitReader(os.Stdin, 200<<10))
		return string(b), nil
	}
	return "", fmt.Errorf("no advisory: pass text, --from <file>, --url <url>, or pipe it via stdin")
}

var chainForgeCmd = &cobra.Command{
	Use:   "forge [advisory-text]",
	Short: "Draft a new exploit chain from an advisory using your configured reasoning model",
	Long: `Chain Forge turns a vulnerability advisory into a draft exploit chain — the
fingerprint, the ordered links with their CVEs, and a SAFE (non-weaponized)
verification for each. It uses whatever reasoning model you've configured
(Ollama, Together, GLM, Claude, Gemini, Muse Spark…), validates the result
against the schema, and prints it for your review. It never auto-publishes:
review the draft, then --save it locally or open a PR.`,
	Example: `  pentestswarm chain forge --url https://vendor.example/advisory --cve CVE-2026-1234
  pentestswarm chain forge --from advisory.txt --save`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fromFile, _ := cmd.Flags().GetString("from")
		url, _ := cmd.Flags().GetString("url")
		cve, _ := cmd.Flags().GetString("cve")
		out, _ := cmd.Flags().GetString("out")
		save, _ := cmd.Flags().GetBool("save")

		advisory, err := readAdvisory(args, fromFile, url)
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
		provider, perr := prompts.NewProviderWithRetry(cfg.Orchestrator)
		if perr != nil {
			return fmt.Errorf("no reasoning model configured (%w) — set a provider in config.yaml or run 'pentestswarm init'", perr)
		}

		fmt.Printf("\n  %s forging exploit chain with %s…\n\n", colorCyan("⚒"), provider.ModelName())
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		ch, raw, ferr := chains.Forge(ctx, provider, advisory, cve)
		if ferr != nil {
			return fmt.Errorf("forge failed: %w", ferr)
		}

		fmt.Println(raw)
		fmt.Printf("\n  %s drafted %q (%s, CVSS %.1f) — %s\n",
			colorGreen("✓"), ch.ID, joinStr(ch.CVEs, ", "), ch.CVSS,
			colorDim("review it before you trust or ship it"))

		switch {
		case out != "":
			if werr := os.WriteFile(out, []byte(raw+"\n"), 0o644); werr != nil {
				return werr
			}
			fmt.Printf("  %s written to %s\n", colorGreen("✓"), out)
		case save:
			path := filepath.Join(localChainsDir(), ch.ID+".yaml")
			if werr := os.MkdirAll(localChainsDir(), 0o755); werr != nil {
				return werr
			}
			if werr := os.WriteFile(path, []byte(raw+"\n"), 0o644); werr != nil {
				return werr
			}
			fmt.Printf("  %s saved to %s — now runnable via 'chain run %s'\n", colorGreen("✓"), path, ch.ID)
		default:
			fmt.Printf("  %s keep it with %s or %s (or open a PR to the public library)\n",
				colorDim("→"), colorCyan("--save"), colorCyan("--out <path>"))
		}
		return nil
	},
}

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

// chainRegistry resolves the registry URL: --registry flag, then the
// PENTESTSWARM_CHAINS_REGISTRY env var, else "" (chains.Update defaults it to the
// community feed).
func chainRegistry(cmd *cobra.Command) string {
	if r, _ := cmd.Flags().GetString("registry"); r != "" {
		return r
	}
	return os.Getenv("PENTESTSWARM_CHAINS_REGISTRY")
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

var chainUpdateCmd = &cobra.Command{
	Use:     "update",
	Short:   "Fetch the latest exploit chains from the registry (grows the library without a binary upgrade)",
	Example: "  pentestswarm chain update",
	RunE: func(cmd *cobra.Command, args []string) error {
		registry := chainRegistry(cmd)
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		fmt.Println(colorDim("  fetching exploit chains…"))
		ids, err := chains.Update(ctx, registry, localChainsDir())
		if err != nil {
			return fmt.Errorf("chain update failed: %w", err)
		}
		fmt.Printf("  %s %d chains synced to %s\n", colorGreen("✓"), len(ids), localChainsDir())
		return nil
	},
}

var chainPullCmd = &cobra.Command{
	Use:     "pull <id>",
	Short:   "Fetch a single exploit chain from the registry",
	Args:    cobra.ExactArgs(1),
	Example: "  pentestswarm chain pull sonicwall-sma1000-ssrf-rce",
	RunE: func(cmd *cobra.Command, args []string) error {
		registry := chainRegistry(cmd)
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if err := chains.Pull(ctx, registry, args[0], localChainsDir()); err != nil {
			return err
		}
		fmt.Printf("  %s pulled %s\n", colorGreen("✓"), args[0])
		return nil
	},
}

func init() {
	rootCmd.AddCommand(chainCmd)
	chainCmd.AddCommand(chainListCmd, chainInfoCmd, chainRunCmd, chainUpdateCmd, chainPullCmd, chainForgeCmd)
	chainForgeCmd.Flags().String("from", "", "read the advisory from a file")
	chainForgeCmd.Flags().String("url", "", "fetch the advisory from a URL")
	chainForgeCmd.Flags().String("cve", "", "CVE id(s) to anchor the chain, comma-separated")
	chainForgeCmd.Flags().String("out", "", "write the drafted chain YAML to this path")
	chainForgeCmd.Flags().Bool("save", false, "save the drafted chain to your local library (~/.pentestswarm/chains)")
	chainRunCmd.Flags().String("target", "", "target URL / host (required)")
	chainRunCmd.Flags().String("scope", "", "extra authorized scope — CIDRs/domains, comma-separated")
	chainRunCmd.Flags().String("format", "md", "report format: md | json | html | all")
	chainRunCmd.Flags().String("report-dir", "./reports", "directory to write the report into")
	chainUpdateCmd.Flags().String("registry", "", "exploit-chain registry URL (default: the community feed; or set PENTESTSWARM_CHAINS_REGISTRY)")
	chainPullCmd.Flags().String("registry", "", "exploit-chain registry URL (default: the community feed)")
}
