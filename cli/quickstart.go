package cli

import (
	"fmt"
	"os/exec"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/config"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/toolpath"
	"github.com/spf13/cobra"
)

var quickstartCmd = &cobra.Command{
	Use:   "quickstart",
	Short: "Guided first-run — check your setup, fix what's missing, then launch",
	Long: `quickstart shepherds a fresh machine to a first real run:

  1. checks your environment (Go, Docker, recon tools, AI provider),
  2. offers to install any missing recon tools for you,
  3. hands off to the interactive launcher so you can pick a provider and a
     target (or a bundled, legal practice lab) and go.

Nothing here fails hard — anything missing is shown with the one command to
fix it, and you can always continue.`,
	Example: `  pentestswarm quickstart`,
	RunE:    func(cmd *cobra.Command, _ []string) error { return runQuickstart() },
}

func init() {
	rootCmd.AddCommand(quickstartCmd)
}

func runQuickstart() error {
	fmt.Println()
	fmt.Println("  " + colorBold("Welcome to Pentest Swarm AI") + colorDim(" — let's get you to a first run."))
	fmt.Println()

	// 1. Readiness checks (same signals the launcher shows).
	cfg, cfgErr := config.Load(cfgFile)
	fmt.Println(colorBold("  Checking your setup"))

	_, goErr := exec.LookPath("go")
	qsCheck("Go toolchain", goErr == nil, "ready", "not found — needed to install Go-based tools (https://go.dev/dl)")

	dockerDetail, dockerOK := checkDocker()
	qsCheck("Docker", dockerOK, dockerDetail, dockerDetail+" — only needed for bundled --lab targets")

	provOK := cfgErr == nil && hasAIProviderConfigured(cfg)
	qsCheck("AI provider", provOK, "configured", "not set yet — you'll pick one (paste a key, or use a local model) in the launcher")

	missing := missingReconTools()
	if len(missing) == 0 {
		qsCheck("Recon tools", true, "httpx, nuclei, katana ready", "")
	} else {
		qsCheck("Recon tools", false, "", fmt.Sprintf("missing %d (%v)", len(missing), missing))
	}
	fmt.Println()

	// 2. Offer to fix the most common gap — missing recon tools.
	if len(missing) > 0 {
		if goErr != nil {
			fmt.Println("  " + colorYellow("Install Go first (https://go.dev/dl), then re-run quickstart to fetch the tools."))
		} else if Confirm(fmt.Sprintf("Install the %d missing recon tool(s) now?", len(missing))) {
			fmt.Println()
			installGoTools(missing)
			fmt.Println()
		} else {
			fmt.Println("  " + colorDim("Skipped — you can run ") + colorCyan("pentestswarm install-tools") + colorDim(" any time.\n"))
		}
	}

	// 3. Hand off to the interactive launcher for provider + target + go.
	if !toolpathHasAny() && len(missing) > 0 {
		// Nothing to scan with and tools still missing — still open the
		// launcher; recon will degrade rather than hard-fail.
		fmt.Println("  " + colorDim("Opening the launcher — pick a provider and a target (or a bundled lab)…"))
	} else {
		fmt.Println("  " + colorGreen("You're set.") + colorDim(" Opening the launcher — pick a provider and a target (or a bundled lab)…"))
	}
	fmt.Println()
	return launchInteractive()
}

// qsCheck prints one readiness line with the detail appropriate to the state.
func qsCheck(label string, ok bool, okDetail, failDetail string) {
	mark, detail := colorGreen("✓"), okDetail
	if !ok {
		mark, detail = colorYellow("!"), failDetail
	}
	fmt.Printf("    %s %-14s %s\n", mark, label, colorDim(detail))
}

// toolpathHasAny reports whether at least one core recon tool resolves — a
// cheap "can we actually scan something" signal.
func toolpathHasAny() bool {
	for _, t := range []string{"httpx", "nuclei", "katana"} {
		if _, ok := toolpath.Resolve(t); ok {
			return true
		}
	}
	return false
}
