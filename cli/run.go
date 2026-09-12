package cli

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/Armur-Ai/Pentest-Swarm-AI/cli/ui"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/config"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/keychain"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/toolpath"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Interactive launcher — pick options and attack, no flags",
	Long: `Opens an interactive terminal UI: choose a target (a URL or a bundled
lab like crAPI), pick the scan mode, AI provider, and toggles, then launch.
A flag-free way to run the swarm — equivalent to 'pentestswarm scan …'.`,
	RunE: func(cmd *cobra.Command, _ []string) error { return launchInteractive() },
}

func init() {
	rootCmd.AddCommand(runCmd)
	// Bare `pentestswarm` in a terminal opens the launcher; otherwise (scripts,
	// pipes) it keeps printing help so nothing surprising happens in CI.
	rootCmd.RunE = func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 && term.IsTerminal(int(os.Stdin.Fd())) {
			return launchInteractive()
		}
		return cmd.Help()
	}
}

// launchInteractive runs the TUI launcher, then hands the chosen configuration
// to the normal scan path (reusing all of runScan: config load, API-key
// resolution, lab boot, dashboard, and the swarm run).
func launchInteractive() error {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return errors.New("the interactive launcher needs a terminal.\n  In scripts, use: " +
			colorCyan("pentestswarm scan <target> --scope <target> --swarm"))
	}

	preflight()

	def := ui.LaunchConfig{Mode: "manual", Swarm: true, ActiveScan: true, Dashboard: true}
	providers := []string{"claude", "openai", "gemini", "ollama", "lmstudio", "orcarouter"}
	if cfg, err := config.Load(cfgFile); err == nil && cfg.Orchestrator.Provider != "" {
		def.Provider = cfg.Orchestrator.Provider
	}

	choice, launched, err := ui.RunLauncher(providers, def)
	if err != nil {
		return err
	}
	if !launched {
		fmt.Println(colorDim("  cancelled."))
		return nil
	}

	// Translate the launcher choice into scan flags and reuse runScan.
	f := scanCmd.Flags()
	set := func(name, val string) { _ = f.Set(name, val) }
	set("mode", choice.Mode)
	set("provider", choice.Provider)
	set("swarm", strconv.FormatBool(choice.Swarm))
	set("active-scan", strconv.FormatBool(choice.ActiveScan))
	set("dashboard", strconv.FormatBool(choice.Dashboard))
	set("follow", "true")
	set("format", "all")

	if choice.IsLab {
		set("lab", "true")
		set("lab-target", choice.Lab)
		return runScan(scanCmd, []string{})
	}

	if s := scopeFor(choice.Target); s != "" {
		set("scope", s)
	}
	return runScan(scanCmd, []string{choice.Target})
}

// scopeFor returns a sensible default scope for a target: loopback for a local
// target, otherwise empty (runScan then defaults scope to the target itself).
func scopeFor(target string) string {
	l := strings.ToLower(target)
	if strings.Contains(l, "localhost") || strings.Contains(l, "127.0.0.1") {
		return "127.0.0.1/32,localhost"
	}
	return ""
}

// preflight prints a compact readiness checklist before the interactive
// form opens, and offers to fix the two most common "nothing is set up
// yet" gaps inline — missing recon tools and no AI provider/key — so a
// first-time researcher doesn't have to abort, read docs, and come back.
// Everything here is advisory: it never blocks the launcher from
// proceeding.
func preflight() {
	if quiet {
		return
	}

	fmt.Println(colorBold("Preflight"))

	_, goErr := exec.LookPath("go")
	printPreflightCheck("Go toolchain", goErr == nil, "not found — https://go.dev/dl/")

	dockerDetail, dockerOK := checkDocker()
	printPreflightCheck("Docker daemon", dockerOK, dockerDetail)

	cfg, cfgErr := config.Load(cfgFile)
	providerOK := cfgErr == nil && hasAIProviderConfigured(cfg)
	providerDetail := "configured"
	if !providerOK {
		providerDetail = "not configured — run 'pentestswarm init' or paste a key below"
	}
	printPreflightCheck("AI provider/key", providerOK, providerDetail)

	missing := missingReconTools()
	if len(missing) == 0 {
		printPreflightCheck("Recon tools", true, "httpx, nuclei, katana")
	} else {
		printPreflightCheck("Recon tools", false, "missing: "+strings.Join(missing, ", "))
	}
	fmt.Println()

	if len(missing) > 0 && promptYesNo("Install missing recon tools now?") {
		fmt.Println()
		installGoTools(missing)
		fmt.Println()
	}

	if !providerOK {
		promptForAPIKeyOnce()
	}
}

// printPreflightCheck renders one line of the preflight checklist.
func printPreflightCheck(label string, ok bool, detail string) {
	mark := colorGreen("✓")
	if !ok {
		mark = colorRed("✗")
	}
	fmt.Printf("  %s %-16s %s\n", mark, label, colorDim(detail))
}

// promptYesNo asks a simple y/N question on stdin. Anything but an
// explicit y/yes counts as no — this runs before the TUI opens and must
// never block indefinitely or install something the researcher didn't
// ask for.
func promptYesNo(question string) bool {
	fmt.Print("  " + colorCyan(question+" [y/N] "))
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		answer := strings.ToLower(strings.TrimSpace(scanner.Text()))
		return answer == "y" || answer == "yes"
	}
	return false
}

// hasAIProviderConfigured mirrors the key-resolution order runScan uses
// (config → env → keychain) so the preflight check and the actual run
// never disagree about whether a key is set. Non-Claude providers (e.g.
// a local ollama) don't need an API key at all, so a configured provider
// name is sufficient for them.
func hasAIProviderConfigured(cfg *config.Config) bool {
	if cfg.Orchestrator.Provider == "" {
		return false
	}
	if cfg.Orchestrator.Provider != "claude" {
		return true
	}
	if cfg.Orchestrator.APIKey != "" {
		return true
	}
	if os.Getenv("PENTESTSWARM_ORCHESTRATOR_API_KEY") != "" || os.Getenv("ANTHROPIC_API_KEY") != "" {
		return true
	}
	if key, err := keychain.Get(keychain.KeyClaudeAPI); err == nil && key != "" {
		return true
	}
	return false
}

// missingReconTools reports which of the core recon binaries aren't
// resolvable via internal/toolpath (PATH plus our managed toolbin and
// the other well-known install locations).
func missingReconTools() []string {
	var missing []string
	for _, t := range []string{"httpx", "nuclei", "katana"} {
		if _, ok := toolpath.Resolve(t); !ok {
			missing = append(missing, t)
		}
	}
	return missing
}
