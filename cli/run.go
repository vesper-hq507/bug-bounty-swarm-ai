package cli

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/Armur-Ai/Pentest-Swarm-AI/cli/ui"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/config"
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
