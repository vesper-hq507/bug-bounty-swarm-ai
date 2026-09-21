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
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/config"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/plugins"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/tools"
	"github.com/spf13/cobra"
)

// resolvePlaybook loads a playbook by path or name: an explicit file path first,
// then ./playbooks/<name>.yaml on disk, then the playbook bundled into the
// binary. This is why `playbook run <name>` works for npm/brew/binary installs
// that don't have the repo's playbooks/ directory on disk.
func resolvePlaybook(nameOrPath string) (*plugins.Playbook, error) {
	if pb, err := plugins.LoadPlaybook(nameOrPath); err == nil {
		return pb, nil
	}
	if pb, err := plugins.LoadPlaybook(filepath.Join("playbooks", nameOrPath+".yaml")); err == nil {
		return pb, nil
	}
	if pb, err := plugins.LoadPlaybookFS(pentestswarm.BundledPlaybooks(), nameOrPath); err == nil {
		return pb, nil
	}
	return nil, fmt.Errorf("playbook not found: %s (try 'pentestswarm playbook list')", nameOrPath)
}

var playbookCmd = &cobra.Command{
	Use:   "playbook",
	Short: "Manage and run community attack playbooks",
}

var playbookRunCmd = &cobra.Command{
	Use:   "run <path-or-name>",
	Short: "Run a playbook against a target",
	Args:  cobra.ExactArgs(1),
	Example: `  pentestswarm playbook run playbooks/owasp-top10.yaml --target example.com
  pentestswarm playbook run aws-cloud-audit --target app.example.com`,
	RunE: func(cmd *cobra.Command, args []string) error {
		playbookPath := args[0]
		target, _ := cmd.Flags().GetString("target")

		if target == "" {
			return fmt.Errorf("--target is required")
		}

		pb, err := resolvePlaybook(playbookPath)
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
			fmt.Printf("\n  %s Running playbook: %s\n", colorCyan("*"), colorBold(pb.Name))
			fmt.Printf("  %s Author: %s\n", colorDim("*"), pb.Author.Name)
			fmt.Printf("  %s Target: %s\n", colorDim("*"), target)
			fmt.Printf("  %s Phases: %d\n\n", colorDim("*"), len(pb.Phases))
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigCh
			cancel()
		}()

		runner := plugins.NewPlaybookRunner(cfg)
		err = runner.Run(ctx, pb, target, make(map[string]string), func(event pipeline.CampaignEvent) {
			printEvent(event)
		})

		if err != nil {
			return fmt.Errorf("playbook failed: %w", err)
		}

		fmt.Println(colorGreen("\n  Playbook complete."))
		return nil
	},
}

var playbookListCmd = &cobra.Command{
	Use:     "list",
	Short:   "List installed playbooks",
	Example: "  pentestswarm playbook list",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Bundled (embedded) playbooks are always available; a same-named file
		// in ./playbooks overrides its embedded copy.
		byName := map[string]*plugins.Playbook{}
		if bundled, berr := plugins.DiscoverPlaybooksFS(pentestswarm.BundledPlaybooks()); berr == nil {
			for _, pb := range bundled {
				byName[pb.Name] = pb
			}
		}
		if onDisk, derr := plugins.DiscoverPlaybooks("playbooks"); derr == nil {
			for _, pb := range onDisk {
				byName[pb.Name] = pb
			}
		}
		if len(byName) == 0 {
			fmt.Println(colorDim("  No playbooks found."))
			fmt.Println(colorDim("  Add YAML playbooks to ./playbooks or run: pentestswarm playbook create"))
			return nil
		}
		playbooks := make([]*plugins.Playbook, 0, len(byName))
		for _, pb := range byName {
			playbooks = append(playbooks, pb)
		}
		sort.Slice(playbooks, func(i, j int) bool { return playbooks[i].Name < playbooks[j].Name })

		fmt.Println(colorBold("  NAME                          PHASES  TAGS"))
		fmt.Println(colorDim("  ──────────────────────────────────────────────────"))
		for _, pb := range playbooks {
			tags := ""
			if len(pb.Tags) > 0 {
				tags = fmt.Sprintf("[%s]", joinStr(pb.Tags, ", "))
			}
			fmt.Printf("  %-30s %d       %s\n", pb.Name, len(pb.Phases), tags)
		}
		return nil
	},
}

var playbookValidateCmd = &cobra.Command{
	Use:     "validate <path>",
	Short:   "Validate a playbook YAML file",
	Args:    cobra.ExactArgs(1),
	Example: "  pentestswarm playbook validate my-playbook.yaml",
	RunE: func(cmd *cobra.Command, args []string) error {
		pb, err := plugins.LoadPlaybook(args[0])
		if err != nil {
			fmt.Printf("  %s %s\n", colorRed("[INVALID]"), err)
			return fmt.Errorf("parse failed")
		}
		report := plugins.Validate(pb, tools.NewCoordinator().AvailableTools())
		if report.OK() {
			fmt.Printf("  %s %s (%d phases, %d variables)\n",
				colorGreen("[VALID]"), pb.Name, len(pb.Phases), len(pb.Variables))
			if len(report.Warnings) > 0 {
				fmt.Println(report.Format())
			}
			return nil
		}
		fmt.Printf("  %s %s\n", colorRed("[INVALID]"), pb.Name)
		fmt.Print(report.Format())
		return fmt.Errorf("%d error(s), %d warning(s)", len(report.Errors), len(report.Warnings))
	},
}

var playbookCreateCmd = &cobra.Command{
	Use:     "create",
	Short:   "Scaffold a new playbook YAML",
	Example: "  pentestswarm playbook create",
	RunE: func(cmd *cobra.Command, args []string) error {
		template := `name: my-playbook
description: Description of what this playbook tests
author:
  name: Your Name
  github: yourgithub
version: 1.0.0
tags: [web, custom]

variables:
  target_domain:
    type: string
    required: true

phases:
  - name: reconnaissance
    tools:
      - name: subfinder
        options: { recursive: false }
      - name: httpx
        options: { follow_redirects: true }
    post_analysis: |
      Analyze discovered assets and identify interesting targets.

  - name: vulnerability_scan
    tools:
      - name: nuclei
        options:
          severity: [critical, high, medium]
    post_analysis: |
      Classify findings and prioritize for exploitation.
`
		path := "playbooks/my-playbook.yaml"
		os.MkdirAll("playbooks", 0755)
		if err := os.WriteFile(path, []byte(template), 0644); err != nil {
			return err
		}
		fmt.Printf("  %s Created %s\n", colorGreen("*"), path)
		fmt.Println(colorDim("  Edit the file, then run: pentestswarm playbook validate " + path))
		return nil
	},
}

func joinStr(ss []string, sep string) string {
	result := ""
	for i, s := range ss {
		if i > 0 {
			result += sep
		}
		result += s
	}
	return result
}

func init() {
	playbookRunCmd.Flags().String("target", "", "target domain or IP (required)")
	_ = playbookRunCmd.MarkFlagRequired("target")

	playbookCmd.AddCommand(playbookRunCmd)
	playbookCmd.AddCommand(playbookListCmd)
	playbookCmd.AddCommand(playbookValidateCmd)
	playbookCmd.AddCommand(playbookCreateCmd)

	rootCmd.AddCommand(playbookCmd)
}
