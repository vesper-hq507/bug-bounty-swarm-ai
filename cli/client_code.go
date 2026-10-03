package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/clientcode"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/monitor"
	"github.com/spf13/cobra"
)

var clientCodeCmd = &cobra.Command{
	Use:   "client-code",
	Short: "Statically analyze JavaScript and source maps without executing them",
}

var clientCodeAnalyzeCmd = &cobra.Command{
	Use:   "analyze <asset.js>",
	Short: "Extract bounded client-side security signals from a local artifact",
	Args:  cobra.ExactArgs(1),
	RunE:  runClientCodeAnalyze,
}

func runClientCodeAnalyze(cmd *cobra.Command, args []string) error {
	assetURL, _ := cmd.Flags().GetString("url")
	sourceMapPath, _ := cmd.Flags().GetString("source-map")
	outPath, _ := cmd.Flags().GetString("out")
	snapshotPath, _ := cmd.Flags().GetString("snapshot")
	snapshotOut, _ := cmd.Flags().GetString("snapshot-out")

	script, err := readBoundedArtifact(args[0], clientcode.MaxAssetBytes)
	if err != nil {
		return err
	}
	var sourceMap []byte
	if strings.TrimSpace(sourceMapPath) != "" {
		sourceMap, err = readBoundedArtifact(sourceMapPath, clientcode.MaxSourceMapBytes)
		if err != nil {
			return err
		}
	}

	analysis, err := clientcode.Analyze(assetURL, script, sourceMap)
	if err != nil {
		return err
	}

	if strings.TrimSpace(snapshotPath) != "" {
		if strings.TrimSpace(assetURL) == "" {
			return fmt.Errorf("--url is required when attaching analysis to a monitor snapshot")
		}
		snapshot, err := readMonitorSnapshot(snapshotPath)
		if err != nil {
			return err
		}
		if err := monitor.AttachClientAnalysis(&snapshot, analysis); err != nil {
			return err
		}
		if strings.TrimSpace(snapshotOut) == "" {
			snapshotOut = snapshotPath
		}
		if err := writeJSONFile(snapshotOut, snapshot); err != nil {
			return err
		}
	}

	if strings.TrimSpace(outPath) != "" {
		if err := writeJSONFile(outPath, analysis); err != nil {
			return err
		}
	}

	if OutputIsJSON() {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(analysis)
	}
	renderClientCodeAnalysis(analysis)
	return nil
}

func readBoundedArtifact(path string, maxBytes int) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat artifact: %w", err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("artifact is a directory: %s", path)
	}
	if info.Size() > int64(maxBytes) {
		return nil, fmt.Errorf("artifact %s exceeds %d bytes", filepath.Base(path), maxBytes)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read artifact: %w", err)
	}
	return b, nil
}

func renderClientCodeAnalysis(a clientcode.Analysis) {
	fmt.Println()
	fmt.Printf("  %s Static client-code analysis - code was not executed\n", colorCyan("[client-code]"))
	if a.AssetURL != "" {
		fmt.Printf("  asset: %s\n", a.AssetURL)
	}
	fmt.Printf("  content hash: %s\n", a.Summary.ContentHash)
	if a.Summary.SourceMapHash != "" {
		fmt.Printf("  source map: %d source files\n", len(a.Summary.SourceFiles))
	}
	fmt.Printf("  routes: %d | realtime: %d | parameters: %d | roles: %d | flags: %d | workflow states: %d\n",
		len(a.Summary.Routes), len(a.Summary.RealtimeEndpoints), len(a.Summary.Parameters),
		len(a.Summary.RoleHints), len(a.Summary.FeatureFlags), len(a.Summary.WorkflowStates))
	for i := range a.Signals {
		s := &a.Signals[i]
		fmt.Printf("    - %-18s %-8s %s (%s)\n", s.Kind, s.Confidence, s.Value, s.Source)
	}
	fmt.Println()
}

func init() {
	clientCodeAnalyzeCmd.Flags().String("url", "", "canonical URL for the JavaScript asset; resolves relative routes")
	clientCodeAnalyzeCmd.Flags().String("source-map", "", "optional local source-map file")
	clientCodeAnalyzeCmd.Flags().String("out", "", "write analysis JSON to this file")
	clientCodeAnalyzeCmd.Flags().String("snapshot", "", "optional monitor snapshot to enrich with this analysis")
	clientCodeAnalyzeCmd.Flags().String("snapshot-out", "", "write enriched snapshot here; defaults to overwriting --snapshot")
	clientCodeCmd.AddCommand(clientCodeAnalyzeCmd)
	rootCmd.AddCommand(clientCodeCmd)
}
