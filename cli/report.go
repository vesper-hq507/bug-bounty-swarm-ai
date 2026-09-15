package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/agent/prompts"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/agent/report"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/agent/report/qualitygate"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/config"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/keychain"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/spf13/cobra"
)

var reportCmd = &cobra.Command{
	Use:   "report [path]",
	Short: "Re-render a saved report to another format (or work with drafts)",
	Long: `report re-renders an existing run's saved JSON report to another format
without re-running a scan.

  [path]  a report .json file, a directory (the newest *.json in it is used),
          or omitted (default: the newest report under ./reports).

This is how you turn a completed run into a PDF or a polished, self-contained
shareable HTML file after the fact.`,
	Args: cobra.MaximumNArgs(1),
	Example: `  pentestswarm report                       # newest report in ./reports → PDF
  pentestswarm report ./reports             # newest json in a dir → PDF
  pentestswarm report run.json --format shareable
  pentestswarm report run.json --format pdf --output ./out`,
	RunE: runReportRender,
}

var reportPolishCmd = &cobra.Command{
	Use:   "polish <path-to-draft.md>",
	Short: "Re-run the quality-gate rubric on an edited draft",
	Long: `polish is what you reach for after hand-editing a submission draft
the swarm produced. It re-grades the draft on clarity / impact /
reproducibility and prints actionable suggestions for another pass.

Prints score + suggestions only — the draft file is never modified.
Use it as a 'ready to submit?' check.`,
	Args:    cobra.ExactArgs(1),
	Example: `  pentestswarm report polish ./submissions/sql-injection.md`,
	RunE:    runReportPolish,
}

func runReportPolish(cmd *cobra.Command, args []string) error {
	body, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("read %s: %w", args[0], err)
	}
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	if cfg.Orchestrator.APIKey == "" {
		if k, err := keychain.Get(keychain.KeyClaudeAPI); err == nil {
			cfg.Orchestrator.APIKey = k
		}
	}
	if cfg.Orchestrator.APIKey == "" {
		return fmt.Errorf("no API key configured — run %s first", colorCyan("pentestswarm init"))
	}

	provider, err := prompts.NewProviderWithRetry(cfg.Orchestrator)
	if err != nil {
		return fmt.Errorf("provider: %w", err)
	}

	fmt.Println()
	fmt.Printf("  %s %s\n", colorCyan("[polish]"), args[0])
	fmt.Println()

	r, err := qualitygate.Grade(context.Background(), provider, string(body))
	if err != nil {
		return fmt.Errorf("quality gate: %w", err)
	}
	verdict := colorGreen(fmt.Sprintf("PASS (%.1f/10)", r.OverallScore))
	if !r.Pass() {
		verdict = colorRed(fmt.Sprintf("FAIL (%.1f/10)", r.OverallScore))
	}
	fmt.Printf("  Overall:          %s\n", verdict)
	fmt.Printf("  Clarity:          %.1f/10\n", r.ClarityScore)
	fmt.Printf("  Impact:           %.1f/10\n", r.ImpactScore)
	fmt.Printf("  Reproducibility:  %.1f/10\n", r.ReproducibilityScore)

	if r.BlockingIssue != "" {
		fmt.Println()
		fmt.Println(colorYellow("  Blocking issue: ") + r.BlockingIssue)
	}
	if len(r.Suggestions) > 0 {
		fmt.Println()
		fmt.Println("  Suggestions:")
		for _, s := range r.Suggestions {
			fmt.Printf("    • %s\n", s)
		}
	}

	if r.Pass() {
		fmt.Println()
		fmt.Println(colorGreen("  Ready to submit.") + " Paste the draft into the platform's report form.")
	} else {
		// Non-zero exit so CI / scripts can gate on polish.
		return fmt.Errorf("draft below quality threshold")
	}
	return nil
}

// runReportRender re-renders a saved JSON report to another format.
func runReportRender(cmd *cobra.Command, args []string) error {
	format, _ := cmd.Flags().GetString("format")
	output, _ := cmd.Flags().GetString("output")

	format = strings.ToLower(strings.TrimSpace(format))
	if !isRenderFormat(format) {
		return fmt.Errorf("unknown --format %q (want: md|html|json|pdf|shareable)", format)
	}

	arg := ""
	if len(args) == 1 {
		arg = args[0]
	}
	jsonPath, err := resolveReportJSON(arg)
	if err != nil {
		return err
	}

	rep, err := loadPentestReport(jsonPath)
	if err != nil {
		return fmt.Errorf("load report %s: %w", jsonPath, err)
	}

	// Default the output dir to wherever the source report lives, so a
	// re-render lands next to the original run.
	if output == "" {
		output = filepath.Dir(jsonPath)
	}
	if err := os.MkdirAll(output, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	written, msg, err := writeRenderedReport(rep, format, output, "report")
	if err != nil {
		return err
	}

	fmt.Println()
	fmt.Printf("  %s %s\n", colorCyan("[report]"), jsonPath)
	fmt.Printf("  %s %s\n", colorGreen("wrote"), written)
	if msg != "" {
		fmt.Printf("  %s %s\n", colorYellow("[note]"), msg)
	}
	return nil
}

// isRenderFormat reports whether f is a format the report command can render.
func isRenderFormat(f string) bool {
	switch f {
	case "md", "html", "json", "pdf", "shareable":
		return true
	}
	return false
}

// resolveReportJSON turns the optional path argument into a concrete .json
// report file: a file is used as-is; a directory (or omission → ./reports)
// resolves to the newest *.json inside it.
func resolveReportJSON(arg string) (string, error) {
	if arg == "" {
		arg = "./reports"
	}
	info, err := os.Stat(arg)
	if err != nil {
		return "", fmt.Errorf("no such report path %q: %w", arg, err)
	}
	if !info.IsDir() {
		return arg, nil
	}
	newest, err := newestJSONReport(arg)
	if err != nil {
		return "", err
	}
	return newest, nil
}

// newestJSONReport returns the most recently modified *.json file in dir.
func newestJSONReport(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("read dir %s: %w", dir, err)
	}
	type cand struct {
		path    string
		modTime int64
	}
	var cands []cand
	for _, e := range entries {
		if e.IsDir() || !strings.EqualFold(filepath.Ext(e.Name()), ".json") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		cands = append(cands, cand{path: filepath.Join(dir, e.Name()), modTime: fi.ModTime().UnixNano()})
	}
	if len(cands) == 0 {
		return "", fmt.Errorf("no *.json report found in %s — run a scan first, or pass a report file", dir)
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].modTime > cands[j].modTime })
	return cands[0].path, nil
}

// loadPentestReport reads a saved JSON report into a PentestReport.
func loadPentestReport(path string) (*pipeline.PentestReport, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rep pipeline.PentestReport
	if err := json.Unmarshal(b, &rep); err != nil {
		return nil, fmt.Errorf("parse report json: %w", err)
	}
	return &rep, nil
}

// writeRenderedReport renders rep in the given format and writes it into dir
// under the given base name (extension chosen by format). It returns the path
// written and an optional human note (e.g. the PDF-fallback message).
func writeRenderedReport(rep *pipeline.PentestReport, format, dir, base string) (written, message string, err error) {
	r := report.NewRenderer()
	switch format {
	case "md":
		return writeBytes(r.ToMarkdown, rep, filepath.Join(dir, base+".md"))
	case "html":
		return writeBytes(r.ToHTML, rep, filepath.Join(dir, base+".html"))
	case "json":
		return writeBytes(r.ToJSON, rep, filepath.Join(dir, base+".json"))
	case "shareable":
		return writeBytes(r.ToShareableHTML, rep, filepath.Join(dir, base+"-shareable.html"))
	case "pdf":
		res, err := r.ToPDF(rep, filepath.Join(dir, base+".pdf"))
		if err != nil {
			return "", "", err
		}
		return res.Path, res.Message, nil
	default:
		return "", "", fmt.Errorf("unsupported render format %q", format)
	}
}

// writeBytes runs a renderer function and writes its output to path.
func writeBytes(render func(*pipeline.PentestReport) ([]byte, error), rep *pipeline.PentestReport, path string) (string, string, error) {
	b, err := render(rep)
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return "", "", err
	}
	return path, "", nil
}

func init() {
	reportCmd.AddCommand(reportPolishCmd)
	reportCmd.Flags().StringP("format", "f", "pdf", "output format: md|html|json|pdf|shareable")
	reportCmd.Flags().StringP("output", "o", "", "output directory (default: alongside the source report)")
	rootCmd.AddCommand(reportCmd)
}
