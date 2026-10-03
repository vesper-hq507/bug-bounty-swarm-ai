package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/agent/prompts"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/agent/report"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/agent/report/dedup"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/agent/report/qualitygate"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/bugbounty"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/config"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/evidence"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/keychain"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/llm"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope/importer/hackerone"
	"github.com/spf13/cobra"
)

var submitCmd = &cobra.Command{
	Use:   "submit",
	Short: "Turn a campaign report into platform-specific submission drafts",
	Long: `Reads a campaign report (JSON emitted by 'scan --format json') and
writes one ready-to-paste markdown file per finding, formatted for the
chosen bug-bounty platform.

By default this is a dry-run that writes to ./submissions/<id>.md.
External HackerOne submission is a separate two-step path: first approve
the durable manifest with 'submit approve', then invoke 'submit send'
with an explicit program-handle confirmation. Draft generation never posts.`,
	Example: `  pentestswarm submit --platform h1 --report ./reports/scan.json
  pentestswarm submit --platform bugcrowd --report ./reports/scan.json --program acme
`,
	RunE: runSubmit,
}

var submitApproveCmd = &cobra.Command{
	Use:   "approve <submission-manifest.json>",
	Short: "Explicitly approve a submission-ready local manifest without posting it",
	Args:  cobra.ExactArgs(1),
	RunE:  runSubmitApprove,
}

var submitSendCmd = &cobra.Command{
	Use:   "send <submission-manifest.json>",
	Short: "Send one already-approved manifest to HackerOne",
	Long: "Performs the optional external HackerOne submission step. The manifest must already be " +
		"human-approved, durable evidence is revalidated immediately before sending, and --confirm-program " +
		"must exactly match the manifest program handle. This command never submits unapproved drafts.",
	Args: cobra.ExactArgs(1),
	RunE: runSubmitSend,
}

func runSubmit(cmd *cobra.Command, args []string) error {
	platform, _ := cmd.Flags().GetString("platform")
	reportPath, _ := cmd.Flags().GetString("report")
	outDir, _ := cmd.Flags().GetString("out")
	live, _ := cmd.Flags().GetBool("live")
	program, _ := cmd.Flags().GetString("program")
	stateDir, _ := cmd.Flags().GetString("state-dir")

	if platform == "" {
		return fmt.Errorf("--platform is required (h1 | bugcrowd | intigriti)")
	}
	if reportPath == "" {
		return fmt.Errorf("--report <path-to-report.json> is required")
	}
	if live {
		return fmt.Errorf("--live draft submission is disabled; generate the draft, run 'submit approve', then use 'submit send'")
	}
	if outDir == "" {
		outDir = "./submissions"
	}

	data, err := os.ReadFile(reportPath)
	if err != nil {
		return fmt.Errorf("read report: %w", err)
	}
	var pr pipeline.PentestReport
	if err := json.Unmarshal(data, &pr); err != nil {
		return fmt.Errorf("parse report: %w", err)
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", outDir, err)
	}

	fmt.Println()
	fmt.Printf("  %s %d findings → %s format\n", colorCyan("[submit]"),
		len(pr.Findings), platform)
	if program != "" {
		fmt.Printf("  %s program slug: %s\n", colorCyan("[submit]"), program)
	}

	// Phase 4.4.5: pull the researcher's prior submissions so we can flag
	// duplicate candidates before the draft is pasted into the platform.
	// Best-effort — missing credentials = silent skip, not a failure.
	priors := loadPriors(context.Background(), platform, program)
	if len(priors.Similarity) > 0 {
		fmt.Printf("  %s loaded %d prior submissions for dedup (%d structured fingerprints)\n",
			colorDim("[dedup]"), len(priors.Similarity), priors.structuredCount())
	}

	// Phase 4.4.7: optional quality-gate grader. Only fires when the
	// researcher asked for it AND a tool-use-capable LLM is configured
	// (falls back to 'disabled with warning' otherwise).
	var gate llm.Provider
	if qg, _ := cmd.Flags().GetBool("quality-gate"); qg {
		if cfg, cerr := config.Load(cfgFile); cerr == nil {
			if cfg.Orchestrator.APIKey == "" {
				if k, err := keychain.Get(keychain.KeyClaudeAPI); err == nil {
					cfg.Orchestrator.APIKey = k
				}
			}
			if p, err := prompts.NewProviderWithRetry(cfg.Orchestrator); err == nil {
				gate = p
				fmt.Printf("  %s quality gate on (rubric: clarity / impact / reproducibility)\n",
					colorDim("[qg]"))
			}
		}
		if gate == nil {
			fmt.Printf("  %s --quality-gate set but no LLM provider ready — skipping\n",
				colorYellow("[warn]"))
		}
	}
	fmt.Println()

	evStore, evStoreErr := loadSubmissionEvidenceStore(stateDir)
	if evStoreErr != nil {
		fmt.Printf("  %s durable evidence verification unavailable: %s\n", colorYellow("[evidence]"), evStoreErr)
	}

	written := 0
	for _, rf := range pr.Findings {
		v := report.BuildSubmissionView(rf, nil, nil)
		body, err := report.RenderSubmission(platform, v)
		if err != nil {
			fmt.Printf("  %s %s — %s\n", colorRed("[skip]"), rf.Title, err)
			continue
		}

		// Duplicate annotation: prepend a visible callout when a prior
		// submission looks similar.
		dupeTarget := ""
		if len(rf.AffectedComponents) > 0 {
			dupeTarget = rf.AffectedComponents[0]
		}
		hits := dedup.FindDuplicates(rf.Title, dupeTarget, priors.Similarity, 0.6, 2)
		if len(hits) > 0 {
			var sb strings.Builder
			sb.WriteString("> ⚠ Possible duplicate of:\n")
			for _, h := range hits {
				sb.WriteString(fmt.Sprintf("> - #%s (%s) — %.0f%% title similarity\n",
					h.Prior.ID, h.Prior.State, h.Similarity*100))
			}
			body = append([]byte(sb.String()+"\n"), body...)
			fmt.Printf("  %s %-40s ↔ #%s (%.0f%% match)\n",
				colorYellow("[dupe?]"), truncateCLI(rf.Title, 40),
				hits[0].Prior.ID, hits[0].Similarity*100)
		}

		// Quality gate — runs per-finding so the rubric sees one draft at a time.
		if gate != nil {
			qr, err := qualitygate.Grade(context.Background(), gate, string(body))
			if err == nil && qr != nil {
				if !qr.Pass() {
					var sb strings.Builder
					sb.WriteString(fmt.Sprintf("> 🛑 **Quality gate blocked** — overall %.1f/10\n", qr.OverallScore))
					if qr.BlockingIssue != "" {
						sb.WriteString("> " + qr.BlockingIssue + "\n")
					}
					sb.WriteString("> Polish:\n")
					for _, s := range qr.Suggestions {
						sb.WriteString("> - " + s + "\n")
					}
					body = append([]byte(sb.String()+"\n"), body...)
					fmt.Printf("  %s %-40s  %.1f/10\n", colorRed("[block]"), truncateCLI(rf.Title, 40), qr.OverallScore)
				} else {
					fmt.Printf("  %s %-40s  %.1f/10\n", colorGreen("[pass]"), truncateCLI(rf.Title, 40), qr.OverallScore)
				}
			}
		}

		fname := filepath.Join(outDir, sanitiseFilename(rf.Title)+".md")
		if err := os.WriteFile(fname, body, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", fname, err)
		}

		pkg := bugbounty.PrepareVerifiedSubmission(program, rf, priors.Structured, evStore)
		manifestName := fname + ".submission.json"
		manifest, err := json.MarshalIndent(pkg, "", "  ")
		if err != nil {
			return fmt.Errorf("encode submission manifest: %w", err)
		}
		manifest = append(manifest, '\n')
		if err := os.WriteFile(manifestName, manifest, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", manifestName, err)
		}

		fmt.Printf("  %s %-50s → %s\n", colorGreen("[draft]"), truncateCLI(rf.Title, 50), colorCyan(fname))
		fmt.Printf("  %s state=%s duplicate-confidence=%.0f%% manifest=%s\n",
			colorDim("[manifest]"), pkg.State, pkg.Duplicate.Confidence*100, colorCyan(manifestName))
		written++
	}
	fmt.Println()
	fmt.Printf("  Wrote %d submission drafts to %s\n", written, colorCyan(outDir))
	fmt.Println(colorDim("  Review each draft, then paste into the platform's submission form."))
	fmt.Println(colorDim("  (--live will post via the platform API in a future release.)"))
	return nil
}

// loadPriors pulls past submissions to compare against. Two sources:
//
//  1. The researcher's OWN reports (any program) — needs API creds.
//     Catches "I already filed this last week."
//  2. The program's PUBLIC disclosed reports (4.4.6) — works without
//     creds. Catches "this is already disclosed; would file as duplicate."
//
// Missing credentials degrade to public-only; fully empty list when
// neither source returns anything. Dedup is an enhancement, never a
// hard block on submit.
type priorCorpus struct {
	Similarity []dedup.Prior
	Structured []bugbounty.Submission
	seen       map[string]struct{}
}

func (p *priorCorpus) add(prefix string, r *hackerone.Report) {
	if p == nil || r == nil || r.ID == "" {
		return
	}
	if p.seen == nil {
		p.seen = map[string]struct{}{}
	}
	if _, ok := p.seen[r.ID]; ok {
		return
	}
	p.seen[r.ID] = struct{}{}

	p.Similarity = append(p.Similarity, dedup.Prior{
		ID: prefix + ":" + r.ID, Title: r.Title, Target: r.AssetIdentifier, State: r.State,
	})

	fp := bugbounty.FingerprintHistoricalReport(bugbounty.HistoricalReportFingerprintInput{
		Program: r.Program,
		Title: r.Title,
		VulnerabilityInformation: r.VulnerabilityInformation,
		WeaknessName: r.WeaknessName,
		WeaknessExternalID: r.WeaknessExternalID,
		AssetIdentifier: r.AssetIdentifier,
	})
	sub := bugbounty.Submission{
		ID: prefix + ":" + r.ID,
		Title: r.Title,
		State: r.State,
		Severity: r.Severity,
		SubmittedAt: r.CreatedAt,
	}
	if bugbounty.HistoricalFingerprintInformative(fp) {
		sub.Fingerprint = &fp
	}
	p.Structured = append(p.Structured, sub)
}

func (p priorCorpus) structuredCount() int {
	count := 0
	for i := range p.Structured {
		if p.Structured[i].Fingerprint != nil {
			count++
		}
	}
	return count
}

// loadPriors pulls past submissions to compare against. Rich owned report
// metadata is preferred; public history fills gaps. Missing credentials remain
// a best-effort degradation rather than blocking local report preparation.
func loadPriors(ctx context.Context, platform, program string) priorCorpus {
	var corpus priorCorpus
	if strings.ToLower(platform) != "h1" && strings.ToLower(platform) != "hackerone" {
		return corpus
	}

	user, token := resolveHackerOneCredentials()
	client := hackerone.NewClient(hackerone.Config{APIUser: user, APIToken: token})

	if user != "" && token != "" {
		if reports, err := client.Reports(ctx, 300); err == nil {
			for i := range reports {
				r := &reports[i]
				if program != "" && !strings.EqualFold(r.Program, program) {
					continue
				}
				corpus.add("own", r)
			}
		}
	}

	if program != "" {
		if reports, err := client.PublicReports(ctx, program, 300); err == nil {
			for i := range reports {
				corpus.add("public", &reports[i])
			}
		}
	}
	return corpus
}

func runSubmitApprove(cmd *cobra.Command, args []string) error {
	path := args[0]
	by, _ := cmd.Flags().GetString("by")
	duplicateReviewed, _ := cmd.Flags().GetBool("duplicate-reviewed")
	stateDir, _ := cmd.Flags().GetString("state-dir")

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read submission manifest: %w", err)
	}
	var pkg bugbounty.SubmissionPackage
	if err := json.Unmarshal(data, &pkg); err != nil {
		return fmt.Errorf("parse submission manifest: %w", err)
	}
	if duplicateReviewed {
		pkg.MarkDuplicateReviewed()
	}
	evStore, err := loadSubmissionEvidenceStore(stateDir)
	if err != nil {
		return fmt.Errorf("open durable evidence store: %w", err)
	}
	if err := pkg.ApproveVerified(by, evStore); err != nil {
		return err
	}

	updated, err := json.MarshalIndent(pkg, "", "  ")
	if err != nil {
		return fmt.Errorf("encode approved manifest: %w", err)
	}
	updated = append(updated, '\n')
	if err := os.WriteFile(path, updated, 0o600); err != nil {
		return fmt.Errorf("write approved manifest: %w", err)
	}

	fmt.Printf("  %s approved locally by %s; no external submission was performed\n",
		colorGreen("[approved]"), by)
	return nil
}

func runSubmitSend(cmd *cobra.Command, args []string) error {
	path := args[0]
	stateDir, _ := cmd.Flags().GetString("state-dir")
	confirmProgram, _ := cmd.Flags().GetString("confirm-program")
	weaknessID, _ := cmd.Flags().GetInt64("weakness-id")
	structuredScopeID, _ := cmd.Flags().GetInt64("structured-scope-id")

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read submission manifest: %w", err)
	}
	var pkg bugbounty.SubmissionPackage
	if err := json.Unmarshal(data, &pkg); err != nil {
		return fmt.Errorf("parse submission manifest: %w", err)
	}
	if pkg.Submission != nil {
		return fmt.Errorf("submission manifest already records external report %q", pkg.Submission.ExternalID)
	}
	if pkg.State == bugbounty.StateSubmitted {
		return fmt.Errorf("submission manifest is already in submitted state")
	}
	if strings.TrimSpace(pkg.Program) == "" {
		return fmt.Errorf("submission manifest has no HackerOne program handle")
	}
	if !strings.EqualFold(strings.TrimSpace(confirmProgram), strings.TrimSpace(pkg.Program)) {
		return fmt.Errorf("--confirm-program must match manifest program %q", pkg.Program)
	}

	evStore, err := loadSubmissionEvidenceStore(stateDir)
	if err != nil {
		return fmt.Errorf("open durable evidence store: %w", err)
	}
	pkg.ValidateEvidence(evStore)
	if !pkg.CanSubmit() {
		switch {
		case !pkg.EvidenceVerified:
			return fmt.Errorf("submission evidence failed send-time verification: %s", strings.Join(pkg.EvidenceIssues, "; "))
		case !pkg.Approval.Approved:
			return fmt.Errorf("submission manifest is not currently human-approved; run 'submit approve' after resolving any evidence/duplicate issues")
		default:
			return fmt.Errorf("submission manifest state %q is not eligible for external submission", pkg.State)
		}
	}

	user, token := resolveHackerOneCredentials()
	if strings.TrimSpace(user) == "" || strings.TrimSpace(token) == "" {
		return fmt.Errorf("HackerOne API credentials are required via HACKERONE_API_USER/HACKERONE_API_TOKEN or the configured keychain token")
	}
	client := hackerone.NewClient(hackerone.Config{APIUser: user, APIToken: token})
	created, err := client.CreateReport(cmd.Context(), hackerone.CreateReportInput{
		TeamHandle:               pkg.Program,
		Title:                    pkg.Report.Title,
		VulnerabilityInformation: hackerOneSubmissionInformation(pkg.Report),
		Impact:                   pkg.Report.Impact,
		SeverityRating:           pkg.Report.SeverityRating,
		WeaknessID:               weaknessID,
		StructuredScopeID:        structuredScopeID,
	})
	if err != nil {
		return err
	}
	if err := pkg.MarkSubmitted("hackerone", created.ID); err != nil {
		return fmt.Errorf("record HackerOne submission receipt: %w", err)
	}
	updated, err := json.MarshalIndent(pkg, "", "  ")
	if err != nil {
		return fmt.Errorf("encode submitted manifest: %w", err)
	}
	updated = append(updated, '\n')
	if err := os.WriteFile(path, updated, 0o600); err != nil {
		return fmt.Errorf("write submitted manifest: %w", err)
	}
	fmt.Printf("  %s HackerOne report %s submitted for program %s\n",
		colorGreen("[submitted]"), created.ID, pkg.Program)
	fmt.Printf("  %s manifest updated with immutable local submission receipt\n", colorDim("[receipt]"))
	return nil
}

func hackerOneSubmissionInformation(h1Report bugbounty.HackerOneReport) string {
	parts := make([]string, 0, 3)
	if v := strings.TrimSpace(h1Report.VulnerabilityInformation); v != "" {
		parts = append(parts, v)
	}
	if v := strings.TrimSpace(h1Report.ProofOfConcept); v != "" {
		parts = append(parts, v)
	}
	if v := strings.TrimSpace(h1Report.RecommendedFix); v != "" {
		parts = append(parts, "## Recommended Fix\n\n"+v)
	}
	return strings.Join(parts, "\n\n")
}

func resolveHackerOneCredentials() (user, token string) {
	user = strings.TrimSpace(os.Getenv("HACKERONE_API_USER"))
	token = strings.TrimSpace(os.Getenv("HACKERONE_API_TOKEN"))
	if token == "" {
		if v, err := keychain.Get(keychain.KeyHackerOneToken); err == nil {
			token = strings.TrimSpace(v)
		}
	}
	return user, token
}

func loadSubmissionEvidenceStore(stateDir string) (evidence.Store, error) {
	stateDir = strings.TrimSpace(stateDir)
	if stateDir == "" {
		return nil, fmt.Errorf("state directory is required")
	}
	root := filepath.Join(stateDir, "evidence")
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", root, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", root)
	}
	store, err := evidence.NewFileStore(root)
	if err != nil {
		return nil, err
	}
	return store, nil
}

func sanitiseFilename(s string) string {
	out := make([]byte, 0, len(s))
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			out = append(out, byte(r))
		case r == ' ', r == '-', r == '_':
			out = append(out, '-')
		}
	}
	// Trim trailing hyphens and cap length.
	s2 := strings.Trim(string(out), "-")
	if len(s2) > 60 {
		s2 = s2[:60]
	}
	if s2 == "" {
		s2 = "finding"
	}
	return s2
}

func truncateCLI(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func init() {
	submitCmd.Flags().String("platform", "", "target platform: h1 | bugcrowd | intigriti")
	submitCmd.Flags().String("report", "", "path to the scan's JSON report")
	submitCmd.Flags().String("out", "./submissions", "directory to write submission drafts into")
	submitCmd.Flags().String("program", "", "program slug (only used by --live, not dry-run)")
	submitCmd.Flags().Bool("live", false, "deprecated safety flag; use 'submit approve' then 'submit send' for HackerOne")
	submitCmd.Flags().Bool("quality-gate", false, "run each draft through an LLM rubric and block drafts scoring below 6/10")
	submitCmd.Flags().String("state-dir", ".pentestswarm/state", "campaign state directory containing durable evidence")
	submitApproveCmd.Flags().String("by", "", "human approver name or alias")
	submitApproveCmd.Flags().Bool("duplicate-reviewed", false, "confirm that any duplicate warning was reviewed")
	submitApproveCmd.Flags().String("state-dir", ".pentestswarm/state", "campaign state directory containing durable evidence")
	_ = submitApproveCmd.MarkFlagRequired("by")
	submitSendCmd.Flags().String("state-dir", ".pentestswarm/state", "campaign state directory containing durable evidence")
	submitSendCmd.Flags().String("confirm-program", "", "required explicit confirmation; must match the manifest HackerOne program handle")
	submitSendCmd.Flags().Int64("weakness-id", 0, "optional HackerOne weakness ID")
	submitSendCmd.Flags().Int64("structured-scope-id", 0, "optional HackerOne structured-scope ID")
	_ = submitSendCmd.MarkFlagRequired("confirm-program")
	submitCmd.AddCommand(submitApproveCmd, submitSendCmd)
	rootCmd.AddCommand(submitCmd)
}
