package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/opportunity"
	"github.com/spf13/cobra"
)

var opportunityCmd = &cobra.Command{
	Use:   "opportunity",
	Short: "Discover and filter public bug-bounty opportunities",
	Long: "Reads public platform opportunity metadata only. This command is separate from campaign execution " +
		"and never contacts a program's in-scope assets.",
}

var opportunityDiscoverCmd = &cobra.Command{
	Use:   "discover",
	Short: "Filter HackerOne Campaigns & top-paying opportunities",
	Long: `Renders HackerOne's public "Campaigns & top-paying opportunities" section,
normalizes the visible bounty/competition/response metrics, and applies only
the filters and ordering you request.

By default the command reads only the opportunity page. --enrich also visits
each corresponding public HackerOne program page for total bounties paid,
90-day bounty volume, response-time text, reports resolved, hackers thanked,
and assets in scope.

No program target or in-scope asset is contacted by this command.`,
	Example: `  pentestswarm opportunity discover
  pentestswarm opportunity discover --sort hackers-paid --order asc
  pentestswarm opportunity discover --max-awarded-reporters 100 --min-response-efficiency 90 --min-ceiling-bounty 10000
  pentestswarm opportunity discover --enrich --sort total-paid --order desc
  pentestswarm opportunity discover --json`,
	RunE: runOpportunityDiscover,
}

func runOpportunityDiscover(cmd *cobra.Command, _ []string) error {
	sortBy, _ := cmd.Flags().GetString("sort")
	order, _ := cmd.Flags().GetString("order")
	enrich, _ := cmd.Flags().GetBool("enrich")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	limit, _ := cmd.Flags().GetInt("limit")
	minFloor, _ := cmd.Flags().GetInt64("min-floor-bounty")
	minCeiling, _ := cmd.Flags().GetInt64("min-ceiling-bounty")
	maxReporters, _ := cmd.Flags().GetInt64("max-awarded-reporters")
	maxHackersAlias, _ := cmd.Flags().GetInt64("max-hackers-paid")
	minResponse, _ := cmd.Flags().GetFloat64("min-response-efficiency")
	minTotalPaid, _ := cmd.Flags().GetInt64("min-total-paid")

	if maxHackersAlias >= 0 && (maxReporters < 0 || maxHackersAlias < maxReporters) {
		maxReporters = maxHackersAlias
	}
	// Detail statistics are required to sort or filter on total paid.
	if strings.EqualFold(sortBy, "total-paid") || minTotalPaid >= 0 {
		enrich = true
	}

	items, err := opportunity.DiscoverHackerOneTopPaying(cmd.Context(), opportunity.Options{
		Enrich:  enrich,
		Timeout: timeout,
	})
	if err != nil {
		return err
	}
	items, err = opportunity.FilterAndSort(items, opportunity.Filters{
		MinFloorBountyUSD:       minFloor,
		MinCeilingBountyUSD:     minCeiling,
		MaxAwardedReporters:     maxReporters,
		MinResponseEfficiency:   minResponse,
		MinTotalBountiesPaidUSD: minTotalPaid,
	}, sortBy, order)
	if err != nil {
		return err
	}
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}

	if OutputIsJSON() {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(items)
	}
	renderOpportunityTable(items, enrich, sortBy, order)
	return nil
}

func renderOpportunityTable(items []opportunity.Opportunity, enriched bool, sortBy, order string) {
	fmt.Println()
	fmt.Printf("  %s HackerOne — Campaigns & top-paying opportunities\n", colorCyan("[opportunity]"))
	fmt.Printf("  %s public HackerOne metadata only; no program target traffic\n", colorDim("[zero-target-traffic]"))
	fmt.Printf("  sorted by %s (%s) | %d matching programs\n\n", sortBy, order, len(items))

	if enriched {
		fmt.Printf("  %-25s %-19s %9s %11s %9s %14s\n",
			"PROGRAM", "BOUNTY RANGE", "REPORTS", "REPORTERS", "RESPONSE", "TOTAL PAID")
		fmt.Println(colorDim("  ───────────────────────────────────────────────────────────────────────────────────────────"))
	} else {
		fmt.Printf("  %-25s %-19s %9s %11s %9s\n",
			"PROGRAM", "BOUNTY RANGE", "REPORTS", "REPORTERS", "RESPONSE")
		fmt.Println(colorDim("  ────────────────────────────────────────────────────────────────────────────"))
	}

	for _, item := range items {
		name := truncateCLI(item.Name, 25)
		bounty := formatOpportunityUSD(item.MinBountyUSD) + "–" + formatOpportunityUSD(item.MaxBountyUSD)
		response := fmt.Sprintf("%.0f%%", item.ResponseEfficiencyPercent)
		if enriched {
			total := "-"
			if item.DetailEnriched {
				total = formatOpportunityUSD(item.TotalBountiesPaidUSD)
			}
			fmt.Printf("  %-25s %-19s %9s %11s %9s %14s\n",
				name,
				bounty,
				formatOpportunityInt(item.AwardedReports),
				formatOpportunityInt(item.AwardedReporters),
				response,
				total,
			)
		} else {
			fmt.Printf("  %-25s %-19s %9s %11s %9s\n",
				name,
				bounty,
				formatOpportunityInt(item.AwardedReports),
				formatOpportunityInt(item.AwardedReporters),
				response,
			)
		}
		fmt.Printf("    %s h1:%s\n", colorDim("handle:"), item.Handle)
	}
	fmt.Println()
	fmt.Println(colorDim("  REPORTERS = HackerOne's public 'Number of awarded reporters' metric."))
	if !enriched {
		fmt.Println(colorDim("  Add --enrich to include public program-detail statistics such as total bounties paid."))
	}
	fmt.Println()
}

func formatOpportunityUSD(v int64) string {
	return "$" + formatOpportunityInt(v)
}

func formatOpportunityInt(v int64) string {
	raw := strconv.FormatInt(v, 10)
	if len(raw) <= 3 {
		return raw
	}
	var b strings.Builder
	first := len(raw) % 3
	if first == 0 {
		first = 3
	}
	b.WriteString(raw[:first])
	for i := first; i < len(raw); i += 3 {
		b.WriteByte(',')
		b.WriteString(raw[i : i+3])
	}
	return b.String()
}

func init() {
	opportunityDiscoverCmd.Flags().String("sort", "max-bounty",
		"sort by name|min-bounty|max-bounty|awarded-reports|hackers-paid|response-efficiency|total-paid")
	opportunityDiscoverCmd.Flags().String("order", "desc", "sort direction: asc|desc")
	opportunityDiscoverCmd.Flags().Bool("enrich", false, "visit each public HackerOne program page for richer public statistics")
	opportunityDiscoverCmd.Flags().Duration("timeout", 35*time.Second, "maximum render time per HackerOne page")
	opportunityDiscoverCmd.Flags().Int("limit", 0, "maximum rows after filtering/sorting (0 = all)")
	opportunityDiscoverCmd.Flags().Int64("min-floor-bounty", -1, "require lowest possible bounty to be at least this USD amount")
	opportunityDiscoverCmd.Flags().Int64("min-ceiling-bounty", -1, "require highest possible bounty to be at least this USD amount")
	opportunityDiscoverCmd.Flags().Int64("max-awarded-reporters", -1, "require HackerOne awarded reporters to be at or below this count")
	opportunityDiscoverCmd.Flags().Int64("max-hackers-paid", -1, "alias for --max-awarded-reporters")
	opportunityDiscoverCmd.Flags().Float64("min-response-efficiency", -1, "require response efficiency at or above this percentage")
	opportunityDiscoverCmd.Flags().Int64("min-total-paid", -1, "require total public bounties paid at or above this USD amount (auto-enriches)")

	opportunityCmd.AddCommand(opportunityDiscoverCmd)
	rootCmd.AddCommand(opportunityCmd)
}
