package opportunity

import "testing"

func TestParseHackerOneCard(t *testing.T) {
	raw := `Shopify
Bounty
Retesting, Collaboration
Domain9
Wildcard6
OtherAsset5
SourceCode1
Gold Standard
$500 - $200k
Lowest possible bounty to highest possible bounty.
Number of awarded reports
Number of awarded reports
2k
Number of awarded reporters
Number of awarded reporters
605
52%`

	got, err := ParseHackerOneCard(raw, "https://hackerone.com/shopify?type=team")
	if err != nil {
		t.Fatalf("ParseHackerOneCard() error = %v", err)
	}
	if got.Handle != "shopify" || got.Name != "Shopify" {
		t.Fatalf("identity = %#v", got)
	}
	if got.MinBountyUSD != 500 || got.MaxBountyUSD != 200000 {
		t.Fatalf("bounty range = %d..%d", got.MinBountyUSD, got.MaxBountyUSD)
	}
	if got.AwardedReports != 2000 || got.AwardedReporters != 605 {
		t.Fatalf("awards = reports %d reporters %d", got.AwardedReports, got.AwardedReporters)
	}
	if got.ResponseEfficiencyPercent != 52 {
		t.Fatalf("response efficiency = %v", got.ResponseEfficiencyPercent)
	}
	if !got.Retesting || !got.Collaboration || !got.GoldStandardSafeHarbor {
		t.Fatalf("expected public feature flags, got %#v", got)
	}
}

func TestParseHackerOneCardRejectsNonHackerOne(t *testing.T) {
	_, err := ParseHackerOneCard("$50 - $4k", "https://example.com/eternal?type=team")
	if err == nil {
		t.Fatal("expected non-HackerOne URL to be rejected")
	}
}

func TestFilterAndSort(t *testing.T) {
	items := []Opportunity{
		{Name: "A", MinBountyUSD: 50, MaxBountyUSD: 4000, AwardedReporters: 382, ResponseEfficiencyPercent: 100},
		{Name: "B", MinBountyUSD: 50, MaxBountyUSD: 200000, AwardedReporters: 2, ResponseEfficiencyPercent: 92},
		{Name: "C", MinBountyUSD: 500, MaxBountyUSD: 200000, AwardedReporters: 605, ResponseEfficiencyPercent: 52},
	}
	got, err := FilterAndSort(items, Filters{
		MinCeilingBountyUSD:   10000,
		MaxAwardedReporters:   100,
		MinResponseEfficiency: 90,
	}, "hackers-paid", "asc")
	if err != nil {
		t.Fatalf("FilterAndSort() error = %v", err)
	}
	if len(got) != 1 || got[0].Name != "B" {
		t.Fatalf("got %#v", got)
	}
}

func TestFilterAndSortTotalPaidRequiresEnrichmentForFilter(t *testing.T) {
	items := []Opportunity{
		{Name: "not-enriched", TotalBountiesPaidUSD: 9999999},
		{Name: "enriched", DetailEnriched: true, TotalBountiesPaidUSD: 10000},
	}
	got, err := FilterAndSort(items, Filters{MinTotalBountiesPaidUSD: 1}, "total-paid", "desc")
	if err != nil {
		t.Fatalf("FilterAndSort() error = %v", err)
	}
	if len(got) != 1 || got[0].Name != "enriched" {
		t.Fatalf("got %#v", got)
	}
}

func TestCompactNumbers(t *testing.T) {
	for raw, want := range map[string]int64{
		"1": 1,
		"1k": 1000,
		"4k": 4000,
		"1M": 1000000,
		"200k": 200000,
	} {
		got, err := parseCompactNumber(raw)
		if err != nil || got != want {
			t.Fatalf("parseCompactNumber(%q) = %d, %v; want %d", raw, got, err, want)
		}
	}
}

func TestDetailParsers(t *testing.T) {
	text := normalizeSpace(`
Response efficiency: 52%
4 days, 2 hours
Average time to first response
2 weeks, 4 days
Average time to triage
1 week, 4 days
Average time to bounty
5 months, 3 weeks
Average time to resolution
Total bounties paid $10,080,266
Bounties paid | 90 days $652,538
Reports received | 90 days 1731
Reports resolved 2429
Hackers thanked 1159
Assets In Scope 21
`)
	if got := moneyAfterLabel(text, "Total bounties paid"); got != 10080266 {
		t.Fatalf("total bounties = %d", got)
	}
	if got := integerAfterLabel(text, "Reports resolved"); got != 2429 {
		t.Fatalf("reports resolved = %d", got)
	}
	if got := durationBeforeLabel(text, "Average time to first response"); got != "4 days, 2 hours" {
		t.Fatalf("first response = %q", got)
	}
	if got := durationBeforeLabel(text, "Average time to triage"); got != "2 weeks, 4 days" {
		t.Fatalf("triage = %q", got)
	}
}
