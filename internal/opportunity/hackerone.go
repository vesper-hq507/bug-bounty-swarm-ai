package opportunity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/session"
	"github.com/chromedp/chromedp"
)

const (
	hackerOneOpportunitiesURL = "https://hackerone.com/opportunities/all"
	defaultPageTimeout        = 35 * time.Second
)

// Opportunity is a normalized public HackerOne opportunity card plus optional
// public program-detail statistics. Discovery only contacts hackerone.com; it
// never sends traffic to a program's in-scope assets.
type Opportunity struct {
	Name                       string  `json:"name"`
	Handle                     string  `json:"handle"`
	URL                        string  `json:"url"`
	SourceSection              string  `json:"source_section"`
	MinBountyUSD               int64   `json:"min_bounty_usd"`
	MaxBountyUSD               int64   `json:"max_bounty_usd"`
	AwardedReports             int64   `json:"awarded_reports"`
	AwardedReporters           int64   `json:"awarded_reporters"`
	ResponseEfficiencyPercent  float64 `json:"response_efficiency_percent"`
	TriagedByHackerOne         bool    `json:"triaged_by_hackerone"`
	Retesting                  bool    `json:"retesting"`
	Collaboration              bool    `json:"collaboration"`
	GoldStandardSafeHarbor     bool    `json:"gold_standard_safe_harbor"`
	Updated                    bool    `json:"updated"`
	DetailEnriched             bool    `json:"detail_enriched"`
	TotalBountiesPaidUSD       int64   `json:"total_bounties_paid_usd,omitempty"`
	BountiesPaid90DaysUSD      int64   `json:"bounties_paid_90_days_usd,omitempty"`
	ReportsReceived90Days      int64   `json:"reports_received_90_days,omitempty"`
	ReportsResolved            int64   `json:"reports_resolved,omitempty"`
	HackersThanked             int64   `json:"hackers_thanked,omitempty"`
	AssetsInScope              int64   `json:"assets_in_scope,omitempty"`
	AverageTimeFirstResponse   string  `json:"average_time_first_response,omitempty"`
	AverageTimeTriage          string  `json:"average_time_triage,omitempty"`
	AverageTimeBounty          string  `json:"average_time_bounty,omitempty"`
	AverageTimeResolution      string  `json:"average_time_resolution,omitempty"`
}

// Options controls discovery. Enrichment visits only the public HackerOne
// program page associated with each card.
type Options struct {
	Enrich  bool
	Timeout time.Duration
}

// Filters are deterministic post-discovery filters. A negative value means
// "not set".
type Filters struct {
	MinFloorBountyUSD          int64
	MinCeilingBountyUSD        int64
	MaxAwardedReporters        int64
	MinResponseEfficiency      float64
	MinTotalBountiesPaidUSD    int64
}

// BrowserUnavailableError makes the remediation path explicit without falling
// back to an unguarded or target-facing crawler.
var ErrBrowserUnavailable = errors.New("no Chromium-family browser found; install Chrome/Chromium or set PENTESTSWARM_BROWSER")

type cardRecord struct {
	URL  string `json:"url"`
	Text string `json:"text"`
}

var (
	bountyRangeRE = regexp.MustCompile(`(?i)\$([0-9][0-9,.]*\s*[kmb]?)\s*[-–—]\s*\$([0-9][0-9,.]*\s*[kmb]?)`)
	percentRE     = regexp.MustCompile(`(\\d+(?:\\.\\d+)?)\\s*%`)
	handleRE      = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

const topPayingCardsJS = `(() => {
  const norm = (s) => (s || "").replace(/\s+/g, " ").trim();
  const exact = (label) => Array.from(document.querySelectorAll("body *"))
    .filter((el) => norm(el.textContent) === label)
    .sort((a, b) => a.children.length - b.children.length)[0] || null;
  const start = exact("Campaigns & top-paying opportunities");
  if (!start) return JSON.stringify({ error: "top-paying section not found", cards: [] });
  const end = exact("Collaboration Opportunities");
  const follows = (a, b) => !!(a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING);
  const links = Array.from(document.querySelectorAll('a[href*="?type=team"]'));
  const seen = new Set();
  const cards = [];
  for (const link of links) {
    if (!follows(start, link)) continue;
    if (end && !follows(link, end)) continue;
    const href = link.href || "";
    if (!href.startsWith("https://hackerone.com/") || seen.has(href)) continue;
    let node = link;
    let card = null;
    for (let i = 0; i < 12 && node; i++, node = node.parentElement) {
      const text = norm(node.innerText || "");
      if (text.includes("Lowest possible bounty") &&
          text.includes("Number of awarded reports") &&
          text.includes("Number of awarded reporters")) {
        card = node;
        break;
      }
    }
    if (!card) continue;
    seen.add(href);
    cards.push({ url: href, text: card.innerText || "" });
  }
  return JSON.stringify({ cards });
})()`

type cardsEnvelope struct {
	Error string       `json:"error,omitempty"`
	Cards []cardRecord `json:"cards"`
}

// DiscoverHackerOneTopPaying reads the public "Campaigns & top-paying
// opportunities" section. It is intentionally hard-coded to HackerOne public
// pages so this discovery path cannot be repurposed to bypass campaign policy.
func DiscoverHackerOneTopPaying(ctx context.Context, opts Options) ([]Opportunity, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = defaultPageTimeout
	}
	renderer, err := newHackerOneRenderer(ctx)
	if err != nil {
		return nil, err
	}
	defer renderer.Close()

	var raw string
	if err := renderer.Evaluate(hackerOneOpportunitiesURL, topPayingCardsJS, &raw, opts.Timeout); err != nil {
		return nil, fmt.Errorf("render HackerOne opportunities: %w", err)
	}
	var envelope cardsEnvelope
	if err := json.Unmarshal([]byte(raw), &envelope); err != nil {
		return nil, fmt.Errorf("parse HackerOne opportunity cards: %w", err)
	}
	if envelope.Error != "" {
		return nil, errors.New(envelope.Error)
	}
	if len(envelope.Cards) == 0 {
		return nil, errors.New("HackerOne returned no cards in Campaigns & top-paying opportunities")
	}

	out := make([]Opportunity, 0, len(envelope.Cards))
	seen := map[string]struct{}{}
	for _, card := range envelope.Cards {
		item, err := ParseHackerOneCard(card.Text, card.URL)
		if err != nil {
			continue
		}
		if _, ok := seen[item.Handle]; ok {
			continue
		}
		seen[item.Handle] = struct{}{}
		if opts.Enrich {
			if err := enrichHackerOneProgram(renderer, &item, opts.Timeout); err != nil {
				// Card-level discovery remains useful when a single detail page
				// changes shape. Keep the row and mark it as not enriched.
				item.DetailEnriched = false
			}
		}
		out = append(out, item)
	}
	if len(out) == 0 {
		return nil, errors.New("HackerOne opportunity cards were found but none could be normalized")
	}
	return out, nil
}

// ParseHackerOneCard normalizes one rendered card. It is exported for fixture
// tests and does no network I/O.
func ParseHackerOneCard(raw, rawURL string) (Opportunity, error) {
	u, err := url.Parse(rawURL)
	if err != nil || !strings.EqualFold(u.Hostname(), "hackerone.com") {
		return Opportunity{}, fmt.Errorf("invalid HackerOne card URL %q", rawURL)
	}
	handle := strings.Trim(strings.TrimSpace(u.Path), "/")
	if !handleRE.MatchString(handle) {
		return Opportunity{}, fmt.Errorf("invalid HackerOne handle %q", handle)
	}

	name := ""
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			name = line
			break
		}
	}
	if name == "" {
		name = handle
	}

	text := normalizeSpace(raw)
	rangeMatch := bountyRangeRE.FindStringSubmatch(text)
	if len(rangeMatch) != 3 {
		return Opportunity{}, fmt.Errorf("no bounty range found for %s", handle)
	}
	minBounty, err := parseCompactNumber(rangeMatch[1])
	if err != nil {
		return Opportunity{}, err
	}
	maxBounty, err := parseCompactNumber(rangeMatch[2])
	if err != nil {
		return Opportunity{}, err
	}

	item := Opportunity{
		Name:                      name,
		Handle:                    handle,
		URL:                       "https://hackerone.com/" + handle + "?type=team",
		SourceSection:             "Campaigns & top-paying opportunities",
		MinBountyUSD:              minBounty,
		MaxBountyUSD:              maxBounty,
		AwardedReports:            metricAfterLabel(text, "Number of awarded reports"),
		AwardedReporters:          metricAfterLabel(text, "Number of awarded reporters"),
		TriagedByHackerOne:        strings.Contains(text, "Triaged by HackerOne"),
		Retesting:                 strings.Contains(text, "Retesting"),
		Collaboration:             strings.Contains(text, "Collaboration"),
		GoldStandardSafeHarbor:    strings.Contains(text, "Gold Standard"),
		Updated:                   strings.Contains(text, " Updated ") || strings.HasPrefix(text, "Updated "),
	}
	allPercents := percentRE.FindAllStringSubmatch(text, -1)
	if len(allPercents) > 0 {
		item.ResponseEfficiencyPercent, _ = strconv.ParseFloat(allPercents[len(allPercents)-1][1], 64)
	}
	return item, nil
}

func enrichHackerOneProgram(renderer *h1Renderer, item *Opportunity, timeout time.Duration) error {
	if item == nil || !handleRE.MatchString(item.Handle) {
		return errors.New("invalid HackerOne opportunity handle")
	}
	publicURL := "https://hackerone.com/" + item.Handle + "?type=team"
	var body string
	if err := renderer.Evaluate(publicURL, `document.body ? document.body.innerText : ""`, &body, timeout); err != nil {
		return err
	}
	text := normalizeSpace(body)
	item.TotalBountiesPaidUSD = moneyAfterLabel(text, "Total bounties paid")
	item.BountiesPaid90DaysUSD = moneyAfterLabel(text, "Bounties paid | 90 days")
	item.ReportsReceived90Days = integerAfterLabel(text, "Reports received | 90 days")
	item.ReportsResolved = integerAfterLabel(text, "Reports resolved")
	item.HackersThanked = integerAfterLabel(text, "Hackers thanked")
	item.AssetsInScope = integerAfterLabel(text, "Assets In Scope")
	if v := floatAfterPattern(text, `(?i)Response efficiency:\s*([0-9]+(?:\.[0-9]+)?)\s*%`); v >= 0 {
		item.ResponseEfficiencyPercent = v
	}
	item.AverageTimeFirstResponse = durationBeforeLabel(text, "Average time to first response")
	item.AverageTimeTriage = durationBeforeLabel(text, "Average time to triage")
	item.AverageTimeBounty = durationBeforeLabel(text, "Average time to bounty")
	item.AverageTimeResolution = durationBeforeLabel(text, "Average time to resolution")
	item.DetailEnriched = true
	return nil
}

// FilterAndSort applies user-selected factual filters and sorting. It never
// assigns a "best" score; the operator chooses the criteria and direction.
func FilterAndSort(items []Opportunity, filters Filters, sortBy, order string) ([]Opportunity, error) {
	sortBy = strings.ToLower(strings.TrimSpace(sortBy))
	order = strings.ToLower(strings.TrimSpace(order))
	if sortBy == "" {
		sortBy = "max-bounty"
	}
	if order == "" {
		order = "desc"
	}
	validSort := map[string]bool{
		"name": true, "min-bounty": true, "max-bounty": true,
		"awarded-reports": true, "hackers-paid": true,
		"response-efficiency": true, "total-paid": true,
	}
	if !validSort[sortBy] {
		return nil, fmt.Errorf("unknown sort %q", sortBy)
	}
	if order != "asc" && order != "desc" {
		return nil, fmt.Errorf("unknown order %q (want asc or desc)", order)
	}

	out := make([]Opportunity, 0, len(items))
	for i := range items {
		item := &items[i]
		if filters.MinFloorBountyUSD > 0 && item.MinBountyUSD < filters.MinFloorBountyUSD {
			continue
		}
		if filters.MinCeilingBountyUSD > 0 && item.MaxBountyUSD < filters.MinCeilingBountyUSD {
			continue
		}
		if filters.MaxAwardedReporters > 0 && item.AwardedReporters > filters.MaxAwardedReporters {
			continue
		}
		if filters.MinResponseEfficiency > 0 && item.ResponseEfficiencyPercent < filters.MinResponseEfficiency {
			continue
		}
		if filters.MinTotalBountiesPaidUSD > 0 &&
			(!item.DetailEnriched || item.TotalBountiesPaidUSD < filters.MinTotalBountiesPaidUSD) {
			continue
		}
		out = append(out, *item)
	}

	lessAsc := func(a, b Opportunity) bool {
		switch sortBy {
		case "name":
			return strings.ToLower(a.Name) < strings.ToLower(b.Name)
		case "min-bounty":
			return a.MinBountyUSD < b.MinBountyUSD
		case "max-bounty":
			return a.MaxBountyUSD < b.MaxBountyUSD
		case "awarded-reports":
			return a.AwardedReports < b.AwardedReports
		case "hackers-paid":
			return a.AwardedReporters < b.AwardedReporters
		case "response-efficiency":
			return a.ResponseEfficiencyPercent < b.ResponseEfficiencyPercent
		case "total-paid":
			return a.TotalBountiesPaidUSD < b.TotalBountiesPaidUSD
		default:
			return false
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if equalForSort(out[i], out[j], sortBy) {
			return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
		}
		if order == "asc" {
			return lessAsc(out[i], out[j])
		}
		return lessAsc(out[j], out[i])
	})
	return out, nil
}

func equalForSort(a, b Opportunity, sortBy string) bool {
	switch sortBy {
	case "name":
		return strings.EqualFold(a.Name, b.Name)
	case "min-bounty":
		return a.MinBountyUSD == b.MinBountyUSD
	case "max-bounty":
		return a.MaxBountyUSD == b.MaxBountyUSD
	case "awarded-reports":
		return a.AwardedReports == b.AwardedReports
	case "hackers-paid":
		return a.AwardedReporters == b.AwardedReporters
	case "response-efficiency":
		return a.ResponseEfficiencyPercent == b.ResponseEfficiencyPercent
	case "total-paid":
		return a.TotalBountiesPaidUSD == b.TotalBountiesPaidUSD
	}
	return false
}

func normalizeSpace(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(s, "\u00a0", " ")), " ")
}

func metricAfterLabel(text, label string) int64 {
	q := regexp.QuoteMeta(label)
	re := regexp.MustCompile(`(?i)` + q + `\s*(?:` + q + `\s*)?([0-9][0-9,.]*\s*[kmb]?)`)
	m := re.FindStringSubmatch(text)
	if len(m) != 2 {
		return 0
	}
	n, _ := parseCompactNumber(m[1])
	return n
}

func moneyAfterLabel(text, label string) int64 {
	re := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(label) + `\s*\$([0-9][0-9,.]*\s*[kmb]?)`)
	m := re.FindStringSubmatch(text)
	if len(m) != 2 {
		return 0
	}
	n, _ := parseCompactNumber(m[1])
	return n
}

func integerAfterLabel(text, label string) int64 {
	re := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(label) + `\s*([0-9][0-9,]*)`)
	m := re.FindStringSubmatch(text)
	if len(m) != 2 {
		return 0
	}
	n, _ := strconv.ParseInt(strings.ReplaceAll(m[1], ",", ""), 10, 64)
	return n
}

func durationBeforeLabel(text, label string) string {
	unit := `(?:hours?|days?|weeks?|months?)`
	re := regexp.MustCompile(`(?i)([0-9]+\s+` + unit + `(?:,\s*[0-9]+\s+` + unit + `)?)\s+` + regexp.QuoteMeta(label))
	m := re.FindStringSubmatch(text)
	if len(m) != 2 {
		return ""
	}
	return m[1]
}

func floatAfterPattern(text, pattern string) float64 {
	re := regexp.MustCompile(pattern)
	m := re.FindStringSubmatch(text)
	if len(m) != 2 {
		return -1
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return -1
	}
	return v
}

func parseCompactNumber(raw string) (int64, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.ReplaceAll(s, ",", "")
	s = strings.ReplaceAll(s, " ", "")
	mult := float64(1)
	if s != "" {
		switch s[len(s)-1] {
		case 'k':
			mult, s = 1_000, s[:len(s)-1]
		case 'm':
			mult, s = 1_000_000, s[:len(s)-1]
		case 'b':
			mult, s = 1_000_000_000, s[:len(s)-1]
		}
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("parse compact number %q: %w", raw, err)
	}
	return int64(math.Round(v * mult)), nil
}

type h1Renderer struct {
	ctx    context.Context
	cancel func()
}

func newHackerOneRenderer(parent context.Context) (*h1Renderer, error) {
	bin := findH1Browser()
	if bin == "" {
		return nil, ErrBrowserUnavailable
	}
	ua := session.BrowserHeaders()["User-Agent"]
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(bin),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("headless", "new"),
		chromedp.UserAgent(ua),
	)
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(parent, opts...)
	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	if err := chromedp.Run(browserCtx); err != nil {
		cancelBrowser()
		cancelAlloc()
		return nil, err
	}
	return &h1Renderer{
		ctx: browserCtx,
		cancel: func() {
			cancelBrowser()
			cancelAlloc()
		},
	}, nil
}

func (r *h1Renderer) Close() {
	if r != nil && r.cancel != nil {
		r.cancel()
	}
}

func (r *h1Renderer) Evaluate(rawURL, expression string, out *string, timeout time.Duration) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Hostname(), "hackerone.com") {
		return fmt.Errorf("public opportunity renderer refuses non-HackerOne URL %q", rawURL)
	}
	if timeout <= 0 {
		timeout = defaultPageTimeout
	}
	ctx, cancel := context.WithTimeout(r.ctx, timeout)
	defer cancel()
	return chromedp.Run(ctx,
		chromedp.Navigate(rawURL),
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.Sleep(1500*time.Millisecond),
		chromedp.Evaluate(expression, out),
	)
}

func findH1Browser() string {
	if env := strings.TrimSpace(os.Getenv("PENTESTSWARM_BROWSER")); env != "" && isExecutable(env) {
		return env
	}
	candidates := []string{
		"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/Applications/Chromium.app/Contents/MacOS/Chromium",
	}
	for _, candidate := range candidates {
		if isExecutable(candidate) {
			return candidate
		}
	}
	for _, name := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "brave-browser", "chrome"} {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	return ""
}

func isExecutable(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Mode()&0o111 != 0
}
