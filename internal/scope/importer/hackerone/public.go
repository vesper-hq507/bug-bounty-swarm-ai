package hackerone

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
	"github.com/chromedp/chromedp"
)

const publicPageTimeout = 45 * time.Second

var publicHandleRE = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

type publicScopeRow struct {
	Identifier string `json:"identifier"`
	AssetType  string `json:"asset_type"`
	InScope    bool   `json:"in_scope"`
	Eligible   bool   `json:"eligible"`
	Instruction string `json:"instruction,omitempty"`
}

func (c *Client) policyPublic(ctx context.Context, slug string) (string, error) {
	if !publicHandleRE.MatchString(slug) {
		return "", fmt.Errorf("invalid HackerOne program handle %q", slug)
	}
	renderer, err := newPublicRenderer(ctx)
	if err != nil {
		return "", err
	}
	defer renderer.Close()

	rawURL := "https://hackerone.com/" + slug + "?type=team"
	var body string
	if err := renderer.waitForText(rawURL, &body, func(text string) bool {
		lower := strings.ToLower(text)
		return strings.Contains(lower, "program rules") ||
			strings.Contains(lower, "terms and conditions") ||
			strings.Contains(lower, "disclosure policy")
	}); err != nil {
		return "", fmt.Errorf("render HackerOne public policy: %w", err)
	}
	return body, nil
}

func (c *Client) importPublic(ctx context.Context, slug string) (*scope.ScopeDefinition, error) {
	if !publicHandleRE.MatchString(slug) {
		return nil, fmt.Errorf("invalid HackerOne program handle %q", slug)
	}
	renderer, err := newPublicRenderer(ctx)
	if err != nil {
		return nil, err
	}
	defer renderer.Close()

	rawURL := "https://hackerone.com/" + slug + "/policy_scopes?type=team"
	var rows []publicScopeRow
	if err := renderer.waitForScopeRows(rawURL, &rows); err != nil {
		return nil, fmt.Errorf("render HackerOne public scope: %w", err)
	}
	if len(rows) == 0 {
		return nil, errors.New("HackerOne public scope page returned no structured rows")
	}
	return mapPublicRows(rows), nil
}

func mapPublicRows(rows []publicScopeRow) *scope.ScopeDefinition {
	def := &scope.ScopeDefinition{}
	for _, row := range rows {
		applyScopeAsset(def, row.Identifier, row.AssetType, row.InScope && row.Eligible, row.Instruction)
		if !row.InScope {
			// Explicit out-of-scope rows must override broader wildcards even
			// though they are not bounty eligible.
			applyScopeAsset(def, row.Identifier, row.AssetType, false, row.Instruction)
		}
	}
	return def
}

type publicRenderer struct {
	ctx    context.Context
	cancel func()
}

func newPublicRenderer(parent context.Context) (*publicRenderer, error) {
	bin := findPublicBrowser()
	if bin == "" {
		return nil, errors.New("no Chromium-family browser found; install Chrome/Chromium or set PENTESTSWARM_BROWSER")
	}
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(bin),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("headless", "new"),
	)
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(parent, opts...)
	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	if err := chromedp.Run(browserCtx); err != nil {
		cancelBrowser()
		cancelAlloc()
		return nil, err
	}
	return &publicRenderer{
		ctx: browserCtx,
		cancel: func() {
			cancelBrowser()
			cancelAlloc()
		},
	}, nil
}

func (r *publicRenderer) Close() {
	if r != nil && r.cancel != nil {
		r.cancel()
	}
}

func (r *publicRenderer) waitForText(rawURL string, out *string, ready func(string) bool) error {
	if err := validatePublicHackerOneURL(rawURL); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(r.ctx, publicPageTimeout)
	defer cancel()
	if err := chromedp.Run(ctx, chromedp.Navigate(rawURL), chromedp.WaitReady("body", chromedp.ByQuery)); err != nil {
		return err
	}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	var last string
	for {
		if err := chromedp.Run(ctx, chromedp.Evaluate(`document.body ? document.body.innerText : ""`, &last)); err == nil {
			if ready == nil || ready(last) {
				*out = last
				return nil
			}
		} else if ctx.Err() == nil {
			return err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("public HackerOne page did not reach expected state before timeout")
		case <-ticker.C:
		}
	}
}

const publicScopeRowsJS = `(() => {
  const norm = (s) => (s || "").replace(/\s+/g, " ").trim();
  const rows = [];
  for (const tr of document.querySelectorAll("table tbody tr")) {
    const cells = Array.from(tr.querySelectorAll("td"));
    if (cells.length < 5) continue;
    const rawLines = (cells[0].innerText || "").split(/\n+/)
      .map((v) => norm(v))
      .filter((v) => v && v !== "Menu" && v !== "MenuMenu");
    const identifier = rawLines[0] || "";
    const assetType = norm(cells[1].innerText);
    const coverage = norm(cells[2].innerText);
    const bounty = norm(cells[4].innerText);
    if (!identifier || !assetType || !/scope/i.test(coverage)) continue;
    rows.push({
      identifier,
      asset_type: assetType,
      in_scope: /^in scope$/i.test(coverage),
      eligible: /eligible/i.test(bounty) && !/ineligible/i.test(bounty),
      instruction: rawLines.slice(1).join(" ")
    });
  }
  return JSON.stringify(rows);
})()`

func (r *publicRenderer) waitForScopeRows(rawURL string, out *[]publicScopeRow) error {
	if err := validatePublicHackerOneURL(rawURL); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(r.ctx, publicPageTimeout)
	defer cancel()
	if err := chromedp.Run(ctx, chromedp.Navigate(rawURL), chromedp.WaitReady("body", chromedp.ByQuery)); err != nil {
		return err
	}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		var raw string
		if err := chromedp.Run(ctx, chromedp.Evaluate(publicScopeRowsJS, &raw)); err == nil {
			var rows []publicScopeRow
			if json.Unmarshal([]byte(raw), &rows) == nil && len(rows) > 0 {
				*out = rows
				return nil
			}
		} else if ctx.Err() == nil {
			return err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("public HackerOne scope rows did not become available before timeout")
		case <-ticker.C:
		}
	}
}

func validatePublicHackerOneURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Hostname(), "hackerone.com") {
		return fmt.Errorf("public HackerOne renderer refuses URL %q", raw)
	}
	return nil
}

func findPublicBrowser() string {
	if env := strings.TrimSpace(os.Getenv("PENTESTSWARM_BROWSER")); env != "" && publicExecutable(env) {
		return env
	}
	for _, candidate := range []string{
		"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/Applications/Chromium.app/Contents/MacOS/Chromium",
	} {
		if publicExecutable(candidate) {
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

func publicExecutable(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Mode()&0o111 != 0
}
