package chains

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultRegistry is the community exploit-chain feed: the GitHub Contents API
// for this repo's chains/ directory. It needs no committed index (it auto-tracks
// whatever chains are in the repo). Commercial/self-hosted feeds point elsewhere
// via --registry or PENTESTSWARM_CHAINS_REGISTRY, and can require an auth token
// (PENTESTSWARM_CHAINS_TOKEN) — that's the hook for the SLA-backed live feed.
const DefaultRegistry = "https://api.github.com/repos/Armur-Ai/Pentest-Swarm-AI/contents/chains"

// remoteEntry is one file listed by a registry (GitHub Contents API shape).
type remoteEntry struct {
	Name        string `json:"name"`
	DownloadURL string `json:"download_url"`
	Type        string `json:"type"`
}

func httpClient() *http.Client { return &http.Client{Timeout: 30 * time.Second} }

func fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if tok := os.Getenv("PENTESTSWARM_CHAINS_TOKEN"); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry returned status %d for %s", resp.StatusCode, url)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20)) // 4MB cap per file
}

// listRemote returns the chain files a registry offers. It supports two shapes:
// a GitHub Contents API URL (JSON array of entries) or a plain base URL serving
// an index.json (JSON array of "<id>.yaml" names, downloaded as base/<name>).
func listRemote(ctx context.Context, registry string) ([]remoteEntry, error) {
	if strings.Contains(registry, "api.github.com") {
		data, err := fetch(ctx, registry)
		if err != nil {
			return nil, err
		}
		var entries []remoteEntry
		if err := json.Unmarshal(data, &entries); err != nil {
			return nil, fmt.Errorf("registry: bad contents-API response: %w", err)
		}
		return entries, nil
	}
	base := strings.TrimRight(registry, "/")
	data, err := fetch(ctx, base+"/index.json")
	if err != nil {
		return nil, err
	}
	var names []string
	if err := json.Unmarshal(data, &names); err != nil {
		return nil, fmt.Errorf("registry: bad index.json: %w", err)
	}
	entries := make([]remoteEntry, 0, len(names))
	for _, n := range names {
		if !strings.HasSuffix(n, ".yaml") {
			n += ".yaml"
		}
		entries = append(entries, remoteEntry{Name: n, DownloadURL: base + "/" + n})
	}
	return entries, nil
}

// Update fetches every valid chain from the registry into destDir, returning the
// ids written. Invalid or unfetchable files are skipped (best-effort sync).
func Update(ctx context.Context, registry, destDir string) ([]string, error) {
	if registry == "" {
		registry = DefaultRegistry
	}
	entries, err := listRemote(ctx, registry)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return nil, err
	}
	var written []string
	for _, e := range entries {
		if e.DownloadURL == "" || !strings.HasSuffix(e.Name, ".yaml") {
			continue
		}
		data, ferr := fetch(ctx, e.DownloadURL)
		if ferr != nil {
			continue
		}
		if _, perr := parseChain(data, e.Name); perr != nil {
			continue // never write an invalid chain
		}
		if os.WriteFile(filepath.Join(destDir, e.Name), data, 0o644) == nil {
			written = append(written, strings.TrimSuffix(e.Name, ".yaml"))
		}
	}
	return written, nil
}

// Pull fetches a single chain by id from the registry into destDir.
func Pull(ctx context.Context, registry, id, destDir string) error {
	if registry == "" {
		registry = DefaultRegistry
	}
	id = strings.TrimSuffix(id, ".yaml")
	entries, err := listRemote(ctx, registry)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if strings.TrimSuffix(e.Name, ".yaml") != id || e.DownloadURL == "" {
			continue
		}
		data, ferr := fetch(ctx, e.DownloadURL)
		if ferr != nil {
			return ferr
		}
		if _, perr := parseChain(data, e.Name); perr != nil {
			return fmt.Errorf("fetched chain %q is invalid: %w", id, perr)
		}
		if err := os.MkdirAll(destDir, 0o755); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(destDir, e.Name), data, 0o644)
	}
	return fmt.Errorf("exploit chain %q not found in registry", id)
}
