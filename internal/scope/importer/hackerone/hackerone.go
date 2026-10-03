// Package hackerone imports scope from HackerOne programs.
//
// HackerOne exposes structured_scopes per program through its API:
//
//	GET https://api.hackerone.com/v1/hackers/programs/<slug>/structured_scopes
//
// HackerOne's Hacker API requires authentication. For public programs, this
// client falls back to the rendered public program pages when no API
// credentials are configured and the official API returns 401.
//
// The asset_type field drives how we slot each scope item into our
// scope.ScopeDefinition:
//
//	URL / WILDCARD / DOMAIN → AllowedDomains
//	CIDR                    → AllowedCIDRs
//	IP                      → AllowedCIDRs (as /32)
//	SourceCode              → AllowedSourceCode
//	Anything else           → ignored (not yet represented by our scope model)
package hackerone

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// Client is a thin HackerOne API client.
type Client struct {
	http     *http.Client
	baseURL  string
	apiUser  string
	apiToken string
}

// Config customises a Client.
type Config struct {
	APIUser  string        // your HackerOne username
	APIToken string        // API token from hackerone.com/users/api_tokens
	Timeout  time.Duration // default 30s
}

// NewClient builds a client. Leave API credentials empty for public programs.
func NewClient(cfg Config) *Client {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	return &Client{
		http:     &http.Client{Timeout: cfg.Timeout},
		baseURL:  "https://api.hackerone.com/v1",
		apiUser:  cfg.APIUser,
		apiToken: cfg.APIToken,
	}
}

// Platform implements importer.Importer.
func (c *Client) Platform() string { return "h1" }

// Import pulls structured_scopes for the given program and returns them
// as a scope.ScopeDefinition.
func (c *Client) Import(ctx context.Context, slug string) (*scope.ScopeDefinition, error) {
	url := fmt.Sprintf("%s/hackers/programs/%s/structured_scopes", c.baseURL, slug)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if c.apiUser != "" && c.apiToken != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(c.apiUser + ":" + c.apiToken))
		req.Header.Set("Authorization", "Basic "+auth)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hackerone transport: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		if resp.StatusCode == http.StatusUnauthorized && !c.hasCredentials() && c.isOfficialAPI() {
			return c.importPublic(ctx, slug)
		}
		return nil, fmt.Errorf("hackerone %d: %s", resp.StatusCode, string(body))
	}

	var envelope struct {
		Data []struct {
			Attributes struct {
				AssetIdentifier       string `json:"asset_identifier"`
				AssetType             string `json:"asset_type"`
				EligibleForSubmission bool   `json:"eligible_for_submission"`
				EligibleForBounty     bool   `json:"eligible_for_bounty"`
				Instruction           string `json:"instruction"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("parse hackerone response: %w", err)
	}
	return Map(envelope.Data), nil
}

// Policy fetches the program's rules-of-engagement text. Used by
// `pentestswarm program inspect h1:<slug>` to extract machine-readable
// constraints (rate limits, banned techniques, required headers).
//
// Public programs fall back to the rendered public page when API credentials
// are absent. Private programs still require credentials.
func (c *Client) Policy(ctx context.Context, slug string) (string, error) {
	url := fmt.Sprintf("%s/hackers/programs/%s", c.baseURL, slug)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	if c.apiUser != "" && c.apiToken != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(c.apiUser + ":" + c.apiToken))
		req.Header.Set("Authorization", "Basic "+auth)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("hackerone transport: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		if resp.StatusCode == http.StatusUnauthorized && !c.hasCredentials() && c.isOfficialAPI() {
			return c.policyPublic(ctx, slug)
		}
		return "", fmt.Errorf("hackerone %d: %s", resp.StatusCode, string(body))
	}
	var envelope struct {
		Data struct {
			Attributes struct {
				Policy string `json:"policy"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return "", fmt.Errorf("parse policy: %w", err)
	}
	return envelope.Data.Attributes.Policy, nil
}

// Map converts the HackerOne response shape into our scope definition.
// Exposed for tests + for advanced callers that want to handle the raw
// API response themselves.
func Map(items []struct {
	Attributes struct {
		AssetIdentifier       string `json:"asset_identifier"`
		AssetType             string `json:"asset_type"`
		EligibleForSubmission bool   `json:"eligible_for_submission"`
		EligibleForBounty     bool   `json:"eligible_for_bounty"`
		Instruction           string `json:"instruction"`
	} `json:"attributes"`
}) *scope.ScopeDefinition {
	def := &scope.ScopeDefinition{}
	for _, it := range items {
		applyScopeAsset(def,
			it.Attributes.AssetIdentifier,
			it.Attributes.AssetType,
			it.Attributes.EligibleForSubmission,
			it.Attributes.Instruction,
		)
	}
	return def
}


func normalizeAssetType(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.ReplaceAll(s, "_", "")
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}

func applyScopeAsset(def *scope.ScopeDefinition, rawID, rawType string, eligible bool, instruction string) {
	id := strings.TrimSpace(rawID)
	if def == nil || id == "" {
		return
	}
	assetType := normalizeAssetType(rawType)
	switch assetType {
	case "url", "wildcard", "domain":
		networkID := normalizeNetworkIdentifier(assetType, id)
		if networkID == "" {
			return
		}
		if eligible {
			def.AllowedDomains = append(def.AllowedDomains, networkID)
		} else {
			def.ExcludedDomains = append(def.ExcludedDomains, networkID)
		}
	case "cidr":
		if eligible {
			def.AllowedCIDRs = append(def.AllowedCIDRs, id)
		} else {
			def.ExcludedCIDRs = append(def.ExcludedCIDRs, id)
		}
	case "ipaddress":
		cidr := id + "/32"
		if eligible {
			def.AllowedCIDRs = append(def.AllowedCIDRs, cidr)
		} else {
			def.ExcludedCIDRs = append(def.ExcludedCIDRs, cidr)
		}
	case "sourcecode":
		if !eligible {
			return
		}
		def.AllowedSourceCode = append(def.AllowedSourceCode, id)
		if note := strings.TrimSpace(instruction); note != "" {
			if def.SourceCodeInstructions == nil {
				def.SourceCodeInstructions = map[string]string{}
			}
			def.SourceCodeInstructions[id] = note
		}
	}
}

func normalizeNetworkIdentifier(assetType, raw string) string {
	value := strings.TrimSpace(raw)
	if assetType != "url" {
		return value
	}
	if !strings.Contains(value, "://") {
		value = "https://" + value
	}
	u, err := url.Parse(value)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	return u.Hostname()
}

func (c *Client) hasCredentials() bool {
	return strings.TrimSpace(c.apiUser) != "" && strings.TrimSpace(c.apiToken) != ""
}

func (c *Client) isOfficialAPI() bool {
	u, err := url.Parse(c.baseURL)
	return err == nil && strings.EqualFold(u.Hostname(), "api.hackerone.com")
}
