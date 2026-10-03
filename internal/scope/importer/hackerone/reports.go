package hackerone

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const maxHistoricalReports = 500

// Report is the normalized subset of HackerOne report history used for
// duplicate analysis. VulnerabilityInformation is consumed transiently to
// derive a fingerprint; callers should avoid persisting it unless necessary.
type Report struct {
	ID                       string
	Title                    string
	State                    string
	Program                  string
	CreatedAt                time.Time
	VulnerabilityInformation string
	Severity                 string
	WeaknessName             string
	WeaknessExternalID       string
	AssetIdentifier          string
	AssetType                string
}

type reportEnvelope struct {
	Data []reportData `json:"data"`
}

type reportData struct {
	ID         string `json:"id"`
	Attributes struct {
		Title                    string `json:"title"`
		State                    string `json:"state"`
		CreatedAt                string `json:"created_at"`
		VulnerabilityInformation string `json:"vulnerability_information"`
	} `json:"attributes"`
	Relationships struct {
		Program struct {
			Data struct {
				Attributes struct {
					Handle string `json:"handle"`
				} `json:"attributes"`
			} `json:"data"`
		} `json:"program"`
		Severity struct {
			Data struct {
				Attributes struct {
					Rating string `json:"rating"`
				} `json:"attributes"`
			} `json:"data"`
		} `json:"severity"`
		Weakness struct {
			Data struct {
				Attributes struct {
					Name       string `json:"name"`
					ExternalID string `json:"external_id"`
				} `json:"attributes"`
			} `json:"data"`
		} `json:"weakness"`
		StructuredScope struct {
			Data struct {
				Attributes struct {
					AssetIdentifier string `json:"asset_identifier"`
					AssetType       string `json:"asset_type"`
				} `json:"attributes"`
			} `json:"data"`
		} `json:"structured_scope"`
	} `json:"relationships"`
}

// Reports fetches the authenticated researcher's report history. The method is
// deliberately bounded to maxHistoricalReports and follows numeric pagination
// under the same HackerOne API origin.
func (c *Client) Reports(ctx context.Context, limit int) ([]Report, error) {
	if c.apiUser == "" || c.apiToken == "" {
		return nil, fmt.Errorf("hackerone Reports: API credentials required")
	}
	limit = normalizeReportLimit(limit)
	out := make([]Report, 0, limit)

	for page := 1; len(out) < limit; page++ {
		pageSize := min(100, limit-len(out))
		endpoint := fmt.Sprintf("%s/hackers/me/reports?page[size]=%d&page[number]=%d", c.baseURL, pageSize, page)
		envelope, err := c.fetchReportPage(ctx, endpoint, true)
		if err != nil {
			return nil, err
		}
		for i := range envelope.Data {
			out = append(out, normalizeReport(&envelope.Data[i], ""))
			if len(out) == limit {
				break
			}
		}
		if len(envelope.Data) < pageSize {
			break
		}
	}
	return out, nil
}

// PublicReports fetches bounded public hacktivity for one program. Public
// records are often less richly populated than owned reports; optional
// relationship metadata is retained when HackerOne supplies it.
func (c *Client) PublicReports(ctx context.Context, programSlug string, limit int) ([]Report, error) {
	limit = normalizeReportLimit(limit)
	out := make([]Report, 0, limit)

	for page := 1; len(out) < limit; page++ {
		pageSize := min(100, limit-len(out))
		endpoint := fmt.Sprintf("%s/hackers/hacktivity?queryString=team_handle:%s&page[size]=%d&page[number]=%d",
			c.baseURL, programSlug, pageSize, page)
		envelope, err := c.fetchReportPage(ctx, endpoint, false)
		if err != nil {
			return nil, err
		}
		for i := range envelope.Data {
			out = append(out, normalizeReport(&envelope.Data[i], programSlug))
			if len(out) == limit {
				break
			}
		}
		if len(envelope.Data) < pageSize {
			break
		}
	}
	return out, nil
}

func normalizeReportLimit(limit int) int {
	if limit <= 0 {
		return 100
	}
	if limit > maxHistoricalReports {
		return maxHistoricalReports
	}
	return limit
}

func (c *Client) fetchReportPage(ctx context.Context, endpoint string, requireAuth bool) (reportEnvelope, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return reportEnvelope{}, err
	}
	req.Header.Set("Accept", "application/json")
	if c.apiUser != "" && c.apiToken != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(c.apiUser + ":" + c.apiToken))
		req.Header.Set("Authorization", "Basic "+auth)
	} else if requireAuth {
		return reportEnvelope{}, fmt.Errorf("hackerone report history requires API credentials")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return reportEnvelope{}, fmt.Errorf("hackerone transport: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return reportEnvelope{}, fmt.Errorf("read hackerone reports: %w", err)
	}
	if resp.StatusCode >= 400 {
		return reportEnvelope{}, fmt.Errorf("hackerone %d: %s", resp.StatusCode, string(body))
	}

	var envelope reportEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return reportEnvelope{}, fmt.Errorf("parse hackerone reports: %w", err)
	}
	return envelope, nil
}

func normalizeReport(raw *reportData, programFallback string) Report {
	r := Report{
		ID:                       raw.ID,
		Title:                    raw.Attributes.Title,
		State:                    raw.Attributes.State,
		Program:                  raw.Relationships.Program.Data.Attributes.Handle,
		VulnerabilityInformation: raw.Attributes.VulnerabilityInformation,
		Severity:                 raw.Relationships.Severity.Data.Attributes.Rating,
		WeaknessName:             raw.Relationships.Weakness.Data.Attributes.Name,
		WeaknessExternalID:       raw.Relationships.Weakness.Data.Attributes.ExternalID,
		AssetIdentifier:          raw.Relationships.StructuredScope.Data.Attributes.AssetIdentifier,
		AssetType:                raw.Relationships.StructuredScope.Data.Attributes.AssetType,
	}
	if r.Program == "" {
		r.Program = programFallback
	}
	if raw.Attributes.CreatedAt != "" {
		if parsed, err := time.Parse(time.RFC3339, raw.Attributes.CreatedAt); err == nil {
			r.CreatedAt = parsed
		}
	}
	return r
}
