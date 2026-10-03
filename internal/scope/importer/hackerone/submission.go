package hackerone

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// CreateReportInput contains only the HackerOne hacker-API fields used by the
// human-approved submission path. weakness/scope IDs remain optional because a
// valid report can be submitted without them.
type CreateReportInput struct {
	TeamHandle               string
	Title                    string
	VulnerabilityInformation string
	Impact                   string
	SeverityRating           string
	WeaknessID               int64
	StructuredScopeID        int64
}

// CreateReportResult is the minimal receipt persisted after HackerOne accepts a
// report. It intentionally excludes response data that is not needed locally.
type CreateReportResult struct {
	ID    string
	Title string
	State string
}

type createReportEnvelope struct {
	Data struct {
		Type       string                 `json:"type"`
		Attributes createReportAttributes `json:"attributes"`
	} `json:"data"`
}

type createReportAttributes struct {
	TeamHandle               string `json:"team_handle"`
	Title                    string `json:"title"`
	VulnerabilityInformation string `json:"vulnerability_information"`
	Impact                   string `json:"impact"`
	SeverityRating           string `json:"severity_rating,omitempty"`
	WeaknessID               int64  `json:"weakness_id,omitempty"`
	StructuredScopeID        int64  `json:"structured_scope_id,omitempty"`
}

type createReportResponse struct {
	Data struct {
		ID         json.RawMessage `json:"id"`
		Attributes struct {
			Title string `json:"title"`
			State string `json:"state"`
		} `json:"attributes"`
	} `json:"data"`
}

// CreateReport performs the single external side effect used by the optional
// HackerOne submission command. Callers are responsible for enforcing the
// local approval/evidence gates before invoking this method.
func (c *Client) CreateReport(ctx context.Context, in CreateReportInput) (CreateReportResult, error) {
	if c == nil {
		return CreateReportResult{}, fmt.Errorf("hackerone client unavailable")
	}
	if strings.TrimSpace(c.apiUser) == "" || strings.TrimSpace(c.apiToken) == "" {
		return CreateReportResult{}, fmt.Errorf("hackerone CreateReport: API credentials required")
	}
	if err := validateCreateReport(in); err != nil {
		return CreateReportResult{}, err
	}

	var envelope createReportEnvelope
	envelope.Data.Type = "report"
	envelope.Data.Attributes = createReportAttributes{
		TeamHandle:               strings.TrimSpace(in.TeamHandle),
		Title:                    strings.TrimSpace(in.Title),
		VulnerabilityInformation: strings.TrimSpace(in.VulnerabilityInformation),
		Impact:                   strings.TrimSpace(in.Impact),
		SeverityRating:           strings.ToLower(strings.TrimSpace(in.SeverityRating)),
		WeaknessID:               in.WeaknessID,
		StructuredScopeID:        in.StructuredScopeID,
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		return CreateReportResult{}, fmt.Errorf("encode hackerone report: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/hackers/reports", bytes.NewReader(body))
	if err != nil {
		return CreateReportResult{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	auth := base64.StdEncoding.EncodeToString([]byte(c.apiUser + ":" + c.apiToken))
	req.Header.Set("Authorization", "Basic "+auth)

	resp, err := c.http.Do(req)
	if err != nil {
		return CreateReportResult{}, fmt.Errorf("hackerone create-report transport: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return CreateReportResult{}, fmt.Errorf("read hackerone create-report response: %w", err)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return CreateReportResult{}, fmt.Errorf("hackerone create-report %d: %s", resp.StatusCode, strings.TrimSpace(string(responseBody)))
	}

	var created createReportResponse
	if err := json.Unmarshal(responseBody, &created); err != nil {
		return CreateReportResult{}, fmt.Errorf("parse hackerone create-report response: %w", err)
	}
	id, err := normalizeReportID(created.Data.ID)
	if err != nil {
		return CreateReportResult{}, err
	}
	return CreateReportResult{
		ID: id,
		Title: strings.TrimSpace(created.Data.Attributes.Title),
		State: strings.TrimSpace(created.Data.Attributes.State),
	}, nil
}

func validateCreateReport(in CreateReportInput) error {
	if strings.TrimSpace(in.TeamHandle) == "" {
		return fmt.Errorf("hackerone team handle is required")
	}
	if strings.TrimSpace(in.Title) == "" {
		return fmt.Errorf("hackerone report title is required")
	}
	if strings.TrimSpace(in.VulnerabilityInformation) == "" {
		return fmt.Errorf("hackerone vulnerability information is required")
	}
	if strings.TrimSpace(in.Impact) == "" {
		return fmt.Errorf("hackerone impact is required")
	}
	severity := strings.ToLower(strings.TrimSpace(in.SeverityRating))
	switch severity {
	case "", "none", "low", "medium", "high", "critical":
	default:
		return fmt.Errorf("unsupported hackerone severity %q", in.SeverityRating)
	}
	if in.WeaknessID < 0 || in.StructuredScopeID < 0 {
		return fmt.Errorf("hackerone weakness/scope IDs cannot be negative")
	}
	return nil
}

func normalizeReportID(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", fmt.Errorf("hackerone create-report response is missing report id")
	}
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		asString = strings.TrimSpace(asString)
		if asString == "" {
			return "", fmt.Errorf("hackerone create-report response has empty report id")
		}
		return asString, nil
	}
	var asNumber json.Number
	if err := json.Unmarshal(raw, &asNumber); err == nil {
		if _, err := strconv.ParseInt(asNumber.String(), 10, 64); err == nil {
			return asNumber.String(), nil
		}
	}
	return "", fmt.Errorf("hackerone create-report response has invalid report id")
}
