// Package jev is a tiny client for TypeSafe's Jev "System One" model
// (https://typesafe.ai). Jev is NOT an LLM — it takes state + typed questions
// and returns probabilistic decisions in a single parallel pass, far faster and
// cheaper than a chat model. We use its "noul" primitive (a yes/no probability,
// 0→1) as a final false-positive filter over graded findings: for each finding
// we ask "is this a real, exploitable vulnerability?" and drop the ones Jev is
// confident are noise.
//
// Because Jev has its own /v1/systemone contract (not OpenAI-compatible), it
// can't ride the existing provider path — hence this small dedicated client.
package jev

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const (
	// DefaultEndpoint is TypeSafe's System One evaluation endpoint.
	DefaultEndpoint = "https://api.typesafe.ai/v1/systemone"
	// DefaultModel is the early-access Jev route.
	DefaultModel = "jev-latest"
	// maxQuestionsPerRequest keeps each request well under Jev's 64K-token
	// context by batching a bounded number of findings per call.
	maxQuestionsPerRequest = 16
)

// Client talks to the Jev System One API.
type Client struct {
	apiKey   string
	endpoint string
	model    string
	hc       *http.Client
}

// Option configures a Client.
type Option func(*Client)

// WithEndpoint overrides the API endpoint (e.g. a self-hosted proxy).
func WithEndpoint(url string) Option {
	return func(c *Client) {
		if url != "" {
			c.endpoint = url
		}
	}
}

// WithHTTPClient overrides the HTTP client (timeouts, transport, tests).
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) {
		if h != nil {
			c.hc = h
		}
	}
}

// New builds a Jev client. apiKey is the TypeSafe API key (Bearer token).
func New(apiKey string, opts ...Option) *Client {
	c := &Client{
		apiKey:   apiKey,
		endpoint: DefaultEndpoint,
		model:    DefaultModel,
		hc:       &http.Client{Timeout: 30 * time.Second},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// --- wire types (match docs.typesafe.ai/api.md) ---

type question struct {
	Type         string `json:"type"`         // "noul"
	Instructions string `json:"instructions"` // the yes/no statement to evaluate
}

type sysOneRequest struct {
	State     string              `json:"state"`
	Model     string              `json:"model"`
	Questions map[string]question `json:"questions"`
}

type answer struct {
	Type string  `json:"type"`
	Noul float64 `json:"noul"` // P(yes), 0..1
}

type sysOneResponse struct {
	Model   string            `json:"model"`
	Answers map[string]answer `json:"answers"`
}

// truePositiveInstruction frames a finding as a yes/no the noul primitive scores.
func truePositiveInstruction(findingText string) string {
	return "The following is a candidate security finding produced by an automated " +
		"penetration-testing swarm. Statement to evaluate: this is a REAL, exploitable " +
		"vulnerability (a true positive) — not a false positive, informational note, or scanner noise.\n\n" +
		findingText
}

// TruePositiveProbabilities scores each finding's likelihood of being a real
// (true-positive) vulnerability. state is shared campaign context (e.g. the
// target); findings maps a caller-chosen id → the finding's descriptive text.
// It returns id → probability in [0,1]. Findings are batched to respect Jev's
// context window. An error is returned only for transport/decoding failures —
// callers should fail OPEN (keep the finding) on error, never drop on an API
// hiccup.
func (c *Client) TruePositiveProbabilities(ctx context.Context, state string, findings map[string]string) (map[string]float64, error) {
	out := make(map[string]float64, len(findings))
	if len(findings) == 0 {
		return out, nil
	}

	// Batch the ids in stable chunks.
	ids := make([]string, 0, len(findings))
	for id := range findings {
		ids = append(ids, id)
	}
	for start := 0; start < len(ids); start += maxQuestionsPerRequest {
		end := start + maxQuestionsPerRequest
		if end > len(ids) {
			end = len(ids)
		}
		qs := make(map[string]question, end-start)
		for _, id := range ids[start:end] {
			qs[id] = question{Type: "noul", Instructions: truePositiveInstruction(findings[id])}
		}
		resp, err := c.evaluate(ctx, sysOneRequest{State: state, Model: c.model, Questions: qs})
		if err != nil {
			return out, err
		}
		for id, a := range resp.Answers {
			out[id] = a.Noul
		}
	}
	return out, nil
}

func (c *Client) evaluate(ctx context.Context, req sysOneRequest) (*sysOneResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.hc.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("jev request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("jev returned 401 — check your TypeSafe API key")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jev returned status %d", resp.StatusCode)
	}
	var out sysOneResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("jev: decode response: %w", err)
	}
	return &out, nil
}

// HealthCheck verifies the key/endpoint with a single trivial noul question, so
// a bad key fails fast in preflight (mirrors the LLM providers' HealthCheck).
func (c *Client) HealthCheck(ctx context.Context) error {
	_, err := c.evaluate(ctx, sysOneRequest{
		State:     "health check",
		Model:     c.model,
		Questions: map[string]question{"ping": {Type: "noul", Instructions: "This is a health check."}},
	})
	return err
}
