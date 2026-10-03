package realtime

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/evidence"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/policygateway"
	"github.com/fasthttp/websocket"
	"github.com/google/uuid"
)

const (
	defaultTimeout     = 10 * time.Second
	defaultMaxMessages = 10
	defaultMaxBytes    = 64 << 10
)

type Message struct {
	Type        string
	Text        string
	Length      int
	Fingerprint string
}

type Observation struct {
	Protocol      string
	URL           string
	StatusCode    int
	Messages      []Message
	BytesRead     int
	DecisionID    string
	PolicyVersion string
	Evidence      pipeline.Evidence
}

type Observer struct {
	Gateway       *policygateway.Gateway
	Evidence      evidence.Store
	CampaignID    uuid.UUID
	ActorID       string
	IdentityAlias string
	Headers       http.Header
	BaseTransport http.RoundTripper
	Timeout       time.Duration
	MaxMessages   int
	MaxBytes      int
}

func (o *Observer) normalize() error {
	if o == nil || o.Gateway == nil {
		return fmt.Errorf("realtime observer requires a policy gateway")
	}
	if o.Evidence == nil {
		return fmt.Errorf("realtime observer requires an evidence store")
	}
	if o.CampaignID == uuid.Nil {
		return fmt.Errorf("realtime observer requires a campaign id")
	}
	if strings.TrimSpace(o.ActorID) == "" {
		return fmt.Errorf("realtime observer requires an actor id")
	}
	if o.Timeout <= 0 {
		o.Timeout = defaultTimeout
	}
	if o.MaxMessages <= 0 {
		o.MaxMessages = defaultMaxMessages
	}
	if o.MaxBytes <= 0 {
		o.MaxBytes = defaultMaxBytes
	}
	return nil
}

func (o *Observer) ObserveSSE(ctx context.Context, rawURL string) (Observation, error) {
	if err := o.normalize(); err != nil {
		return Observation{}, err
	}
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return Observation{}, fmt.Errorf("SSE URL must use http or https")
	}

	runCtx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()

	base := o.BaseTransport
	if base == nil {
		base = http.DefaultTransport
	}
	actionID := "realtime:sse:" + rawURL
	client := &http.Client{
		Transport: policygateway.NewHTTPTransport(o.Gateway, base, func(r *http.Request) policygateway.Action {
			return policygateway.Action{
				ActionID:   actionID,
				CampaignID: o.CampaignID.String(),
				ActorID:    o.ActorID,
				Kind:       policygateway.ActionSSE,
				Method:     http.MethodGet,
				URL:        r.URL.String(),
				Path:       r.URL.EscapedPath(),
				Tool:       "realtime-sse",
			}
		}),
	}

	req, err := http.NewRequestWithContext(runCtx, http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		return Observation{}, err
	}
	copyHeaders(req.Header, o.Headers)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := client.Do(req)
	if err != nil {
		return Observation{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	decision, ok := policygateway.DecisionFromResponse(resp)
	if !ok {
		return Observation{}, fmt.Errorf("SSE response is missing policy decision provenance")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return o.recordFailure("sse", rawURL, resp.StatusCode, decision, fmt.Sprintf("HTTP %d", resp.StatusCode))
	}

	messages, raw, err := readSSE(resp.Body, o.MaxMessages, o.MaxBytes)
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return Observation{}, err
	}
	return o.record("sse", rawURL, resp.StatusCode, decision, messages, raw)
}

func (o *Observer) ObserveWebSocket(ctx context.Context, rawURL string) (Observation, error) {
	if err := o.normalize(); err != nil {
		return Observation{}, err
	}
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "ws" && u.Scheme != "wss") {
		return Observation{}, fmt.Errorf("WebSocket URL must use ws or wss")
	}

	runCtx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()

	actionID := "realtime:websocket:" + rawURL
	decision, err := o.Gateway.Decide(runCtx, policygateway.Action{
		ActionID:   actionID,
		CampaignID: o.CampaignID.String(),
		ActorID:    o.ActorID,
		Kind:       policygateway.ActionWebSocket,
		Method:     http.MethodGet,
		URL:        rawURL,
		Path:       u.EscapedPath(),
		Tool:       "realtime-websocket",
	})
	if err != nil {
		return Observation{}, err
	}

	headers := cloneHeaders(o.Headers)
	for k, v := range decision.RequiredHeaders {
		headers.Set(k, v)
	}

	dialer := *websocket.DefaultDialer
	dialer.HandshakeTimeout = o.Timeout
	conn, resp, err := dialer.DialContext(runCtx, rawURL, headers)
	if resp != nil && resp.Body != nil {
		defer func() { _ = resp.Body.Close() }()
	}
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		return o.recordFailure("websocket", rawURL, status, decision, err.Error())
	}
	defer func() { _ = conn.Close() }()
	conn.SetReadLimit(int64(o.MaxBytes + 1))
	_ = conn.SetReadDeadline(time.Now().Add(o.Timeout))

	status := http.StatusSwitchingProtocols
	if resp != nil {
		status = resp.StatusCode
	}
	messages := make([]Message, 0, o.MaxMessages)
	var raw bytes.Buffer
	total := 0
	for len(messages) < o.MaxMessages && total < o.MaxBytes {
		msgType, data, readErr := conn.ReadMessage()
		if readErr != nil {
			if len(messages) == 0 {
				return Observation{}, readErr
			}
			break
		}
		if total+len(data) > o.MaxBytes {
			break
		}
		total += len(data)
		_, _ = raw.Write(data)
		_ = raw.WriteByte('\n')
		msg := Message{
			Type:        websocketMessageType(msgType),
			Length:      len(data),
			Fingerprint: evidence.Fingerprint(data),
		}
		if msgType == websocket.TextMessage {
			msg.Text, _ = evidence.SanitizeText(string(data))
		}
		messages = append(messages, msg)
	}
	return o.record("websocket", rawURL, status, decision, messages, raw.Bytes())
}

func (o *Observer) record(protocol, rawURL string, status int, decision policygateway.Decision, messages []Message, raw []byte) (Observation, error) {
	excerpt := summarizeMessages(messages)
	ref, err := evidence.RecordObservation(o.Evidence, evidence.ObservationInput{
		CampaignID:      o.CampaignID,
		ActionID:        decision.ActionID,
		DecisionID:      decision.ID,
		PolicyVersion:   decision.PolicyVersion,
		ActorID:         o.ActorID,
		IdentityAlias:   o.IdentityAlias,
		Tool:            "realtime-" + protocol,
		Request:         []byte(http.MethodGet + " " + rawURL),
		Response:        raw,
		RequestExcerpt:  http.MethodGet + " " + rawURL,
		ResponseExcerpt: excerpt,
		Verification:    evidence.VerificationUnverified,
	})
	if err != nil {
		return Observation{}, err
	}
	return Observation{
		Protocol: protocol, URL: rawURL, StatusCode: status,
		Messages: messages, BytesRead: len(raw),
		DecisionID: decision.ID, PolicyVersion: decision.PolicyVersion,
		Evidence: ref,
	}, nil
}

func (o *Observer) recordFailure(protocol, rawURL string, status int, decision policygateway.Decision, detail string) (Observation, error) {
	obs, err := o.record(protocol, rawURL, status, decision, nil, []byte(detail))
	if err != nil {
		return Observation{}, err
	}
	return obs, fmt.Errorf("%s observation failed: %s", protocol, detail)
}

func readSSE(r io.Reader, maxMessages, maxBytes int) ([]Message, []byte, error) {
	scanner := bufio.NewScanner(io.LimitReader(r, int64(maxBytes+1)))
	scanner.Buffer(make([]byte, 4096), maxBytes+1)
	var messages []Message
	var raw bytes.Buffer
	var event bytes.Buffer
	total := 0

	flush := func() {
		if event.Len() == 0 || len(messages) >= maxMessages {
			event.Reset()
			return
		}
		data := append([]byte(nil), event.Bytes()...)
		safe, _ := evidence.SanitizeText(string(data))
		messages = append(messages, Message{
			Type: "event", Text: safe, Length: len(data), Fingerprint: evidence.Fingerprint(data),
		})
		event.Reset()
	}

	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		total += len(line) + 1
		if total > maxBytes {
			break
		}
		_, _ = raw.Write(line)
		_ = raw.WriteByte('\n')
		if len(line) == 0 {
			flush()
			if len(messages) >= maxMessages {
				break
			}
			continue
		}
		if len(line) > 0 && line[0] == ':' {
			continue
		}
		if bytes.HasPrefix(line, []byte("data:")) {
			line = bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
		}
		_, _ = event.Write(line)
		_ = event.WriteByte('\n')
	}
	flush()
	if err := scanner.Err(); err != nil {
		return messages, raw.Bytes(), err
	}
	return messages, raw.Bytes(), nil
}

func summarizeMessages(messages []Message) string {
	if len(messages) == 0 {
		return "no messages observed"
	}
	var b strings.Builder
	for i := range messages {
		msg := messages[i]
		_, _ = fmt.Fprintf(&b, "%d. %s length=%d fingerprint=%s", i+1, msg.Type, msg.Length, msg.Fingerprint)
		if msg.Text != "" {
			b.WriteString(" text=")
			b.WriteString(msg.Text)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func websocketMessageType(t int) string {
	switch t {
	case websocket.TextMessage:
		return "text"
	case websocket.BinaryMessage:
		return "binary"
	case websocket.CloseMessage:
		return "close"
	case websocket.PingMessage:
		return "ping"
	case websocket.PongMessage:
		return "pong"
	default:
		return fmt.Sprintf("type-%d", t)
	}
}

func copyHeaders(dst, src http.Header) {
	for k, values := range src {
		for _, value := range values {
			dst.Add(k, value)
		}
	}
}

func cloneHeaders(src http.Header) http.Header {
	out := make(http.Header, len(src))
	copyHeaders(out, src)
	return out
}
