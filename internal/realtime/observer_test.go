package realtime

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/evidence"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/policygateway"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
	"github.com/fasthttp/websocket"
	"github.com/google/uuid"
)

func TestObserveSSEUsesPolicyHeadersAndEvidence(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("X-Bugbounty-User") != "lab" {
			http.Error(w, "missing policy header", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		_, _ = fmt.Fprint(w, "data: first\n\ndata: {\"token\":\"secret-value\"}\n\n")
		if flusher != nil {
			flusher.Flush()
		}
	}))
	defer server.Close()

	observer := testObserver(t, server.URL, map[string]string{"X-Bugbounty-User": "lab"})
	obs, err := observer.ObserveSSE(context.Background(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 1 || obs.Protocol != "sse" || len(obs.Messages) != 2 {
		t.Fatalf("observation = %+v hits=%d", obs, hits.Load())
	}
	if strings.Contains(obs.Messages[1].Text, "secret-value") {
		t.Fatalf("SSE text was not redacted: %q", obs.Messages[1].Text)
	}
	if obs.Evidence.RecordID == "" || obs.Evidence.IntegrityHash == "" {
		t.Fatalf("missing evidence provenance: %+v", obs.Evidence)
	}
}

func TestObserveWebSocketIsReceiveOnlyAndPolicyGoverned(t *testing.T) {
	var hits atomic.Int32
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("X-Bugbounty-User") != "lab" {
			http.Error(w, "missing policy header", http.StatusBadRequest)
			return
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.WriteMessage(websocket.TextMessage, []byte("{\"event\":\"hello\"}"))
		_ = conn.WriteMessage(websocket.BinaryMessage, []byte{0x01, 0x02, 0x03})
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	observer := testObserver(t, wsURL, map[string]string{"X-Bugbounty-User": "lab"})
	obs, err := observer.ObserveWebSocket(context.Background(), wsURL)
	if err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 1 || len(obs.Messages) != 2 {
		t.Fatalf("observation = %+v hits=%d", obs, hits.Load())
	}
	if obs.Messages[0].Type != "text" || obs.Messages[1].Type != "binary" || obs.Messages[1].Text != "" {
		t.Fatalf("unexpected websocket messages: %+v", obs.Messages)
	}
}

func TestObserveWebSocketDenialOccursBeforeNetwork(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hits.Add(1)
	}))
	defer server.Close()
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	store, err := evidence.NewFileStore(filepath.Join(t.TempDir(), "evidence"))
	if err != nil {
		t.Fatal(err)
	}
	observer := &Observer{
		Gateway: policygateway.New(policygateway.Policy{
			Scope: scope.ScopeDefinition{AllowedCIDRs: []string{"192.0.2.0/24"}},
		}),
		Evidence: store, CampaignID: uuid.New(), ActorID: "tester",
		Timeout: time.Second,
	}
	if _, err := observer.ObserveWebSocket(context.Background(), wsURL); err == nil {
		t.Fatal("out-of-scope websocket must be denied")
	}
	if hits.Load() != 0 {
		t.Fatalf("denied websocket reached target %d times", hits.Load())
	}
}

func testObserver(t *testing.T, rawURL string, required map[string]string) *Observer {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	host, _, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	suffix := "/128"
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		suffix = "/32"
	}
	store, err := evidence.NewFileStore(filepath.Join(t.TempDir(), "evidence"))
	if err != nil {
		t.Fatal(err)
	}
	return &Observer{
		Gateway: policygateway.New(policygateway.Policy{
			Scope:           scope.ScopeDefinition{AllowedCIDRs: []string{host + suffix}},
			RequiredHeaders: required,
			Version:         "realtime-test-v1",
		}),
		Evidence: store, CampaignID: uuid.New(), ActorID: "tester",
		Timeout: 2 * time.Second, MaxMessages: 4, MaxBytes: 4096,
	}
}
