package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/evidence"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/policygateway"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/realtime"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/session"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

var realtimeCmd = &cobra.Command{
	Use:   "realtime",
	Short: "Observe policy-governed SSE and WebSocket streams",
	Long:  "Receive-only realtime observation. This command never sends application WebSocket frames and never mutates target state.",
}

var realtimeObserveCmd = &cobra.Command{
	Use:   "observe <url>",
	Short: "Observe a bounded SSE or WebSocket stream",
	Args:  cobra.ExactArgs(1),
	RunE:  runRealtimeObserve,
}

func runRealtimeObserve(cmd *cobra.Command, args []string) error {
	rawURL := strings.TrimSpace(args[0])
	protocol, _ := cmd.Flags().GetString("protocol")
	scopes, _ := cmd.Flags().GetStringArray("scope")
	if len(scopes) == 0 {
		return fmt.Errorf("at least one --scope is required; realtime observation fails closed without explicit scope")
	}
	scopeDef, err := realtimeScope(scopes)
	if err != nil {
		return err
	}

	policyRawHeaders, _ := cmd.Flags().GetStringArray("policy-header")
	policyHeaders := session.ParseHeaders(policyRawHeaders, "", "")
	authRawHeaders, _ := cmd.Flags().GetStringArray("header")
	cookie, _ := cmd.Flags().GetString("cookie")
	auth, _ := cmd.Flags().GetString("auth")
	authHeaders := session.ParseHeaders(authRawHeaders, cookie, auth)

	maxRPS, _ := cmd.Flags().GetFloat64("max-rps")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	maxMessages, _ := cmd.Flags().GetInt("max-messages")
	maxBytes, _ := cmd.Flags().GetInt("max-bytes")
	stateDir, _ := cmd.Flags().GetString("state-dir")
	policyVersion, _ := cmd.Flags().GetString("policy-version")
	campaignRaw, _ := cmd.Flags().GetString("campaign-id")

	campaignID := uuid.New()
	if strings.TrimSpace(campaignRaw) != "" {
		parsed, parseErr := uuid.Parse(strings.TrimSpace(campaignRaw))
		if parseErr != nil {
			return fmt.Errorf("invalid --campaign-id: %w", parseErr)
		}
		campaignID = parsed
	}

	store, err := evidence.NewFileStore(filepath.Join(stateDir, "evidence"))
	if err != nil {
		return fmt.Errorf("open durable evidence store: %w", err)
	}
	gateway := policygateway.New(policygateway.Policy{
		Scope:             scopeDef,
		RequiredHeaders:   policyHeaders,
		RequestsPerSecond: maxRPS,
		Burst:             1,
		Version:           strings.TrimSpace(policyVersion),
	})
	observer := &realtime.Observer{
		Gateway:     gateway,
		Evidence:    store,
		CampaignID:  campaignID,
		ActorID:     "realtime-cli",
		Headers:     realtimeHTTPHeaders(authHeaders),
		Timeout:     timeout,
		MaxMessages: maxMessages,
		MaxBytes:    maxBytes,
	}

	resolved, err := realtimeProtocol(protocol, rawURL)
	if err != nil {
		return err
	}
	ctx := context.Background()
	var observation realtime.Observation
	switch resolved {
	case "sse":
		observation, err = observer.ObserveSSE(ctx, rawURL)
	case "websocket":
		observation, err = observer.ObserveWebSocket(ctx, rawURL)
	default:
		return fmt.Errorf("unsupported realtime protocol %q", resolved)
	}
	if err != nil {
		return err
	}

	if OutputIsJSON() {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(observation)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "\n  %s receive-only %s observation\n", colorCyan("[realtime]"), observation.Protocol)
	fmt.Fprintf(cmd.OutOrStdout(), "  target: %s\n", observation.URL)
	fmt.Fprintf(cmd.OutOrStdout(), "  status: %d | messages: %d | bytes: %d\n", observation.StatusCode, len(observation.Messages), observation.BytesRead)
	fmt.Fprintf(cmd.OutOrStdout(), "  policy: %s | decision: %s\n", observation.PolicyVersion, observation.DecisionID)
	fmt.Fprintf(cmd.OutOrStdout(), "  evidence: %s\n\n", observation.Evidence.RecordID)
	return nil
}

func realtimeHTTPHeaders(values map[string]string) http.Header {
	headers := make(http.Header, len(values))
	for name, value := range values {
		headers.Set(name, value)
	}
	return headers
}

func realtimeProtocol(raw, rawURL string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" || value == "auto" {
		u, err := url.Parse(rawURL)
		if err != nil {
			return "", fmt.Errorf("parse realtime URL: %w", err)
		}
		switch strings.ToLower(u.Scheme) {
		case "ws", "wss":
			return "websocket", nil
		case "http", "https":
			return "sse", nil
		default:
			return "", fmt.Errorf("cannot infer realtime protocol from scheme %q", u.Scheme)
		}
	}
	switch value {
	case "sse", "websocket":
		return value, nil
	default:
		return "", fmt.Errorf("--protocol must be auto, sse, or websocket")
	}
}

func realtimeScope(values []string) (scope.ScopeDefinition, error) {
	var out scope.ScopeDefinition
	for _, raw := range values {
		for _, item := range strings.Split(raw, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			if _, _, err := net.ParseCIDR(item); err == nil {
				out.AllowedCIDRs = append(out.AllowedCIDRs, item)
				continue
			}
			if u, err := url.Parse(item); err == nil && u.Hostname() != "" {
				item = u.Hostname()
			}
			item = strings.TrimSuffix(strings.TrimSpace(item), ".")
			if item == "" {
				return scope.ScopeDefinition{}, fmt.Errorf("invalid scope value %q", raw)
			}
			out.AllowedDomains = append(out.AllowedDomains, item)
		}
	}
	if len(out.AllowedCIDRs) == 0 && len(out.AllowedDomains) == 0 {
		return scope.ScopeDefinition{}, fmt.Errorf("scope resolved to no allowed domains or CIDRs")
	}
	return out, nil
}

func init() {
	realtimeObserveCmd.Flags().String("protocol", "auto", "stream protocol: auto|sse|websocket")
	realtimeObserveCmd.Flags().StringArray("scope", nil, "explicit allowed domain/CIDR; repeat or comma-separate")
	realtimeObserveCmd.Flags().StringArray("policy-header", nil, "program-required request header (Name: Value)")
	realtimeObserveCmd.Flags().StringArray("header", nil, "session/request header (Name: Value)")
	realtimeObserveCmd.Flags().String("cookie", "", "Cookie header for the controlled session")
	realtimeObserveCmd.Flags().String("auth", "", "Bearer token for the controlled session")
	realtimeObserveCmd.Flags().Float64("max-rps", 0, "program request-rate allowance")
	realtimeObserveCmd.Flags().Duration("timeout", 10*time.Second, "hard observation timeout")
	realtimeObserveCmd.Flags().Int("max-messages", 10, "maximum received messages/events")
	realtimeObserveCmd.Flags().Int("max-bytes", 64<<10, "maximum response bytes retained")
	realtimeObserveCmd.Flags().String("state-dir", ".pentestswarm/state", "durable evidence state directory")
	realtimeObserveCmd.Flags().String("policy-version", "", "explicit program-policy version identifier")
	realtimeObserveCmd.Flags().String("campaign-id", "", "existing campaign UUID; defaults to a new local observation campaign")
	realtimeCmd.AddCommand(realtimeObserveCmd)
	rootCmd.AddCommand(realtimeCmd)
}
