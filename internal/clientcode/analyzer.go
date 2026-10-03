package clientcode

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
)

const (
	// MaxAssetBytes bounds local JavaScript analysis.
	MaxAssetBytes = 4 << 20
	// MaxSourceMapBytes bounds local source-map analysis.
	MaxSourceMapBytes = 8 << 20
	// MaxSourceFiles bounds the number of source-map source files inspected.
	MaxSourceFiles = 128
	// MaxSignals bounds the total static signals emitted per asset.
	MaxSignals = 512
)

// Kind classifies a static client-code signal.
type Kind string

const (
	KindRoute         Kind = "route"
	KindParameter     Kind = "parameter"
	KindRealtime      Kind = "realtime-endpoint"
	KindFeatureFlag   Kind = "feature-flag"
	KindRoleHint      Kind = "role-hint"
	KindWorkflowState Kind = "workflow-state"
)

// Signal is one static, non-executed observation derived from client code.
type Signal struct {
	Kind       Kind   `json:"kind"`
	Value      string `json:"value"`
	Source     string `json:"source"`
	Confidence string `json:"confidence"`
}

// Summary is the stable, monitor-friendly projection of one client asset.
type Summary struct {
	ContentHash       string   `json:"content_hash"`
	SourceMapHash     string   `json:"source_map_hash,omitempty"`
	SourceMapURL      string   `json:"source_map_url,omitempty"`
	SourceFiles       []string `json:"source_files,omitempty"`
	Routes            []string `json:"routes,omitempty"`
	Parameters        []string `json:"parameters,omitempty"`
	RealtimeEndpoints []string `json:"realtime_endpoints,omitempty"`
	FeatureFlags      []string `json:"feature_flags,omitempty"`
	RoleHints         []string `json:"role_hints,omitempty"`
	WorkflowStates    []string `json:"workflow_states,omitempty"`
}

// Analysis contains bounded static signals for one JavaScript asset.
type Analysis struct {
	AssetURL string   `json:"asset_url"`
	Summary  Summary  `json:"summary"`
	Signals  []Signal `json:"signals"`
}

type sourceMap struct {
	Version        int       `json:"version"`
	File           string    `json:"file,omitempty"`
	Sources        []string  `json:"sources,omitempty"`
	SourcesContent []*string `json:"sourcesContent,omitempty"`
}

var (
	sourceMapURLPattern = regexp.MustCompile("(?m)[#@]\\s*sourceMappingURL\\s*=\\s*([^\\s*]+)")
	quotedURLPattern    = regexp.MustCompile("[\\x22'\\x60]((?:https?://|wss?://|/)[^\\x22'\\x60\\s]{2,512})[\\x22'\\x60]")
	fetchPattern        = regexp.MustCompile("(?i)\\b(?:fetch|axios\\.(?:get|post|put|patch|delete)|request)\\s*\\(\\s*[\\x22'\\x60]([^\\x22'\\x60]+)[\\x22'\\x60]")
	webSocketPattern    = regexp.MustCompile("(?i)\\b(?:new\\s+WebSocket|WebSocket|new\\s+EventSource|EventSource)\\s*\\(\\s*[\\x22'\\x60]([^\\x22'\\x60]+)[\\x22'\\x60]")
	paramPattern        = regexp.MustCompile("(?i)\\b(?:searchParams|params|query|queryParams)\\.(?:get|set|append|has|delete)\\s*\\(\\s*[\\x22']([A-Za-z0-9_.:-]{1,64})[\\x22']")
	featureFlagPattern  = regexp.MustCompile("(?i)\\b(?:isFeatureEnabled|featureEnabled|useFeatureFlag|featureFlag)\\s*\\(\\s*[\\x22']([A-Za-z0-9_.:-]{1,96})[\\x22']")
	flagMemberPattern   = regexp.MustCompile("(?i)\\b(?:featureFlags?|flags)\\.([A-Za-z][A-Za-z0-9_]{1,63})\\b")
	rolePattern         = regexp.MustCompile("(?i)\\b(?:user\\.)?roles?\\s*(?:===|==|!==|!=)\\s*[\\x22']([A-Za-z0-9_.:-]{1,64})[\\x22']")
	roleIncludesPattern = regexp.MustCompile("(?i)\\broles?\\.(?:includes|has)\\s*\\(\\s*[\\x22']([A-Za-z0-9_.:-]{1,64})[\\x22']")
	statePattern        = regexp.MustCompile("(?i)\\b(?:state|status)\\s*(?:===|==|!==|!=)\\s*[\\x22']([A-Za-z0-9_.:-]{1,64})[\\x22']")
	transitionPattern   = regexp.MustCompile("(?i)\\b(?:setState|setStatus|transitionTo|goToState)\\s*\\(\\s*[\\x22']([A-Za-z0-9_.:-]{1,64})[\\x22']")
)

// Analyze statically inspects JavaScript and optional source-map content.
// It never evaluates or executes the supplied code.
func Analyze(assetURL string, script, sourceMapBytes []byte) (Analysis, error) {
	if len(script) == 0 {
		return Analysis{}, fmt.Errorf("javascript asset is empty")
	}
	if len(script) > MaxAssetBytes {
		return Analysis{}, fmt.Errorf("javascript asset exceeds %d bytes", MaxAssetBytes)
	}
	if len(sourceMapBytes) > MaxSourceMapBytes {
		return Analysis{}, fmt.Errorf("source map exceeds %d bytes", MaxSourceMapBytes)
	}

	a := Analysis{
		AssetURL: strings.TrimSpace(assetURL),
		Summary: Summary{
			ContentHash:  hash(script),
			SourceMapURL: extractSourceMapURL(string(script)),
		},
	}
	collector := newCollector(a.AssetURL)
	collector.scan("bundle", string(script))

	if len(sourceMapBytes) > 0 {
		a.Summary.SourceMapHash = hash(sourceMapBytes)
		var sm sourceMap
		if err := json.Unmarshal(sourceMapBytes, &sm); err != nil {
			return Analysis{}, fmt.Errorf("parsing source map: %w", err)
		}
		if sm.Version != 3 {
			return Analysis{}, fmt.Errorf("unsupported source map version %d", sm.Version)
		}
		limit := len(sm.Sources)
		if limit > MaxSourceFiles {
			limit = MaxSourceFiles
		}
		a.Summary.SourceFiles = append(a.Summary.SourceFiles, sm.Sources[:limit]...)
		for i := 0; i < limit && i < len(sm.SourcesContent); i++ {
			if sm.SourcesContent[i] == nil {
				continue
			}
			content := *sm.SourcesContent[i]
			if len(content) > MaxAssetBytes {
				content = content[:MaxAssetBytes]
			}
			collector.scan(sm.Sources[i], content)
			if len(collector.signals) >= MaxSignals {
				break
			}
		}
	}

	a.Signals = collector.sortedSignals()
	a.Summary.Routes = values(a.Signals, KindRoute)
	a.Summary.Parameters = values(a.Signals, KindParameter)
	a.Summary.RealtimeEndpoints = values(a.Signals, KindRealtime)
	a.Summary.FeatureFlags = values(a.Signals, KindFeatureFlag)
	a.Summary.RoleHints = values(a.Signals, KindRoleHint)
	a.Summary.WorkflowStates = values(a.Signals, KindWorkflowState)
	sort.Strings(a.Summary.SourceFiles)
	return a, nil
}

func extractSourceMapURL(script string) string {
	m := sourceMapURLPattern.FindStringSubmatch(script)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

type collector struct {
	assetURL string
	seen     map[string]struct{}
	signals  []Signal
}

func newCollector(assetURL string) *collector {
	return &collector{assetURL: assetURL, seen: map[string]struct{}{}}
}

func (c *collector) scan(source, code string) {
	if len(c.signals) >= MaxSignals {
		return
	}
	c.addMatches(KindRealtime, source, "high", webSocketPattern, code, true)
	c.addMatches(KindRoute, source, "high", fetchPattern, code, true)
	c.addMatches(KindRoute, source, "medium", quotedURLPattern, code, true)
	c.addMatches(KindParameter, source, "medium", paramPattern, code, false)
	c.addMatches(KindFeatureFlag, source, "high", featureFlagPattern, code, false)
	c.addMatches(KindFeatureFlag, source, "medium", flagMemberPattern, code, false)
	c.addMatches(KindRoleHint, source, "medium", rolePattern, code, false)
	c.addMatches(KindRoleHint, source, "medium", roleIncludesPattern, code, false)
	c.addMatches(KindWorkflowState, source, "medium", statePattern, code, false)
	c.addMatches(KindWorkflowState, source, "high", transitionPattern, code, false)
}

func (c *collector) addMatches(kind Kind, source, confidence string, re *regexp.Regexp, code string, normalizeURL bool) {
	for _, m := range re.FindAllStringSubmatch(code, -1) {
		if len(c.signals) >= MaxSignals || len(m) < 2 {
			return
		}
		value := strings.TrimSpace(m[1])
		actualKind := kind
		if normalizeURL {
			value = c.normalizeURL(value)
			if !usefulURL(value) {
				continue
			}
			lower := strings.ToLower(value)
			if strings.HasPrefix(lower, "ws://") || strings.HasPrefix(lower, "wss://") {
				actualKind = KindRealtime
			}
		}
		if value == "" {
			continue
		}
		key := string(actualKind) + "\x00" + value
		if _, ok := c.seen[key]; ok {
			continue
		}
		c.seen[key] = struct{}{}
		c.signals = append(c.signals, Signal{Kind: actualKind, Value: value, Source: source, Confidence: confidence})
	}
}

func (c *collector) normalizeURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "/") && c.assetURL != "" {
		base, err := url.Parse(c.assetURL)
		if err == nil && base.Scheme != "" && base.Host != "" {
			ref, err := url.Parse(raw)
			if err == nil {
				return base.ResolveReference(ref).String()
			}
		}
	}
	return raw
}

func usefulURL(raw string) bool {
	lower := strings.ToLower(raw)
	if strings.HasPrefix(lower, "data:") || strings.HasPrefix(lower, "blob:") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	ext := strings.ToLower(path.Ext(u.Path))
	switch ext {
	case ".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot":
		return false
	}
	return u.Path != "" || u.Host != ""
}

func (c *collector) sortedSignals() []Signal {
	out := append([]Signal(nil), c.signals...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind == out[j].Kind {
			if out[i].Value == out[j].Value {
				return out[i].Source < out[j].Source
			}
			return out[i].Value < out[j].Value
		}
		return out[i].Kind < out[j].Kind
	})
	return out
}

func values(signals []Signal, kind Kind) []string {
	var out []string
	for i := range signals {
		if signals[i].Kind == kind {
			out = append(out, signals[i].Value)
		}
	}
	sort.Strings(out)
	return out
}

func hash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
