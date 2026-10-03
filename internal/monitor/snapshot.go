package monitor

import (
	"sort"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
)

type Endpoint struct {
	Method              string   `json:"method"`
	URL                 string   `json:"url"`
	Protocol            string   `json:"protocol,omitempty"`
	Parameters          []string `json:"parameters,omitempty"`
	StatusCode          int      `json:"status_code,omitempty"`
	ResponseFingerprint string   `json:"response_fingerprint,omitempty"`
}

type Snapshot struct {
	Target       string            `json:"target"`
	CapturedAt   time.Time         `json:"captured_at"`
	Subdomains   []string          `json:"subdomains,omitempty"`
	Hosts        []string          `json:"hosts,omitempty"`
	Endpoints    []Endpoint        `json:"endpoints,omitempty"`
	JavaScript   map[string]string `json:"javascript_hashes,omitempty"`
	APISchemas   map[string]string `json:"api_schema_hashes,omitempty"`
	Technologies map[string]string `json:"technologies,omitempty"`
}

func FromAttackSurface(surface pipeline.AttackSurface) Snapshot {
	s := Snapshot{
		Target:       surface.Target,
		CapturedAt:   time.Now().UTC(),
		JavaScript:   map[string]string{},
		APISchemas:   map[string]string{},
		Technologies: cloneMap(surface.Technologies),
	}
	for i := range surface.Subdomains {
		if surface.Subdomains[i].Domain != "" {
			s.Subdomains = append(s.Subdomains, surface.Subdomains[i].Domain)
		}
	}
	for i := range surface.Hosts {
		if surface.Hosts[i].IP != "" {
			s.Hosts = append(s.Hosts, surface.Hosts[i].IP)
		}
	}
	for i := range surface.Endpoints {
		ep := &surface.Endpoints[i]
		if ep.URL == "" {
			continue
		}
		s.Endpoints = append(s.Endpoints, Endpoint{
			Method:     normalizedMethod(ep.Method),
			URL:        ep.URL,
			Protocol:   normalizedProtocol(ep.Protocol),
			Parameters: sortedStrings(ep.Parameters),
			StatusCode: ep.StatusCode,
		})
	}
	sort.Strings(s.Subdomains)
	sort.Strings(s.Hosts)
	sort.Slice(s.Endpoints, func(i, j int) bool {
		return endpointKey(s.Endpoints[i]) < endpointKey(s.Endpoints[j])
	})
	return s
}

func normalizedMethod(method string) string {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		return "GET"
	}
	return method
}

func normalizedProtocol(protocol string) string {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if protocol == "" {
		return "http"
	}
	return protocol
}

func endpointKey(ep Endpoint) string {
	return normalizedMethod(ep.Method) + " " + ep.URL
}

func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func cloneMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
