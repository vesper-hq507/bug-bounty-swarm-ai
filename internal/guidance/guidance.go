package guidance

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/identity"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope/programterms"
)

type Attempt struct {
	Name   string
	Reason string
}

type Input struct {
	Surface     pipeline.AttackSurface
	Constraints programterms.Constraints
	Completed   []string
	Failed      []Attempt
	Identities  []identity.Identity
}

type Recommendation struct {
	Priority          int    `json:"priority"`
	Hypothesis        string `json:"hypothesis"`
	Tool              string `json:"tool"`
	Test              string `json:"test"`
	ExpectedSignal    string `json:"expected_signal"`
	PolicyCompatible  bool   `json:"policy_compatible"`
	PolicyReason      string `json:"policy_reason,omitempty"`
	RequiredIdentity  string `json:"required_identity"`
	ApprovalClass     string `json:"approval_class"`
	Why               string `json:"why"`
	StopCondition     string `json:"stop_condition"`
	Target            string `json:"target,omitempty"`
}

func Recommend(in Input, limit int) []Recommendation {
	if limit <= 0 {
		limit = 5
	}
	completed := make(map[string]struct{}, len(in.Completed))
	for _, name := range in.Completed {
		completed[strings.ToLower(strings.TrimSpace(name))] = struct{}{}
	}
	var out []Recommendation
	add := func(r Recommendation) {
		if _, done := completed[strings.ToLower(r.Test)]; done {
			return
		}
		if !pathAllowed(r.Target, in.Constraints.DisallowedPaths) {
			return
		}
		out = append(out, applyPolicy(r, in.Constraints))
	}

	authIdentities := 0
	for _, ident := range in.Identities {
		if ident.Role != identity.RoleAnonymous {
			authIdentities++
		}
	}

	for _, v := range in.Surface.Vulnerabilities {
		add(Recommendation{
			Priority:         100,
			Hypothesis:       fmt.Sprintf("The existing %s finding is reproducible and materially impacts the target.", v.Title),
			Tool:             "pentestswarm confirm",
			Test:             "verify-existing-finding",
			ExpectedSignal:   "The same vulnerability indicator reproduces under the current policy and identity context.",
			PolicyCompatible: true,
			RequiredIdentity: "same identity context as discovery",
			ApprovalClass:    "read-only-verification",
			Why:              "A tool has already produced a concrete finding; verification has higher value than broadening recon.",
			StopCondition:    "Stop after one clean reproduction or one clear non-reproduction with preserved evidence.",
			Target:           v.URL,
		})
	}

	if authIdentities >= 2 {
		for _, ep := range in.Surface.Endpoints {
			if ep.URL == "" {
				continue
			}
			add(Recommendation{
				Priority:         95,
				Hypothesis:       "An authenticated object endpoint may enforce authorization differently across controlled users.",
				Tool:             "identity-diff",
				Test:             "bola-idor-differential",
				ExpectedSignal:   "A non-owner receives the same successful object representation as the owner.",
				PolicyCompatible: true,
				RequiredIdentity: "two controlled authenticated users",
				ApprovalClass:    "read-only",
				Why:              "Multiple controlled identities are available, making differential authorization testing high-signal and low-noise.",
				StopCondition:    "Stop when owner/non-owner responses clearly diverge or equivalent access is captured with evidence.",
				Target:           ep.URL,
			})
			break
		}
	}

	for _, ep := range in.Surface.Endpoints {
		if ep.URL == "" {
			continue
		}
		if len(ep.Parameters) > 0 {
			add(Recommendation{
				Priority:         80,
				Hypothesis:       "A parameterized endpoint may mishandle untrusted input.",
				Tool:             "nuclei / focused manual request",
				Test:             "parameter-input-validation",
				ExpectedSignal:   "A bounded test changes server behavior in a way consistent with unsafe input handling.",
				PolicyCompatible: true,
				RequiredIdentity: "current authorized session if endpoint requires auth",
				ApprovalClass:    "assist",
				Why:              "Known parameters provide a narrower test surface than broad scanning.",
				StopCondition:    "Stop after the bounded parameter set is covered or the first reproducible signal is captured.",
				Target:           ep.URL,
			})
			break
		}
	}

	if hasAuthEndpoint(in.Surface.Endpoints) {
		add(Recommendation{
			Priority:         75,
			Hypothesis:       "Authentication or session lifecycle controls may have inconsistent invalidation or role boundaries.",
			Tool:             "browser + httpreq",
			Test:             "session-boundary-check",
			ExpectedSignal:   "A stale, logged-out, downgraded, or cross-role session retains access it should lose.",
			PolicyCompatible: true,
			RequiredIdentity: "controlled authenticated account",
			ApprovalClass:    "read-only",
			Why:              "Authentication-related routes are already present in the discovered surface.",
			StopCondition:    "Stop once expected invalidation is confirmed or one reproducible stale-access case is captured.",
			Target:           firstAuthEndpoint(in.Surface.Endpoints),
		})
	}

	if len(in.Surface.Subdomains) > 0 || len(in.Surface.Hosts) > 0 {
		add(Recommendation{
			Priority:         55,
			Hypothesis:       "The known host inventory may contain an unclassified service or application surface.",
			Tool:             "httpx / service fingerprinting",
			Test:             "bounded-service-classification",
			ExpectedSignal:   "A previously unclassified reachable service or technology is identified.",
			PolicyCompatible: true,
			RequiredIdentity: "none",
			ApprovalClass:    "recon",
			Why:              "Known assets can be classified without expanding beyond the existing campaign scope.",
			StopCondition:    "Stop after known hosts are classified once; do not widen discovery automatically.",
			Target:           in.Surface.Target,
		})
	}

	for _, failed := range in.Failed {
		if strings.TrimSpace(failed.Name) == "" {
			continue
		}
		add(Recommendation{
			Priority:         40,
			Hypothesis:       "A previously failed test may become useful if its failure mode is corrected without broadening scope.",
			Tool:             "manual review",
			Test:             "retry-failed-test:" + strings.TrimSpace(failed.Name),
			ExpectedSignal:   "The corrected prerequisite produces a valid observation rather than the prior failure mode.",
			PolicyCompatible: true,
			RequiredIdentity: "same identity as failed attempt",
			ApprovalClass:    "manual-review",
			Why:              "Failure reason: " + strings.TrimSpace(failed.Reason),
			StopCondition:    "Retry once after correcting the prerequisite; do not loop on the same failure.",
			Target:           in.Surface.Target,
		})
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].PolicyCompatible != out[j].PolicyCompatible {
			return out[i].PolicyCompatible
		}
		return out[i].Priority > out[j].Priority
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func applyPolicy(r Recommendation, c programterms.Constraints) Recommendation {
	if c.NoAutomatedScanning {
		switch r.ApprovalClass {
		case "recon", "assist":
			r.PolicyCompatible = false
			r.PolicyReason = "program terms prohibit automated scanning; use a manual, bounded equivalent only if policy permits"
		}
	}
	if c.NoBruteForce && strings.Contains(strings.ToLower(r.Test), "brute") {
		r.PolicyCompatible = false
		r.PolicyReason = "program terms prohibit brute force"
	}
	if c.NoDoS && (strings.Contains(strings.ToLower(r.Test), "dos") || r.ApprovalClass == "concurrency") {
		r.PolicyCompatible = false
		r.PolicyReason = "program terms prohibit denial-of-service or stress-style testing"
	}
	return r
}

func pathAllowed(raw string, denied []string) bool {
	if raw == "" || len(denied) == 0 {
		return true
	}
	u, err := url.Parse(raw)
	if err != nil {
		return true
	}
	for _, d := range denied {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if strings.HasPrefix(u.Path, strings.TrimSuffix(d, "*")) {
			return false
		}
	}
	return true
}

func hasAuthEndpoint(endpoints []pipeline.EndpointRecord) bool {
	return firstAuthEndpoint(endpoints) != ""
}

func firstAuthEndpoint(endpoints []pipeline.EndpointRecord) string {
	for _, ep := range endpoints {
		p := strings.ToLower(ep.URL)
		if strings.Contains(p, "login") || strings.Contains(p, "logout") || strings.Contains(p, "auth") ||
			strings.Contains(p, "session") || strings.Contains(p, "password") || strings.Contains(p, "token") {
			return ep.URL
		}
	}
	return ""
}
