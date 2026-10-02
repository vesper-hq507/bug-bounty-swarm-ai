package monitor

import (
	"fmt"
	"sort"
	"strings"
)

type ChangeKind string

const (
	ChangeNewSubdomain        ChangeKind = "new-subdomain"
	ChangeNewHost             ChangeKind = "new-host"
	ChangeNewEndpoint         ChangeKind = "new-endpoint"
	ChangeEndpointParameters  ChangeKind = "endpoint-parameters-changed"
	ChangeResponseFingerprint ChangeKind = "response-fingerprint-changed"
	ChangeJavaScript          ChangeKind = "javascript-changed"
	ChangeAPISchema           ChangeKind = "api-schema-changed"
	ChangeTechnology          ChangeKind = "technology-changed"
)

type Change struct {
	Kind     ChangeKind `json:"kind"`
	Asset    string     `json:"asset"`
	Priority int        `json:"priority"`
	Reason   string     `json:"reason"`
}

type RetestSuggestion struct {
	Priority      int    `json:"priority"`
	Target        string `json:"target"`
	Test          string `json:"test"`
	Why           string `json:"why"`
	Scope         string `json:"scope"`
	StopCondition string `json:"stop_condition"`
}

type DiffResult struct {
	Changes     []Change           `json:"changes"`
	Suggestions []RetestSuggestion `json:"suggestions"`
}

func Diff(before, after Snapshot) DiffResult {
	var out DiffResult

	for _, sub := range addedStrings(before.Subdomains, after.Subdomains) {
		out.Changes = append(out.Changes, Change{Kind: ChangeNewSubdomain, Asset: sub, Priority: 65, Reason: "new in-scope hostname observed"})
		out.Suggestions = append(out.Suggestions, targeted(65, sub, "classify-new-host", "Classify reachability, technology and authentication requirements for only the new hostname.", "Stop after the new hostname is classified once."))
	}
	for _, host := range addedStrings(before.Hosts, after.Hosts) {
		out.Changes = append(out.Changes, Change{Kind: ChangeNewHost, Asset: host, Priority: 60, Reason: "new host observed"})
		out.Suggestions = append(out.Suggestions, targeted(60, host, "classify-new-service-surface", "Classify services on the newly observed host without widening discovery.", "Stop after known exposed services on this host are classified."))
	}

	beforeEndpoints := endpointMap(before.Endpoints)
	afterEndpoints := endpointMap(after.Endpoints)
	for key, current := range afterEndpoints {
		previous, existed := beforeEndpoints[key]
		if !existed {
			out.Changes = append(out.Changes, Change{Kind: ChangeNewEndpoint, Asset: key, Priority: 95, Reason: "new endpoint appeared"})
			out.Suggestions = append(out.Suggestions, targeted(95, current.URL, "classify-new-endpoint", "Determine authentication/role requirements and compare the endpoint across controlled identities before broader testing.", "Stop after auth, role and parameter shape are classified."))
			continue
		}
		if !sameStrings(previous.Parameters, current.Parameters) {
			out.Changes = append(out.Changes, Change{Kind: ChangeEndpointParameters, Asset: key, Priority: 85, Reason: fmt.Sprintf("parameter set changed from %v to %v", previous.Parameters, current.Parameters)})
			out.Suggestions = append(out.Suggestions, targeted(85, current.URL, "review-changed-parameters", "New or changed parameters can introduce authorization, mass-assignment or input-validation paths.", "Test only the changed parameter set and stop after bounded coverage."))
		}
		if previous.ResponseFingerprint != "" && current.ResponseFingerprint != "" && previous.ResponseFingerprint != current.ResponseFingerprint {
			out.Changes = append(out.Changes, Change{Kind: ChangeResponseFingerprint, Asset: key, Priority: 70, Reason: "response fingerprint changed"})
			out.Suggestions = append(out.Suggestions, targeted(70, current.URL, "revalidate-endpoint-behavior", "Behavior changed on an existing endpoint; re-check the previously relevant control rather than rescanning the whole scope.", "Stop after the changed behavior is classified and prior assumptions are revalidated."))
		}
	}

	diffHashMap(before.JavaScript, after.JavaScript, ChangeJavaScript, 75, &out,
		"review-changed-javascript", "Changed JavaScript may expose new routes, parameters or client-side workflow transitions.", "Inspect only the changed asset and any newly referenced endpoints.")
	diffHashMap(before.APISchemas, after.APISchemas, ChangeAPISchema, 90, &out,
		"review-api-schema-diff", "An API schema change is high-signal for newly exposed operations, objects or authorization boundaries.", "Diff the changed schema and test only new/modified operations.")
	diffValueMap(before.Technologies, after.Technologies, &out)

	sort.SliceStable(out.Changes, func(i, j int) bool {
		if out.Changes[i].Priority == out.Changes[j].Priority {
			return out.Changes[i].Asset < out.Changes[j].Asset
		}
		return out.Changes[i].Priority > out.Changes[j].Priority
	})
	sort.SliceStable(out.Suggestions, func(i, j int) bool {
		if out.Suggestions[i].Priority == out.Suggestions[j].Priority {
			return out.Suggestions[i].Target < out.Suggestions[j].Target
		}
		return out.Suggestions[i].Priority > out.Suggestions[j].Priority
	})
	return out
}

func targeted(priority int, target, test, why, stop string) RetestSuggestion {
	return RetestSuggestion{
		Priority:      priority,
		Target:        target,
		Test:          test,
		Why:           why,
		Scope:         "targeted-change-only",
		StopCondition: stop,
	}
}

func diffHashMap(before, after map[string]string, kind ChangeKind, priority int, out *DiffResult, test, why, stop string) {
	for asset, hash := range after {
		old, existed := before[asset]
		if existed && old == hash {
			continue
		}
		reason := "new asset observed"
		if existed {
			reason = "content hash changed"
		}
		out.Changes = append(out.Changes, Change{Kind: kind, Asset: asset, Priority: priority, Reason: reason})
		out.Suggestions = append(out.Suggestions, targeted(priority, asset, test, why, stop))
	}
}

func diffValueMap(before, after map[string]string, out *DiffResult) {
	for tech, version := range after {
		old, existed := before[tech]
		if existed && old == version {
			continue
		}
		reason := fmt.Sprintf("technology %s appeared at version %s", tech, version)
		if existed {
			reason = fmt.Sprintf("technology %s changed from %s to %s", tech, old, version)
		}
		out.Changes = append(out.Changes, Change{Kind: ChangeTechnology, Asset: tech, Priority: 50, Reason: reason})
		out.Suggestions = append(out.Suggestions, targeted(50, tech, "review-technology-change", "A technology/version change can invalidate prior assumptions and change the relevant vulnerability classes.", "Review only the changed technology and affected endpoints."))
	}
}

func addedStrings(before, after []string) []string {
	seen := make(map[string]struct{}, len(before))
	for _, value := range before {
		seen[strings.TrimSpace(value)] = struct{}{}
	}
	var out []string
	for _, value := range after {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; !ok {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func endpointMap(in []Endpoint) map[string]Endpoint {
	out := make(map[string]Endpoint, len(in))
	for i := range in {
		ep := in[i]
		ep.Method = normalizedMethod(ep.Method)
		ep.Parameters = sortedStrings(ep.Parameters)
		out[endpointKey(ep)] = ep
	}
	return out
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aa, bb := sortedStrings(a), sortedStrings(b)
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}
