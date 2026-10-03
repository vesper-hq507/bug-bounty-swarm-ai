package monitor

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/clientcode"
)

type ChangeKind string

const (
	ChangeNewSubdomain        ChangeKind = "new-subdomain"
	ChangeNewHost             ChangeKind = "new-host"
	ChangeNewEndpoint         ChangeKind = "new-endpoint"
	ChangeEndpointParameters  ChangeKind = "endpoint-parameters-changed"
	ChangeEndpointProtocol    ChangeKind = "endpoint-protocol-changed"
	ChangeResponseFingerprint ChangeKind = "response-fingerprint-changed"
	ChangeJavaScript          ChangeKind = "javascript-changed"
	ChangeClientRoute         ChangeKind = "client-route-added"
	ChangeClientRealtime      ChangeKind = "client-realtime-added"
	ChangeClientParameter     ChangeKind = "client-parameter-added"
	ChangeClientFeatureFlag   ChangeKind = "client-feature-flag-added"
	ChangeClientRoleHint      ChangeKind = "client-role-hint-added"
	ChangeClientWorkflowState ChangeKind = "client-workflow-state-added"
	ChangeClientSourceMap     ChangeKind = "client-source-map-changed"
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
	Priority         int    `json:"priority"`
	Target           string `json:"target"`
	Test             string `json:"test"`
	Hypothesis       string `json:"hypothesis,omitempty"`
	ExpectedSignal   string `json:"expected_signal,omitempty"`
	RequiredIdentity string `json:"required_identity,omitempty"`
	ApprovalClass    string `json:"approval_class,omitempty"`
	Why              string `json:"why"`
	Scope            string `json:"scope"`
	StopCondition    string `json:"stop_condition"`
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
			priority := 95
			test := "classify-new-endpoint"
			why := "Determine authentication/role requirements and compare the endpoint across controlled identities before broader testing."
			stop := "Stop after auth, role and parameter shape are classified."
			if isRealtimeProtocol(current.Protocol) {
				priority = 97
				test = "observe-new-realtime-endpoint"
				why = "A newly observed realtime endpoint can carry identity- or tenant-scoped events that are not visible in ordinary request/response coverage."
				stop = "Perform one bounded receive-only observation and stop after the stream authorization/payload shape is classified."
			}
			out.Changes = append(out.Changes, Change{Kind: ChangeNewEndpoint, Asset: key, Priority: priority, Reason: "new endpoint appeared"})
			out.Suggestions = append(out.Suggestions, targeted(priority, current.URL, test, why, stop))
			continue
		}
		if normalizedProtocol(previous.Protocol) != normalizedProtocol(current.Protocol) {
			out.Changes = append(out.Changes, Change{
				Kind: ChangeEndpointProtocol, Asset: key, Priority: 90,
				Reason: fmt.Sprintf("protocol changed from %s to %s", normalizedProtocol(previous.Protocol), normalizedProtocol(current.Protocol)),
			})
			out.Suggestions = append(out.Suggestions, targeted(
				90, current.URL, "reclassify-endpoint-protocol",
				"A protocol change can introduce persistent-stream authorization and event-boundary behavior not covered by the prior endpoint model.",
				"Classify only the changed protocol using bounded receive-only observation.",
			))
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

	diffClientCode(before.ClientCode, after.ClientCode, &out)
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

func isRealtimeProtocol(protocol string) bool {
	switch normalizedProtocol(protocol) {
	case "sse", "websocket":
		return true
	default:
		return false
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
		ep.Protocol = normalizedProtocol(ep.Protocol)
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


func diffClientCode(before, after map[string]clientcode.Summary, out *DiffResult) {
	for asset := range after {
		current := after[asset]
		previous := before[asset]
		for _, route := range addedStrings(previous.Routes, current.Routes) {
			addClientSuggestion(out, ChangeClientRoute, 94, route, "review-client-route",
				"Client code references a newly observed application route that may expose a new authorization or object boundary.",
				"Confirm whether the route is reachable and classify its authentication/authorization requirements using one bounded request.",
				"current controlled identity if authentication is required", "observe", asset)
		}
		for _, endpoint := range addedStrings(previous.RealtimeEndpoints, current.RealtimeEndpoints) {
			addClientSuggestion(out, ChangeClientRealtime, 97, endpoint, "observe-client-realtime-endpoint",
				"Client code references a newly observed realtime endpoint whose event authorization may differ from ordinary HTTP coverage.",
				"A bounded receive-only observation identifies whether stream access or payload classes cross identity/tenant boundaries.",
				"current controlled identity/session if authentication is required", "observe", asset)
		}
		for _, param := range addedStrings(previous.Parameters, current.Parameters) {
			addClientSuggestion(out, ChangeClientParameter, 86, asset, "review-client-parameter",
				fmt.Sprintf("Client code newly references parameter %q, which may alter object selection, filtering, or server-side behavior.", param),
				"One bounded request determines whether the parameter changes an authorization, object, or input-validation boundary.",
				"same controlled identity used for the baseline", "observe", asset)
		}
		for _, role := range addedStrings(previous.RoleHints, current.RoleHints) {
			addClientSuggestion(out, ChangeClientRoleHint, 88, asset, "review-client-role-boundary",
				fmt.Sprintf("Client code contains a newly observed role hint %q; client-side role gating must not substitute for server authorization.", role),
				"Server behavior remains correctly authorized when the corresponding client-side role path is reached or omitted.",
				"two controlled roles when available", "observe", asset)
		}
		for _, state := range addedStrings(previous.WorkflowStates, current.WorkflowStates) {
			addClientSuggestion(out, ChangeClientWorkflowState, 84, asset, "review-client-workflow-state",
				fmt.Sprintf("Client code exposes a newly observed workflow state %q that may reveal a server-side transition invariant.", state),
				"The server enforces required transition prerequisites independently of client-side navigation.",
				"same controlled identity context as the workflow", "observe", asset)
		}
		for _, flag := range addedStrings(previous.FeatureFlags, current.FeatureFlags) {
			addClientSuggestion(out, ChangeClientFeatureFlag, 72, asset, "review-client-feature-gate",
				fmt.Sprintf("Client code exposes feature flag %q; disabled UI paths can still map to live server-side functionality.", flag),
				"Only explicitly enabled server-side functionality is reachable for the controlled identity.",
				"current controlled identity", "observe", asset)
		}
		if current.SourceMapHash != "" && current.SourceMapHash != previous.SourceMapHash {
			reason := "source map appeared or changed"
			out.Changes = append(out.Changes, Change{Kind: ChangeClientSourceMap, Asset: asset, Priority: 78, Reason: reason})
			out.Suggestions = append(out.Suggestions, RetestSuggestion{
				Priority: 78, Target: asset, Test: "review-source-map-change",
				Hypothesis: "A source-map change may expose newly added client routes, role gates, feature flags, or workflow states.",
				ExpectedSignal: "Only newly added source-map signals are promoted into bounded follow-up tests.",
				RequiredIdentity: "none", ApprovalClass: "observe",
				Why: "Source maps can make client-side application boundaries explicit without executing the code.",
				Scope: "targeted-change-only",
				StopCondition: "Stop after the changed sources are statically analyzed; do not execute embedded code.",
			})
		}
	}
}

func addClientSuggestion(out *DiffResult, kind ChangeKind, priority int, target, test, hypothesis, expected, identity, approval, asset string) {
	out.Changes = append(out.Changes, Change{Kind: kind, Asset: target, Priority: priority, Reason: "new signal derived from " + asset})
	out.Suggestions = append(out.Suggestions, RetestSuggestion{
		Priority: priority, Target: target, Test: test,
		Hypothesis: hypothesis, ExpectedSignal: expected,
		RequiredIdentity: identity, ApprovalClass: approval,
		Why: "Static client-code analysis identified a bounded new signal in " + asset + ".",
		Scope: "targeted-change-only",
		StopCondition: "Test only the newly derived signal and stop after its server-side behavior is classified.",
	})
}
