package preflight

import (
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/approval"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/benchmark"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/identity"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/policygateway"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope/programterms"
	"github.com/google/uuid"
)

type Input struct {
	Target               string
	Scope                scope.ScopeDefinition
	Constraints          programterms.Constraints
	Identities           []identity.Identity
	PrimaryIdentity      identity.ID
	ApprovedCapabilities []string
	StateDir             string
	MaxDuration          time.Duration
	MaxRequestsPerSecond float64
	ActiveScan           bool
	SafeMode             bool
	Assist               bool
}

type Check struct {
	Name     string `json:"name"`
	Passed   bool   `json:"passed"`
	Required bool   `json:"required"`
	Detail   string `json:"detail"`
}

type Report struct {
	Ready         bool             `json:"ready"`
	Target        string           `json:"target"`
	PolicyVersion string           `json:"policy_version,omitempty"`
	Checks        []Check          `json:"checks"`
	Warnings      []string         `json:"warnings,omitempty"`
	Benchmark     benchmark.Report `json:"benchmark"`
}

func Run(ctx context.Context, in Input) (Report, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	report := Report{Target: strings.TrimSpace(in.Target)}
	add := func(name string, passed, required bool, detail string) {
		report.Checks = append(report.Checks, Check{
			Name: name, Passed: passed, Required: required, Detail: detail,
		})
	}

	if report.Target == "" {
		add("target", false, true, "target is required")
	} else if err := scope.Validate(report.Target, in.Scope); err != nil {
		add("target-scope", false, true, err.Error())
	} else {
		add("target-scope", true, true, "target is inside the supplied program scope")
	}

	effectiveRPS := in.Constraints.MaxRequestsPerSecond
	if in.MaxRequestsPerSecond > 0 && (effectiveRPS <= 0 || in.MaxRequestsPerSecond < effectiveRPS) {
		effectiveRPS = in.MaxRequestsPerSecond
	}
	if in.MaxRequestsPerSecond > 0 && in.Constraints.MaxRequestsPerSecond > 0 &&
		in.MaxRequestsPerSecond > in.Constraints.MaxRequestsPerSecond {
		report.Warnings = append(report.Warnings,
			fmt.Sprintf("requested --max-rps %.3f was clamped to stricter program limit %.3f",
				in.MaxRequestsPerSecond, in.Constraints.MaxRequestsPerSecond))
	}
	if effectiveRPS <= 0 {
		add("global-rate-limit", false, true, "no program rate limit or explicit --max-rps was supplied")
	} else {
		add("global-rate-limit", true, true, fmt.Sprintf("%.3f requests/second", effectiveRPS))
	}

	maxDuration := in.MaxDuration
	if maxDuration <= 0 {
		add("campaign-timeout", false, true, "hard campaign duration must be positive")
	} else {
		add("campaign-timeout", true, true, maxDuration.String())
	}

	policyCompatible := true
	var policyReasons []string
	if in.Constraints.NoAutomatedScanning {
		if in.ActiveScan {
			policyCompatible = false
			policyReasons = append(policyReasons, "active scanning requested while program terms forbid automated scanning")
		}
		if !in.SafeMode {
			policyCompatible = false
			policyReasons = append(policyReasons, "safe mode is required when automated scanning is forbidden")
		}
		if !in.Assist {
			policyCompatible = false
			policyReasons = append(policyReasons, "assist mode is required when automated scanning is forbidden")
		}
	}
	if in.Constraints.NoDoS {
		report.Warnings = append(report.Warnings, "program forbids denial-of-service/stress testing")
	}
	if in.Constraints.NoBruteForce {
		report.Warnings = append(report.Warnings, "program forbids brute-force/password guessing")
	}
	if in.Constraints.NoSocialEngineering {
		report.Warnings = append(report.Warnings, "program forbids social engineering")
	}
	if in.Constraints.NoPhysical {
		report.Warnings = append(report.Warnings, "program forbids physical-security testing")
	}
	if len(in.Constraints.Notes) > 0 {
		report.Warnings = append(report.Warnings, "program parser left policy notes that require manual review")
	}
	if policyCompatible {
		add("program-policy-mode", true, true, "requested operating mode is compatible with extracted program constraints")
	} else {
		add("program-policy-mode", false, true, strings.Join(policyReasons, "; "))
	}

	idsOK, idsDetail := validateIdentities(in.Identities, in.PrimaryIdentity)
	add("identity-context", idsOK, true, idsDetail)

	capsOK, capsDetail := validateCapabilities(in.ApprovedCapabilities)
	add("approval-capabilities", capsOK, true, capsDetail)

	stateOK, stateDetail := validateStateDir(in.StateDir)
	add("durable-state", stateOK, true, stateDetail)

	burst := effectiveRPS
	if burst > 0 {
		burst = math.Max(1, burst)
	}
	gateway := policygateway.New(policygateway.Policy{
		Scope: in.Scope,
		RequiredHeaders: in.Constraints.RequiredHeaders,
		DisallowedPaths: in.Constraints.DisallowedPaths,
		RequestsPerSecond: effectiveRPS,
		Burst: burst,
	})
	report.PolicyVersion = gateway.PolicyVersion()
	if report.Target != "" {
		action := policygateway.Action{
			ActionID: "preflight-target-check",
			CampaignID: uuid.NewString(),
			ActorID: "preflight",
			Kind: policygateway.ActionHTTP,
			Method: "GET",
			URL: report.Target,
		}
		if decision, err := gateway.Decide(ctx, action); err != nil {
			add("policy-gateway", false, true, err.Error())
		} else {
			add("policy-gateway", decision.Allowed && decision.PolicyVersion != "", true,
				"fail-closed gateway accepted the target without performing network I/O")
		}
	} else {
		add("policy-gateway", false, true, "target unavailable for policy decision")
	}

	bench, err := benchmark.RunControlled(ctx, filepath.Join(strings.TrimSpace(in.StateDir), "preflight-benchmark"))
	if err != nil {
		add("controlled-benchmark", false, true, err.Error())
	} else {
		report.Benchmark = bench
		add("controlled-benchmark", bench.Passed, true, bench.Summary())
	}

	report.Ready = true
	for i := range report.Checks {
		if report.Checks[i].Required && !report.Checks[i].Passed {
			report.Ready = false
			break
		}
	}
	return report, nil
}

func validateIdentities(ids []identity.Identity, primary identity.ID) (ok bool, detail string) {
	if len(ids) == 0 {
		return true, "anonymous/read-only campaign identity will be used"
	}
	registry := identity.NewRegistry()
	for i := range ids {
		if err := registry.Add(ids[i]); err != nil {
			return false, err.Error()
		}
	}
	if len(ids) > 1 && primary == "" {
		return false, "primary identity is required when more than one controlled identity is configured"
	}
	if primary == "" {
		primary = ids[0].ID
	}
	if _, err := registry.Get(primary); err != nil {
		return false, fmt.Sprintf("primary identity %q is not configured", primary)
	}
	return true, fmt.Sprintf("%d controlled identity/identities configured; primary=%s", len(ids), primary)
}

func validateCapabilities(values []string) (ok bool, detail string) {
	if len(values) == 0 {
		return true, "no sensitive capabilities are pre-approved; read-only observation remains automatic"
	}
	seen := map[approval.Capability]struct{}{}
	for _, raw := range values {
		capability, err := approval.ParseCapability(raw)
		if err != nil {
			return false, err.Error()
		}
		if capability == approval.CapabilityObserve {
			continue
		}
		seen[capability] = struct{}{}
	}
	return true, fmt.Sprintf("%d sensitive capability grant(s) validated", len(seen))
}

func validateStateDir(root string) (ok bool, detail string) {
	root = strings.TrimSpace(root)
	if root == "" {
		return false, "state directory is required"
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return false, err.Error()
	}
	tmp, err := os.MkdirTemp(root, ".preflight-*")
	if err != nil {
		return false, err.Error()
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	probe := filepath.Join(tmp, "write-probe")
	if err := os.WriteFile(probe, []byte("preflight"), 0o600); err != nil {
		return false, err.Error()
	}
	if _, err := pipeline.NewFileCleanupRegistry(filepath.Join(tmp, "cleanup"), nil); err != nil {
		return false, fmt.Sprintf("cleanup ledger unavailable: %v", err)
	}
	return true, "durable state directory is writable and cleanup ledger can be initialized"
}
