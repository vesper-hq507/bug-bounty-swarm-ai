package preflight

import (
	"context"
	"testing"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/identity"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope/programterms"
)

func TestRunReadyForBoundedControlledPilot(t *testing.T) {
	report, err := Run(context.Background(), Input{
		Target: "https://api.example.test/api/me",
		Scope: scope.ScopeDefinition{AllowedDomains: []string{"example.test"}},
		Constraints: programterms.Constraints{
			MaxRequestsPerSecond: 2,
			RequiredHeaders: map[string]string{"X-Bugbounty-User": "researcher"},
			DisallowedPaths: []string{"/admin"},
		},
		Identities: []identity.Identity{{
			ID: "user-a", Alias: "User A", Role: identity.RoleUser, SessionRef: "vault:user-a",
		}},
		PrimaryIdentity: "user-a",
		StateDir: t.TempDir(),
		MaxDuration: 10 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Ready {
		t.Fatalf("preflight not ready: %+v", report.Checks)
	}
	if report.PolicyVersion == "" || !report.Benchmark.Passed {
		t.Fatalf("policy/benchmark missing: %+v", report)
	}
	for i := range report.Checks {
		if report.Checks[i].Required && !report.Checks[i].Passed {
			t.Fatalf("required check failed: %+v", report.Checks[i])
		}
	}
}

func TestRunBlocksUnsafeModeAndMissingTrafficLimit(t *testing.T) {
	report, err := Run(context.Background(), Input{
		Target: "https://api.example.test/api/me",
		Scope: scope.ScopeDefinition{AllowedDomains: []string{"example.test"}},
		Constraints: programterms.Constraints{NoAutomatedScanning: true},
		StateDir: t.TempDir(),
		MaxDuration: 10 * time.Minute,
		ActiveScan: true,
		SafeMode: false,
		Assist: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Ready {
		t.Fatalf("unsafe preflight unexpectedly ready: %+v", report.Checks)
	}
	var rateFailed, policyFailed bool
	for i := range report.Checks {
		switch report.Checks[i].Name {
		case "global-rate-limit":
			rateFailed = !report.Checks[i].Passed
		case "program-policy-mode":
			policyFailed = !report.Checks[i].Passed
		}
	}
	if !rateFailed || !policyFailed {
		t.Fatalf("expected rate and policy failures: %+v", report.Checks)
	}
}


func TestRunReadyForExactSourceCodePilotWithoutRPS(t *testing.T) {
	repoURL := "https://github.com/circlefin/arc-node"
	report, err := Run(context.Background(), Input{
		Target:     repoURL,
		SourceCode: true,
		Scope: scope.ScopeDefinition{
			AllowedSourceCode: []string{repoURL},
			SourceCodeInstructions: map[string]string{
				repoURL: "review repository source only",
			},
		},
		Constraints: programterms.Constraints{},
		StateDir:    t.TempDir(),
		MaxDuration: 10 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Ready {
		t.Fatalf("source preflight not ready: %+v", report.Checks)
	}
	var sawInstruction bool
	for _, warning := range report.Warnings {
		if warning == "source-code scope instruction: review repository source only" {
			sawInstruction = true
		}
	}
	if !sawInstruction {
		t.Fatalf("source instruction warning missing: %+v", report.Warnings)
	}
}

func TestRunBlocksOutOfScopeSourceCodeRepository(t *testing.T) {
	report, err := Run(context.Background(), Input{
		Target:     "https://github.com/circlefin/not-allowed",
		SourceCode: true,
		Scope: scope.ScopeDefinition{
			AllowedSourceCode: []string{"https://github.com/circlefin/arc-node"},
		},
		StateDir:    t.TempDir(),
		MaxDuration: 5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Ready {
		t.Fatalf("out-of-scope source repository unexpectedly ready: %+v", report.Checks)
	}
}

func TestRunBlocksActiveNetworkScanInSourceMode(t *testing.T) {
	repoURL := "https://github.com/circlefin/arc-node"
	report, err := Run(context.Background(), Input{
		Target:     repoURL,
		SourceCode: true,
		Scope:      scope.ScopeDefinition{AllowedSourceCode: []string{repoURL}},
		StateDir:   t.TempDir(),
		MaxDuration: 5 * time.Minute,
		ActiveScan: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Ready {
		t.Fatal("source-code preflight with active network scan must fail")
	}
}

func TestRunRequiresPrimaryIdentityForMultiIdentityCampaign(t *testing.T) {
	report, err := Run(context.Background(), Input{
		Target: "https://api.example.test/api/me",
		Scope: scope.ScopeDefinition{AllowedDomains: []string{"example.test"}},
		Constraints: programterms.Constraints{MaxRequestsPerSecond: 1},
		Identities: []identity.Identity{
			{ID: "user-a", Alias: "User A", Role: identity.RoleUser, SessionRef: "vault:user-a"},
			{ID: "user-b", Alias: "User B", Role: identity.RoleUser, SessionRef: "vault:user-b"},
		},
		StateDir: t.TempDir(),
		MaxDuration: 5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Ready {
		t.Fatal("multi-identity preflight without primary identity must fail")
	}
}


func TestRunClampsOperatorRPSAgainstStricterProgramLimit(t *testing.T) {
	report, err := Run(context.Background(), Input{
		Target: "https://api.example.test/api/me",
		Scope: scope.ScopeDefinition{AllowedDomains: []string{"example.test"}},
		Constraints: programterms.Constraints{MaxRequestsPerSecond: 1},
		StateDir: t.TempDir(),
		MaxDuration: 5 * time.Minute,
		MaxRequestsPerSecond: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Ready {
		t.Fatalf("preflight unexpectedly failed: %+v", report.Checks)
	}
	var foundClamp bool
	for _, warning := range report.Warnings {
		if warning == "requested --max-rps 10.000 was clamped to stricter program limit 1.000" {
			foundClamp = true
		}
	}
	if !foundClamp {
		t.Fatalf("clamp warning missing: %+v", report.Warnings)
	}
}
