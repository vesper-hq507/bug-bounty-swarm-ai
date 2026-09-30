// Package coverage produces an honest "what did we actually test, and how much
// can you trust this?" assessment for a campaign report.
//
// It exists because of a real failure mode a bug-bounty hunter flagged: a tool
// can hand back a clean, professional-looking report — even "zero findings,
// assessment complete" — for a target it never actually reached (blocked by a
// WAF/CDN, recon failed, or it fell back to canned paths). A security team
// reads that as "we're secure" when the truth is "we don't know." This package
// makes the report say which of those it is.
package coverage

import "fmt"

// Level is the confidence the report should convey in its own results.
type Level string

const (
	LevelHigh   Level = "high"
	LevelMedium Level = "medium"
	LevelLow    Level = "low"
)

// Inputs are the raw signals gathered from the campaign's blackboard.
type Inputs struct {
	Target string

	// ReconObservations is how many recon facts (endpoints, services, ports,
	// technologies, subdomains) were established for the target. Zero means we
	// never got a meaningful response — we did not reach the app.
	ReconObservations int
	// Endpoints is the number of distinct HTTP endpoints discovered.
	Endpoints int
	// BlockedSignals counts WAF/CDN/blocked indicators observed (Cloudflare
	// 1101, 403 from a WAF, connection resets, mass timeouts).
	BlockedSignals int

	// Findings that made it into the report, split by whether they carry a
	// reproduction that was actually confirmed (Verified) or reached the report
	// without proof (Unverified).
	Verified   int
	Unverified int
}

// Assessment is the honest coverage verdict rendered into the report.
type Assessment struct {
	Target        string
	Reached       bool
	Blocked       bool
	Endpoints     int
	TotalFindings int
	Verified      int
	Unverified    int
	Confidence    Level
	Caveats       []string
	// Summary is a one-paragraph plain-English verdict, including the qualified
	// zero-finding language when there are no findings.
	Summary string
}

// Assess turns raw signals into an honest coverage verdict.
func Assess(in Inputs) Assessment {
	a := Assessment{
		Target:        in.Target,
		Endpoints:     in.Endpoints,
		Verified:      in.Verified,
		Unverified:    in.Unverified,
		TotalFindings: in.Verified + in.Unverified,
		Reached:       in.ReconObservations > 0,
		// Blocked is asserted only when we saw block signals AND nothing got
		// through — block signals alongside real responses just mean a WAF is
		// present, not that testing failed.
		Blocked: in.BlockedSignals > 0 && in.ReconObservations == 0,
	}

	switch {
	case !a.Reached || a.Blocked:
		a.Confidence = LevelLow
	case a.Endpoints < 3, a.TotalFindings > 0 && a.Verified == 0, a.Unverified > a.Verified:
		// Shallow coverage, or a finding set that's mostly (or entirely)
		// unproven, does not earn high confidence.
		a.Confidence = LevelMedium
	default:
		a.Confidence = LevelHigh
	}

	if a.Blocked {
		a.Caveats = append(a.Caveats, "Requests appear to have been blocked by a WAF/CDN (e.g. Cloudflare) — the application was likely never reached.")
	} else if !a.Reached {
		a.Caveats = append(a.Caveats, "No successful responses were observed from the target — it may be down, out of scope, or unreachable from here.")
	}
	if a.Reached && a.Endpoints > 0 && a.Endpoints < 3 {
		a.Caveats = append(a.Caveats, fmt.Sprintf("Only %d endpoint(s) were discovered — coverage is shallow; authenticated or JavaScript-rendered surface may be untested.", a.Endpoints))
	}
	if a.Unverified > 0 {
		a.Caveats = append(a.Caveats, fmt.Sprintf("%d finding(s) are UNVERIFIED — no reproduction was confirmed, so treat them as leads, not proven vulnerabilities.", a.Unverified))
	}

	a.Summary = summarize(a)
	return a
}

func summarize(a Assessment) string {
	if a.TotalFindings == 0 {
		if a.Blocked {
			return fmt.Sprintf("INCONCLUSIVE. No findings — but the requests to %s appear to have been blocked before reaching the application, so this is NOT evidence that the target is secure. Re-run with a browser engine / WAF evasion or from an allowed source.", a.Target)
		}
		if !a.Reached {
			return fmt.Sprintf("INCONCLUSIVE. No findings — but the target %s was never reliably reached, so zero findings does NOT mean it is secure. Verify reachability and scope, then re-run.", a.Target)
		}
		return fmt.Sprintf("No vulnerabilities were found across %d endpoint(s) tested on %s. This is a limited negative result for the surface actually reached — not a security guarantee for the whole application.", a.Endpoints, a.Target)
	}

	base := fmt.Sprintf("%d finding(s) reported for %s (%d verified, %d unverified) across %d endpoint(s). Confidence in this assessment: %s.",
		a.TotalFindings, a.Target, a.Verified, a.Unverified, a.Endpoints, a.Confidence)
	if a.Confidence == LevelLow {
		base += " Coverage was limited (see caveats) — absence of other findings is not conclusive."
	}
	return base
}
