// Package failure classifies why an exploit attempt or HTTP probe failed, so
// the swarm can act on the reason instead of blindly mutating everything that
// didn't succeed.
//
// A bug-bounty hunter flagged the core gap: when an attempt fails the system
// creates a low-signal result and the mutator spins up variants — but "failed"
// lumps together a 404 (the route doesn't exist — a dead end), a timeout (no
// response — a dead end), a 401 (needs authentication — actionable), and a WAF
// block (needs a browser / evasion — actionable). Mutating a dead end just
// floods the blackboard with variations of paths that don't exist. This package
// tells those cases apart: dead ends are dropped, payload-rejections are worth
// mutating, and actionable failures carry a hint for the operator.
package failure

import (
	"errors"
	"net"
	"strings"
)

// Reason is the classified cause of a failed attempt.
type Reason string

const (
	ReasonSuccess     Reason = "success"      // 2xx / 3xx — it worked
	ReasonNotFound    Reason = "not_found"    // 404 — the route/object doesn't exist
	ReasonTimeout     Reason = "timeout"      // no response in time
	ReasonUnreachable Reason = "unreachable"  // connection refused/reset/DNS
	ReasonAuthNeeded  Reason = "auth_needed"  // 401 (or bare 403) — needs a session
	ReasonBlocked     Reason = "blocked"      // WAF/CDN challenge, 429 — needs a browser / evasion
	ReasonRejected    Reason = "rejected"     // 400/422 — payload malformed; worth mutating
	ReasonServerError Reason = "server_error" // 5xx — server-side error
	ReasonOther       Reason = "other"
)

// Result is the classification of one attempt.
type Result struct {
	Reason Reason
	// DeadEnd is true when there is nothing to learn or mutate here (a route
	// that doesn't exist, an unreachable/timed-out request). The mutator must
	// NOT spawn variants of a dead end.
	DeadEnd bool
	// Mutable is true when mutating the payload is the right next move (the
	// request reached the app but was rejected as malformed).
	Mutable bool
	// Actionable, when set, is a one-line hint about what would unblock progress
	// (e.g. supply a session, or use a browser engine).
	Actionable string
}

// blockMarkers are body/hint substrings that identify a WAF/CDN challenge rather
// than a genuine application response.
var blockMarkers = []string{
	"cloudflare", "cf-ray", "attention required", "just a moment",
	"captcha", "access denied", "request blocked", "error 1101", "error 1020",
	"akamai", "incapsula", "please enable javascript", "ddos protection",
}

// Classify determines why an attempt failed from its HTTP status, response body,
// and any transport error. status 0 with a nil error means "no status" (treat as
// unreachable).
func Classify(status int, body string, transportErr error) Result {
	if transportErr != nil {
		if isTimeout(transportErr) {
			return Result{Reason: ReasonTimeout, DeadEnd: true, Actionable: "Target did not respond in time — likely unreachable, rate-limited, or dropping the connection."}
		}
		return Result{Reason: ReasonUnreachable, DeadEnd: true, Actionable: "Could not connect (refused/reset/DNS) — check the target is up and in scope."}
	}

	low := strings.ToLower(body)
	blocked := hasAny(low, blockMarkers)

	switch {
	case status == 0:
		return Result{Reason: ReasonUnreachable, DeadEnd: true, Actionable: "No response — target unreachable."}
	case status >= 200 && status < 400:
		return Result{Reason: ReasonSuccess}
	case status == 404:
		return Result{Reason: ReasonNotFound, DeadEnd: true}
	case status == 429 || blocked:
		return Result{Reason: ReasonBlocked, Actionable: "Requests are being blocked by a WAF/CDN — retry via a real browser engine or from an allowed source."}
	case status == 401:
		return Result{Reason: ReasonAuthNeeded, Actionable: "Endpoint requires authentication — provide a session with --auth/--cookie/--header."}
	case status == 403:
		// A bare 403 is usually authorization; a 403 that smells of a WAF was
		// already caught above via blockMarkers.
		return Result{Reason: ReasonAuthNeeded, Actionable: "Access forbidden — provide a session with the right privileges (--auth/--cookie), or the resource is out of reach without a browser."}
	case status == 400 || status == 422:
		return Result{Reason: ReasonRejected, Mutable: true}
	case status >= 500:
		return Result{Reason: ReasonServerError, Actionable: "Server error — the request reached the app but it failed; the payload may still be worth refining."}
	default:
		return Result{Reason: ReasonOther}
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "timeout") || strings.Contains(s, "deadline exceeded")
}

func hasAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
