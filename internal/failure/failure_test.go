package failure

import (
	"errors"
	"testing"
)

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "context deadline exceeded" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestClassify(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		body       string
		err        error
		wantReason Reason
		wantDead   bool
		wantMut    bool
		wantAction bool
	}{
		{"404 is a dead end", 404, "", nil, ReasonNotFound, true, false, false},
		{"timeout is a dead end", 0, "", timeoutErr{}, ReasonTimeout, true, false, true},
		{"conn refused is a dead end", 0, "", errors.New("connection refused"), ReasonUnreachable, true, false, true},
		{"no status is unreachable", 0, "", nil, ReasonUnreachable, true, false, true},
		{"200 is success", 200, "ok", nil, ReasonSuccess, false, false, false},
		{"401 needs auth", 401, "", nil, ReasonAuthNeeded, false, false, true},
		{"403 needs auth", 403, "forbidden", nil, ReasonAuthNeeded, false, false, true},
		{"cloudflare block", 403, "Attention Required! | Cloudflare error 1020", nil, ReasonBlocked, false, false, true},
		{"429 is blocked", 429, "", nil, ReasonBlocked, false, false, true},
		{"400 is mutable", 400, "bad json", nil, ReasonRejected, false, true, false},
		{"422 is mutable", 422, "", nil, ReasonRejected, false, true, false},
		{"5xx server error", 500, "", nil, ReasonServerError, false, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := Classify(c.status, c.body, c.err)
			if r.Reason != c.wantReason {
				t.Errorf("reason = %s, want %s", r.Reason, c.wantReason)
			}
			if r.DeadEnd != c.wantDead {
				t.Errorf("deadEnd = %v, want %v", r.DeadEnd, c.wantDead)
			}
			if r.Mutable != c.wantMut {
				t.Errorf("mutable = %v, want %v", r.Mutable, c.wantMut)
			}
			if (r.Actionable != "") != c.wantAction {
				t.Errorf("actionable=%q, want present=%v", r.Actionable, c.wantAction)
			}
		})
	}
}

// The key #9 property: a 404 or timeout must be a dead end (never mutated),
// while a 400 must be mutable (worth refining the payload).
func TestClassify_DeadEndVsMutable(t *testing.T) {
	if !Classify(404, "", nil).DeadEnd {
		t.Error("404 must be a dead end")
	}
	if Classify(404, "", nil).Mutable {
		t.Error("404 must not be mutable")
	}
	if !Classify(400, "", nil).Mutable {
		t.Error("400 must be mutable")
	}
	if Classify(400, "", nil).DeadEnd {
		t.Error("400 must not be a dead end")
	}
}
