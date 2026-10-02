package approval

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Capability string

const (
	CapabilityObserve       Capability = "observe"
	CapabilityStateChange   Capability = "state-change"
	CapabilityAccountChange Capability = "account-change"
	CapabilityUpload        Capability = "upload"
	CapabilityConcurrency   Capability = "concurrency"
	CapabilityProofImpact   Capability = "proof-impact"
)

var validCapabilities = map[Capability]struct{}{
	CapabilityObserve:       {},
	CapabilityStateChange:   {},
	CapabilityAccountChange: {},
	CapabilityUpload:        {},
	CapabilityConcurrency:   {},
	CapabilityProofImpact:   {},
}

func ParseCapability(raw string) (Capability, error) {
	c := Capability(strings.ToLower(strings.TrimSpace(raw)))
	if _, ok := validCapabilities[c]; !ok {
		return "", fmt.Errorf("unknown approval capability %q", raw)
	}
	return c, nil
}

func ValidCapabilities() []string {
	out := make([]string, 0, len(validCapabilities))
	for c := range validCapabilities {
		out = append(out, string(c))
	}
	sort.Strings(out)
	return out
}

type Request struct {
	CampaignID    uuid.UUID
	ActionID      string
	ActorID       string
	IdentityAlias string
	Capability    Capability
	StepName      string
	Command       string
	Method        string
	Target        string
	Tool          string
	Technique     string
	Reason        string
}

type Grant struct {
	ID         string
	Capability Capability
	Granted    bool
	Source     string
	Reason     string
	GrantedAt  time.Time
}

type Broker interface {
	Authorize(context.Context, Request) (Grant, error)
}

type PromptFunc func(context.Context, Request) (bool, error)

var ErrApprovalRequired = errors.New("explicit approval required")

type RequiredError struct {
	Request Request
}

func (e *RequiredError) Error() string {
	if e == nil {
		return ErrApprovalRequired.Error()
	}
	return fmt.Sprintf("%s for capability %q: %s", ErrApprovalRequired, e.Request.Capability, e.Request.Reason)
}

func (e *RequiredError) Unwrap() error { return ErrApprovalRequired }

type StaticBroker struct {
	approved      map[Capability]struct{}
	prompt        PromptFunc
	promptObserve bool
}

func NewStaticBroker(approved []Capability, prompt PromptFunc, promptObserve bool) *StaticBroker {
	set := make(map[Capability]struct{}, len(approved))
	for _, c := range approved {
		if _, ok := validCapabilities[c]; ok {
			set[c] = struct{}{}
		}
	}
	return &StaticBroker{approved: set, prompt: prompt, promptObserve: promptObserve}
}

func (b *StaticBroker) Authorize(ctx context.Context, req Request) (Grant, error) {
	if b == nil {
		return Grant{}, &RequiredError{Request: req}
	}
	if _, ok := validCapabilities[req.Capability]; !ok {
		return Grant{}, fmt.Errorf("invalid approval capability %q", req.Capability)
	}
	if req.Capability == CapabilityObserve && !b.promptObserve {
		return newGrant(req.Capability, "automatic-read-only", "read-only observation"), nil
	}
	if _, ok := b.approved[req.Capability]; ok {
		return newGrant(req.Capability, "campaign-grant", "capability pre-approved for this campaign"), nil
	}
	if b.prompt != nil {
		allowed, err := b.prompt(ctx, req)
		if err != nil {
			return Grant{}, err
		}
		if allowed {
			return newGrant(req.Capability, "interactive", "operator approved this action"), nil
		}
	}
	return Grant{}, &RequiredError{Request: req}
}

func newGrant(cap Capability, source, reason string) Grant {
	return Grant{
		ID:         uuid.NewString(),
		Capability: cap,
		Granted:    true,
		Source:     source,
		Reason:     reason,
		GrantedAt:  time.Now().UTC(),
	}
}
