package approval

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

func TestStaticBrokerAllowsReadOnlyAutomatically(t *testing.T) {
	b := NewStaticBroker(nil, nil, false)
	grant, err := b.Authorize(context.Background(), Request{
		CampaignID: uuid.New(), Capability: CapabilityObserve,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !grant.Granted || grant.Source != "automatic-read-only" {
		t.Fatalf("grant = %+v", grant)
	}
}

func TestStaticBrokerDeniesSensitiveWithoutGrant(t *testing.T) {
	b := NewStaticBroker(nil, nil, false)
	_, err := b.Authorize(context.Background(), Request{
		CampaignID: uuid.New(), Capability: CapabilityStateChange,
		Reason: "POST changes server state",
	})
	if !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("err = %v, want approval required", err)
	}
}

func TestStaticBrokerHonorsCampaignGrant(t *testing.T) {
	b := NewStaticBroker([]Capability{CapabilityConcurrency}, nil, false)
	grant, err := b.Authorize(context.Background(), Request{
		CampaignID: uuid.New(), Capability: CapabilityConcurrency,
	})
	if err != nil {
		t.Fatal(err)
	}
	if grant.Source != "campaign-grant" {
		t.Fatalf("grant = %+v", grant)
	}
}

func TestStaticBrokerPromptsWhenConfigured(t *testing.T) {
	called := false
	b := NewStaticBroker(nil, func(_ context.Context, req Request) (bool, error) {
		called = true
		return req.Capability == CapabilityUpload, nil
	}, false)
	if _, err := b.Authorize(context.Background(), Request{Capability: CapabilityUpload}); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("prompt was not called")
	}
}

func TestClassifyHTTPCannotDowngradeRace(t *testing.T) {
	if got := ClassifyHTTP(string(CapabilityObserve), http.MethodGet, "https://example.test/items", 3); got != CapabilityConcurrency {
		t.Fatalf("got %q", got)
	}
}

func TestClassifyHTTPPromotesAccountAndUpload(t *testing.T) {
	if got := ClassifyHTTP("", http.MethodPost, "https://example.test/account/password", 0); got != CapabilityAccountChange {
		t.Fatalf("account capability = %q", got)
	}
	if got := ClassifyHTTP("", http.MethodPost, "https://example.test/api/upload", 0); got != CapabilityUpload {
		t.Fatalf("upload capability = %q", got)
	}
}
