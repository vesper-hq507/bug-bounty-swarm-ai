package engine

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/policygateway"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

const (
	// DefaultCampaignTimeout is the hard wall-clock ceiling applied when a
	// caller does not provide a shorter deadline. Individual tools/LLM calls
	// retain their own tighter limits.
	DefaultCampaignTimeout = 30 * time.Minute

	liveScopePollInterval = 2 * time.Second
)

type campaignPolicyRuntime struct {
	scope   *scope.ScopeDefinition
	gateway *policygateway.Gateway
	watcher *scope.Watcher
}

func withCampaignDeadline(ctx context.Context, maxDuration time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if maxDuration <= 0 {
		maxDuration = DefaultCampaignTimeout
	}
	return context.WithTimeout(ctx, maxDuration)
}

func prepareCampaignPolicy(ctx context.Context, cc CampaignConfig) (*campaignPolicyRuntime, error) {
	return prepareCampaignPolicyWithScopeChange(ctx, cc, nil)
}

func prepareCampaignPolicyWithScopeChange(ctx context.Context, cc CampaignConfig, onScopeChange func(scope.Diff)) (*campaignPolicyRuntime, error) {
	var (
		def     *scope.ScopeDefinition
		watcher *scope.Watcher
	)

	if cc.ScopeFile != "" {
		watcher = scope.NewWatcher(cc.ScopeFile, liveScopePollInterval)
		current := watcher.Current()
		if emptyScope(current) {
			return nil, fmt.Errorf("live scope file %q is unreadable, invalid, or empty", cc.ScopeFile)
		}
		def = &current
	} else {
		var err error
		def, err = buildScope(cc.Scope)
		if err != nil {
			return nil, err
		}
	}

	burst := cc.PolicyBurst
	if cc.MaxRequestsPerSecond > 0 && burst <= 0 {
		burst = math.Max(1, cc.MaxRequestsPerSecond)
	}

	gateway := policygateway.New(policygateway.Policy{
		Scope:                *def,
		RequiredHeaders:      cc.RequiredHeaders,
		DisallowedPaths:      cc.DisallowedPaths,
		DisallowedTechniques: cc.DisallowedTechniques,
		RequestsPerSecond:    cc.MaxRequestsPerSecond,
		Burst:                burst,
		DynamicScope:         watcher != nil,
		Version:              cc.PolicyVersion,
	})

	runtime := &campaignPolicyRuntime{
		scope:   def,
		gateway: gateway,
		watcher: watcher,
	}
	if watcher != nil {
		watcher.Start(ctx)
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case diff, ok := <-watcher.Changes():
					if !ok {
						return
					}
					// Current() is intentionally allowed to be empty: an unreadable
					// live scope forces the gateway into fail-closed mode.
					gateway.UpdateScope(watcher.Current())
					if onScopeChange != nil {
						onScopeChange(diff)
					}
				}
			}
		}()
	}

	return runtime, nil
}

func (r *campaignPolicyRuntime) close() {
	if r != nil && r.watcher != nil {
		r.watcher.Stop()
	}
}

func emptyScope(def scope.ScopeDefinition) bool {
	return len(def.AllowedDomains) == 0 && len(def.AllowedCIDRs) == 0
}
