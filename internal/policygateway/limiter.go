package policygateway

import (
	"context"
	"sync"
	"time"
)

// Limiter is a concurrency-safe, evenly-spaced request governor. It is shared
// by one Gateway so all execution paths consume the same program-level rate.
type Limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

// NewLimiter creates a limiter for requests per second. Non-positive rates
// produce a disabled limiter.
func NewLimiter(perSecond float64) *Limiter {
	l := &Limiter{}
	if perSecond > 0 {
		l.interval = time.Duration(float64(time.Second) / perSecond)
	}
	return l
}

// Wait reserves the next request slot and blocks until it becomes available.
func (l *Limiter) Wait(ctx context.Context) error {
	if l == nil || l.interval <= 0 {
		return nil
	}

	l.mu.Lock()
	now := time.Now()
	at := now
	if l.next.After(now) {
		at = l.next
	}
	l.next = at.Add(l.interval)
	l.mu.Unlock()

	delay := time.Until(at)
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
