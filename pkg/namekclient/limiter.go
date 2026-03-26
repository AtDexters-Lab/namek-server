package namekclient

import (
	"context"
	"sync"
	"time"
)

// clientLimiter is a simple token bucket that blocks until a token is available.
type clientLimiter struct {
	mu         sync.Mutex
	tokens     float64
	maxTokens  float64
	refillRate float64 // tokens per second
	lastRefill time.Time
}

func newClientLimiter(requestsPerSecond float64, burst int) *clientLimiter {
	return &clientLimiter{
		tokens:     float64(burst),
		maxTokens:  float64(burst),
		refillRate: requestsPerSecond,
		lastRefill: time.Now(),
	}
}

// Wait blocks until a token is available or ctx is cancelled.
func (l *clientLimiter) Wait(ctx context.Context) error {
	for {
		l.mu.Lock()
		l.refill()
		if l.tokens >= 1 {
			l.tokens--
			l.mu.Unlock()
			return nil
		}
		// Calculate wait time until next token
		wait := time.Duration(float64(time.Second) * (1 - l.tokens) / l.refillRate)
		if wait < 10*time.Millisecond {
			wait = 10 * time.Millisecond
		}
		l.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

func (l *clientLimiter) refill() {
	now := time.Now()
	elapsed := now.Sub(l.lastRefill).Seconds()
	l.tokens += elapsed * l.refillRate
	if l.tokens > l.maxTokens {
		l.tokens = l.maxTokens
	}
	l.lastRefill = now
}
