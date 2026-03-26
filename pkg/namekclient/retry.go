package namekclient

import (
	"context"
	"errors"
	"math"
	"math/rand/v2"
	"time"
)

type retryConfig struct {
	maxAttempts int
	baseDelay   time.Duration
	maxDelay    time.Duration
	jitterFrac  float64 // 0.0 to 1.0
}

var defaultRetry = retryConfig{
	maxAttempts: 3,
	baseDelay:   500 * time.Millisecond,
	maxDelay:    30 * time.Second,
	jitterFrac:  0.25,
}

// shouldRetry determines if an error is retryable given the HTTP method.
// For mutations (POST, PATCH, DELETE), only explicit server rejections (429, 503)
// are retried — ambiguous network errors are not, to avoid double-mutation.
// For reads (GET), all transient errors are retried.
func shouldRetry(err error, method string) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.IsRetryable()
	}
	// Ambiguous error (network timeout, connection reset, etc.)
	// Only retry for read-only methods
	return method == "GET"
}

// retryDelay computes the delay before the next retry attempt.
func (rc *retryConfig) retryDelay(err error, attempt int) time.Duration {
	// Use server-specified Retry-After if available
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.RetryAfter > 0 {
		return apiErr.RetryAfter
	}

	// Exponential backoff: baseDelay * 2^attempt
	delay := float64(rc.baseDelay) * math.Pow(2, float64(attempt))
	if delay > float64(rc.maxDelay) {
		delay = float64(rc.maxDelay)
	}

	// Apply jitter: delay * (1 + random(-jitter, +jitter))
	if rc.jitterFrac > 0 {
		jitter := (rand.Float64()*2 - 1) * rc.jitterFrac
		delay *= 1 + jitter
	}

	return time.Duration(delay)
}

// doWithRetry executes fn with retry logic according to the config.
func doWithRetry(ctx context.Context, rc *retryConfig, method string, fn func() error) error {
	if rc == nil {
		return fn()
	}

	maxAttempts := rc.maxAttempts
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		lastErr = fn()
		if lastErr == nil {
			return nil
		}

		if !shouldRetry(lastErr, method) {
			return lastErr
		}

		if attempt < rc.maxAttempts-1 {
			delay := rc.retryDelay(lastErr, attempt)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}
	}
	return lastErr
}
