package namekclient

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// ErrEscrowNotFound is returned by PickupUnlockEscrow when the device has no
// outstanding escrow (never deposited, already expired, or already revoked).
// Callers should treat this as a terminal signal — fall through to the manual
// unlock fallback ladder rather than retry.
var ErrEscrowNotFound = errors.New("namek: no outstanding unlock escrow")

// APIError represents an HTTP error response from the namek server.
type APIError struct {
	StatusCode int
	Message    string
	RetryAfter time.Duration // parsed from Retry-After header; zero if absent
}

func (e *APIError) Error() string {
	return fmt.Sprintf("server error %d: %s", e.StatusCode, e.Message)
}

// IsRetryable returns true for status codes that indicate the request can be retried.
func (e *APIError) IsRetryable() bool {
	return e.StatusCode == http.StatusTooManyRequests || e.StatusCode == http.StatusServiceUnavailable
}

func parseError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	apiErr := &APIError{
		StatusCode: resp.StatusCode,
		Message:    string(body),
	}
	if ra := resp.Header.Get("Retry-After"); ra != "" {
		if secs, err := strconv.Atoi(ra); err == nil && secs > 0 {
			apiErr.RetryAfter = time.Duration(secs) * time.Second
		}
	}
	return apiErr
}
