package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"sync"
	"time"
)

const (
	nonceSize     = 32
	nonceTTL      = 60 * time.Second
	maxNonces     = 10000
	cleanupPeriod = 30 * time.Second
)

var (
	ErrNonceNotFound = errors.New("nonce not found or expired")
	ErrNonceCapacity = errors.New("nonce store at capacity")
)

type nonceEntry struct {
	expiresAt time.Time
}

type NonceStore struct {
	mu      sync.Mutex
	entries map[string]nonceEntry
	logger  *slog.Logger
}

func NewNonceStore(logger *slog.Logger) *NonceStore {
	return &NonceStore{
		entries: make(map[string]nonceEntry),
		logger:  logger,
	}
}

// Generate creates a new nonce and returns it as base64-encoded string.
func (s *NonceStore) Generate() (string, time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.entries) >= maxNonces {
		return "", time.Time{}, ErrNonceCapacity
	}

	b := make([]byte, nonceSize)
	if _, err := rand.Read(b); err != nil {
		return "", time.Time{}, err
	}

	nonce := base64.RawURLEncoding.EncodeToString(b)
	expiresAt := time.Now().Add(nonceTTL)
	s.entries[nonce] = nonceEntry{expiresAt: expiresAt}

	return nonce, expiresAt, nil
}

// Consume validates and removes a nonce (one-time use).
func (s *NonceStore) Consume(nonce string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.entries[nonce]
	if !ok {
		return ErrNonceNotFound
	}

	delete(s.entries, nonce)

	if time.Now().After(entry.expiresAt) {
		return ErrNonceNotFound
	}

	return nil
}

// CleanupLoop removes expired nonces periodically.
func (s *NonceStore) CleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(cleanupPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.cleanup()
		}
	}
}

func (s *NonceStore) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	removed := 0
	for k, v := range s.entries {
		if now.After(v.expiresAt) {
			delete(s.entries, k)
			removed++
		}
	}

	if removed > 0 {
		s.logger.Debug("nonce cleanup", "removed", removed, "remaining", len(s.entries))
	}
}
