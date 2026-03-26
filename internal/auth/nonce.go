package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

const (
	nonceSize       = 32
	nonceNumShards  = 64
	cleanupPeriod   = 30 * time.Second
)

var (
	ErrNonceNotFound = errors.New("nonce not found or expired")
	ErrNonceCapacity = errors.New("nonce store at capacity")
)

type nonceEntry struct {
	expiresAt time.Time
}

type nonceShard struct {
	mu      sync.Mutex
	entries map[string]nonceEntry
}

// NonceStore is a sharded in-memory store for one-time-use nonces.
// Sharding eliminates the single-mutex bottleneck at high concurrency.
type NonceStore struct {
	shards    [nonceNumShards]nonceShard
	count     atomic.Int64 // optimistic global counter (reconciled during cleanup)
	maxNonces int
	ttl       time.Duration
	logger    *slog.Logger
}

// NewNonceStore creates a sharded nonce store with the given capacity and TTL.
func NewNonceStore(logger *slog.Logger, maxNonces int, ttl time.Duration) *NonceStore {
	s := &NonceStore{
		maxNonces: maxNonces,
		ttl:       ttl,
		logger:    logger,
	}
	for i := range s.shards {
		s.shards[i].entries = make(map[string]nonceEntry)
	}
	return s
}

// Generate creates a new nonce and returns it as a base64-encoded string.
func (s *NonceStore) Generate() (string, time.Time, error) {
	// Optimistic capacity check (soft limit — may overshoot by up to nonceNumShards)
	if s.count.Load() >= int64(s.maxNonces) {
		return "", time.Time{}, ErrNonceCapacity
	}

	b := make([]byte, nonceSize)
	if _, err := rand.Read(b); err != nil {
		return "", time.Time{}, err
	}

	nonce := base64.RawURLEncoding.EncodeToString(b)
	expiresAt := time.Now().Add(s.ttl)

	// Shard by first byte of random data (uniform distribution)
	shardIdx := b[0] % nonceNumShards
	sh := &s.shards[shardIdx]

	sh.mu.Lock()
	sh.entries[nonce] = nonceEntry{expiresAt: expiresAt}
	sh.mu.Unlock()

	s.count.Add(1)
	return nonce, expiresAt, nil
}

// Consume validates and removes a nonce (one-time use).
func (s *NonceStore) Consume(nonce string) error {
	raw, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || len(raw) < 1 {
		return ErrNonceNotFound
	}

	shardIdx := raw[0] % nonceNumShards
	sh := &s.shards[shardIdx]

	sh.mu.Lock()
	entry, ok := sh.entries[nonce]
	if !ok {
		sh.mu.Unlock()
		return ErrNonceNotFound
	}
	delete(sh.entries, nonce)
	sh.mu.Unlock()

	s.count.Add(-1)

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
	now := time.Now()
	totalRemoved := 0
	var totalRemaining int

	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.Lock()
		removed := 0
		for k, v := range sh.entries {
			if now.After(v.expiresAt) {
				delete(sh.entries, k)
				removed++
			}
		}
		totalRemaining += len(sh.entries)
		sh.mu.Unlock()
		totalRemoved += removed
	}

	// Reconcile atomic counter with actual count to prevent drift
	s.count.Store(int64(totalRemaining))

	if totalRemoved > 0 {
		s.logger.Debug("nonce cleanup", "removed", totalRemoved, "remaining", totalRemaining)
	}
}
