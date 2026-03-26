package ratelimit

import (
	"context"
	"hash/maphash"
	"math"
	"sync"
	"time"
)

// Bucket is a token-bucket rate limiter with separate refill rate and burst capacity.
type Bucket struct {
	mu        sync.Mutex
	tokens    float64
	maxTokens float64
	rate      float64 // tokens per second
	lastCheck time.Time
}

// NewBucket creates a token bucket that refills at ratePerSec tokens/second
// and allows bursts up to burstMax tokens.
func NewBucket(ratePerSec, burstMax float64) *Bucket {
	return &Bucket{
		tokens:    burstMax,
		maxTokens: burstMax,
		rate:      ratePerSec,
		lastCheck: time.Now(),
	}
}

// TryConsume attempts to consume one token. Returns true if the token was
// available, false if the bucket is empty.
func (b *Bucket) TryConsume() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.refill()
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// RetryAfterSecs returns the estimated seconds until a token becomes available.
// Always returns at least 1.
func (b *Bucket) RetryAfterSecs() int {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.refill()
	if b.tokens >= 1 {
		return 1
	}
	secs := math.Ceil((1 - b.tokens) / b.rate)
	if secs < 1 {
		secs = 1
	}
	if secs > 60 {
		secs = 60
	}
	return int(secs)
}

// LastCheck returns the last time the bucket was accessed. Used for staleness checks.
func (b *Bucket) LastCheck() time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.lastCheck
}


func (b *Bucket) refill() {
	now := time.Now()
	elapsed := now.Sub(b.lastCheck).Seconds()
	b.tokens += elapsed * b.rate
	if b.tokens > b.maxTokens {
		b.tokens = b.maxTokens
	}
	b.lastCheck = now
}

const numShards = 64

// BucketMap is a sharded, concurrent map of token buckets keyed by K.
// Each shard has an independent lock, eliminating global contention.
type BucketMap[K comparable] struct {
	shards           [numShards]shard[K]
	maxPerShard      int
	seed             maphash.Seed
	cleanupStopOnce  sync.Once
	cleanupStop      chan struct{}
}

type shard[K comparable] struct {
	mu      sync.RWMutex
	buckets map[K]*Bucket
}

// NewBucketMap creates a sharded bucket map. maxPerShard caps entries per shard
// to prevent unbounded growth (0 means no cap).
func NewBucketMap[K comparable](maxPerShard int) *BucketMap[K] {
	bm := &BucketMap[K]{
		maxPerShard: maxPerShard,
		seed:        maphash.MakeSeed(),
		cleanupStop: make(chan struct{}),
	}
	for i := range bm.shards {
		bm.shards[i].buckets = make(map[K]*Bucket)
	}
	return bm
}

// GetOrCreate returns the bucket for key, creating one if it doesn't exist.
func (bm *BucketMap[K]) GetOrCreate(key K, ratePerSec, burstMax float64) *Bucket {
	idx := bm.shardIndex(key)
	s := &bm.shards[idx]

	// Fast path: read lock
	s.mu.RLock()
	if b, ok := s.buckets[key]; ok {
		s.mu.RUnlock()
		return b
	}
	s.mu.RUnlock()

	// Slow path: write lock, create
	s.mu.Lock()
	defer s.mu.Unlock()

	// Double-check after acquiring write lock
	if b, ok := s.buckets[key]; ok {
		return b
	}

	// Evict stalest entry if at capacity
	if bm.maxPerShard > 0 && len(s.buckets) >= bm.maxPerShard {
		s.evictStalest()
	}

	b := NewBucket(ratePerSec, burstMax)
	s.buckets[key] = b
	return b
}

// Cleanup removes entries that haven't been accessed for staleAfter duration.
func (bm *BucketMap[K]) Cleanup(staleAfter time.Duration) {
	now := time.Now()
	for i := range bm.shards {
		s := &bm.shards[i]
		s.mu.Lock()
		for k, b := range s.buckets {
			if now.Sub(b.LastCheck()) > staleAfter {
				delete(s.buckets, k)
			}
		}
		s.mu.Unlock()
	}
}

// StartCleanupLoop runs periodic cleanup in a background goroutine.
// Stops when ctx is cancelled or Stop is called.
func (bm *BucketMap[K]) StartCleanupLoop(ctx context.Context, interval, staleAfter time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-bm.cleanupStop:
				return
			case <-ticker.C:
				bm.Cleanup(staleAfter)
			}
		}
	}()
}

// Stop halts the cleanup loop if running.
func (bm *BucketMap[K]) Stop() {
	bm.cleanupStopOnce.Do(func() {
		close(bm.cleanupStop)
	})
}

func (bm *BucketMap[K]) shardIndex(key K) uint64 {
	return maphash.Comparable(bm.seed, key) % numShards
}

// evictStalest removes the entry with the oldest lastCheck. Caller must hold write lock.
func (s *shard[K]) evictStalest() {
	var stalestKey K
	var stalestTime time.Time
	first := true

	for k, b := range s.buckets {
		lc := b.LastCheck()
		if first || lc.Before(stalestTime) {
			stalestKey = k
			stalestTime = lc
			first = false
		}
	}
	if !first {
		delete(s.buckets, stalestKey)
	}
}
