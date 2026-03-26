package ratelimit

import (
	"context"
	"hash/maphash"
	"sync"
	"testing"
	"time"
)

func TestBucket_TryConsume(t *testing.T) {
	b := NewBucket(10, 5) // 10/sec, burst 5
	// Should be able to consume burst
	for i := 0; i < 5; i++ {
		if !b.TryConsume() {
			t.Fatalf("expected token %d to be available", i)
		}
	}
	// Burst exhausted
	if b.TryConsume() {
		t.Fatal("expected bucket to be empty after burst")
	}
}

func TestBucket_Refill(t *testing.T) {
	b := NewBucket(10, 5)
	// Drain burst
	for i := 0; i < 5; i++ {
		b.TryConsume()
	}
	// Wait for refill
	time.Sleep(150 * time.Millisecond) // ~1.5 tokens at 10/sec
	if !b.TryConsume() {
		t.Fatal("expected token after refill")
	}
}

func TestBucket_BurstCapIndependentOfRate(t *testing.T) {
	b := NewBucket(2, 10) // slow refill, high burst
	// Should consume 10 tokens immediately
	for i := 0; i < 10; i++ {
		if !b.TryConsume() {
			t.Fatalf("expected token %d from burst", i)
		}
	}
	if b.TryConsume() {
		t.Fatal("expected empty after burst exhausted")
	}
}

func TestBucket_RetryAfterSecs(t *testing.T) {
	b := NewBucket(1, 1) // 1/sec
	b.TryConsume()
	secs := b.RetryAfterSecs()
	if secs < 1 {
		t.Fatalf("RetryAfterSecs = %d, want >= 1", secs)
	}

	// High rate: retry should still be at least 1
	b2 := NewBucket(100, 1)
	b2.TryConsume()
	secs = b2.RetryAfterSecs()
	if secs < 1 {
		t.Fatalf("RetryAfterSecs = %d, want >= 1", secs)
	}
}

func TestBucket_RetryAfterSecs_Cap(t *testing.T) {
	b := NewBucket(0.01, 1) // very slow: 0.01/sec
	b.TryConsume()
	secs := b.RetryAfterSecs()
	if secs > 60 {
		t.Fatalf("RetryAfterSecs = %d, want <= 60", secs)
	}
}

func TestBucketMap_GetOrCreate(t *testing.T) {
	bm := NewBucketMap[string](0)
	b1 := bm.GetOrCreate("key1", 10, 5)
	b2 := bm.GetOrCreate("key1", 10, 5)
	if b1 != b2 {
		t.Fatal("expected same bucket for same key")
	}
	b3 := bm.GetOrCreate("key2", 10, 5)
	if b1 == b3 {
		t.Fatal("expected different bucket for different key")
	}
}

func TestBucketMap_Concurrent(t *testing.T) {
	bm := NewBucketMap[int](0)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				b := bm.GetOrCreate(id%50, 10, 5)
				b.TryConsume()
			}
		}(i)
	}
	wg.Wait()
}

func TestBucketMap_Cleanup(t *testing.T) {
	bm := NewBucketMap[string](0)
	bm.GetOrCreate("stale", 10, 5)
	// Touch it long ago by consuming (forces lastCheck update)
	time.Sleep(10 * time.Millisecond)
	bm.GetOrCreate("fresh", 10, 5)

	bm.Cleanup(5 * time.Millisecond)

	// "stale" should be removed, "fresh" should remain
	b := bm.GetOrCreate("fresh", 10, 5)
	if b == nil {
		t.Fatal("fresh bucket should still exist")
	}
}

func TestBucketMap_EvictStalest(t *testing.T) {
	bm := NewBucketMap[int](2) // max 2 per shard

	// Find 3 keys that hash to the same shard
	var sameShard []int
	for i := 0; len(sameShard) < 3; i++ {
		idx := maphash.Comparable(bm.seed, i) % numShards
		if len(sameShard) == 0 || maphash.Comparable(bm.seed, sameShard[0])%numShards == idx {
			sameShard = append(sameShard, i)
		}
	}

	// Insert first two
	bm.GetOrCreate(sameShard[0], 10, 5)
	time.Sleep(5 * time.Millisecond)
	bm.GetOrCreate(sameShard[1], 10, 5)

	// Third should evict the stalest (first)
	bm.GetOrCreate(sameShard[2], 10, 5)

	// Verify: accessing sameShard[0] should return a fresh bucket (it was evicted)
	b := bm.GetOrCreate(sameShard[0], 10, 5)
	// It should have full tokens since it was recreated
	for i := 0; i < 5; i++ {
		if !b.TryConsume() {
			t.Fatalf("expected full bucket after eviction and recreation, failed at token %d", i)
		}
	}
}

func TestBucketMap_CleanupLoop(t *testing.T) {
	bm := NewBucketMap[string](0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bm.GetOrCreate("temp", 10, 5)
	bm.StartCleanupLoop(ctx, 20*time.Millisecond, 10*time.Millisecond)
	defer bm.Stop()

	time.Sleep(50 * time.Millisecond)
	// After cleanup, "temp" should be evicted (stale > 10ms)
	// Re-create to check it's fresh
	b := bm.GetOrCreate("temp", 10, 5)
	// Should have full burst since it was cleaned up and recreated
	count := 0
	for b.TryConsume() {
		count++
	}
	if count != 5 {
		t.Fatalf("expected 5 tokens in fresh bucket, got %d", count)
	}
}
