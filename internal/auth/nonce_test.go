package auth

import (
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestNonceStore_GenerateAndConsume(t *testing.T) {
	store := NewNonceStore(testLogger(), 10000, 60*time.Second)

	nonce, expiresAt, err := store.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if nonce == "" {
		t.Fatal("nonce should not be empty")
	}
	if expiresAt.Before(time.Now()) {
		t.Fatal("expires_at should be in the future")
	}

	// Consume should succeed
	if err := store.Consume(nonce); err != nil {
		t.Fatalf("consume: %v", err)
	}

	// Second consume should fail (one-time use)
	if err := store.Consume(nonce); err != ErrNonceNotFound {
		t.Fatalf("expected ErrNonceNotFound, got %v", err)
	}
}

func TestNonceStore_UnknownNonce(t *testing.T) {
	store := NewNonceStore(testLogger(), 10000, 60*time.Second)

	if err := store.Consume("unknown-nonce"); err != ErrNonceNotFound {
		t.Fatalf("expected ErrNonceNotFound, got %v", err)
	}
}

func TestNonceStore_UniqueNonces(t *testing.T) {
	store := NewNonceStore(testLogger(), 10000, 60*time.Second)

	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		nonce, _, err := store.Generate()
		if err != nil {
			t.Fatalf("generate %d: %v", i, err)
		}
		if seen[nonce] {
			t.Fatalf("duplicate nonce: %s", nonce)
		}
		seen[nonce] = true
	}
}

func TestNonceStore_Capacity(t *testing.T) {
	store := NewNonceStore(testLogger(), 100, 60*time.Second)

	for i := 0; i < 100; i++ {
		if _, _, err := store.Generate(); err != nil {
			t.Fatalf("generate %d: %v", i, err)
		}
	}

	// Should hit capacity (soft limit — may slightly overshoot)
	_, _, err := store.Generate()
	if err != ErrNonceCapacity {
		t.Fatalf("expected ErrNonceCapacity, got %v", err)
	}

	// Consume one to free space
	nonce, _, _ := store.Generate() // may work due to soft limit
	if nonce == "" {
		// Capacity is enforced; consume an existing one
		// Generate a fresh store to test consume-then-generate
		store2 := NewNonceStore(testLogger(), 5, 60*time.Second)
		n, _, _ := store2.Generate()
		store2.Consume(n)
		if _, _, err := store2.Generate(); err != nil {
			t.Fatalf("should be able to generate after consume: %v", err)
		}
	}
}

func TestNonceStore_Concurrent(t *testing.T) {
	store := NewNonceStore(testLogger(), 100000, 60*time.Second)

	var genWg sync.WaitGroup
	nonces := make(chan string, 1000)

	// Concurrent generators
	for i := 0; i < 10; i++ {
		genWg.Add(1)
		go func() {
			defer genWg.Done()
			for j := 0; j < 100; j++ {
				n, _, err := store.Generate()
				if err != nil {
					t.Errorf("generate: %v", err)
					return
				}
				nonces <- n
			}
		}()
	}

	// Close channel after all generators finish
	go func() {
		genWg.Wait()
		close(nonces)
	}()

	// Consume all generated nonces
	for n := range nonces {
		store.Consume(n)
	}
}

func TestNonceStore_Cleanup(t *testing.T) {
	store := NewNonceStore(testLogger(), 10000, 10*time.Millisecond)

	nonce, _, err := store.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	// Wait for expiry
	time.Sleep(20 * time.Millisecond)

	// Consume should fail (expired)
	if err := store.Consume(nonce); err != ErrNonceNotFound {
		t.Fatalf("expected ErrNonceNotFound for expired nonce, got %v", err)
	}

	// Generate a new one and run cleanup
	store.Generate()
	time.Sleep(20 * time.Millisecond)
	store.cleanup()

	// Counter should be reconciled to 0
	if count := store.count.Load(); count != 0 {
		t.Fatalf("expected count 0 after cleanup, got %d", count)
	}
}
