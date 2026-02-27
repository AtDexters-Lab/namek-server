package auth

import (
	"log/slog"
	"os"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestNonceStore_GenerateAndConsume(t *testing.T) {
	store := NewNonceStore(testLogger())

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
	store := NewNonceStore(testLogger())

	if err := store.Consume("unknown-nonce"); err != ErrNonceNotFound {
		t.Fatalf("expected ErrNonceNotFound, got %v", err)
	}
}

func TestNonceStore_UniqueNonces(t *testing.T) {
	store := NewNonceStore(testLogger())

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
