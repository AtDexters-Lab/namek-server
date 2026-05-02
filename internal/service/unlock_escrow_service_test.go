package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AtDexters-Lab/namek-server/internal/config"
)

// TestUnlockEscrowDeposit_ValidationRejects covers the input-validation paths
// of Deposit that return before any store interaction. Walking the validation
// gates here avoids needing a DB; the happy paths and store interactions are
// covered by the integration suite (tests/integration).
func TestUnlockEscrowDeposit_ValidationRejects(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoUnlock.MaxWindowSeconds = 600
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// nil store is safe — every case below returns ErrValidation before any
	// store method is called.
	svc := NewUnlockEscrowService(nil, nil, cfg, logger)

	cases := []struct {
		name    string
		secret  []byte
		window  int
		wantMsg string
	}{
		{"zero window", make([]byte, 32), 0, "window_seconds must be positive"},
		{"negative window", make([]byte, 32), -1, "window_seconds must be positive"},
		{"short secret", make([]byte, 31), 60, "secret must be 32 bytes"},
		{"long secret", make([]byte, 33), 60, "secret must be 32 bytes"},
		{"empty secret", []byte{}, 60, "secret must be 32 bytes"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.Deposit(context.Background(), uuid.New(), tc.secret, tc.window)
			require.Error(t, err)
			var verr *ErrValidation
			require.True(t, errors.As(err, &verr), "expected *ErrValidation, got %T", err)
			assert.Equal(t, tc.wantMsg, verr.Message)
		})
	}
}
