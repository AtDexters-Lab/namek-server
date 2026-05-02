package model

import (
	"time"

	"github.com/google/uuid"
)

// UnlockEscrow is the per-device, single-row escrow record that holds the
// per-cycle auto-unlock secret F. Every field carries json:"-" so accidental
// JSON marshaling cannot leak the secret.
type UnlockEscrow struct {
	DeviceID   uuid.UUID  `json:"-"`
	Secret     []byte     `json:"-"`
	ExpiresAt  time.Time  `json:"-"`
	CreatedAt  time.Time  `json:"-"`
	PickedUpAt *time.Time `json:"-"`
}
