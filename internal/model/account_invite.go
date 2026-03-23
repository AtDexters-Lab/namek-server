package model

import (
	"time"

	"github.com/google/uuid"
)

type AccountInvite struct {
	ID                uuid.UUID  `json:"id"`
	AccountID         uuid.UUID  `json:"account_id"`
	InviteCodeHash    string     `json:"-"`
	CreatedByDeviceID uuid.UUID  `json:"created_by_device_id"`
	ExpiresAt         time.Time  `json:"expires_at"`
	ConsumedAt        *time.Time `json:"consumed_at,omitempty"`
	ConsumedByDeviceID *uuid.UUID `json:"consumed_by_device_id,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
}
