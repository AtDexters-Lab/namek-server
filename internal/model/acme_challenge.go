package model

import (
	"time"

	"github.com/google/uuid"
)

type ACMEChallenge struct {
	ID               uuid.UUID `json:"id"`
	DeviceID         uuid.UUID `json:"device_id"`
	FQDN             string    `json:"fqdn"`
	KeyAuthorization string    `json:"key_authorization"`
	CreatedAt        time.Time `json:"created_at"`
	ExpiresAt        time.Time `json:"expires_at"`
}
