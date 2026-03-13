package model

import (
	"time"

	"github.com/google/uuid"
)

type DomainStatus string

const (
	DomainStatusPending  DomainStatus = "pending"
	DomainStatusVerified DomainStatus = "verified"
)

type AccountDomain struct {
	ID                 uuid.UUID    `json:"id"`
	AccountID          uuid.UUID    `json:"account_id"`
	Domain             string       `json:"domain"`
	CNAMETarget        string       `json:"cname_target"`
	Status             DomainStatus `json:"status"`
	CreatedAt          time.Time    `json:"created_at"`
	ExpiresAt          *time.Time   `json:"expires_at,omitempty"`
	VerifiedAt         *time.Time   `json:"verified_at,omitempty"`
	VerifiedByDeviceID *uuid.UUID   `json:"verified_by_device_id,omitempty"`

	// Populated by list queries
	AssignedDeviceIDs []uuid.UUID `json:"assigned_devices,omitempty"`
}

type DomainAssignment struct {
	DeviceID  uuid.UUID `json:"device_id"`
	Domain    string    `json:"domain"`
	CreatedAt time.Time `json:"created_at"`
}
