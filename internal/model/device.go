package model

import (
	"net"
	"time"

	"github.com/google/uuid"
)

type DeviceStatus string

const (
	DeviceStatusActive    DeviceStatus = "active"
	DeviceStatusSuspended DeviceStatus = "suspended"
	DeviceStatusRevoked   DeviceStatus = "revoked"
)

type Device struct {
	ID             uuid.UUID    `json:"id"`
	Slug           string       `json:"slug"`
	Hostname       string       `json:"hostname"`
	CustomHostname *string      `json:"custom_hostname"`
	IdentityClass  string       `json:"identity_class"`
	EKFingerprint  string       `json:"ek_fingerprint"`
	AKPublicKey    []byte       `json:"-"`
	IPAddress      net.IP       `json:"ip_address,omitempty"`
	Timezone       *string      `json:"timezone,omitempty"`
	Status         DeviceStatus `json:"status"`

	HostnameChangesThisYear int        `json:"-"`
	HostnameYear            int        `json:"-"`
	LastHostnameChangeAt    *time.Time `json:"-"`

	CreatedAt  time.Time  `json:"created_at"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
}
