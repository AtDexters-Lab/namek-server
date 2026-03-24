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
	AccountID      uuid.UUID    `json:"account_id"`
	Slug           string       `json:"slug"`
	Hostname       string       `json:"hostname"`
	CustomHostname *string      `json:"custom_hostname"`
	IdentityClass  string       `json:"identity_class"`
	EKFingerprint  string       `json:"ek_fingerprint"`
	EKCertDER      []byte       `json:"-"`
	AKPublicKey    []byte       `json:"-"`
	IssuerFingerprint *string           `json:"issuer_fingerprint,omitempty"`
	OSVersion         *string           `json:"os_version,omitempty"`
	PCRValues         map[string]string `json:"pcr_values,omitempty"`
	TrustLevel        TrustLevel        `json:"trust_level"`
	IPAddress         net.IP            `json:"ip_address,omitempty"`
	Timezone          *string           `json:"timezone,omitempty"`
	Status            DeviceStatus      `json:"status"`

	HostnameChangesThisYear int        `json:"-"`
	HostnameYear            int        `json:"-"`
	LastHostnameChangeAt    *time.Time `json:"-"`
	VoucherPendingSince     *time.Time `json:"-"`

	CreatedAt  time.Time  `json:"created_at"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
}
