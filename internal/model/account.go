package model

import (
	"time"

	"github.com/google/uuid"
)

type AccountStatus string

const (
	AccountStatusActive          AccountStatus = "active"
	AccountStatusPendingRecovery AccountStatus = "pending_recovery"
)

type Account struct {
	ID                    uuid.UUID     `json:"id"`
	Status                AccountStatus `json:"status"`
	MembershipEpoch       int           `json:"membership_epoch"`
	FoundingEKFingerprint string        `json:"founding_ek_fingerprint,omitempty"`
	RecoveryDeadline      *time.Time    `json:"recovery_deadline,omitempty"`
	DissolvedAt           *time.Time    `json:"dissolved_at,omitempty"`
	CreatedAt             time.Time     `json:"created_at"`
}
