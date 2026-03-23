package model

import (
	"time"

	"github.com/google/uuid"
)

type RecoveryClaim struct {
	ID                  uuid.UUID  `json:"id"`
	DeviceID            uuid.UUID  `json:"device_id"`
	ClaimedAccountID    uuid.UUID  `json:"claimed_account_id"`
	VoucherData         string     `json:"voucher_data"`
	VoucherQuote        string     `json:"voucher_quote"`
	VoucherEpoch        int        `json:"voucher_epoch"`
	IssuerAKPublicKey   []byte     `json:"-"`
	IssuerEKFingerprint string     `json:"issuer_ek_fingerprint"`
	IssuerEKCert        []byte     `json:"-"`
	Attributed          bool       `json:"attributed"`
	Rejected            bool       `json:"rejected"`
	RejectionReason     *string    `json:"rejection_reason,omitempty"`
	AttributedAt        *time.Time `json:"attributed_at,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
}
