package model

import (
	"time"

	"github.com/google/uuid"
)

type VoucherRequestStatus string

const (
	VoucherRequestStatusPending VoucherRequestStatus = "pending"
	VoucherRequestStatusSigned  VoucherRequestStatus = "signed"
	VoucherRequestStatusExpired VoucherRequestStatus = "expired"
)

type VoucherRequest struct {
	ID              uuid.UUID            `json:"id"`
	AccountID       uuid.UUID            `json:"account_id"`
	IssuerDeviceID  uuid.UUID            `json:"issuer_device_id"`
	SubjectDeviceID uuid.UUID            `json:"subject_device_id"`
	VoucherData     string               `json:"voucher_data"`
	Epoch           int                  `json:"epoch"`
	Status          VoucherRequestStatus `json:"status"`
	Quote           *string              `json:"quote,omitempty"`
	CreatedAt       time.Time            `json:"created_at"`
	SignedAt        *time.Time           `json:"signed_at,omitempty"`
}
