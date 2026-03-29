package service

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/AtDexters-Lab/namek-server/internal/config"
	"github.com/AtDexters-Lab/namek-server/internal/identity"
	"github.com/AtDexters-Lab/namek-server/internal/model"
	"github.com/AtDexters-Lab/namek-server/internal/store"
	"github.com/AtDexters-Lab/namek-server/internal/tpm"
	"github.com/AtDexters-Lab/namek-server/internal/voucher"
)

type VoucherService struct {
	voucherStore *store.VoucherStore
	deviceStore  *store.DeviceStore
	accountStore *store.AccountStore
	auditStore   *store.AuditStore
	tpmVerifier  tpm.Verifier
	cfg          *config.Config
	logger       *slog.Logger
}

func NewVoucherService(
	voucherStore *store.VoucherStore,
	deviceStore *store.DeviceStore,
	accountStore *store.AccountStore,
	auditStore *store.AuditStore,
	tpmVerifier tpm.Verifier,
	cfg *config.Config,
	logger *slog.Logger,
) *VoucherService {
	return &VoucherService{
		voucherStore: voucherStore,
		deviceStore:  deviceStore,
		accountStore: accountStore,
		auditStore:   auditStore,
		tpmVerifier:  tpmVerifier,
		cfg:          cfg,
		logger:       logger,
	}
}

// CreateVoucherRequests creates all-pairs voucher requests for devices in an account.
// Called after join/leave to trigger voucher exchange.
func (s *VoucherService) CreateVoucherRequests(ctx context.Context, accountID uuid.UUID) error {
	account, err := s.accountStore.GetByID(ctx, accountID)
	if err != nil {
		return fmt.Errorf("get account: %w", err)
	}

	devices, err := s.deviceStore.ListByAccountID(ctx, accountID)
	if err != nil {
		return fmt.Errorf("list account devices: %w", err)
	}

	if len(devices) < 2 {
		return nil // no voucher exchange needed for single-device accounts
	}

	// Use founding EK fingerprint from account record (set at account creation)
	foundingEKFingerprint := account.FoundingEKFingerprint
	if foundingEKFingerprint == "" {
		// Legacy fallback: discover from device whose EK derives the account ID
		for _, d := range devices {
			if identity.AccountID(d.EKFingerprint) == accountID {
				foundingEKFingerprint = d.EKFingerprint
				break
			}
		}
		if foundingEKFingerprint == "" {
			s.logger.Warn("no founding EK fingerprint found for account, skipping voucher creation",
				"account_id", accountID)
			return nil
		}
	}

	now := time.Now().UTC()

	// Create all-pairs requests
	for _, issuer := range devices {
		for _, subject := range devices {
			if issuer.ID == subject.ID {
				continue
			}

			vd := &voucher.VoucherData{
				AccountID:             accountID.String(),
				Epoch:                 account.MembershipEpoch,
				FoundingEKFingerprint: foundingEKFingerprint,
				IssuedAt:              now.Format(time.RFC3339),
				IssuerEKFingerprint:   issuer.EKFingerprint,
				SubjectEKFingerprint:  subject.EKFingerprint,
				Type:                  voucher.VoucherTypePeerMembership,
				Version:               1,
			}

			canonical, err := voucher.Canonicalize(vd)
			if err != nil {
				return fmt.Errorf("canonicalize voucher data: %w", err)
			}

			req := &model.VoucherRequest{
				ID:              uuid.New(),
				AccountID:       accountID,
				IssuerDeviceID:  issuer.ID,
				SubjectDeviceID: subject.ID,
				VoucherData:     base64.StdEncoding.EncodeToString(canonical),
				Epoch:           account.MembershipEpoch,
			}

			if err := s.voucherStore.CreateRequest(ctx, req); err != nil {
				return fmt.Errorf("create voucher request: %w", err)
			}
		}

		// Set voucher_pending_since on the issuer
		t := time.Now()
		if err := s.deviceStore.SetVoucherPendingSince(ctx, issuer.ID, &t); err != nil {
			s.logger.Warn("failed to set voucher_pending_since", "device_id", issuer.ID, "error", err)
		}
	}

	s.logger.Info("voucher requests created",
		"account_id", accountID,
		"device_count", len(devices),
		"epoch", account.MembershipEpoch,
	)

	return nil
}

// SignVoucher verifies a TPM quote and marks a voucher request as signed.
func (s *VoucherService) SignVoucher(ctx context.Context, deviceID uuid.UUID, requestID uuid.UUID, quoteB64 string) error {
	req, err := s.voucherStore.GetByID(ctx, requestID)
	if err != nil {
		if errors.Is(err, store.ErrVoucherRequestNotFound) {
			return &ErrValidation{Message: "voucher request not found"}
		}
		return fmt.Errorf("get voucher request: %w", err)
	}

	// Verify the device is the issuer
	if req.IssuerDeviceID != deviceID {
		return &ErrValidation{Message: "device is not the issuer of this voucher request"}
	}
	if req.Status != model.VoucherRequestStatusPending {
		return &ErrValidation{Message: "voucher request is not pending"}
	}

	// Get the issuer device for AK public key
	issuer, err := s.deviceStore.GetByID(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("get issuer device: %w", err)
	}

	// Decode voucher data and compute expected nonce
	voucherDataBytes, err := base64.StdEncoding.DecodeString(req.VoucherData)
	if err != nil {
		return fmt.Errorf("decode voucher data: %w", err)
	}
	expectedNonce := voucher.NonceFromData(voucherDataBytes)

	// Verify the TPM quote against the expected nonce
	if _, err := s.tpmVerifier.VerifyQuote(issuer.AKPublicKey, expectedNonce, quoteB64, nil); err != nil {
		return &ErrValidation{Message: "quote verification failed"}
	}

	// Mark the request as signed
	if err := s.voucherStore.SignRequest(ctx, requestID, quoteB64); err != nil {
		return fmt.Errorf("sign request: %w", err)
	}

	s.auditStore.LogAction(ctx, model.ActorTypeDevice, deviceID.String(),
		"voucher.sign", "voucher_request", strPtr(requestID.String()),
		map[string]string{
			"subject_device_id": req.SubjectDeviceID.String(),
			"epoch":             fmt.Sprintf("%d", req.Epoch),
		}, nil)

	s.logger.Info("voucher signed",
		"device_id", deviceID,
		"request_id", requestID,
		"subject_device_id", req.SubjectDeviceID,
	)

	return nil
}

// PendingVoucherRequest is the API response format for pending voucher requests.
type PendingVoucherRequest struct {
	RequestID   uuid.UUID `json:"request_id"`
	VoucherData string    `json:"voucher_data"`
	Nonce       string    `json:"nonce"`
}

// GetPendingRequests returns pending voucher requests for a device (as issuer).
func (s *VoucherService) GetPendingRequests(ctx context.Context, deviceID uuid.UUID) ([]PendingVoucherRequest, error) {
	reqs, err := s.voucherStore.GetPendingForDevice(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("get pending requests: %w", err)
	}

	result := make([]PendingVoucherRequest, 0, len(reqs))
	for _, r := range reqs {
		voucherDataBytes, err := base64.StdEncoding.DecodeString(r.VoucherData)
		if err != nil {
			s.logger.Warn("invalid voucher data base64", "request_id", r.ID, "error", err)
			continue
		}
		result = append(result, PendingVoucherRequest{
			RequestID:   r.ID,
			VoucherData: r.VoucherData,
			Nonce:       hex.EncodeToString(voucher.NonceFromData(voucherDataBytes)),
		})
	}
	return result, nil
}

// CompleteVoucher is the API response format for a signed voucher.
type CompleteVoucher struct {
	Data             string `json:"data"`
	Quote            string `json:"quote"`
	IssuerAKPubKey   string `json:"issuer_ak_public_key"`
	IssuerEKCert     string `json:"issuer_ek_cert,omitempty"`
}

// GetNewVouchers returns signed vouchers where the device is the subject.
func (s *VoucherService) GetNewVouchers(ctx context.Context, deviceID uuid.UUID) ([]CompleteVoucher, error) {
	reqs, err := s.voucherStore.GetSignedForSubject(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("get signed vouchers: %w", err)
	}

	result := make([]CompleteVoucher, 0, len(reqs))
	for _, r := range reqs {
		if r.Quote == nil {
			continue
		}

		// Get issuer's EK cert and AK public key
		issuer, err := s.deviceStore.GetByID(ctx, r.IssuerDeviceID)
		if err != nil {
			s.logger.Warn("failed to get issuer device for voucher", "issuer_id", r.IssuerDeviceID, "error", err)
			continue
		}

		cv := CompleteVoucher{
			Data:           r.VoucherData,
			Quote:          *r.Quote,
			IssuerAKPubKey: base64.StdEncoding.EncodeToString(issuer.AKPublicKey),
		}
		if len(issuer.EKCertDER) > 0 {
			cv.IssuerEKCert = base64.StdEncoding.EncodeToString(issuer.EKCertDER)
		}
		result = append(result, cv)
	}
	return result, nil
}

// CleanupExpiredRequests expires unfulfilled voucher requests older than 30 days.
func (s *VoucherService) CleanupExpiredRequests(ctx context.Context) {
	expired, err := s.voucherStore.ExpireStale(ctx, 30*24*time.Hour)
	if err != nil {
		s.logger.Error("voucher request cleanup failed", "error", err)
		return
	}
	if expired > 0 {
		s.logger.Info("voucher request cleanup", "expired", expired)
	}
}
