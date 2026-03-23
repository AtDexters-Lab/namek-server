package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
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
)

// VoucherRequestCreator is an interface to decouple AccountService from VoucherService.
type VoucherRequestCreator interface {
	CreateVoucherRequests(ctx context.Context, accountID uuid.UUID) error
}

type AccountService struct {
	accountStore    *store.AccountStore
	deviceStore     *store.DeviceStore
	inviteStore     *store.InviteStore
	auditStore      *store.AuditStore
	voucherCreator  VoucherRequestCreator
	cfg             *config.Config
	logger          *slog.Logger
}

func NewAccountService(
	accountStore *store.AccountStore,
	deviceStore *store.DeviceStore,
	inviteStore *store.InviteStore,
	auditStore *store.AuditStore,
	cfg *config.Config,
	logger *slog.Logger,
) *AccountService {
	return &AccountService{
		accountStore: accountStore,
		deviceStore:  deviceStore,
		inviteStore:  inviteStore,
		auditStore:   auditStore,
		cfg:          cfg,
		logger:       logger,
	}
}

// SetVoucherCreator sets the voucher request creator for triggering voucher
// exchange after join/leave. Set after construction to break circular init.
func (s *AccountService) SetVoucherCreator(vc VoucherRequestCreator) {
	s.voucherCreator = vc
}

type InviteResponse struct {
	InviteCode string    `json:"invite_code"`
	AccountID  uuid.UUID `json:"account_id"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func (s *AccountService) CreateInvite(ctx context.Context, deviceID uuid.UUID) (*InviteResponse, error) {
	device, err := s.deviceStore.GetByID(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("get device: %w", err)
	}

	// Check account status
	account, err := s.accountStore.GetByID(ctx, device.AccountID)
	if err != nil {
		return nil, fmt.Errorf("get account: %w", err)
	}
	if account.Status == model.AccountStatusPendingRecovery {
		return nil, &ErrValidation{Message: "account management not available during recovery"}
	}

	// Check active invite limit
	activeCount, err := s.inviteStore.CountActiveByAccount(ctx, device.AccountID)
	if err != nil {
		return nil, fmt.Errorf("count active invites: %w", err)
	}
	if activeCount >= s.cfg.Account.MaxInvitesPerAccount {
		return nil, &ErrValidation{Message: "maximum active invites reached"}
	}

	// Generate random invite code (32 bytes = 64 hex chars)
	codeBytes := make([]byte, 32)
	if _, err := rand.Read(codeBytes); err != nil {
		return nil, fmt.Errorf("generate invite code: %w", err)
	}
	inviteCode := hex.EncodeToString(codeBytes)

	// Store hash of the code
	hash := sha256.Sum256([]byte(inviteCode))
	codeHash := hex.EncodeToString(hash[:])

	expiresAt := time.Now().Add(s.cfg.InviteTTL())

	invite := &model.AccountInvite{
		ID:                uuid.New(),
		AccountID:         device.AccountID,
		InviteCodeHash:    codeHash,
		CreatedByDeviceID: deviceID,
		ExpiresAt:         expiresAt,
	}

	if err := s.inviteStore.Create(ctx, invite); err != nil {
		return nil, fmt.Errorf("create invite: %w", err)
	}

	s.auditStore.LogAction(ctx, model.ActorTypeDevice, deviceID.String(),
		"account.invite_created", "account", strPtr(device.AccountID.String()), nil, nil)

	s.logger.Info("invite created",
		"account_id", device.AccountID,
		"device_id", deviceID,
		"expires_at", expiresAt,
	)

	return &InviteResponse{
		InviteCode: inviteCode,
		AccountID:  device.AccountID,
		ExpiresAt:  expiresAt,
	}, nil
}

func (s *AccountService) JoinAccount(ctx context.Context, deviceID uuid.UUID, inviteCode string) error {
	device, err := s.deviceStore.GetByID(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("get device: %w", err)
	}

	// Check device's current account status
	currentAccount, err := s.accountStore.GetByID(ctx, device.AccountID)
	if err != nil {
		return fmt.Errorf("get current account: %w", err)
	}
	if currentAccount.Status == model.AccountStatusPendingRecovery {
		return &ErrValidation{Message: "account management not available during recovery"}
	}

	// Look up invite by hash
	hash := sha256.Sum256([]byte(inviteCode))
	codeHash := hex.EncodeToString(hash[:])

	invite, err := s.inviteStore.GetByCodeHash(ctx, codeHash)
	if err != nil {
		if errors.Is(err, store.ErrInviteNotFound) {
			return &ErrValidation{Message: "invalid invite code"}
		}
		return fmt.Errorf("get invite: %w", err)
	}

	// Verify invite is valid
	if invite.ConsumedAt != nil {
		return &ErrValidation{Message: "invite code already used"}
	}
	if time.Now().After(invite.ExpiresAt) {
		return &ErrValidation{Message: "invite code expired"}
	}

	// Check target account status
	targetAccount, err := s.accountStore.GetByID(ctx, invite.AccountID)
	if err != nil {
		return fmt.Errorf("get target account: %w", err)
	}
	if targetAccount.Status == model.AccountStatusPendingRecovery {
		return &ErrValidation{Message: "target account is in recovery"}
	}

	// Check device limit
	deviceCount, err := s.accountStore.CountDevices(ctx, invite.AccountID)
	if err != nil {
		return fmt.Errorf("count devices: %w", err)
	}
	if deviceCount >= s.cfg.Account.MaxDevicesPerAccount {
		return &ErrValidation{Message: "target account has reached maximum devices"}
	}

	// Already in this account?
	if device.AccountID == invite.AccountID {
		return &ErrValidation{Message: "device already in this account"}
	}

	oldAccountID := device.AccountID

	// Consume the invite first (atomic WHERE consumed_at IS NULL serializes
	// concurrent joins — if this fails, no side effects have occurred yet)
	if err := s.inviteStore.Consume(ctx, invite.ID, deviceID); err != nil {
		return &ErrValidation{Message: "invite code already used"}
	}

	// Move device to the new account (safe: invite is consumed, no race)
	if err := s.deviceStore.UpdateAccountID(ctx, deviceID, invite.AccountID); err != nil {
		return fmt.Errorf("move device: %w", err)
	}

	// Increment membership epoch on the target account
	if _, err := s.accountStore.IncrementEpoch(ctx, invite.AccountID); err != nil {
		return fmt.Errorf("increment epoch: %w", err)
	}

	// Clean up old single-device account if now empty
	if err := s.accountStore.DeleteEmpty(ctx, oldAccountID); err != nil {
		s.logger.Warn("failed to delete empty account", "account_id", oldAccountID, "error", err)
	}

	// Trigger voucher exchange for the account
	if s.voucherCreator != nil {
		if err := s.voucherCreator.CreateVoucherRequests(ctx, invite.AccountID); err != nil {
			s.logger.Warn("failed to create voucher requests after join", "account_id", invite.AccountID, "error", err)
		}
	}

	s.auditStore.LogAction(ctx, model.ActorTypeDevice, deviceID.String(),
		"account.device_joined", "account", strPtr(invite.AccountID.String()),
		map[string]string{"invited_by": invite.CreatedByDeviceID.String()}, nil)

	s.logger.Info("device joined account",
		"device_id", deviceID,
		"account_id", invite.AccountID,
		"old_account_id", oldAccountID,
	)

	return nil
}

func (s *AccountService) LeaveAccount(ctx context.Context, deviceID uuid.UUID) error {
	device, err := s.deviceStore.GetByID(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("get device: %w", err)
	}

	// Check account status
	account, err := s.accountStore.GetByID(ctx, device.AccountID)
	if err != nil {
		return fmt.Errorf("get account: %w", err)
	}
	if account.Status == model.AccountStatusPendingRecovery {
		return &ErrValidation{Message: "account management not available during recovery"}
	}

	// Check if sole device
	deviceCount, err := s.accountStore.CountDevices(ctx, device.AccountID)
	if err != nil {
		return fmt.Errorf("count devices: %w", err)
	}
	if deviceCount <= 1 {
		return &ErrValidation{Message: "cannot leave: you are the only device in this account"}
	}

	oldAccountID := device.AccountID

	// Create a new single-device account with deterministic ID.
	// Use CreateOrIgnore because for the founding device, identity.AccountID(ek)
	// equals the current account ID — the insert would collide. In that case,
	// generate a fresh random account ID instead.
	newAccountID := identity.AccountID(device.EKFingerprint)
	if newAccountID == oldAccountID {
		newAccountID = uuid.New()
	}
	newAccount := &model.Account{
		ID:              newAccountID,
		Status:          model.AccountStatusActive,
		MembershipEpoch: 1,
	}
	if err := s.accountStore.Create(ctx, newAccount); err != nil {
		return fmt.Errorf("create new account: %w", err)
	}

	// Move device to the new account
	if err := s.deviceStore.UpdateAccountID(ctx, deviceID, newAccountID); err != nil {
		return fmt.Errorf("move device: %w", err)
	}

	// Increment membership epoch on the old account
	if _, err := s.accountStore.IncrementEpoch(ctx, oldAccountID); err != nil {
		return fmt.Errorf("increment epoch: %w", err)
	}

	// Trigger voucher exchange for the old account (remaining members need new vouchers)
	if s.voucherCreator != nil {
		if err := s.voucherCreator.CreateVoucherRequests(ctx, oldAccountID); err != nil {
			s.logger.Warn("failed to create voucher requests after leave", "account_id", oldAccountID, "error", err)
		}
	}

	s.auditStore.LogAction(ctx, model.ActorTypeDevice, deviceID.String(),
		"account.device_left", "account", strPtr(oldAccountID.String()), nil, nil)

	s.logger.Info("device left account",
		"device_id", deviceID,
		"old_account_id", oldAccountID,
		"new_account_id", newAccountID,
	)

	return nil
}

// CleanupExpiredInvites removes expired unconsumed invites.
func (s *AccountService) CleanupExpiredInvites(ctx context.Context) {
	deleted, err := s.inviteStore.DeleteExpired(ctx)
	if err != nil {
		s.logger.Error("expired invite cleanup failed", "error", err)
		return
	}
	if deleted > 0 {
		s.logger.Info("expired invite cleanup", "deleted", deleted)
	}
}
