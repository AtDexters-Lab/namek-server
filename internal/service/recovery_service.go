package service

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
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

type RecoveryService struct {
	recoveryStore *store.RecoveryStore
	accountStore  *store.AccountStore
	deviceStore   *store.DeviceStore
	auditStore    *store.AuditStore
	tpmVerifier   tpm.Verifier
	cfg           *config.Config
	logger        *slog.Logger
}

func NewRecoveryService(
	recoveryStore *store.RecoveryStore,
	accountStore *store.AccountStore,
	deviceStore *store.DeviceStore,
	auditStore *store.AuditStore,
	tpmVerifier tpm.Verifier,
	cfg *config.Config,
	logger *slog.Logger,
) *RecoveryService {
	return &RecoveryService{
		recoveryStore: recoveryStore,
		accountStore:  accountStore,
		deviceStore:   deviceStore,
		auditStore:    auditStore,
		tpmVerifier:   tpmVerifier,
		cfg:           cfg,
		logger:        logger,
	}
}

// RecoveryBundle represents a recovery bundle from the enrollment request.
type RecoveryBundle struct {
	AccountID      string         `json:"account_id"`
	Vouchers       []VoucherProof `json:"vouchers"`
	CustomHostname string         `json:"custom_hostname,omitempty"`
	AliasDomains   []string       `json:"alias_domains,omitempty"`
}

// VoucherProof is a single voucher in a recovery bundle.
type VoucherProof struct {
	Data              string `json:"data"`
	Quote             string `json:"quote"`
	IssuerAKPublicKey string `json:"issuer_ak_public_key"`
	IssuerEKCert      string `json:"issuer_ek_cert,omitempty"`
}

// ValidateRecoveryBundle performs structural and consistency checks on the bundle.
func (s *RecoveryService) ValidateRecoveryBundle(bundle *RecoveryBundle) error {
	claimedAccountID, err := uuid.Parse(bundle.AccountID)
	if err != nil {
		return fmt.Errorf("invalid account_id in recovery bundle: %w", err)
	}

	if len(bundle.Vouchers) == 0 {
		return fmt.Errorf("recovery bundle must contain at least one voucher")
	}

	// 1. Consistency check: all vouchers must claim the same account_id
	for i, vp := range bundle.Vouchers {
		voucherDataBytes, err := base64.StdEncoding.DecodeString(vp.Data)
		if err != nil {
			return fmt.Errorf("decode voucher data [%d]: %w", i, err)
		}
		var vd voucher.VoucherData
		if err := json.Unmarshal(voucherDataBytes, &vd); err != nil {
			return fmt.Errorf("parse voucher data [%d]: %w", i, err)
		}
		if vd.AccountID != bundle.AccountID {
			return fmt.Errorf("voucher [%d] account_id %q != bundle account_id %q", i, vd.AccountID, bundle.AccountID)
		}

		// 2. Account ID verification: founding_ek_fingerprint must produce the claimed account_id
		expectedAccountID := identity.AccountID(vd.FoundingEKFingerprint)
		if expectedAccountID != claimedAccountID {
			return fmt.Errorf("voucher [%d] founding_ek_fingerprint produces account %s, expected %s",
				i, expectedAccountID, claimedAccountID)
		}
	}

	return nil
}

// ProcessRecoveryBundle validates vouchers and stores recovery claims.
// Errors are logged but do not block enrollment (non-blocking).
func (s *RecoveryService) ProcessRecoveryBundle(ctx context.Context, deviceID uuid.UUID, ekFingerprint string, bundle *RecoveryBundle) error {
	claimedAccountID, err := uuid.Parse(bundle.AccountID)
	if err != nil {
		return fmt.Errorf("invalid account_id in recovery bundle: %w", err)
	}

	// 3. Phase 1 verification + claim storage
	storedCount := 0
	for i, vp := range bundle.Vouchers {
		voucherDataBytes, err := base64.StdEncoding.DecodeString(vp.Data)
		if err != nil {
			s.logger.Warn("skip voucher: invalid base64", "index", i, "error", err)
			continue
		}

		// Derive expected nonce
		expectedNonce := voucher.NonceFromData(voucherDataBytes)

		// Decode issuer AK public key
		issuerAKPub, err := base64.StdEncoding.DecodeString(vp.IssuerAKPublicKey)
		if err != nil {
			s.logger.Warn("skip voucher: invalid issuer AK base64", "index", i, "error", err)
			continue
		}

		// Verify TPM quote
		if _, err := s.tpmVerifier.VerifyQuote(issuerAKPub, expectedNonce, vp.Quote, nil); err != nil {
			s.logger.Warn("skip voucher: quote verification failed", "index", i, "error", err)
			continue
		}

		// Parse voucher data for epoch and issuer fingerprint
		var vd voucher.VoucherData
		if err := json.Unmarshal(voucherDataBytes, &vd); err != nil {
			continue
		}

		// Validate voucher subject matches the enrolling device
		if vd.SubjectEKFingerprint != ekFingerprint {
			s.logger.Warn("skip voucher: subject EK fingerprint mismatch",
				"index", i, "expected", ekFingerprint, "got", vd.SubjectEKFingerprint)
			continue
		}

		// Decode optional issuer EK cert
		var issuerEKCert []byte
		if vp.IssuerEKCert != "" {
			issuerEKCert, _ = base64.StdEncoding.DecodeString(vp.IssuerEKCert)
		}

		// 4. Store unattributed claim
		claim := &model.RecoveryClaim{
			ID:                  uuid.New(),
			DeviceID:            deviceID,
			ClaimedAccountID:    claimedAccountID,
			VoucherData:         vp.Data,
			VoucherQuote:        vp.Quote,
			VoucherEpoch:        vd.Epoch,
			IssuerAKPublicKey:   issuerAKPub,
			IssuerEKFingerprint: vd.IssuerEKFingerprint,
			IssuerEKCert:        issuerEKCert,
		}
		if err := s.recoveryStore.UpsertClaim(ctx, claim); err != nil {
			s.logger.Warn("failed to store recovery claim", "index", i, "error", err)
			continue
		}
		storedCount++

		// 5. Immediate attribution: check if issuer already re-enrolled
		issuer, err := s.deviceStore.GetByEKFingerprint(ctx, vd.IssuerEKFingerprint)
		if err == nil && bytes.Equal(issuer.AKPublicKey, issuerAKPub) {
			if err := s.recoveryStore.AttributeClaim(ctx, claim.ID); err != nil {
				s.logger.Warn("failed to attribute claim immediately", "claim_id", claim.ID, "error", err)
			} else {
				s.auditStore.LogAction(ctx, model.ActorTypeSystem, "system",
					"voucher.attributed", "recovery_claim", strPtr(claim.ID.String()),
					map[string]string{
						"issuer_ek_fingerprint": vd.IssuerEKFingerprint,
						"account_id":            bundle.AccountID,
					}, nil)
			}
		} else if err == nil {
			// AK mismatch — reject
			if err := s.recoveryStore.RejectClaim(ctx, claim.ID, "issuer AK mismatch"); err != nil {
				s.logger.Warn("failed to reject claim", "claim_id", claim.ID, "error", err)
			}
			s.auditStore.LogAction(ctx, model.ActorTypeSystem, "system",
				"voucher.rejected", "recovery_claim", strPtr(claim.ID.String()),
				map[string]string{
					"issuer_ek_fingerprint": vd.IssuerEKFingerprint,
					"reason":               "issuer AK mismatch",
				}, nil)
		}
	}

	s.auditStore.LogAction(ctx, model.ActorTypeDevice, deviceID.String(),
		"recovery.claim_submitted", "account", strPtr(bundle.AccountID),
		map[string]string{"voucher_count": fmt.Sprintf("%d", storedCount)}, nil)

	// 6. Evaluate quorum
	if _, err := s.EvaluateQuorum(ctx, claimedAccountID); err != nil {
		s.logger.Warn("quorum evaluation failed", "account_id", claimedAccountID, "error", err)
	}

	return nil
}

// AttributeClaimsForDevice attributes unattributed claims where this device is the issuer.
// Called during enrollment after a device re-enrolls.
func (s *RecoveryService) AttributeClaimsForDevice(ctx context.Context, ekFingerprint string, akPublicKey []byte) error {
	hasUnattributed, err := s.recoveryStore.HasUnattributedClaims(ctx, ekFingerprint)
	if err != nil {
		return fmt.Errorf("check unattributed claims: %w", err)
	}
	if !hasUnattributed {
		return nil
	}

	claims, err := s.recoveryStore.GetUnattributedByIssuer(ctx, ekFingerprint)
	if err != nil {
		return fmt.Errorf("get unattributed claims: %w", err)
	}

	affectedAccounts := make(map[uuid.UUID]bool)
	for _, claim := range claims {
		if bytes.Equal(claim.IssuerAKPublicKey, akPublicKey) {
			if err := s.recoveryStore.AttributeClaim(ctx, claim.ID); err != nil {
				s.logger.Warn("failed to attribute claim", "claim_id", claim.ID, "error", err)
				continue
			}
			affectedAccounts[claim.ClaimedAccountID] = true

			s.auditStore.LogAction(ctx, model.ActorTypeSystem, "system",
				"voucher.attributed", "recovery_claim", strPtr(claim.ID.String()),
				map[string]string{
					"issuer_ek_fingerprint": ekFingerprint,
					"account_id":            claim.ClaimedAccountID.String(),
				}, nil)
		} else {
			if err := s.recoveryStore.RejectClaim(ctx, claim.ID, "issuer AK mismatch"); err != nil {
				s.logger.Warn("failed to reject claim", "claim_id", claim.ID, "error", err)
			}
			s.auditStore.LogAction(ctx, model.ActorTypeSystem, "system",
				"voucher.rejected", "recovery_claim", strPtr(claim.ID.String()),
				map[string]string{
					"issuer_ek_fingerprint": ekFingerprint,
					"reason":               "issuer AK mismatch",
				}, nil)
		}
	}

	// Re-evaluate quorum for affected accounts
	for accountID := range affectedAccounts {
		if _, err := s.EvaluateQuorum(ctx, accountID); err != nil {
			s.logger.Warn("quorum evaluation failed after attribution", "account_id", accountID, "error", err)
		}
	}

	return nil
}

// EvaluateQuorum checks if an account has reached quorum and promotes it to active.
func (s *RecoveryService) EvaluateQuorum(ctx context.Context, accountID uuid.UUID) (bool, error) {
	account, err := s.accountStore.GetByID(ctx, accountID)
	if err != nil {
		return false, fmt.Errorf("get account: %w", err)
	}
	if account.Status != model.AccountStatusPendingRecovery {
		return true, nil // already active
	}

	enrolledCount, err := s.accountStore.CountDevices(ctx, accountID)
	if err != nil {
		return false, fmt.Errorf("count enrolled devices: %w", err)
	}

	// Use distinct devices with attributed claims (not total claim count)
	distinctAttested, err := s.recoveryStore.CountDistinctDevicesByAccount(ctx, accountID)
	if err != nil {
		return false, fmt.Errorf("count distinct devices with attributed claims: %w", err)
	}

	// Expected membership: the larger of enrolled devices and distinct EK fingerprints
	// referenced across all recovery claims. This prevents the first device to re-enroll
	// from getting quorum=0 when the account was multi-device before the wipe.
	expectedSize, err := s.recoveryStore.CountExpectedMembersByAccount(ctx, accountID)
	if err != nil {
		s.logger.Warn("failed to count expected members, using enrolled count", "account_id", accountID, "error", err)
		expectedSize = enrolledCount
	}
	if enrolledCount > expectedSize {
		expectedSize = enrolledCount
	}

	// Quorum rules based on expected account size
	var quorumNeeded int
	switch {
	case expectedSize <= 1:
		quorumNeeded = 0 // single-device, no vouchers needed
	case expectedSize == 2:
		quorumNeeded = 2 // both must present
	default:
		quorumNeeded = expectedSize/2 + 1 // majority
	}

	quorumReached := distinctAttested >= quorumNeeded

	s.logger.Info("quorum evaluation",
		"account_id", accountID,
		"enrolled", enrolledCount,
		"expected_size", expectedSize,
		"distinct_attested", distinctAttested,
		"quorum_needed", quorumNeeded,
		"reached", quorumReached,
	)

	if quorumReached {
		if err := s.accountStore.UpdateStatus(ctx, accountID, model.AccountStatusActive); err != nil {
			return false, fmt.Errorf("promote account: %w", err)
		}

		s.auditStore.LogAction(ctx, model.ActorTypeSystem, "system",
			"recovery.quorum_reached", "account", strPtr(accountID.String()),
			map[string]string{
				"device_count":     fmt.Sprintf("%d", enrolledCount),
				"quorum_threshold": fmt.Sprintf("%d", quorumNeeded),
			}, nil)

		s.auditStore.LogAction(ctx, model.ActorTypeSystem, "system",
			"recovery.account_promoted", "account", strPtr(accountID.String()), nil, nil)

		s.logger.Info("account promoted to active", "account_id", accountID)
	}

	return quorumReached, nil
}

// QuorumReEvaluationLoop periodically re-evaluates quorum for pending_recovery accounts.
func (s *RecoveryService) QuorumReEvaluationLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.reEvaluateQuorums(ctx)
		}
	}
}

func (s *RecoveryService) reEvaluateQuorums(ctx context.Context) {
	accountIDs, err := s.recoveryStore.ListPendingRecoveryAccounts(ctx)
	if err != nil {
		s.logger.Error("list pending recovery accounts failed", "error", err)
		return
	}

	for _, accountID := range accountIDs {
		account, err := s.accountStore.GetByID(ctx, accountID)
		if err != nil {
			s.logger.Warn("get account failed during re-evaluation", "account_id", accountID, "error", err)
			continue
		}

		// Check timeout
		if account.RecoveryDeadline != nil && time.Now().After(*account.RecoveryDeadline) {
			s.DissolveAccount(ctx, accountID)
			continue
		}

		// Re-evaluate quorum
		if _, err := s.EvaluateQuorum(ctx, accountID); err != nil {
			s.logger.Warn("quorum re-evaluation failed", "account_id", accountID, "error", err)
		}
	}
}

// DissolveAccount moves each device in a pending_recovery account to its own
// standalone account, marks the original as dissolved, and logs the event.
func (s *RecoveryService) DissolveAccount(ctx context.Context, accountID uuid.UUID) {
	s.logger.Info("dissolving pending recovery account (timeout)", "account_id", accountID)

	// Move each device to its own standalone account per RFC spec
	devices, err := s.deviceStore.ListByAccountID(ctx, accountID)
	if err != nil {
		s.logger.Error("failed to list devices for dissolution", "account_id", accountID, "error", err)
		return
	}

	for _, device := range devices {
		newAccountID := identity.AccountID(device.EKFingerprint)
		newAccount := &model.Account{
			ID:              newAccountID,
			Status:          model.AccountStatusActive,
			MembershipEpoch: 1,
		}
		// Create new standalone account (may already exist if device was founding)
		if err := s.accountStore.CreateOrIgnore(ctx, newAccount); err != nil {
			s.logger.Error("failed to create standalone account", "device_id", device.ID, "error", err)
			continue
		}
		// Set dissolved_at on the new standalone account
		now := time.Now()
		if _, err := s.accountStore.SetDissolvedAt(ctx, newAccountID, &now); err != nil {
			s.logger.Warn("failed to set dissolved_at on standalone account", "account_id", newAccountID, "error", err)
		}
		// Move device
		if err := s.deviceStore.UpdateAccountID(ctx, device.ID, newAccountID); err != nil {
			s.logger.Error("failed to move device to standalone account", "device_id", device.ID, "error", err)
		}
	}

	// Mark original account as dissolved
	if err := s.accountStore.UpdateStatus(ctx, accountID, model.AccountStatusActive); err != nil {
		s.logger.Error("failed to update dissolved account status", "account_id", accountID, "error", err)
	}
	now := time.Now()
	if _, err := s.accountStore.SetDissolvedAt(ctx, accountID, &now); err != nil {
		s.logger.Error("failed to set dissolved_at", "account_id", accountID, "error", err)
	}

	s.auditStore.LogAction(ctx, model.ActorTypeSystem, "system",
		"recovery.account_dissolved", "account", strPtr(accountID.String()),
		map[string]string{"reason": "quorum_timeout", "device_count": fmt.Sprintf("%d", len(devices))}, nil)
}

// CleanupLoop periodically cleans up old recovery claims.
func (s *RecoveryService) CleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.cleanupClaims(ctx)
		}
	}
}

func (s *RecoveryService) cleanupClaims(ctx context.Context) {
	// Delete claims for promoted/dissolved accounts (24h retention per RFC)
	promoted, err := s.recoveryStore.DeleteClaimsForActiveAccounts(ctx, 1)
	if err != nil {
		s.logger.Error("promoted account claims cleanup failed", "error", err)
	} else if promoted > 0 {
		s.logger.Info("promoted account claims cleanup", "deleted", promoted)
	}

	// Delete orphaned claims (no matching account, >7 days old)
	orphaned, err := s.recoveryStore.DeleteOrphaned(ctx, 7)
	if err != nil {
		s.logger.Error("orphaned claims cleanup failed", "error", err)
	} else if orphaned > 0 {
		s.logger.Info("orphaned claims cleanup", "deleted", orphaned)
	}
}
