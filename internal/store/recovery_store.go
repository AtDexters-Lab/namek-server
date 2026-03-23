package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/AtDexters-Lab/namek-server/internal/model"
)

var ErrRecoveryClaimNotFound = errors.New("recovery claim not found")

type RecoveryStore struct {
	pool *pgxpool.Pool
}

func NewRecoveryStore(pool *pgxpool.Pool) *RecoveryStore {
	return &RecoveryStore{pool: pool}
}

// UpsertClaim inserts or updates a recovery claim.
func (s *RecoveryStore) UpsertClaim(ctx context.Context, claim *model.RecoveryClaim) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO recovery_claims (id, device_id, claimed_account_id, voucher_data, voucher_quote,
			voucher_epoch, issuer_ak_public_key, issuer_ek_fingerprint, issuer_ek_cert)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (device_id, claimed_account_id, issuer_ek_fingerprint) DO UPDATE SET
			voucher_data = EXCLUDED.voucher_data,
			voucher_quote = EXCLUDED.voucher_quote,
			voucher_epoch = EXCLUDED.voucher_epoch,
			issuer_ak_public_key = EXCLUDED.issuer_ak_public_key,
			issuer_ek_cert = EXCLUDED.issuer_ek_cert,
			attributed = FALSE,
			rejected = FALSE,
			rejection_reason = NULL,
			attributed_at = NULL
	`, claim.ID, claim.DeviceID, claim.ClaimedAccountID, claim.VoucherData, claim.VoucherQuote,
		claim.VoucherEpoch, claim.IssuerAKPublicKey, claim.IssuerEKFingerprint, claim.IssuerEKCert)
	if err != nil {
		return fmt.Errorf("upsert recovery claim: %w", err)
	}
	return nil
}

// GetByAccount returns all recovery claims for a given account.
func (s *RecoveryStore) GetByAccount(ctx context.Context, accountID uuid.UUID) ([]model.RecoveryClaim, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, device_id, claimed_account_id, voucher_data, voucher_quote,
			voucher_epoch, issuer_ak_public_key, issuer_ek_fingerprint, issuer_ek_cert,
			attributed, rejected, rejection_reason, attributed_at, created_at
		FROM recovery_claims
		WHERE claimed_account_id = $1
	`, accountID)
	if err != nil {
		return nil, fmt.Errorf("get recovery claims by account: %w", err)
	}
	defer rows.Close()
	return scanRecoveryClaims(rows)
}

// GetUnattributedByIssuer returns unattributed, non-rejected claims from a specific issuer EK.
func (s *RecoveryStore) GetUnattributedByIssuer(ctx context.Context, issuerEKFingerprint string) ([]model.RecoveryClaim, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, device_id, claimed_account_id, voucher_data, voucher_quote,
			voucher_epoch, issuer_ak_public_key, issuer_ek_fingerprint, issuer_ek_cert,
			attributed, rejected, rejection_reason, attributed_at, created_at
		FROM recovery_claims
		WHERE issuer_ek_fingerprint = $1 AND attributed = FALSE AND rejected = FALSE
	`, issuerEKFingerprint)
	if err != nil {
		return nil, fmt.Errorf("get unattributed claims by issuer: %w", err)
	}
	defer rows.Close()
	return scanRecoveryClaims(rows)
}

// HasUnattributedClaims checks if there are any unattributed claims from this issuer.
func (s *RecoveryStore) HasUnattributedClaims(ctx context.Context, issuerEKFingerprint string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM recovery_claims
			WHERE issuer_ek_fingerprint = $1 AND attributed = FALSE AND rejected = FALSE
			LIMIT 1
		)
	`, issuerEKFingerprint).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check unattributed claims: %w", err)
	}
	return exists, nil
}

// AttributeClaim marks a claim as attributed.
func (s *RecoveryStore) AttributeClaim(ctx context.Context, claimID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE recovery_claims SET attributed = TRUE, attributed_at = NOW()
		WHERE id = $1
	`, claimID)
	if err != nil {
		return fmt.Errorf("attribute claim: %w", err)
	}
	return nil
}

// RejectClaim marks a claim as rejected with a reason.
func (s *RecoveryStore) RejectClaim(ctx context.Context, claimID uuid.UUID, reason string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE recovery_claims SET rejected = TRUE, rejection_reason = $1
		WHERE id = $2
	`, reason, claimID)
	if err != nil {
		return fmt.Errorf("reject claim: %w", err)
	}
	return nil
}

// CountAttributedByAccount returns the count of attributed claims for an account.
func (s *RecoveryStore) CountAttributedByAccount(ctx context.Context, accountID uuid.UUID) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM recovery_claims
		WHERE claimed_account_id = $1 AND attributed = TRUE
	`, accountID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count attributed claims: %w", err)
	}
	return count, nil
}

// CountDistinctDevicesByAccount returns the number of distinct devices with attributed claims.
func (s *RecoveryStore) CountDistinctDevicesByAccount(ctx context.Context, accountID uuid.UUID) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT device_id) FROM recovery_claims
		WHERE claimed_account_id = $1 AND attributed = TRUE
	`, accountID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count distinct devices: %w", err)
	}
	return count, nil
}

// CountExpectedMembersByAccount returns the number of distinct EK fingerprints
// referenced across all recovery claims for an account (both issuer and subject).
// This gives the expected account size from the voucher graph.
func (s *RecoveryStore) CountExpectedMembersByAccount(ctx context.Context, accountID uuid.UUID) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT ek) FROM (
			SELECT issuer_ek_fingerprint AS ek FROM recovery_claims WHERE claimed_account_id = $1
			UNION
			SELECT d.ek_fingerprint AS ek FROM devices d WHERE d.account_id = $1
		) sub
	`, accountID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count expected members: %w", err)
	}
	return count, nil
}

// GetMaxEpochByAccount returns the maximum voucher epoch for an account.
func (s *RecoveryStore) GetMaxEpochByAccount(ctx context.Context, accountID uuid.UUID) (int, error) {
	var maxEpoch int
	err := s.pool.QueryRow(ctx, `
		SELECT COALESCE(MAX(voucher_epoch), 0) FROM recovery_claims
		WHERE claimed_account_id = $1
	`, accountID).Scan(&maxEpoch)
	if err != nil {
		return 0, fmt.Errorf("get max epoch: %w", err)
	}
	return maxEpoch, nil
}

// DeleteByAccount removes all recovery claims for an account.
func (s *RecoveryStore) DeleteByAccount(ctx context.Context, accountID uuid.UUID) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM recovery_claims WHERE claimed_account_id = $1
	`, accountID)
	if err != nil {
		return 0, fmt.Errorf("delete claims by account: %w", err)
	}
	return tag.RowsAffected(), nil
}

// DeleteClaimsForActiveAccounts removes claims whose account is now active and
// were created more than retentionDays ago (24h retention for forensic review per RFC).
func (s *RecoveryStore) DeleteClaimsForActiveAccounts(ctx context.Context, retentionDays int) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM recovery_claims
		WHERE created_at < NOW() - ($1 || ' days')::interval
		AND EXISTS (
			SELECT 1 FROM accounts WHERE id = claimed_account_id AND status = 'active'
		)
	`, retentionDays)
	if err != nil {
		return 0, fmt.Errorf("delete claims for active accounts: %w", err)
	}
	return tag.RowsAffected(), nil
}

// DeleteOrphaned removes claims older than the given age whose account doesn't exist.
func (s *RecoveryStore) DeleteOrphaned(ctx context.Context, olderThanDays int) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM recovery_claims
		WHERE created_at < NOW() - ($1 || ' days')::interval
		AND NOT EXISTS (SELECT 1 FROM accounts WHERE id = claimed_account_id)
	`, olderThanDays)
	if err != nil {
		return 0, fmt.Errorf("delete orphaned claims: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ListPendingRecoveryAccounts returns account IDs in pending_recovery state.
func (s *RecoveryStore) ListPendingRecoveryAccounts(ctx context.Context) ([]uuid.UUID, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id FROM accounts WHERE status = 'pending_recovery'
	`)
	if err != nil {
		return nil, fmt.Errorf("list pending recovery accounts: %w", err)
	}
	defer rows.Close()

	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan account id: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func scanRecoveryClaims(rows pgx.Rows) ([]model.RecoveryClaim, error) {
	var claims []model.RecoveryClaim
	for rows.Next() {
		var c model.RecoveryClaim
		if err := rows.Scan(&c.ID, &c.DeviceID, &c.ClaimedAccountID, &c.VoucherData, &c.VoucherQuote,
			&c.VoucherEpoch, &c.IssuerAKPublicKey, &c.IssuerEKFingerprint, &c.IssuerEKCert,
			&c.Attributed, &c.Rejected, &c.RejectionReason, &c.AttributedAt, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan recovery claim: %w", err)
		}
		claims = append(claims, c)
	}
	return claims, rows.Err()
}

