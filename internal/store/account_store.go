package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/AtDexters-Lab/namek-server/internal/model"
)

var ErrAccountNotFound = errors.New("account not found")

type AccountStore struct {
	pool *pgxpool.Pool
}

func NewAccountStore(pool *pgxpool.Pool) *AccountStore {
	return &AccountStore{pool: pool}
}

func (s *AccountStore) Create(ctx context.Context, account *model.Account) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO accounts (id, status, membership_epoch, founding_ek_fingerprint) VALUES ($1, $2, $3, $4)
	`, account.ID, account.Status, account.MembershipEpoch, account.FoundingEKFingerprint)
	if err != nil {
		return fmt.Errorf("insert account: %w", err)
	}
	return nil
}

// CreateOrIgnore inserts an account or does nothing if it already exists.
// Used for concurrent recovery enrollment where multiple devices may
// try to create the same account simultaneously.
func (s *AccountStore) CreateOrIgnore(ctx context.Context, account *model.Account) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO accounts (id, status, membership_epoch, founding_ek_fingerprint, recovery_deadline)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (id) DO NOTHING
	`, account.ID, account.Status, account.MembershipEpoch, account.FoundingEKFingerprint, account.RecoveryDeadline)
	if err != nil {
		return fmt.Errorf("insert or ignore account: %w", err)
	}
	return nil
}

func (s *AccountStore) GetByID(ctx context.Context, id uuid.UUID) (*model.Account, error) {
	a := &model.Account{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, status, membership_epoch, founding_ek_fingerprint, recovery_deadline, dissolved_at, created_at
		FROM accounts WHERE id = $1
	`, id).Scan(&a.ID, &a.Status, &a.MembershipEpoch, &a.FoundingEKFingerprint, &a.RecoveryDeadline, &a.DissolvedAt, &a.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAccountNotFound
		}
		return nil, fmt.Errorf("get account by id: %w", err)
	}
	return a, nil
}

// UpdateStatus sets the account status.
func (s *AccountStore) UpdateStatus(ctx context.Context, id uuid.UUID, status model.AccountStatus) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE accounts SET status = $1 WHERE id = $2
	`, status, id)
	if err != nil {
		return fmt.Errorf("update account status: %w", err)
	}
	return nil
}

// IncrementEpoch atomically increments the membership epoch and returns the new value.
func (s *AccountStore) IncrementEpoch(ctx context.Context, id uuid.UUID) (int, error) {
	var epoch int
	err := s.pool.QueryRow(ctx, `
		UPDATE accounts SET membership_epoch = membership_epoch + 1
		WHERE id = $1
		RETURNING membership_epoch
	`, id).Scan(&epoch)
	if err != nil {
		return 0, fmt.Errorf("increment epoch: %w", err)
	}
	return epoch, nil
}

// SetDissolvedAt sets the dissolved_at timestamp on an account.
func (s *AccountStore) SetDissolvedAt(ctx context.Context, id uuid.UUID, dissolvedAt *time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE accounts SET dissolved_at = $1 WHERE id = $2
	`, dissolvedAt, id)
	if err != nil {
		return false, fmt.Errorf("set dissolved_at: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// DeleteEmpty deletes an account if it has no devices.
func (s *AccountStore) DeleteEmpty(ctx context.Context, accountID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `
		DELETE FROM accounts WHERE id = $1 AND NOT EXISTS (
			SELECT 1 FROM devices WHERE account_id = $1
		)
	`, accountID)
	if err != nil {
		return fmt.Errorf("delete empty account: %w", err)
	}
	return nil
}

// CountDevices returns the number of devices in an account.
func (s *AccountStore) CountDevices(ctx context.Context, accountID uuid.UUID) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM devices WHERE account_id = $1
	`, accountID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count devices: %w", err)
	}
	return count, nil
}
