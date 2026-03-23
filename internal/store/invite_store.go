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

var ErrInviteNotFound = errors.New("invite not found")

type InviteStore struct {
	pool *pgxpool.Pool
}

func NewInviteStore(pool *pgxpool.Pool) *InviteStore {
	return &InviteStore{pool: pool}
}

func (s *InviteStore) Create(ctx context.Context, invite *model.AccountInvite) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO account_invites (id, account_id, invite_code_hash, created_by_device_id, expires_at)
		VALUES ($1, $2, $3, $4, $5)
	`, invite.ID, invite.AccountID, invite.InviteCodeHash, invite.CreatedByDeviceID, invite.ExpiresAt)
	if err != nil {
		return fmt.Errorf("insert invite: %w", err)
	}
	return nil
}

func (s *InviteStore) GetByCodeHash(ctx context.Context, codeHash string) (*model.AccountInvite, error) {
	inv := &model.AccountInvite{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, account_id, invite_code_hash, created_by_device_id, expires_at,
		       consumed_at, consumed_by_device_id, created_at
		FROM account_invites
		WHERE invite_code_hash = $1
	`, codeHash).Scan(
		&inv.ID, &inv.AccountID, &inv.InviteCodeHash, &inv.CreatedByDeviceID, &inv.ExpiresAt,
		&inv.ConsumedAt, &inv.ConsumedByDeviceID, &inv.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInviteNotFound
		}
		return nil, fmt.Errorf("get invite by code hash: %w", err)
	}
	return inv, nil
}

// CountActiveByAccount returns the number of unconsumed, unexpired invites for an account.
func (s *InviteStore) CountActiveByAccount(ctx context.Context, accountID uuid.UUID) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM account_invites
		WHERE account_id = $1 AND consumed_at IS NULL AND expires_at > NOW()
	`, accountID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count active invites: %w", err)
	}
	return count, nil
}

func (s *InviteStore) Consume(ctx context.Context, inviteID uuid.UUID, deviceID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE account_invites
		SET consumed_at = NOW(), consumed_by_device_id = $1
		WHERE id = $2 AND consumed_at IS NULL
	`, deviceID, inviteID)
	if err != nil {
		return fmt.Errorf("consume invite: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("invite already consumed or not found")
	}
	return nil
}

// DeleteExpired removes expired unconsumed invites. Returns the number deleted.
func (s *InviteStore) DeleteExpired(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM account_invites
		WHERE consumed_at IS NULL AND expires_at < NOW()
	`)
	if err != nil {
		return 0, fmt.Errorf("delete expired invites: %w", err)
	}
	return tag.RowsAffected(), nil
}



