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

var ErrChallengeNotFound = errors.New("acme challenge not found")

type ACMEStore struct {
	pool *pgxpool.Pool
}

func NewACMEStore(pool *pgxpool.Pool) *ACMEStore {
	return &ACMEStore{pool: pool}
}

func (s *ACMEStore) Create(ctx context.Context, c *model.ACMEChallenge) error {
	// Use RETURNING id to get the actual row ID (may differ from c.ID on upsert)
	err := s.pool.QueryRow(ctx, `
		INSERT INTO acme_challenges (id, device_id, fqdn, key_authorization, expires_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (device_id, fqdn) DO UPDATE SET
			key_authorization = EXCLUDED.key_authorization,
			expires_at = EXCLUDED.expires_at,
			created_at = NOW()
		RETURNING id
	`, c.ID, c.DeviceID, c.FQDN, c.KeyAuthorization, c.ExpiresAt).Scan(&c.ID)
	if err != nil {
		return fmt.Errorf("create acme challenge: %w", err)
	}
	return nil
}

func (s *ACMEStore) GetByID(ctx context.Context, id uuid.UUID) (*model.ACMEChallenge, error) {
	c := &model.ACMEChallenge{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, device_id, fqdn, key_authorization, created_at, expires_at
		FROM acme_challenges WHERE id = $1
	`, id).Scan(&c.ID, &c.DeviceID, &c.FQDN, &c.KeyAuthorization, &c.CreatedAt, &c.ExpiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrChallengeNotFound
		}
		return nil, fmt.Errorf("get acme challenge: %w", err)
	}
	return c, nil
}

func (s *ACMEStore) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM acme_challenges WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete acme challenge: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrChallengeNotFound
	}
	return nil
}

func (s *ACMEStore) GetExpired(ctx context.Context) ([]*model.ACMEChallenge, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, device_id, fqdn, key_authorization, created_at, expires_at
		FROM acme_challenges
		WHERE expires_at < NOW()
	`)
	if err != nil {
		return nil, fmt.Errorf("get expired challenges: %w", err)
	}
	defer rows.Close()

	var challenges []*model.ACMEChallenge
	for rows.Next() {
		c := &model.ACMEChallenge{}
		if err := rows.Scan(&c.ID, &c.DeviceID, &c.FQDN, &c.KeyAuthorization, &c.CreatedAt, &c.ExpiresAt); err != nil {
			return nil, fmt.Errorf("scan expired challenge: %w", err)
		}
		challenges = append(challenges, c)
	}
	return challenges, rows.Err()
}
