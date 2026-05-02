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

var ErrEscrowNotFound = errors.New("unlock escrow not found")

type UnlockEscrowStore struct {
	pool *pgxpool.Pool
}

func NewUnlockEscrowStore(pool *pgxpool.Pool) *UnlockEscrowStore {
	return &UnlockEscrowStore{pool: pool}
}

// Upsert inserts or replaces the device's escrow row. picked_up_at is reset to
// NULL on every call so the next pickup re-arms the first-pickup audit emit.
// replacedPrior is true when ON CONFLICT path fired (xmax = 0 indicates a fresh
// insert; non-zero xmax indicates an update).
func (s *UnlockEscrowStore) Upsert(ctx context.Context, e *model.UnlockEscrow) (replacedPrior bool, err error) {
	var inserted bool
	err = s.pool.QueryRow(ctx, `
		INSERT INTO unlock_escrows (device_id, secret, expires_at, created_at, picked_up_at)
		VALUES ($1, $2, $3, NOW(), NULL)
		ON CONFLICT (device_id) DO UPDATE SET
			secret       = EXCLUDED.secret,
			expires_at   = EXCLUDED.expires_at,
			created_at   = NOW(),
			picked_up_at = NULL
		RETURNING xmax = 0
	`, e.DeviceID, e.Secret, e.ExpiresAt).Scan(&inserted)
	if err != nil {
		return false, fmt.Errorf("upsert unlock escrow: %w", err)
	}
	return !inserted, nil
}

// Get returns the device's outstanding escrow row, filtering out expired rows
// at read time. INTERNAL/test-only — request handlers MUST go through
// ClaimFirstPickup so audit dedupe is preserved.
func (s *UnlockEscrowStore) Get(ctx context.Context, deviceID uuid.UUID) (*model.UnlockEscrow, error) {
	e := &model.UnlockEscrow{}
	err := s.pool.QueryRow(ctx, `
		SELECT device_id, secret, expires_at, created_at, picked_up_at
		FROM unlock_escrows
		WHERE device_id = $1 AND expires_at > NOW()
	`, deviceID).Scan(&e.DeviceID, &e.Secret, &e.ExpiresAt, &e.CreatedAt, &e.PickedUpAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrEscrowNotFound
		}
		return nil, fmt.Errorf("get unlock escrow: %w", err)
	}
	return e, nil
}

// ClaimFirstPickup atomically marks the first pickup of the current cycle and
// returns the row in a single query. Both arms of the UNION execute under the
// same Postgres MVCC snapshot — the NOT EXISTS predicate ensures only one arm
// contributes rows. firstPickup is true when the UPDATE arm matched (this
// transaction won the first-pickup race); false when the row already had
// picked_up_at set (a prior pickup won) and the SELECT arm returned the row.
//
// Returns ErrEscrowNotFound if no non-expired row exists for the device.
//
// Note: under READ COMMITTED, the UPDATE arm uses EvalPlanQual to re-read the
// latest committed row at lock-acquire time; the SELECT arm uses the statement
// snapshot. Callers must NOT assume snapshot-coherence between this read and
// any other read in the same transaction.
//
// Cross-cycle race (benign): a Deposit committing concurrently with this
// statement may produce a SELECT-arm return that reflects the prior cycle's
// row (old secret, picked_up_at set); the next pickup will see the new cycle
// via the UPDATE arm. Both cycles' secrets are valid retrievals within their
// respective windows, so this does not violate any device-side contract.
func (s *UnlockEscrowStore) ClaimFirstPickup(ctx context.Context, deviceID uuid.UUID) (*model.UnlockEscrow, bool, error) {
	e := &model.UnlockEscrow{}
	var firstPickup bool
	err := s.pool.QueryRow(ctx, `
		WITH claimed AS (
		    UPDATE unlock_escrows
		    SET picked_up_at = NOW()
		    WHERE device_id = $1 AND expires_at > NOW() AND picked_up_at IS NULL
		    RETURNING device_id, secret, expires_at, created_at, picked_up_at
		)
		SELECT device_id, secret, expires_at, created_at, picked_up_at, true AS first_pickup
		  FROM claimed
		UNION ALL
		SELECT device_id, secret, expires_at, created_at, picked_up_at, false AS first_pickup
		  FROM unlock_escrows
		 WHERE device_id = $1 AND expires_at > NOW() AND NOT EXISTS (SELECT 1 FROM claimed)
	`, deviceID).Scan(&e.DeviceID, &e.Secret, &e.ExpiresAt, &e.CreatedAt, &e.PickedUpAt, &firstPickup)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, ErrEscrowNotFound
		}
		return nil, false, fmt.Errorf("claim first pickup: %w", err)
	}
	return e, firstPickup, nil
}

// Delete removes the device's escrow row. Idempotent — returns deleted=false
// (no error) if no row was present. Callers use deleted to gate audit emit so
// idempotent retries don't inflate the audit trail.
func (s *UnlockEscrowStore) Delete(ctx context.Context, deviceID uuid.UUID) (bool, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM unlock_escrows WHERE device_id = $1`, deviceID)
	if err != nil {
		return false, fmt.Errorf("delete unlock escrow: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// DeleteExpired chunked-deletes up to limit expired rows in one call and
// returns the deleted device IDs so the caller can emit per-device audit
// entries.
//
// The outer DELETE re-checks expires_at < NOW() — without it, a concurrent
// Upsert that replaces the about-to-be-swept row with a fresh non-expired
// one (between subquery materialization and DELETE execution) would have its
// fresh row deleted by device_id alone. EvalPlanQual under READ COMMITTED
// re-evaluates the predicate against the locked row version, so the renewed
// row survives the sweep.
func (s *UnlockEscrowStore) DeleteExpired(ctx context.Context, limit int) ([]uuid.UUID, error) {
	rows, err := s.pool.Query(ctx, `
		DELETE FROM unlock_escrows
		WHERE device_id IN (
		    SELECT device_id FROM unlock_escrows
		    WHERE expires_at < NOW()
		    LIMIT $1
		)
		AND expires_at < NOW()
		RETURNING device_id
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("delete expired unlock escrows: %w", err)
	}
	defer rows.Close()

	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan expired unlock escrow id: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// OldestExpiredAge returns the age of the oldest expired row, or 0 if none
// exist. The age is computed server-side via NOW() so the value is immune to
// clock skew between the Postgres host and namek-server.
func (s *UnlockEscrowStore) OldestExpiredAge(ctx context.Context) (time.Duration, error) {
	var seconds *int64
	err := s.pool.QueryRow(ctx, `
		SELECT EXTRACT(EPOCH FROM (NOW() - MIN(expires_at)))::bigint
		FROM unlock_escrows WHERE expires_at < NOW()
	`).Scan(&seconds)
	if err != nil {
		return 0, fmt.Errorf("oldest expired age: %w", err)
	}
	if seconds == nil {
		return 0, nil
	}
	return time.Duration(*seconds) * time.Second, nil
}
