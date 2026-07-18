//go:build integration

package store

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRecoveryStore_CleanupClaims exercises the cleanup queries against real
// Postgres so pgx parameter-type inference remains covered alongside the
// retention predicates.
func TestRecoveryStore_CleanupClaims(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, testDBURL())
	require.NoError(t, err, "connect to test DB")
	t.Cleanup(pool.Close)

	accountID := uuid.New()
	deviceID := uuid.New()
	orphanedAccountID := uuid.New()
	slug := "cleanup" + deviceID.String()[:12]

	_, err = pool.Exec(ctx, `
		INSERT INTO accounts (id, status, membership_epoch)
		VALUES ($1, 'active', 1)
	`, accountID)
	require.NoError(t, err)

	_, err = pool.Exec(ctx, `
		INSERT INTO devices (
			id, account_id, slug, hostname, identity_class,
			ek_fingerprint, ak_public_key, status
		) VALUES (
			$1, $2, $3, $3 || '.test.local', 'unverified',
			$4, '\x01'::bytea, 'active'
		)
	`, deviceID, accountID, slug, "cleanup-ek-"+deviceID.String())
	require.NoError(t, err)

	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM devices WHERE id = $1`, deviceID)
		_, _ = pool.Exec(ctx, `DELETE FROM accounts WHERE id = $1`, accountID)
	})

	insertClaim := func(claimedAccountID uuid.UUID, createdAt time.Time) uuid.UUID {
		t.Helper()
		claimID := uuid.New()
		_, insertErr := pool.Exec(ctx, `
			INSERT INTO recovery_claims (
				id, device_id, claimed_account_id, voucher_data,
				voucher_quote, voucher_epoch, issuer_ak_public_key,
				issuer_ek_fingerprint, created_at
			) VALUES ($1, $2, $3, 'voucher', 'quote', 1, '\x01'::bytea, $4, $5)
		`, claimID, deviceID, claimedAccountID, "cleanup-issuer-"+claimID.String(), createdAt)
		require.NoError(t, insertErr)
		return claimID
	}

	activeOld := insertClaim(accountID, time.Now().Add(-48*time.Hour))
	activeRecent := insertClaim(accountID, time.Now())
	orphanedOld := insertClaim(orphanedAccountID, time.Now().Add(-8*24*time.Hour))
	orphanedRecent := insertClaim(orphanedAccountID, time.Now())

	store := NewRecoveryStore(pool)
	deleted, err := store.DeleteClaimsForActiveAccounts(ctx, 1)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, deleted, int64(1),
		"the active fixture must contribute one deletion; a shared test DB may contain other eligible rows")

	deleted, err = store.DeleteOrphaned(ctx, 7)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, deleted, int64(1),
		"the orphaned fixture must contribute one deletion; a shared test DB may contain other eligible rows")

	var remaining []uuid.UUID
	rows, err := pool.Query(ctx, `
		SELECT id FROM recovery_claims
		WHERE id = ANY($1)
		ORDER BY id
	`, []uuid.UUID{activeOld, activeRecent, orphanedOld, orphanedRecent})
	require.NoError(t, err)
	defer rows.Close()

	for rows.Next() {
		var id uuid.UUID
		require.NoError(t, rows.Scan(&id))
		remaining = append(remaining, id)
	}
	require.NoError(t, rows.Err())
	assert.ElementsMatch(t, []uuid.UUID{activeRecent, orphanedRecent}, remaining)
}
