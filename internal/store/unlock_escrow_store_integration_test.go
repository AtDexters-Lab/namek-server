//go:build integration

// Concurrent-CTE regression test for ClaimFirstPickup. The CTE is the
// load-bearing primitive for the audit-emit-once-per-cycle invariant; if a
// future refactor splits it into two statements or relaxes the NOT EXISTS
// predicate, this test catches it loudly.
//
// Lives under the integration build tag because it exercises a live Postgres
// (the store has no mocking surface).

package store

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AtDexters-Lab/namek-server/internal/model"
)

func TestUnlockEscrow_ClaimFirstPickup_ConcurrentRace(t *testing.T) {
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, testDBURL())
	require.NoError(t, err)
	defer pool.Close()

	// Insert a synthetic device row so the FK on unlock_escrows is satisfied.
	// Mirrors insertMinimalDevice from last_seen_batcher_integration_test.go
	// but inlined here to avoid coupling the two tests.
	deviceID, _ := setupDeviceForEscrowTest(t, ctx, pool)
	defer cleanupDeviceForEscrowTest(t, ctx, pool, deviceID)

	store := NewUnlockEscrowStore(pool)

	// Deposit a fresh secret with a generous window.
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	expiresAt := time.Now().Add(60 * time.Second)
	_, err = store.Upsert(ctx, &model.UnlockEscrow{
		DeviceID:  deviceID,
		Secret:    secret,
		ExpiresAt: expiresAt,
	})
	require.NoError(t, err)

	// Fire N goroutines concurrently against ClaimFirstPickup. Postgres
	// serializes the UPDATE arm via row lock; only one transaction's
	// firstPickup may be true. All others must see the row via the SELECT
	// arm with firstPickup=false. Every return must yield the same secret.
	const goroutines = 16
	var firstCount atomic.Int64
	var notFoundCount atomic.Int64
	results := make([][]byte, goroutines)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	start := make(chan struct{})

	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start
			row, first, err := store.ClaimFirstPickup(ctx, deviceID)
			if err != nil {
				notFoundCount.Add(1)
				return
			}
			if first {
				firstCount.Add(1)
			}
			results[idx] = append([]byte(nil), row.Secret...)
		}(i)
	}

	close(start)
	wg.Wait()

	assert.Equal(t, int64(0), notFoundCount.Load(), "no goroutine should observe ErrEscrowNotFound for a fresh, non-expired row")
	assert.Equal(t, int64(1), firstCount.Load(), "exactly one goroutine must win the first-pickup race; the CTE atomicity is what guarantees audit-emit-once-per-cycle")

	for i, got := range results {
		assert.Equal(t, secret, got, "goroutine %d must return the deposited secret", i)
	}
}

// setupDeviceForEscrowTest inserts a synthetic device + account so the
// unlock_escrows FK is satisfied. Returns the device UUID.
func setupDeviceForEscrowTest(t *testing.T, ctx context.Context, pool *pgxpool.Pool) (uuid.UUID, time.Time) {
	t.Helper()
	accountID := uuid.New()
	deviceID := uuid.New()
	ekFingerprint := "escrow-concurrent-test-ek-" + deviceID.String()
	slug := "ecst" + deviceID.String()[:16]

	_, err := pool.Exec(ctx, `
		INSERT INTO accounts (id, status, membership_epoch)
		VALUES ($1, 'active', 1)
	`, accountID)
	require.NoError(t, err)

	var lastSeenAt time.Time
	err = pool.QueryRow(ctx, `
		INSERT INTO devices (
			id, account_id, slug, hostname, identity_class,
			ek_fingerprint, ak_public_key, status,
			hostname_changes_this_year, hostname_year, last_seen_at
		)
		VALUES (
			$1, $2, $3, $4, 'unverified',
			$5, $6::bytea, 'active',
			0, EXTRACT(YEAR FROM NOW())::int, NOW()
		)
		RETURNING last_seen_at
	`, deviceID, accountID, slug, slug+".test.local", ekFingerprint, []byte("ak-public-key-bytes")).Scan(&lastSeenAt)
	require.NoError(t, err)

	return deviceID, lastSeenAt
}

func cleanupDeviceForEscrowTest(t *testing.T, ctx context.Context, pool *pgxpool.Pool, deviceID uuid.UUID) {
	t.Helper()
	// CASCADE on the FK from unlock_escrows → devices removes the escrow row;
	// devices.account_id has a non-cascading FK to accounts so the account row
	// stays, but the test creates a fresh account UUID per run so it's fine to
	// leave it in the table.
	_, err := pool.Exec(ctx, `DELETE FROM devices WHERE id = $1`, deviceID)
	if err != nil {
		t.Logf("cleanup devices: %v", err)
	}
}
