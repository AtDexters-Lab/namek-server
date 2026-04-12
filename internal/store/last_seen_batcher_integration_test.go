//go:build integration

// This file is compiled only under `go test -tags=integration`. It exercises
// the LastSeenBatcher monotonic guard (WHERE v.ts > d.last_seen_at) against a
// real Postgres so the guard survives future refactors. It lives in
// package store so it can expose a test-only recordAt helper that reaches into
// the unexported pending map.

package store

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordAt is a test-only analog of LastSeenBatcher.Record that pins the
// entry's timestamp instead of calling time.Now(). The race-fix regression
// test needs deterministic timestamps to assert guard behaviour without
// relying on wall-clock arithmetic. Declared in a _test.go file so it never
// compiles into production binaries.
func (b *LastSeenBatcher) recordAt(deviceID uuid.UUID, ip net.IP, ts time.Time) {
	b.mu.Lock()
	b.pending[deviceID] = lastSeenEntry{ip: ip, timestamp: ts}
	b.mu.Unlock()
}

func testDBURL() string {
	if v := os.Getenv("NAMEK_TEST_DB"); v != "" {
		return v
	}
	return "postgres://namek:namek@localhost:5432/namek?sslmode=disable"
}

// insertMinimalDevice directly INSERTs a synthetic device row so the batcher
// race test doesn't need the full enrollment stack. Returns the device ID and
// the DB-side last_seen_at value — the test uses the DB-assigned timestamp to
// derive stale/fresh offsets, which keeps the assertion independent of any
// Go vs Postgres wall-clock skew on CI hosts.
func insertMinimalDevice(t *testing.T, ctx context.Context, pool *pgxpool.Pool) (uuid.UUID, time.Time) {
	t.Helper()
	accountID := uuid.New()
	deviceID := uuid.New()
	ekFingerprint := "race-test-ek-" + deviceID.String()
	slug := "racetestslug" + deviceID.String()[:8]

	_, err := pool.Exec(ctx, `
		INSERT INTO accounts (id, status, membership_epoch)
		VALUES ($1, 'active', 1)
	`, accountID)
	require.NoError(t, err)

	_, err = pool.Exec(ctx, `
		INSERT INTO devices (
			id, account_id, slug, hostname,
			identity_class, ek_fingerprint, ak_public_key,
			trust_level, ip_address, status, last_seen_at
		) VALUES (
			$1, $2, $3, $3 || '.test.local',
			'unverified', $4, '\x00'::bytea,
			'provisional', '10.0.0.100'::inet, 'active', NOW()
		)
	`, deviceID, accountID, slug, ekFingerprint)
	require.NoError(t, err)

	var baseline time.Time
	err = pool.QueryRow(ctx,
		"SELECT last_seen_at FROM devices WHERE id = $1", deviceID,
	).Scan(&baseline)
	require.NoError(t, err)
	return deviceID, baseline
}

// TestLastSeenBatcher_MonotonicGuard is the regression guard for the
// WHERE clause fix in flushChunk. It does NOT depend on wall-clock arithmetic:
// the "stale" and "fresh" entry timestamps are derived from the baseline
// DB NOW() observed at INSERT time, so the test is stable even if the
// Go host and Postgres host disagree on UTC by several seconds.
//
// If a future refactor drops the `AND (d.last_seen_at IS NULL OR v.ts > d.last_seen_at)`
// guard, the stale case will fail: the batcher will overwrite the row.
func TestLastSeenBatcher_MonotonicGuard(t *testing.T) {
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, testDBURL())
	require.NoError(t, err, "connect to test DB")
	defer pool.Close()

	// Clean any leftover state from prior runs. Order matters for FKs.
	_, err = pool.Exec(ctx, `
		DELETE FROM audit_log;
		DELETE FROM device_domain_assignments;
		DELETE FROM account_domains;
		DELETE FROM acme_challenges;
		DELETE FROM released_hostnames;
		DELETE FROM voucher_requests;
		DELETE FROM recovery_claims;
		DELETE FROM ek_issuer_observations;
		DELETE FROM devices;
		DELETE FROM accounts;
	`)
	require.NoError(t, err)

	deviceID, baseline := insertMinimalDevice(t, ctx, pool)
	t.Logf("inserted device %s with last_seen_at=%s ip_address=10.0.0.100",
		deviceID, baseline.Format(time.RFC3339Nano))

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	batcher := NewLastSeenBatcher(pool, logger)

	// --- Case 1: stale entry must NOT overwrite a fresher row. ---
	// staleTS is strictly earlier than the row's baseline last_seen_at, so the
	// guard predicate (v.ts > d.last_seen_at) evaluates false and the UPDATE
	// must be skipped.
	staleTS := baseline.Add(-1 * time.Second)
	staleIP := net.ParseIP("10.0.0.200")
	batcher.recordAt(deviceID, staleIP, staleTS)
	batcher.Flush(ctx)

	var gotIP *string
	var gotLastSeen time.Time
	err = pool.QueryRow(ctx,
		"SELECT host(ip_address), last_seen_at FROM devices WHERE id = $1", deviceID,
	).Scan(&gotIP, &gotLastSeen)
	require.NoError(t, err)
	require.NotNil(t, gotIP, "ip_address should still be populated")
	assert.Equal(t, "10.0.0.100", *gotIP,
		"stale batcher entry must not overwrite row whose last_seen_at is newer")
	assert.True(t, gotLastSeen.Equal(baseline),
		"last_seen_at should be unchanged when guard rejects the write (want %s got %s)",
		baseline, gotLastSeen)

	// --- Case 2: fresh entry SHOULD overwrite. ---
	// freshTS is strictly after the row's baseline last_seen_at, so the guard
	// predicate is true and the UPDATE lands.
	freshTS := baseline.Add(1 * time.Hour)
	freshIP := net.ParseIP("10.0.0.250")
	batcher.recordAt(deviceID, freshIP, freshTS)
	batcher.Flush(ctx)

	err = pool.QueryRow(ctx,
		"SELECT host(ip_address), last_seen_at FROM devices WHERE id = $1", deviceID,
	).Scan(&gotIP, &gotLastSeen)
	require.NoError(t, err)
	require.NotNil(t, gotIP)
	assert.Equal(t, "10.0.0.250", *gotIP,
		"fresh batcher entry should overwrite the row")
	assert.True(t, gotLastSeen.Equal(freshTS),
		"last_seen_at should advance to freshTS (want %s got %s)",
		freshTS, gotLastSeen)
}

// TestLastSeenBatcher_NullLastSeenIsNotBlocked covers the `d.last_seen_at IS NULL`
// branch of the guard. When a row was created without last_seen_at (older
// schema path, rare but possible), any batcher entry must be allowed through
// — otherwise those rows would never get their first last_seen_at populated.
func TestLastSeenBatcher_NullLastSeenIsNotBlocked(t *testing.T) {
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, testDBURL())
	require.NoError(t, err)
	defer pool.Close()

	_, err = pool.Exec(ctx, `
		DELETE FROM audit_log;
		DELETE FROM device_domain_assignments;
		DELETE FROM account_domains;
		DELETE FROM acme_challenges;
		DELETE FROM released_hostnames;
		DELETE FROM voucher_requests;
		DELETE FROM recovery_claims;
		DELETE FROM ek_issuer_observations;
		DELETE FROM devices;
		DELETE FROM accounts;
	`)
	require.NoError(t, err)

	// Insert a row with last_seen_at explicitly NULL.
	accountID := uuid.New()
	deviceID := uuid.New()
	_, err = pool.Exec(ctx, `
		INSERT INTO accounts (id, status, membership_epoch)
		VALUES ($1, 'active', 1)
	`, accountID)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO devices (
			id, account_id, slug, hostname,
			identity_class, ek_fingerprint, ak_public_key,
			trust_level, ip_address, status, last_seen_at
		) VALUES (
			$1, $2, 'nullseenslug', 'nullseenslug.test.local',
			'unverified', 'null-seen-ek', '\x00'::bytea,
			'provisional', NULL, 'active', NULL
		)
	`, deviceID, accountID)
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	batcher := NewLastSeenBatcher(pool, logger)

	// Truncate to microsecond resolution — Postgres timestamptz stores with
	// microsecond precision, so comparing the Go-source ts against the DB-read
	// value requires dropping sub-microsecond nanoseconds.
	ts := time.Now().UTC().Truncate(time.Microsecond)
	batcher.recordAt(deviceID, net.ParseIP("192.168.1.42"), ts)
	batcher.Flush(ctx)

	var gotIP *string
	var gotLastSeen *time.Time
	err = pool.QueryRow(ctx,
		"SELECT host(ip_address), last_seen_at FROM devices WHERE id = $1", deviceID,
	).Scan(&gotIP, &gotLastSeen)
	require.NoError(t, err)
	require.NotNil(t, gotIP, "ip_address should be populated after first flush")
	assert.Equal(t, "192.168.1.42", *gotIP)
	require.NotNil(t, gotLastSeen, "last_seen_at should be populated after first flush")
	assert.True(t, gotLastSeen.Equal(ts),
		"first write against NULL last_seen_at must land regardless of guard")
}
