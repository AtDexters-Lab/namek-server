//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AtDexters-Lab/namek-server/pkg/namekclient"
	"github.com/AtDexters-Lab/namek-server/pkg/swtpm"
	"github.com/AtDexters-Lab/namek-server/pkg/tpmdevice"
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func TestFullFlow(t *testing.T) {
	ctx := context.Background()

	// Clean up devices from previous test runs so re-enrollment works.
	dbURL := envOr("NAMEK_TEST_DB", "postgres://namek:namek@localhost:5432/namek?sslmode=disable")
	conn, err := pgx.Connect(ctx, dbURL)
	require.NoError(t, err, "connect to DB for cleanup")
	_, err = conn.Exec(ctx, "DELETE FROM audit_log; DELETE FROM device_domain_assignments; DELETE FROM account_domains; DELETE FROM acme_challenges; DELETE FROM unlock_escrows; DELETE FROM released_hostnames; DELETE FROM devices; DELETE FROM accounts")
	require.NoError(t, err, "clean DB")
	conn.Close(ctx)

	// Use the well-known swtpm state dir. The separately-running namek
	// server accepts software TPMs when tpm.allowSoftwareTPM is true.
	rootDir, err := filepath.Abs("../..")
	require.NoError(t, err)
	stateDir := filepath.Join(rootDir, ".local", "swtpm")

	// Start swtpm natively
	proc, err := swtpm.Start(ctx, stateDir)
	require.NoError(t, err, "swtpm start failed — ensure swtpm and swtpm-tools are installed")
	defer proc.Stop()

	// Open TPM connection
	tpm, err := tpmdevice.Open(ctx, proc.Addr())
	require.NoError(t, err)
	defer tpm.Close()

	// Create namekclient
	serverURL := envOr("NAMEK_TEST_URL", "https://localhost:8443")
	client := namekclient.New(serverURL, tpm, namekclient.WithInsecureSkipVerify())

	// Wait for server
	require.Eventually(t, func() bool {
		return client.Ready(ctx) == nil
	}, 30*time.Second, 1*time.Second, "server not ready")

	// 1. Health
	require.NoError(t, client.Health(ctx))

	// 2. Enroll (fresh)
	result, err := client.Enroll(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, result.DeviceID)
	assert.Contains(t, result.Hostname, ".test.local")
	assert.Equal(t, "unverified", result.IdentityClass)
	// Slug-based hostname: should be 20-char slug + ".test.local", not UUID-based
	assert.NotContains(t, result.Hostname, "-", "hostname should be slug-based, not UUID-based")

	// 3. Device info (authenticated)
	info, err := client.GetDeviceInfo(ctx)
	require.NoError(t, err)
	assert.Equal(t, result.DeviceID, info.DeviceID)

	// 4. Custom hostname (unique per run to avoid conflicts)
	hostname := fmt.Sprintf("test%d", time.Now().UnixNano()%100000)
	require.NoError(t, client.SetHostname(ctx, hostname))

	// 5. Nexus token
	token, err := client.RequestNexusToken(ctx, 0, "")
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// 6. Verify token — skipped: /tokens/verify now requires Nexus mTLS credentials.
	// Covered by Nexus integration tests with a properly configured mTLS client.

	// 7. Re-enrollment: same TPM enrolling again should succeed (active device)
	result2, err := client.Enroll(ctx)
	require.NoError(t, err)
	assert.Equal(t, result.DeviceID, result2.DeviceID, "re-enrollment should return same device ID")
	assert.Equal(t, result.Hostname, result2.Hostname, "re-enrollment should preserve hostname")

	// 8. ACME challenge lifecycle (canonical hostname)
	// Digest validation now accepts any printable ASCII up to 512 chars
	challenge, err := client.CreateACMEChallenge(ctx, "dGVzdHRlc3R0ZXN0dGVzdHRlc3R0ZXN0dGVzdHRlc3Q", "")
	if err != nil {
		t.Skipf("ACME challenge failed (PowerDNS?): %v", err)
	}
	assert.NotEmpty(t, challenge.ID)
	assert.Contains(t, challenge.FQDN, "_acme-challenge.")
	require.NoError(t, client.DeleteACMEChallenge(ctx, challenge.ID))

	// 8b. ACME challenge with custom hostname
	customFQDN := hostname + ".test.local"
	customChallenge, err := client.CreateACMEChallenge(ctx, "Y3VzdG9tY2hhbGxlbmdl", customFQDN)
	if err != nil {
		t.Skipf("ACME custom hostname challenge failed (PowerDNS?): %v", err)
	}
	assert.NotEmpty(t, customChallenge.ID)
	assert.Equal(t, "_acme-challenge."+customFQDN, customChallenge.FQDN)
	require.NoError(t, client.DeleteACMEChallenge(ctx, customChallenge.ID))

	// 9. AK persistence: create a new TPM device with state dir, close it,
	// reopen from the same state dir, and verify the AK is identical.
	tpm.Close()

	akStateDir := t.TempDir()
	tpm2dev, err := tpmdevice.Open(ctx, proc.Addr(), tpmdevice.WithStateDir(akStateDir))
	require.NoError(t, err, "open tpm with state dir (first time creates AK)")

	akPub1, err := tpm2dev.AKPublic()
	require.NoError(t, err)
	tpm2dev.Close()

	// Verify AK files were written
	_, err = os.Stat(filepath.Join(akStateDir, "ak_pub"))
	require.NoError(t, err, "ak_pub file should exist")
	_, err = os.Stat(filepath.Join(akStateDir, "ak_priv"))
	require.NoError(t, err, "ak_priv file should exist")

	// Reopen — should load the persisted AK (same key material)
	tpm2dev, err = tpmdevice.Open(ctx, proc.Addr(), tpmdevice.WithStateDir(akStateDir))
	require.NoError(t, err, "open tpm with state dir (reload)")

	akPub2, err := tpm2dev.AKPublic()
	require.NoError(t, err)
	assert.Equal(t, akPub1, akPub2, "reloaded AK public key should match original")

	// 10. WithDeviceID: verify the option correctly sets the device ID
	// on a new client (smoke test — full auth round-trip would require
	// the server to know this AK, which differs from the enrolled one).
	client2 := namekclient.New(serverURL, tpm2dev,
		namekclient.WithInsecureSkipVerify(),
		namekclient.WithDeviceID(result.DeviceID),
	)
	assert.Equal(t, result.DeviceID, client2.DeviceID())

	tpm2dev.Close()
}

// TestUnlockEscrow covers the per-device singleton escrow that holds the
// auto-unlock secret F. The dev config sets cleanupIntervalSeconds=5 so the
// sweep scenario doesn't have to wait minutes.
func TestUnlockEscrow(t *testing.T) {
	ctx := context.Background()

	dbURL := envOr("NAMEK_TEST_DB", "postgres://namek:namek@localhost:5432/namek?sslmode=disable")
	conn, err := pgx.Connect(ctx, dbURL)
	require.NoError(t, err, "connect to DB for cleanup")
	_, err = conn.Exec(ctx, "DELETE FROM audit_log; DELETE FROM unlock_escrows; DELETE FROM devices; DELETE FROM accounts")
	require.NoError(t, err, "clean DB")
	defer conn.Close(ctx)

	rootDir, err := filepath.Abs("../..")
	require.NoError(t, err)
	stateDir := filepath.Join(rootDir, ".local", "swtpm")

	proc, err := swtpm.Start(ctx, stateDir)
	require.NoError(t, err, "swtpm start failed")
	defer proc.Stop()

	tpm, err := tpmdevice.Open(ctx, proc.Addr())
	require.NoError(t, err)
	defer tpm.Close()

	serverURL := envOr("NAMEK_TEST_URL", "https://localhost:8443")
	client := namekclient.New(serverURL, tpm, namekclient.WithInsecureSkipVerify())

	require.Eventually(t, func() bool {
		return client.Ready(ctx) == nil
	}, 30*time.Second, 1*time.Second, "server not ready")

	enroll, err := client.Enroll(ctx)
	require.NoError(t, err)
	deviceID := enroll.DeviceID

	// Helper: count audit rows for this device with the given action.
	countAudit := func(action string) int {
		var n int
		err := conn.QueryRow(ctx,
			`SELECT COUNT(*) FROM audit_log WHERE actor_id = $1 AND action = $2`,
			deviceID, action,
		).Scan(&n)
		require.NoError(t, err)
		return n
	}
	// Helper: count system-actor sweep audit rows for this device.
	countSweepAudit := func(action string) int {
		var n int
		err := conn.QueryRow(ctx,
			`SELECT COUNT(*) FROM audit_log WHERE resource_id = $1 AND action = $2`,
			deviceID, action,
		).Scan(&n)
		require.NoError(t, err)
		return n
	}

	// Scenario 1: deposit with requested window above the ceiling, pickup
	// twice (idempotent, second pickup must NOT emit audit), revoke twice
	// (second revoke is a no-op and must NOT emit audit), then GET expects 404.
	t.Run("deposit_pickup_revoke_idempotent", func(t *testing.T) {
		secret := make([]byte, 32)
		_, err := rand.Read(secret)
		require.NoError(t, err)

		// requested 1800s; dev config ceiling is 600s — expect clamp.
		dep, err := client.DepositUnlockEscrow(ctx, secret, 1800)
		require.NoError(t, err)
		assert.True(t, dep.RequestedClamped, "1800s > 600s ceiling should clamp")
		assert.Equal(t, 600, dep.EffectiveWindowSeconds)
		assert.NotEmpty(t, dep.ExpiresAt)
		assert.Equal(t, 1, countAudit("auto_unlock.escrow.deposited"))

		// First pickup — should win the CTE UPDATE arm and emit audit.
		pick1, err := client.PickupUnlockEscrow(ctx)
		require.NoError(t, err)
		assert.NotEmpty(t, pick1.Secret)
		assert.Equal(t, 1, countAudit("auto_unlock.escrow.picked_up"))

		// Second pickup — fall-through SELECT arm, same secret, NO new audit.
		pick2, err := client.PickupUnlockEscrow(ctx)
		require.NoError(t, err)
		assert.Equal(t, pick1.Secret, pick2.Secret, "idempotent pickup should return same secret")
		assert.Equal(t, 1, countAudit("auto_unlock.escrow.picked_up"), "retry must not emit additional audit")

		// First revoke — actually deletes the row, emits audit.
		require.NoError(t, client.RevokeUnlockEscrow(ctx))
		assert.Equal(t, 1, countAudit("auto_unlock.escrow.revoked"))

		// Second revoke — no-op (row already gone), must NOT emit audit.
		require.NoError(t, client.RevokeUnlockEscrow(ctx))
		assert.Equal(t, 1, countAudit("auto_unlock.escrow.revoked"), "no-op revoke must not emit audit")

		// Pickup after revoke → ErrEscrowNotFound (404).
		_, err = client.PickupUnlockEscrow(ctx)
		require.Error(t, err)
		assert.True(t, errors.Is(err, namekclient.ErrEscrowNotFound), "expected ErrEscrowNotFound, got %v", err)
	})

	// Scenario 2: short window, sleep past expiry, pickup must return 404
	// via the lazy-expiry filter (without waiting for the sweep).
	t.Run("lazy_expiry_filter", func(t *testing.T) {
		// Reset state — prior scenario left no escrow row but wipes deposit count.
		_, err := conn.Exec(ctx, `DELETE FROM unlock_escrows WHERE device_id = $1`, deviceID)
		require.NoError(t, err)

		secret := make([]byte, 32)
		_, err = rand.Read(secret)
		require.NoError(t, err)

		_, err = client.DepositUnlockEscrow(ctx, secret, 1)
		require.NoError(t, err)

		time.Sleep(2 * time.Second)

		_, err = client.PickupUnlockEscrow(ctx)
		require.Error(t, err)
		assert.True(t, errors.Is(err, namekclient.ErrEscrowNotFound), "expected ErrEscrowNotFound, got %v", err)
	})

	// Scenario 3: deposit a row, force its expires_at into the past via SQL,
	// wait for the sweep tick (dev config: 5 s), assert the row is gone and a
	// per-device escrow.expired audit entry was emitted.
	t.Run("sweep_per_device_audit", func(t *testing.T) {
		_, err := conn.Exec(ctx, `DELETE FROM unlock_escrows WHERE device_id = $1`, deviceID)
		require.NoError(t, err)
		// Reset prior expired-audit counts so the assertion is per-scenario.
		_, err = conn.Exec(ctx, `DELETE FROM audit_log WHERE action = 'auto_unlock.escrow.expired' AND resource_id = $1`, deviceID)
		require.NoError(t, err)

		secret := make([]byte, 32)
		_, err = rand.Read(secret)
		require.NoError(t, err)

		_, err = client.DepositUnlockEscrow(ctx, secret, 60)
		require.NoError(t, err)

		// Force the row into the past. pgx coerces the UUID-shaped string.
		_, err = conn.Exec(ctx,
			`UPDATE unlock_escrows SET expires_at = NOW() - INTERVAL '1 minute' WHERE device_id = $1`,
			deviceID,
		)
		require.NoError(t, err)

		// Dev config sweeps every 5 s; allow up to 15 s for the next tick.
		require.Eventually(t, func() bool {
			var n int
			_ = conn.QueryRow(ctx, `SELECT COUNT(*) FROM unlock_escrows WHERE device_id = $1`, deviceID).Scan(&n)
			return n == 0
		}, 15*time.Second, 500*time.Millisecond, "sweep should remove expired row")

		assert.Equal(t, 1, countSweepAudit("auto_unlock.escrow.expired"))
	})
}
