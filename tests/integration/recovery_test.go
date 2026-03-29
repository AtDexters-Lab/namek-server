//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

// TestMultiDeviceVoucherExchange tests:
// 1. Enroll two devices
// 2. Group them via invite/join
// 3. Sign vouchers
// 4. Verify deterministic identity properties
func TestMultiDeviceVoucherExchange(t *testing.T) {
	ctx := context.Background()
	serverURL := envOr("NAMEK_TEST_URL", "https://localhost:8443")
	dbURL := envOr("NAMEK_TEST_DB", "postgres://namek:namek@localhost:5432/namek?sslmode=disable")

	// Clean DB
	conn, err := pgx.Connect(ctx, dbURL)
	require.NoError(t, err, "connect to DB")
	_, err = conn.Exec(ctx, `
		DELETE FROM recovery_claims;
		DELETE FROM voucher_requests;
		DELETE FROM account_invites;
		DELETE FROM audit_log;
		DELETE FROM device_domain_assignments;
		DELETE FROM account_domains;
		DELETE FROM acme_challenges;
		DELETE FROM released_hostnames;
		DELETE FROM devices;
		DELETE FROM accounts`)
	require.NoError(t, err, "clean DB")
	conn.Close(ctx)

	// Start two separate swtpm instances
	stateDir1 := t.TempDir()
	stateDir2 := t.TempDir()

	proc1, err := swtpm.Start(ctx, stateDir1)
	require.NoError(t, err, "swtpm 1 start")
	defer proc1.Stop()

	proc2, err := swtpm.Start(ctx, stateDir2)
	require.NoError(t, err, "swtpm 2 start")
	defer proc2.Stop()

	// Open TPM connections
	tpm1, err := tpmdevice.Open(ctx, proc1.Addr())
	require.NoError(t, err, "open tpm1")
	defer tpm1.Close()

	tpm2, err := tpmdevice.Open(ctx, proc2.Addr())
	require.NoError(t, err, "open tpm2")
	defer tpm2.Close()

	// Create clients
	client1 := namekclient.New(serverURL, tpm1, namekclient.WithInsecureSkipVerify())
	client2 := namekclient.New(serverURL, tpm2, namekclient.WithInsecureSkipVerify())

	// Wait for server
	require.Eventually(t, func() bool {
		return client1.Ready(ctx) == nil
	}, 30*time.Second, 1*time.Second, "server not ready")

	// === Step 1: Enroll both devices ===
	result1, err := client1.Enroll(ctx)
	require.NoError(t, err, "enroll device 1")
	t.Logf("Device 1: id=%s hostname=%s", result1.DeviceID, result1.Hostname)

	result2, err := client2.Enroll(ctx)
	require.NoError(t, err, "enroll device 2")
	t.Logf("Device 2: id=%s hostname=%s", result2.DeviceID, result2.Hostname)

	// Verify deterministic properties
	assert.Len(t, extractSlug(result1.Hostname), 20, "device 1 slug should be 20 chars")
	assert.Len(t, extractSlug(result2.Hostname), 20, "device 2 slug should be 20 chars")
	assert.NotEqual(t, result1.DeviceID, result2.DeviceID, "different TPMs should get different device IDs")
	assert.NotEqual(t, result1.Hostname, result2.Hostname, "different TPMs should get different hostnames")

	// Verify they're in separate accounts initially
	info1, err := client1.GetDeviceInfo(ctx)
	require.NoError(t, err)
	info2, err := client2.GetDeviceInfo(ctx)
	require.NoError(t, err)
	assert.NotEqual(t, info1.AccountID, info2.AccountID, "freshly enrolled devices should be in separate accounts")
	assert.Equal(t, "active", info1.RecoveryStatus)
	assert.Equal(t, "active", info2.RecoveryStatus)

	// === Step 2: Group via invite/join ===
	invite, err := client1.CreateInvite(ctx)
	require.NoError(t, err, "create invite")
	assert.NotEmpty(t, invite.InviteCode)
	assert.Equal(t, info1.AccountID, invite.AccountID)
	t.Logf("Invite created: account=%s", invite.AccountID)

	err = client2.JoinAccount(ctx, invite.InviteCode)
	require.NoError(t, err, "join account")

	// Verify both devices are now in the same account
	info1, err = client1.GetDeviceInfo(ctx)
	require.NoError(t, err)
	info2, err = client2.GetDeviceInfo(ctx)
	require.NoError(t, err)
	assert.Equal(t, info1.AccountID, info2.AccountID, "devices should be in the same account after join")
	t.Logf("Both devices in account: %s", info1.AccountID)

	// === Step 3: Sign vouchers ===
	// After join, voucher requests should be created for both devices.
	// Device 1 should have pending voucher requests (as issuer).

	// Poll for pending voucher requests (may take a moment after join)
	var pendingReqs1 []namekclient.PendingVoucherRequest
	require.Eventually(t, func() bool {
		info, err := client1.GetDeviceInfo(ctx)
		if err != nil {
			return false
		}
		pendingReqs1 = info.PendingVoucherRequests
		return len(pendingReqs1) > 0
	}, 5*time.Second, 200*time.Millisecond, "device 1 should have pending voucher requests")

	t.Logf("Device 1 has %d pending voucher requests", len(pendingReqs1))

	// Sign each pending request for device 1
	for _, req := range pendingReqs1 {
		// Decode voucher data and generate quote over it
		voucherDataBytes, err := base64.StdEncoding.DecodeString(req.VoucherData)
		require.NoError(t, err, "decode voucher data")

		quoteB64, err := tpm1.QuoteOverData(voucherDataBytes)
		require.NoError(t, err, "generate quote over voucher data")

		err = client1.SignVoucher(ctx, req.RequestID, quoteB64)
		require.NoError(t, err, "sign voucher request %s", req.RequestID)
	}
	t.Logf("Device 1 signed %d vouchers", len(pendingReqs1))

	// Device 2 should also have pending requests
	var pendingReqs2 []namekclient.PendingVoucherRequest
	require.Eventually(t, func() bool {
		info, err := client2.GetDeviceInfo(ctx)
		if err != nil {
			return false
		}
		pendingReqs2 = info.PendingVoucherRequests
		return len(pendingReqs2) > 0
	}, 5*time.Second, 200*time.Millisecond, "device 2 should have pending voucher requests")

	for _, req := range pendingReqs2 {
		voucherDataBytes, err := base64.StdEncoding.DecodeString(req.VoucherData)
		require.NoError(t, err)
		quoteB64, err := tpm2.QuoteOverData(voucherDataBytes)
		require.NoError(t, err)
		err = client2.SignVoucher(ctx, req.RequestID, quoteB64)
		require.NoError(t, err, "sign voucher request %s", req.RequestID)
	}
	t.Logf("Device 2 signed %d vouchers", len(pendingReqs2))

	// Both devices should now have received vouchers
	vouchers1, err := client1.GetVouchers(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, vouchers1, "device 1 should have received vouchers from device 2")
	t.Logf("Device 1 received %d vouchers", len(vouchers1))

	vouchers2, err := client2.GetVouchers(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, vouchers2, "device 2 should have received vouchers from device 1")
	t.Logf("Device 2 received %d vouchers", len(vouchers2))

	// === Step 4: Verify re-enrollment produces same identity ===
	result1b, err := client1.Enroll(ctx)
	require.NoError(t, err, "re-enroll device 1")
	assert.Equal(t, result1.DeviceID, result1b.DeviceID, "re-enrollment should preserve device ID")
	assert.Equal(t, result1.Hostname, result1b.Hostname, "re-enrollment should preserve hostname")
	assert.True(t, result1b.Reenrolled, "should be flagged as re-enrolled")

	// === Step 5: Verify audit trail ===
	conn, err = pgx.Connect(ctx, dbURL)
	require.NoError(t, err)
	defer conn.Close(ctx)

	var joinCount int
	err = conn.QueryRow(ctx,
		"SELECT COUNT(*) FROM audit_log WHERE action = 'account.device_joined'").Scan(&joinCount)
	require.NoError(t, err)
	assert.Equal(t, 1, joinCount, "should have 1 device join audit entry")

	var voucherSignCount int
	err = conn.QueryRow(ctx,
		"SELECT COUNT(*) FROM audit_log WHERE action = 'voucher.sign'").Scan(&voucherSignCount)
	require.NoError(t, err)
	assert.Equal(t, len(pendingReqs1)+len(pendingReqs2), voucherSignCount, "should have voucher sign audit entries")

	t.Log("Multi-device voucher exchange test passed")
}

// TestDeterministicIdentityRecovery tests that after a DB wipe,
// re-enrollment produces the same deterministic identity.
func TestDeterministicIdentityRecovery(t *testing.T) {
	ctx := context.Background()
	serverURL := envOr("NAMEK_TEST_URL", "https://localhost:8443")
	dbURL := envOr("NAMEK_TEST_DB", "postgres://namek:namek@localhost:5432/namek?sslmode=disable")

	// Clean DB
	conn, err := pgx.Connect(ctx, dbURL)
	require.NoError(t, err)
	_, err = conn.Exec(ctx, `
		DELETE FROM recovery_claims;
		DELETE FROM voucher_requests;
		DELETE FROM account_invites;
		DELETE FROM audit_log;
		DELETE FROM device_domain_assignments;
		DELETE FROM account_domains;
		DELETE FROM acme_challenges;
		DELETE FROM released_hostnames;
		DELETE FROM devices;
		DELETE FROM accounts`)
	require.NoError(t, err, "clean DB")
	conn.Close(ctx)

	// Start swtpm with persistent state dir
	rootDir, err := filepath.Abs("../..")
	require.NoError(t, err)
	stateDir := filepath.Join(rootDir, ".local", "swtpm-recovery-test")

	// Clean any previous state to get a fresh TPM
	os.RemoveAll(stateDir)

	proc, err := swtpm.Start(ctx, stateDir)
	require.NoError(t, err, "swtpm start")
	defer proc.Stop()

	tpm, err := tpmdevice.Open(ctx, proc.Addr())
	require.NoError(t, err)

	client := namekclient.New(serverURL, tpm, namekclient.WithInsecureSkipVerify())

	require.Eventually(t, func() bool {
		return client.Ready(ctx) == nil
	}, 30*time.Second, 1*time.Second, "server not ready")

	// Enroll
	result1, err := client.Enroll(ctx)
	require.NoError(t, err, "first enrollment")

	// Capture EK fingerprint for verification
	ekCert, err := tpm.EKCertDER()
	require.NoError(t, err)
	h := sha256.Sum256(ekCert)
	ekFingerprint := hex.EncodeToString(h[:])
	t.Logf("EK fingerprint: %s", ekFingerprint)
	t.Logf("First enrollment: device=%s hostname=%s", result1.DeviceID, result1.Hostname)

	tpm.Close()

	// Simulate DB wipe: delete all device/account data
	conn, err = pgx.Connect(ctx, dbURL)
	require.NoError(t, err)
	_, err = conn.Exec(ctx, `
		DELETE FROM recovery_claims;
		DELETE FROM voucher_requests;
		DELETE FROM account_invites;
		DELETE FROM audit_log;
		DELETE FROM device_domain_assignments;
		DELETE FROM account_domains;
		DELETE FROM acme_challenges;
		DELETE FROM released_hostnames;
		DELETE FROM devices;
		DELETE FROM accounts`)
	require.NoError(t, err, "wipe DB")
	conn.Close(ctx)

	// Restart swtpm (same state dir = same EK)
	proc.Stop()
	proc, err = swtpm.Start(ctx, stateDir)
	require.NoError(t, err, "swtpm restart")
	defer proc.Stop()

	// Open new TPM connection (new AK, same EK)
	tpm, err = tpmdevice.Open(ctx, proc.Addr())
	require.NoError(t, err)
	defer tpm.Close()

	client = namekclient.New(serverURL, tpm, namekclient.WithInsecureSkipVerify())

	// Re-enroll after DB wipe — should get same deterministic identity
	result2, err := client.Enroll(ctx)
	require.NoError(t, err, "re-enrollment after wipe")

	t.Logf("After wipe: device=%s hostname=%s", result2.DeviceID, result2.Hostname)

	// Core assertion: deterministic identity is preserved across DB wipe
	assert.Equal(t, result1.DeviceID, result2.DeviceID,
		"device ID should be the same after DB wipe (deterministic from EK)")
	assert.Equal(t, result1.Hostname, result2.Hostname,
		"hostname should be the same after DB wipe (deterministic slug from EK)")

	// Verify the slug in the hostname is 20 characters
	slug := extractSlug(result2.Hostname)
	assert.Len(t, slug, 20, "slug should be 20 chars")

	// Verify the identity class is correct
	assert.Equal(t, "unverified", result2.IdentityClass)

	// Cleanup
	os.RemoveAll(stateDir)

	t.Log("Deterministic identity recovery test passed")
}

// TestRecoveryBundleProcessing tests that recovery bundles are accepted
// during enrollment and claims are stored.
func TestRecoveryBundleProcessing(t *testing.T) {
	ctx := context.Background()
	serverURL := envOr("NAMEK_TEST_URL", "https://localhost:8443")
	dbURL := envOr("NAMEK_TEST_DB", "postgres://namek:namek@localhost:5432/namek?sslmode=disable")

	// Clean DB
	conn, err := pgx.Connect(ctx, dbURL)
	require.NoError(t, err)
	_, err = conn.Exec(ctx, `
		DELETE FROM recovery_claims;
		DELETE FROM voucher_requests;
		DELETE FROM account_invites;
		DELETE FROM audit_log;
		DELETE FROM device_domain_assignments;
		DELETE FROM account_domains;
		DELETE FROM acme_challenges;
		DELETE FROM released_hostnames;
		DELETE FROM devices;
		DELETE FROM accounts`)
	require.NoError(t, err, "clean DB")
	conn.Close(ctx)

	// Start two swtpm instances
	stateDir1 := t.TempDir()
	stateDir2 := t.TempDir()

	proc1, err := swtpm.Start(ctx, stateDir1)
	require.NoError(t, err)
	defer proc1.Stop()

	proc2, err := swtpm.Start(ctx, stateDir2)
	require.NoError(t, err)
	defer proc2.Stop()

	tpm1, err := tpmdevice.Open(ctx, proc1.Addr())
	require.NoError(t, err)
	defer tpm1.Close()

	tpm2, err := tpmdevice.Open(ctx, proc2.Addr())
	require.NoError(t, err)
	defer tpm2.Close()

	client1 := namekclient.New(serverURL, tpm1, namekclient.WithInsecureSkipVerify())
	client2 := namekclient.New(serverURL, tpm2, namekclient.WithInsecureSkipVerify())

	require.Eventually(t, func() bool {
		return client1.Ready(ctx) == nil
	}, 30*time.Second, 1*time.Second)

	// Enroll, group, exchange vouchers
	result1, err := client1.Enroll(ctx)
	require.NoError(t, err)
	_, err = client2.Enroll(ctx)
	require.NoError(t, err)

	invite, err := client1.CreateInvite(ctx)
	require.NoError(t, err)
	err = client2.JoinAccount(ctx, invite.InviteCode)
	require.NoError(t, err)

	info1, _ := client1.GetDeviceInfo(ctx)
	accountID := info1.AccountID

	// Sign all vouchers
	signAllPending(t, ctx, client1, tpm1)
	signAllPending(t, ctx, client2, tpm2)

	// Collect vouchers (device 1's vouchers from device 2)
	vouchers1, err := client1.GetVouchers(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, vouchers1, "device 1 should have vouchers")

	t.Logf("Pre-wipe state: account=%s, device1=%s, device2=%s, vouchers=%d",
		accountID, result1.DeviceID, client2.DeviceID(), len(vouchers1))

	// === DB WIPE ===
	conn, err = pgx.Connect(ctx, dbURL)
	require.NoError(t, err)
	_, err = conn.Exec(ctx, `
		DELETE FROM recovery_claims;
		DELETE FROM voucher_requests;
		DELETE FROM account_invites;
		DELETE FROM audit_log;
		DELETE FROM device_domain_assignments;
		DELETE FROM account_domains;
		DELETE FROM acme_challenges;
		DELETE FROM released_hostnames;
		DELETE FROM devices;
		DELETE FROM accounts`)
	require.NoError(t, err, "wipe DB")
	conn.Close(ctx)

	t.Log("DB wiped. Re-enrolling with recovery bundles...")

	// === Re-enroll with recovery bundle ===
	// Device 1 re-enrolls with vouchers from device 2 as recovery bundle
	bundle := &namekclient.RecoveryBundleInput{
		AccountID: accountID,
		Vouchers:  vouchers1,
	}

	result1b, err := client1.EnrollWithRecovery(ctx, bundle)
	require.NoError(t, err, "device 1 re-enrollment with recovery bundle")

	assert.Equal(t, result1.DeviceID, result1b.DeviceID, "deterministic device ID preserved")
	assert.Equal(t, result1.Hostname, result1b.Hostname, "deterministic hostname preserved")
	t.Logf("Device 1 re-enrolled: %s at %s", result1b.DeviceID, result1b.Hostname)

	// Verify recovery claims were stored
	conn, err = pgx.Connect(ctx, dbURL)
	require.NoError(t, err)
	defer conn.Close(ctx)

	var claimCount int
	err = conn.QueryRow(ctx,
		"SELECT COUNT(*) FROM recovery_claims WHERE claimed_account_id = $1", accountID).Scan(&claimCount)
	require.NoError(t, err)
	assert.Greater(t, claimCount, 0, "recovery claims should be stored")
	t.Logf("Recovery claims stored: %d", claimCount)

	// Verify account exists. Since only device 1 has re-enrolled so far,
	// the account has 1 device. Per quorum rules, 1 device needs 0 vouchers,
	// so quorum is immediately reached and account is promoted to active.
	var accountStatus string
	err = conn.QueryRow(ctx,
		"SELECT status FROM accounts WHERE id = $1", accountID).Scan(&accountStatus)
	require.NoError(t, err)
	// With only 1 device enrolled, quorum is 0 → immediately active
	assert.Equal(t, "active", accountStatus, "1-device account should be immediately promoted to active")

	t.Log("Recovery bundle processing test passed")
}

// Helper: extract slug from hostname (e.g., "abc123.test.local" -> "abc123")
func extractSlug(hostname string) string {
	for i, c := range hostname {
		if c == '.' {
			return hostname[:i]
		}
	}
	return hostname
}

// Helper: sign all pending voucher requests for a client
func signAllPending(t *testing.T, ctx context.Context, client *namekclient.Client, tpm tpmdevice.Device) {
	t.Helper()
	var pending []namekclient.PendingVoucherRequest
	require.Eventually(t, func() bool {
		info, err := client.GetDeviceInfo(ctx)
		if err != nil {
			return false
		}
		pending = info.PendingVoucherRequests
		return len(pending) > 0
	}, 5*time.Second, 200*time.Millisecond, "expected pending voucher requests")

	for _, req := range pending {
		data, err := base64.StdEncoding.DecodeString(req.VoucherData)
		require.NoError(t, err)
		quote, err := tpm.QuoteOverData(data)
		require.NoError(t, err)
		require.NoError(t, client.SignVoucher(ctx, req.RequestID, quote))
	}
}

