//go:build integration

package integration

import (
	"context"
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
	_, err = conn.Exec(ctx, "DELETE FROM audit_log; DELETE FROM device_domain_assignments; DELETE FROM account_domains; DELETE FROM acme_challenges; DELETE FROM released_hostnames; DELETE FROM devices; DELETE FROM accounts")
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
	assert.Equal(t, "software", result.IdentityClass)
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
