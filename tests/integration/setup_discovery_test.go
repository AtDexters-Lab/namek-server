//go:build integration

package integration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AtDexters-Lab/namek-server/pkg/namekclient"
	"github.com/AtDexters-Lab/namek-server/pkg/swtpm"
	"github.com/AtDexters-Lab/namek-server/pkg/tpmdevice"
)

// cleanDevicesDB wipes the devices table (and cascading references) so each
// test starts from a known-empty state. Run this at the top of every setup-
// discovery test because the tests enroll and heartbeat real TPM-backed
// devices that would otherwise accumulate across runs.
func cleanDevicesDB(t *testing.T, ctx context.Context) {
	t.Helper()
	dbURL := envOr("NAMEK_TEST_DB", "postgres://namek:namek@localhost:5432/namek?sslmode=disable")
	conn, err := pgx.Connect(ctx, dbURL)
	require.NoError(t, err, "connect to DB for cleanup")
	defer conn.Close(ctx)
	_, err = conn.Exec(ctx, `
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
	require.NoError(t, err, "clean DB")
}

// startTestTPM spawns the shared swtpm process and opens a TPM device handle.
// Caller is responsible for Close() on both via the returned cleanup func.
func startTestTPM(t *testing.T, ctx context.Context) (tpmdevice.Device, func()) {
	t.Helper()
	rootDir, err := filepath.Abs("../..")
	require.NoError(t, err)
	stateDir := filepath.Join(rootDir, ".local", "swtpm")

	proc, err := swtpm.Start(ctx, stateDir)
	require.NoError(t, err, "swtpm start failed — ensure swtpm and swtpm-tools are installed")

	// Use a per-test AK state dir so each test gets a fresh AK and therefore
	// a distinct device identity on the server. This is critical for the
	// multi-device tests below — without distinct AKs, every enrollment
	// collapses to the same device ID.
	akStateDir := t.TempDir()
	tpm, err := tpmdevice.Open(ctx, proc.Addr(), tpmdevice.WithStateDir(akStateDir))
	if err != nil {
		proc.Stop()
		t.Fatalf("tpmdevice.Open: %v", err)
	}
	cleanup := func() {
		tpm.Close()
		proc.Stop()
	}
	return tpm, cleanup
}

// newClientReady waits until the server responds to Ready(). Used at the top
// of every test because the shared namek server is started out-of-band.
func newClientReady(t *testing.T, ctx context.Context, tpm tpmdevice.Device) *namekclient.Client {
	t.Helper()
	serverURL := envOr("NAMEK_TEST_URL", "https://localhost:8443")
	client := namekclient.New(serverURL, tpm, namekclient.WithInsecureSkipVerify())
	require.Eventually(t, func() bool {
		return client.Ready(ctx) == nil
	}, 30*time.Second, 1*time.Second, "server not ready")
	return client
}

// discoverResponse is the shape returned by GET /api/v1/setup/discover.
type discoverResponse struct {
	Devices []struct {
		HardwareModel *string  `json:"hardware_model,omitempty"`
		LANIPs        []string `json:"lan_ips"`
	} `json:"devices"`
}

// callDiscover hits the unauthenticated /api/v1/setup/discover endpoint and
// returns the parsed response plus the raw HTTP response for header assertions.
func callDiscover(t *testing.T, ctx context.Context, extraHeaders http.Header) (*discoverResponse, *http.Response) {
	t.Helper()
	serverURL := envOr("NAMEK_TEST_URL", "https://localhost:8443")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, serverURL+"/api/v1/setup/discover", nil)
	require.NoError(t, err)
	for k, vs := range extraHeaders {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	hc := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	resp, err := hc.Do(req)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)

	var out discoverResponse
	if len(body) > 0 {
		require.NoError(t, json.Unmarshal(body, &out), "unmarshal discover response: %s", body)
	}
	return &out, resp
}

// callDiscoverPreflight sends an OPTIONS preflight and returns the response
// for CORS header + status assertions.
func callDiscoverPreflight(t *testing.T, ctx context.Context, origin string) *http.Response {
	t.Helper()
	serverURL := envOr("NAMEK_TEST_URL", "https://localhost:8443")
	req, err := http.NewRequestWithContext(ctx, http.MethodOptions, serverURL+"/api/v1/setup/discover", nil)
	require.NoError(t, err)
	req.Header.Set("Origin", origin)
	req.Header.Set("Access-Control-Request-Method", "GET")
	hc := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	resp, err := hc.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	return resp
}

// TestSetupDiscover_EnrollWithHardwareModel exercises the additive extension
// to the attest request and confirms the server persists hardware_model.
func TestSetupDiscover_EnrollWithHardwareModel(t *testing.T) {
	ctx := context.Background()
	cleanDevicesDB(t, ctx)

	tpm, cleanup := startTestTPM(t, ctx)
	defer cleanup()

	serverURL := envOr("NAMEK_TEST_URL", "https://localhost:8443")
	client := namekclient.New(serverURL, tpm,
		namekclient.WithInsecureSkipVerify(),
		namekclient.WithHardwareModel("Raspberry Pi 4 Model B Rev 1.5"),
	)
	require.Eventually(t, func() bool { return client.Ready(ctx) == nil }, 30*time.Second, 1*time.Second)

	result, err := client.Enroll(ctx)
	require.NoError(t, err, "enroll with hardware model")
	assert.NotEmpty(t, result.DeviceID)

	// Verify the hardware_model landed in the DB.
	dbURL := envOr("NAMEK_TEST_DB", "postgres://namek:namek@localhost:5432/namek?sslmode=disable")
	conn, err := pgx.Connect(ctx, dbURL)
	require.NoError(t, err)
	defer conn.Close(ctx)
	var hm *string
	err = conn.QueryRow(ctx, "SELECT hardware_model FROM devices WHERE id = $1", result.DeviceID).Scan(&hm)
	require.NoError(t, err)
	require.NotNil(t, hm, "hardware_model should be persisted")
	assert.Equal(t, "Raspberry Pi 4 Model B Rev 1.5", *hm)
}

// TestSetupDiscover_EnrollWithoutHardwareModel confirms backward compatibility:
// old clients that omit hardware_model continue to work and the column is NULL.
func TestSetupDiscover_EnrollWithoutHardwareModel(t *testing.T) {
	ctx := context.Background()
	cleanDevicesDB(t, ctx)

	tpm, cleanup := startTestTPM(t, ctx)
	defer cleanup()

	client := newClientReady(t, ctx, tpm) // no WithHardwareModel option
	result, err := client.Enroll(ctx)
	require.NoError(t, err)

	dbURL := envOr("NAMEK_TEST_DB", "postgres://namek:namek@localhost:5432/namek?sslmode=disable")
	conn, err := pgx.Connect(ctx, dbURL)
	require.NoError(t, err)
	defer conn.Close(ctx)
	var hm *string
	err = conn.QueryRow(ctx, "SELECT hardware_model FROM devices WHERE id = $1", result.DeviceID).Scan(&hm)
	require.NoError(t, err)
	assert.Nil(t, hm, "hardware_model should be NULL when not provided")
}

// TestSetupDiscover_HeartbeatDiscoverComplete is the golden path: enroll →
// heartbeat → discover (match) → heartbeat setup_complete → discover (empty).
func TestSetupDiscover_HeartbeatDiscoverComplete(t *testing.T) {
	ctx := context.Background()
	cleanDevicesDB(t, ctx)

	tpm, cleanup := startTestTPM(t, ctx)
	defer cleanup()

	serverURL := envOr("NAMEK_TEST_URL", "https://localhost:8443")
	client := namekclient.New(serverURL, tpm,
		namekclient.WithInsecureSkipVerify(),
		namekclient.WithHardwareModel("Piccolo Dev Kit"),
	)
	require.Eventually(t, func() bool { return client.Ready(ctx) == nil }, 30*time.Second, 1*time.Second)

	result, err := client.Enroll(ctx)
	require.NoError(t, err)
	t.Logf("enrolled device %s", result.DeviceID)

	// Pre-heartbeat discover: row exists but no heartbeat yet → empty result.
	pre, _ := callDiscover(t, ctx, nil)
	assert.Empty(t, pre.Devices, "discover should be empty before heartbeat")

	// Send heartbeat with a set of private LAN IPs.
	err = client.SendHeartbeat(ctx, &namekclient.HeartbeatRequest{
		LANIPs:        []string{"10.0.0.5", "192.168.1.7"},
		SetupComplete: false,
	})
	require.NoError(t, err, "heartbeat should succeed")

	// Discover should now return this device.
	mid, _ := callDiscover(t, ctx, nil)
	require.Len(t, mid.Devices, 1, "discover should return one device after heartbeat")
	d := mid.Devices[0]
	require.NotNil(t, d.HardwareModel)
	assert.Equal(t, "Piccolo Dev Kit", *d.HardwareModel)
	assert.ElementsMatch(t, []string{"10.0.0.5", "192.168.1.7"}, d.LANIPs)

	// Send setup_complete=true (with empty lan_ips — validates the fix for
	// codex P2: terminal heartbeat must accept no lan_ips).
	err = client.SendHeartbeat(ctx, &namekclient.HeartbeatRequest{
		LANIPs:        nil,
		SetupComplete: true,
	})
	require.NoError(t, err, "setup_complete heartbeat should succeed without lan_ips")

	// Discover should no longer return this device.
	post, _ := callDiscover(t, ctx, nil)
	assert.Empty(t, post.Devices, "discover should be empty after setup_complete")

	// Verify DB state: setup_heartbeat_at and lan_ips are NULL.
	dbURL := envOr("NAMEK_TEST_DB", "postgres://namek:namek@localhost:5432/namek?sslmode=disable")
	conn, err := pgx.Connect(ctx, dbURL)
	require.NoError(t, err)
	defer conn.Close(ctx)
	var shAt *time.Time
	var lanIPs []string
	err = conn.QueryRow(ctx,
		"SELECT setup_heartbeat_at, coalesce(lan_ips, '{}'::text[]) FROM devices WHERE id = $1",
		result.DeviceID,
	).Scan(&shAt, &lanIPs)
	require.NoError(t, err)
	assert.Nil(t, shAt, "setup_heartbeat_at should be NULL after completion")
	assert.Empty(t, lanIPs, "lan_ips should be NULL/empty after completion")
}

// TestSetupDiscover_RejectPublicIP verifies isPrivateLANIP does its job at
// runtime — the server must reject a compromised device's attempt to submit
// a public IP. This is the core of the SSRF-mitigation threat model.
func TestSetupDiscover_RejectPublicIP(t *testing.T) {
	ctx := context.Background()
	cleanDevicesDB(t, ctx)

	tpm, cleanup := startTestTPM(t, ctx)
	defer cleanup()

	client := newClientReady(t, ctx, tpm)
	_, err := client.Enroll(ctx)
	require.NoError(t, err)

	cases := []struct {
		name string
		ips  []string
	}{
		{"public IPv4", []string{"8.8.8.8"}},
		{"cloud IMDS link-local", []string{"169.254.169.254"}},
		{"mixed private + public", []string{"10.0.0.5", "203.0.113.7"}},
		{"loopback", []string{"127.0.0.1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := client.SendHeartbeat(ctx, &namekclient.HeartbeatRequest{
				LANIPs:        tc.ips,
				SetupComplete: false,
			})
			require.Error(t, err, "server must reject %v", tc.ips)
			// The parseError chain on the client wraps the server's 400 body;
			// it should mention "invalid lan ip" somewhere.
			assert.Contains(t, strings.ToLower(err.Error()), "invalid",
				"error should surface as an 'invalid' validation rejection: %v", err)
		})
	}
}

// TestSetupDiscover_IPv4MappedIPv6Canonicalization verifies the service-layer
// canonicalization: a device submitting ::ffff:10.0.0.5 should have it stored
// (and discovered) as the canonical 10.0.0.5 — no "::ffff:" prefix in the
// discover response.
func TestSetupDiscover_IPv4MappedIPv6Canonicalization(t *testing.T) {
	ctx := context.Background()
	cleanDevicesDB(t, ctx)

	tpm, cleanup := startTestTPM(t, ctx)
	defer cleanup()

	client := newClientReady(t, ctx, tpm)
	_, err := client.Enroll(ctx)
	require.NoError(t, err)

	err = client.SendHeartbeat(ctx, &namekclient.HeartbeatRequest{
		LANIPs:        []string{"::ffff:10.0.0.42"},
		SetupComplete: false,
	})
	require.NoError(t, err, "v4-mapped IPv6 private should be accepted")

	resp, _ := callDiscover(t, ctx, nil)
	require.Len(t, resp.Devices, 1)
	assert.Equal(t, []string{"10.0.0.42"}, resp.Devices[0].LANIPs,
		"v4-mapped form should be canonicalized to dotted v4")
}

// TestSetupDiscover_CORSPreflight verifies the hand-rolled CORS middleware.
func TestSetupDiscover_CORSPreflight(t *testing.T) {
	ctx := context.Background()

	t.Run("allowed origin", func(t *testing.T) {
		resp := callDiscoverPreflight(t, ctx, "https://piccolospace.com")
		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
		assert.Equal(t, "https://piccolospace.com", resp.Header.Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "Origin", resp.Header.Get("Vary"))
		assert.Contains(t, resp.Header.Get("Access-Control-Allow-Methods"), "GET")
		assert.Equal(t, "3600", resp.Header.Get("Access-Control-Max-Age"))
	})

	t.Run("disallowed origin", func(t *testing.T) {
		resp := callDiscoverPreflight(t, ctx, "https://evil.example.com")
		// Preflight still succeeds (204) but without an ACAO header — browser
		// will then refuse the cross-origin read.
		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
		assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "Origin", resp.Header.Get("Vary"), "Vary: Origin should be set unconditionally")
	})
}

// TestSetupDiscover_CacheControl verifies the codex P2 fix: discover responses
// must carry Cache-Control: no-store,private so a future shared cache cannot
// replay one caller's device list to another caller.
func TestSetupDiscover_CacheControl(t *testing.T) {
	ctx := context.Background()
	_, resp := callDiscover(t, ctx, nil)
	cc := resp.Header.Get("Cache-Control")
	assert.Contains(t, cc, "no-store", "discover response must be uncacheable")
	assert.Contains(t, cc, "private", "discover response must be marked private")
}

// TestSetupDiscover_TTLExpiry injects a stale setup_heartbeat_at directly into
// the DB (to sidestep the 2-minute wait) and confirms the device drops out of
// discover results. This exercises the `make_interval(secs => $2)` TTL clause.
func TestSetupDiscover_TTLExpiry(t *testing.T) {
	ctx := context.Background()
	cleanDevicesDB(t, ctx)

	tpm, cleanup := startTestTPM(t, ctx)
	defer cleanup()

	client := newClientReady(t, ctx, tpm)
	result, err := client.Enroll(ctx)
	require.NoError(t, err)

	// Normal heartbeat → appears in discover.
	require.NoError(t, client.SendHeartbeat(ctx, &namekclient.HeartbeatRequest{
		LANIPs: []string{"10.0.0.5"},
	}))
	mid, _ := callDiscover(t, ctx, nil)
	require.Len(t, mid.Devices, 1)

	// Backdate setup_heartbeat_at to 5 minutes ago — outside the default 120s TTL.
	dbURL := envOr("NAMEK_TEST_DB", "postgres://namek:namek@localhost:5432/namek?sslmode=disable")
	conn, err := pgx.Connect(ctx, dbURL)
	require.NoError(t, err)
	defer conn.Close(ctx)
	_, err = conn.Exec(ctx,
		"UPDATE devices SET setup_heartbeat_at = NOW() - interval '5 minutes' WHERE id = $1",
		result.DeviceID,
	)
	require.NoError(t, err)

	// Discover should now return empty.
	post, _ := callDiscover(t, ctx, nil)
	assert.Empty(t, post.Devices, "device past TTL should not appear in discover")
}

// TestSetupDiscover_ExplainUsesIndex is the planner-regression guard: the
// setup-discover query must use idx_devices_setup_discovery (the partial index
// on ip_address WHERE setup_heartbeat_at IS NOT NULL), not a seq scan. Postgres's
// predicate_implied_by relies on setup_heartbeat_at > X implying IS NOT NULL.
func TestSetupDiscover_ExplainUsesIndex(t *testing.T) {
	ctx := context.Background()
	cleanDevicesDB(t, ctx)

	// Insert a synthetic row via SQL so we have at least one candidate without
	// needing a full enroll + heartbeat cycle (faster test).
	dbURL := envOr("NAMEK_TEST_DB", "postgres://namek:namek@localhost:5432/namek?sslmode=disable")
	conn, err := pgx.Connect(ctx, dbURL)
	require.NoError(t, err)
	defer conn.Close(ctx)

	// Need a synthetic account + device so the FK holds.
	_, err = conn.Exec(ctx, `
		INSERT INTO accounts (id, status, membership_epoch)
		VALUES ('00000000-0000-0000-0000-000000000042', 'active', 1)
	`)
	require.NoError(t, err)
	_, err = conn.Exec(ctx, `
		INSERT INTO devices (
			id, account_id, slug, hostname, identity_class, ek_fingerprint,
			ak_public_key, trust_level, ip_address, status, setup_heartbeat_at,
			lan_ips, hardware_model
		) VALUES (
			'00000000-0000-0000-0000-000000000043',
			'00000000-0000-0000-0000-000000000042',
			'indexprobe1234567890', 'indexprobe1234567890.test.local',
			'unverified', 'indexprobe-ek-fp', '\x00'::bytea, 'provisional',
			'203.0.113.99'::inet, 'active', NOW(), ARRAY['10.0.0.1'], 'IndexProbe'
		)
	`)
	require.NoError(t, err)

	// Force a Postgres ANALYZE so the planner has row statistics. Without it
	// tiny tables always get seq-scanned regardless of indexes.
	_, err = conn.Exec(ctx, "ANALYZE devices")
	require.NoError(t, err)

	// Run EXPLAIN and verify the partial index is referenced.
	rows, err := conn.Query(ctx, `
		EXPLAIN (FORMAT TEXT)
		SELECT hardware_model, coalesce(lan_ips, '{}'::text[])
		FROM devices
		WHERE ip_address = $1::inet
		  AND setup_heartbeat_at > NOW() - make_interval(secs => $2)
		  AND status = 'active'
	`, "203.0.113.99", 120)
	require.NoError(t, err)
	defer rows.Close()

	var plan strings.Builder
	for rows.Next() {
		var line string
		require.NoError(t, rows.Scan(&line))
		plan.WriteString(line + "\n")
	}
	planText := plan.String()
	t.Logf("EXPLAIN plan:\n%s", planText)
	// On a 1-row table the planner will always pick seq scan — confirming the
	// INDEX is USABLE (not guaranteed to be chosen) is the real invariant.
	// Assert that the index exists and would be considered. We do this by
	// running `SET enable_seqscan = off` to force the planner's hand.
	_, err = conn.Exec(ctx, "SET enable_seqscan = off")
	require.NoError(t, err)
	rows2, err := conn.Query(ctx, `
		EXPLAIN (FORMAT TEXT)
		SELECT hardware_model, coalesce(lan_ips, '{}'::text[])
		FROM devices
		WHERE ip_address = $1::inet
		  AND setup_heartbeat_at > NOW() - make_interval(secs => $2)
		  AND status = 'active'
	`, "203.0.113.99", 120)
	require.NoError(t, err)
	defer rows2.Close()

	var plan2 strings.Builder
	for rows2.Next() {
		var line string
		require.NoError(t, rows2.Scan(&line))
		plan2.WriteString(line + "\n")
	}
	planText2 := plan2.String()
	t.Logf("EXPLAIN (seqscan off) plan:\n%s", planText2)
	assert.Contains(t, planText2, "idx_devices_setup_discovery",
		"partial index must be usable for the discover query")

	_, _ = conn.Exec(ctx, "SET enable_seqscan = on")
}

// TestSetupDiscover_ScanDeviceNullLANIPs covers the coalesce(lan_ips, '{}')
// round-trip in deviceColumns/scanDevice. A device that was never in setup
// mode has lan_ips=NULL in the DB; reading it back via GetMe must not error
// and must produce an empty/nil slice on the Go side.
func TestSetupDiscover_ScanDeviceNullLANIPs(t *testing.T) {
	ctx := context.Background()
	cleanDevicesDB(t, ctx)

	tpm, cleanup := startTestTPM(t, ctx)
	defer cleanup()

	client := newClientReady(t, ctx, tpm)
	result, err := client.Enroll(ctx)
	require.NoError(t, err)

	// GetDeviceInfo exercises the scanDevice path via /devices/me.
	info, err := client.GetDeviceInfo(ctx)
	require.NoError(t, err, "GetDeviceInfo must not error on device with NULL lan_ips")
	assert.Equal(t, result.DeviceID, info.DeviceID)
}

// TestSetupDiscover_ReEnrollHardwareModel verifies design decision #7: a
// re-enrollment with a different hardware_model updates the stored value via
// UpdateHardwareModel, not via the untouched UpdateTrustData.
func TestSetupDiscover_ReEnrollHardwareModel(t *testing.T) {
	ctx := context.Background()
	cleanDevicesDB(t, ctx)

	tpm, cleanup := startTestTPM(t, ctx)
	defer cleanup()

	serverURL := envOr("NAMEK_TEST_URL", "https://localhost:8443")

	// First enrollment: model A.
	client1 := namekclient.New(serverURL, tpm,
		namekclient.WithInsecureSkipVerify(),
		namekclient.WithHardwareModel("Model A"),
	)
	require.Eventually(t, func() bool { return client1.Ready(ctx) == nil }, 30*time.Second, 1*time.Second)
	r1, err := client1.Enroll(ctx)
	require.NoError(t, err)

	// Re-enrollment with the same TPM but a new hardware_model string.
	client2 := namekclient.New(serverURL, tpm,
		namekclient.WithInsecureSkipVerify(),
		namekclient.WithHardwareModel("Model B Rev 2"),
	)
	r2, err := client2.Enroll(ctx)
	require.NoError(t, err)
	require.Equal(t, r1.DeviceID, r2.DeviceID, "re-enrollment should preserve device ID")

	// Verify the new model is persisted.
	dbURL := envOr("NAMEK_TEST_DB", "postgres://namek:namek@localhost:5432/namek?sslmode=disable")
	conn, err := pgx.Connect(ctx, dbURL)
	require.NoError(t, err)
	defer conn.Close(ctx)
	var hm *string
	err = conn.QueryRow(ctx, "SELECT hardware_model FROM devices WHERE id = $1", r1.DeviceID).Scan(&hm)
	require.NoError(t, err)
	require.NotNil(t, hm)
	assert.Equal(t, "Model B Rev 2", *hm, "re-enrollment should update hardware_model")
}

// TestSetupDiscover_MigrationV5Applied confirms migration v5 landed and the
// partial index exists.
func TestSetupDiscover_MigrationV5Applied(t *testing.T) {
	ctx := context.Background()
	dbURL := envOr("NAMEK_TEST_DB", "postgres://namek:namek@localhost:5432/namek?sslmode=disable")
	conn, err := pgx.Connect(ctx, dbURL)
	require.NoError(t, err)
	defer conn.Close(ctx)

	var maxVersion int
	err = conn.QueryRow(ctx, "SELECT coalesce(max(version), 0) FROM schema_version").Scan(&maxVersion)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, maxVersion, 5, "migration v5 should be applied")

	var hasHardwareModel bool
	err = conn.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_name = 'devices' AND column_name = 'hardware_model'
		)
	`).Scan(&hasHardwareModel)
	require.NoError(t, err)
	assert.True(t, hasHardwareModel, "devices.hardware_model column should exist")

	var hasLanIPs bool
	err = conn.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_name = 'devices' AND column_name = 'lan_ips'
		)
	`).Scan(&hasLanIPs)
	require.NoError(t, err)
	assert.True(t, hasLanIPs, "devices.lan_ips column should exist")

	var hasIndex bool
	err = conn.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_indexes
			WHERE indexname = 'idx_devices_setup_discovery'
		)
	`).Scan(&hasIndex)
	require.NoError(t, err)
	assert.True(t, hasIndex, "partial index idx_devices_setup_discovery should exist")
}

// TestSetupDiscover_RejectEmptyLANIPsWhenNotComplete verifies the service-layer
// guard: ongoing (setup_complete=false) heartbeats must carry at least one IP.
func TestSetupDiscover_RejectEmptyLANIPsWhenNotComplete(t *testing.T) {
	ctx := context.Background()
	cleanDevicesDB(t, ctx)

	tpm, cleanup := startTestTPM(t, ctx)
	defer cleanup()

	client := newClientReady(t, ctx, tpm)
	_, err := client.Enroll(ctx)
	require.NoError(t, err)

	err = client.SendHeartbeat(ctx, &namekclient.HeartbeatRequest{
		LANIPs:        nil,
		SetupComplete: false,
	})
	require.Error(t, err, "ongoing heartbeat without lan_ips must be rejected")
	assert.Contains(t, strings.ToLower(err.Error()), "invalid")
}

// helper used by the hardware_model assertion above (forward declaration trick)
var _ = fmt.Sprintf
