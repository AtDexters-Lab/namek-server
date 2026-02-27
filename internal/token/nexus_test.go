package token

import (
	"log/slog"
	"os"
	"testing"

	"github.com/AtDexters-Lab/namek-server/internal/config"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func testIssuer(t *testing.T) *Issuer {
	t.Helper()
	cfg := config.TokenConfig{
		TTLSeconds:                 30,
		DefaultWeight:              1,
		HandshakeMaxAgeSeconds:     60,
		ReauthIntervalSeconds:      300,
		ReauthGraceSeconds:         30,
		MaintenanceGraceCapSeconds: 600,
	}
	issuer, err := NewIssuer(cfg, "namek.test.com", testLogger())
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}
	return issuer
}

func TestIssuer_HandshakeToken(t *testing.T) {
	issuer := testIssuer(t)

	tokenStr, err := issuer.Issue(IssueParams{
		DeviceID:  "device-123",
		Hostnames: []string{"device-123.test.com"},
		Stage:     0,
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if tokenStr == "" {
		t.Fatal("token should not be empty")
	}

	// Verify
	claims, err := issuer.Verify(tokenStr)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	if claims.Subject != "device-123" {
		t.Errorf("subject = %q, want device-123", claims.Subject)
	}
	if len(claims.Hostnames) != 1 || claims.Hostnames[0] != "device-123.test.com" {
		t.Errorf("hostnames = %v, want [device-123.test.com]", claims.Hostnames)
	}
	if claims.SessionNonce != "" {
		t.Errorf("session_nonce should be empty for stage 0, got %q", claims.SessionNonce)
	}
	if claims.HandshakeMaxAgeSeconds == nil {
		t.Error("handshake_max_age_seconds should be set for stage 0")
	}
	if len(claims.TCPPorts) != 0 {
		t.Errorf("tcp_ports should be empty, got %v", claims.TCPPorts)
	}
	if len(claims.UDPRoutes) != 0 {
		t.Errorf("udp_routes should be empty, got %v", claims.UDPRoutes)
	}
	if claims.Issuer != "authorizer" {
		t.Errorf("issuer = %q, want authorizer", claims.Issuer)
	}
}

func TestIssuer_AttestToken(t *testing.T) {
	issuer := testIssuer(t)

	tokenStr, err := issuer.Issue(IssueParams{
		DeviceID:     "device-456",
		Hostnames:    []string{"device-456.test.com", "mybox.test.com"},
		Stage:        1,
		SessionNonce: "session-abc",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	claims, err := issuer.Verify(tokenStr)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	if claims.SessionNonce != "session-abc" {
		t.Errorf("session_nonce = %q, want session-abc", claims.SessionNonce)
	}
	if len(claims.Hostnames) != 2 {
		t.Errorf("hostnames len = %d, want 2", len(claims.Hostnames))
	}
	if claims.HandshakeMaxAgeSeconds != nil {
		t.Error("handshake_max_age_seconds should be nil for stage 1")
	}
}

func TestIssuer_ReauthToken(t *testing.T) {
	issuer := testIssuer(t)

	tokenStr, err := issuer.Issue(IssueParams{
		DeviceID:     "device-789",
		Hostnames:    []string{"device-789.test.com"},
		Stage:        2,
		SessionNonce: "session-xyz",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	claims, err := issuer.Verify(tokenStr)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	if claims.SessionNonce != "session-xyz" {
		t.Errorf("session_nonce = %q, want session-xyz", claims.SessionNonce)
	}
	if claims.ReauthIntervalSeconds == nil {
		t.Error("reauth_interval_seconds should be set for stage 2")
	}
}

func TestIssuer_InvalidStage(t *testing.T) {
	issuer := testIssuer(t)

	_, err := issuer.Issue(IssueParams{
		DeviceID:  "device-bad",
		Hostnames: []string{"bad.test.com"},
		Stage:     5,
	})
	if err == nil {
		t.Fatal("expected error for invalid stage")
	}
}

func TestIssuer_VerifyInvalidToken(t *testing.T) {
	issuer := testIssuer(t)

	_, err := issuer.Verify("invalid.token.here")
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestIssuer_DifferentSecrets(t *testing.T) {
	issuer1 := testIssuer(t)
	issuer2 := testIssuer(t)

	tokenStr, err := issuer1.Issue(IssueParams{
		DeviceID:  "device-123",
		Hostnames: []string{"device-123.test.com"},
		Stage:     0,
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Verify with different issuer should fail (different ephemeral secret)
	_, err = issuer2.Verify(tokenStr)
	if err == nil {
		t.Fatal("expected error when verifying with different secret")
	}
}
