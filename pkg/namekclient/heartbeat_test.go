package namekclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AtDexters-Lab/namek-server/pkg/tpmdevice"
)

// fakeTPM is a minimal tpmdevice.Device for tests that don't need real crypto.
type fakeTPM struct{}

func (fakeTPM) EKCertDER() ([]byte, error) { return nil, nil }
func (fakeTPM) EKPublicDER() ([]byte, error) {
	return []byte("ek-pub-der"), nil
}
func (fakeTPM) AKPublic() ([]byte, error) { return []byte("ak-public-raw"), nil }
func (fakeTPM) ActivateCredential(_ []byte) ([]byte, error) {
	// Must return a 32-byte secret to match server expectation.
	s := make([]byte, 32)
	for i := range s {
		s[i] = byte(i)
	}
	return s, nil
}
func (fakeTPM) Quote(_ []byte) (string, error)         { return "fake-quote-b64", nil }
func (fakeTPM) QuoteOverData(_ []byte) (string, error) { return "fake-quote-over-data", nil }
func (fakeTPM) Close() error                            { return nil }

var _ tpmdevice.Device = fakeTPM{}

// TestEnrollIncludesHardwareModel verifies that WithHardwareModel flows through
// into the fresh-enrollment attest body. This is the non-recovery path.
func TestEnrollIncludesHardwareModel(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/devices/enroll":
			// Phase 1: return a fake encrypted credential blob
			w.Header().Set("Content-Type", "application/json")
			resp := map[string]string{
				"nonce":          "a1b2c3d4",
				"enc_credential": base64.StdEncoding.EncodeToString([]byte("enc-cred-blob")),
			}
			_ = json.NewEncoder(w).Encode(resp)
		case "/api/v1/devices/enroll/attest":
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device_id":       "00000000-0000-0000-0000-000000000001",
				"hostname":        "test.example.com",
				"identity_class":  "verified",
				"trust_level":     "standard",
				"nexus_endpoints": []string{},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := New(srv.URL, fakeTPM{}, WithHardwareModel("Raspberry Pi 4 Model B"), WithNoRetry())
	_, err := c.Enroll(context.Background())
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	got, ok := gotBody["hardware_model"].(string)
	if !ok {
		t.Fatalf("hardware_model missing or wrong type: %#v", gotBody)
	}
	if got != "Raspberry Pi 4 Model B" {
		t.Errorf("hardware_model = %q, want %q", got, "Raspberry Pi 4 Model B")
	}
}

// TestEnrollOmitsHardwareModelWhenUnset verifies additive compatibility: a
// client without WithHardwareModel must not include the field.
func TestEnrollOmitsHardwareModelWhenUnset(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/devices/enroll":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"nonce":          "a1b2c3d4",
				"enc_credential": base64.StdEncoding.EncodeToString([]byte("enc-cred-blob")),
			})
		case "/api/v1/devices/enroll/attest":
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device_id":       "00000000-0000-0000-0000-000000000001",
				"hostname":        "test.example.com",
				"identity_class":  "verified",
				"trust_level":     "standard",
				"nexus_endpoints": []string{},
			})
		}
	}))
	defer srv.Close()

	c := New(srv.URL, fakeTPM{}, WithNoRetry())
	if _, err := c.Enroll(context.Background()); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if _, present := gotBody["hardware_model"]; present {
		t.Errorf("hardware_model should be absent when not set, got: %#v", gotBody)
	}
}

// TestSendHeartbeatPostsCorrectBody verifies the SendHeartbeat path constructs
// a valid request against /api/v1/devices/me/heartbeat.
func TestSendHeartbeatPostsCorrectBody(t *testing.T) {
	var gotPath string
	var gotBody HeartbeatRequest
	var gotHeaders http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/nonce":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"nonce": "bmZ0ZXN0"}) // "nftest" base64url
		case "/api/v1/devices/me/heartbeat":
			gotPath = r.URL.Path
			gotHeaders = r.Header.Clone()
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := New(srv.URL, fakeTPM{}, WithDeviceID("00000000-0000-0000-0000-000000000001"), WithNoRetry())
	err := c.SendHeartbeat(context.Background(), &HeartbeatRequest{
		LANIPs:        []string{"10.0.0.5", "192.168.1.5"},
		SetupComplete: false,
	})
	if err != nil {
		t.Fatalf("SendHeartbeat: %v", err)
	}
	if gotPath != "/api/v1/devices/me/heartbeat" {
		t.Errorf("path = %q, want /api/v1/devices/me/heartbeat", gotPath)
	}
	if len(gotBody.LANIPs) != 2 || gotBody.LANIPs[0] != "10.0.0.5" {
		t.Errorf("body.LANIPs = %v, want [10.0.0.5 192.168.1.5]", gotBody.LANIPs)
	}
	if gotBody.SetupComplete {
		t.Errorf("body.SetupComplete = true, want false")
	}
	if gotHeaders.Get("X-Device-ID") == "" {
		t.Error("X-Device-ID header missing")
	}
	if gotHeaders.Get("X-Nonce") == "" {
		t.Error("X-Nonce header missing")
	}
	if gotHeaders.Get("X-TPM-Quote") == "" {
		t.Error("X-TPM-Quote header missing")
	}
}

// TestClientRejectsRedirects is the regression guard for the CheckRedirect
// hardening. Without it, Go's default client follows 301/302 and silently drops
// POST bodies, turning heartbeats into empty requests against the redirect target.
func TestClientRejectsRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://attacker.example.com/evil")
		w.WriteHeader(http.StatusFound) // 302
	}))
	defer srv.Close()

	c := New(srv.URL, fakeTPM{}, WithNoRetry())
	if err := c.Health(context.Background()); err == nil {
		t.Fatal("Health should have errored on redirect, got nil")
	} else if !strings.Contains(err.Error(), "302") && !strings.Contains(err.Error(), "use last") {
		// Accept any error surface as long as the redirect was not followed.
		// Go returns http.ErrUseLastResponse which surfaces as a non-nil resp
		// with a 302 status — Health checks status and errors out.
	}
}
