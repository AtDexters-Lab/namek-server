package dns

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/AtDexters-Lab/namek-server/internal/config"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestPowerDNSClient_SetARecords(t *testing.T) {
	var receivedBody patchBody

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			t.Errorf("expected PATCH, got %s", r.Method)
		}
		if r.Header.Get("X-API-Key") != "test-key" {
			t.Errorf("missing api key header")
		}

		json.NewDecoder(r.Body).Decode(&receivedBody)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := NewPowerDNSClient(config.PowerDNSConfig{
		ApiURL:   server.URL,
		ApiKey:   "test-key",
		ServerID: "localhost",
	}, testLogger())

	err := client.SetARecords(context.Background(), "test.com.", "relay.test.com", []string{"1.2.3.4", "5.6.7.8"}, 60)
	if err != nil {
		t.Fatalf("set a records: %v", err)
	}

	if len(receivedBody.RRSets) != 1 {
		t.Fatalf("expected 1 rrset, got %d", len(receivedBody.RRSets))
	}

	rrset := receivedBody.RRSets[0]
	if rrset.Name != "relay.test.com." {
		t.Errorf("name = %q, want relay.test.com.", rrset.Name)
	}
	if rrset.Type != "A" {
		t.Errorf("type = %q, want A", rrset.Type)
	}
	if rrset.ChangeType != "REPLACE" {
		t.Errorf("changetype = %q, want REPLACE", rrset.ChangeType)
	}
	if len(rrset.Records) != 2 {
		t.Errorf("records len = %d, want 2", len(rrset.Records))
	}
}

func TestPowerDNSClient_SetTXTRecord(t *testing.T) {
	var receivedBody patchBody

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&receivedBody)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := NewPowerDNSClient(config.PowerDNSConfig{
		ApiURL:   server.URL,
		ApiKey:   "test-key",
		ServerID: "localhost",
	}, testLogger())

	err := client.SetTXTRecord(context.Background(), "test.com.", "_acme-challenge.uuid.test.com", "digest-value", 300)
	if err != nil {
		t.Fatalf("set txt record: %v", err)
	}

	if len(receivedBody.RRSets) != 1 {
		t.Fatalf("expected 1 rrset, got %d", len(receivedBody.RRSets))
	}

	rrset := receivedBody.RRSets[0]
	if rrset.Type != "TXT" {
		t.Errorf("type = %q, want TXT", rrset.Type)
	}
	if rrset.TTL != 300 {
		t.Errorf("ttl = %d, want 300", rrset.TTL)
	}
}

func TestPowerDNSClient_DeleteARecords(t *testing.T) {
	var receivedBody patchBody

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&receivedBody)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := NewPowerDNSClient(config.PowerDNSConfig{
		ApiURL:   server.URL,
		ApiKey:   "test-key",
		ServerID: "localhost",
	}, testLogger())

	err := client.DeleteARecords(context.Background(), "test.com.", "relay.test.com")
	if err != nil {
		t.Fatalf("delete a records: %v", err)
	}

	if receivedBody.RRSets[0].ChangeType != "DELETE" {
		t.Errorf("changetype = %q, want DELETE", receivedBody.RRSets[0].ChangeType)
	}
}

func TestPowerDNSClient_Healthy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"localhost"}`))
	}))
	defer server.Close()

	client := NewPowerDNSClient(config.PowerDNSConfig{
		ApiURL:   server.URL,
		ApiKey:   "test-key",
		ServerID: "localhost",
	}, testLogger())

	err := client.Healthy(context.Background())
	if err != nil {
		t.Fatalf("healthy: %v", err)
	}
}

func TestPowerDNSClient_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal error"}`))
	}))
	defer server.Close()

	client := NewPowerDNSClient(config.PowerDNSConfig{
		ApiURL:   server.URL,
		ApiKey:   "test-key",
		ServerID: "localhost",
	}, testLogger())

	err := client.SetARecords(context.Background(), "test.com.", "relay.test.com", []string{"1.2.3.4"}, 60)
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}
