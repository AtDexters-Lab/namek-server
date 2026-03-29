package dns

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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

func TestPowerDNSClient_SetTXTRecords_MultiValue(t *testing.T) {
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

	err := client.SetTXTRecords(context.Background(), "test.com.", "_acme-challenge.uuid.test.com",
		[]string{"digest-A", "digest-B"}, 300)
	if err != nil {
		t.Fatalf("set txt records: %v", err)
	}

	if len(receivedBody.RRSets) != 1 {
		t.Fatalf("expected 1 rrset, got %d", len(receivedBody.RRSets))
	}

	rrset := receivedBody.RRSets[0]
	if rrset.Type != "TXT" {
		t.Errorf("type = %q, want TXT", rrset.Type)
	}
	if len(rrset.Records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(rrset.Records))
	}
	if rrset.Records[0].Content != `"digest-A"` {
		t.Errorf("record[0] = %q, want %q", rrset.Records[0].Content, `"digest-A"`)
	}
	if rrset.Records[1].Content != `"digest-B"` {
		t.Errorf("record[1] = %q, want %q", rrset.Records[1].Content, `"digest-B"`)
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

func TestPowerDNSClient_SetRelayRecords(t *testing.T) {
	t.Run("both ipv4 and ipv6", func(t *testing.T) {
		var receivedBody patchBody

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPatch {
				t.Errorf("expected PATCH, got %s", r.Method)
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

		err := client.SetRelayRecords(context.Background(), "test.com.", "relay.test.com",
			[]string{"1.2.3.4"}, []string{"2001:db8::1"}, 60)
		if err != nil {
			t.Fatalf("set relay records: %v", err)
		}

		if len(receivedBody.RRSets) != 2 {
			t.Fatalf("expected 2 rrsets, got %d", len(receivedBody.RRSets))
		}

		// Verify A record
		aRRSet := receivedBody.RRSets[0]
		if aRRSet.Type != "A" {
			t.Errorf("first rrset type = %q, want A", aRRSet.Type)
		}
		if aRRSet.ChangeType != "REPLACE" {
			t.Errorf("first rrset changetype = %q, want REPLACE", aRRSet.ChangeType)
		}
		if len(aRRSet.Records) != 1 || aRRSet.Records[0].Content != "1.2.3.4" {
			t.Errorf("unexpected A records: %+v", aRRSet.Records)
		}

		// Verify AAAA record
		aaaaRRSet := receivedBody.RRSets[1]
		if aaaaRRSet.Type != "AAAA" {
			t.Errorf("second rrset type = %q, want AAAA", aaaaRRSet.Type)
		}
		if aaaaRRSet.ChangeType != "REPLACE" {
			t.Errorf("second rrset changetype = %q, want REPLACE", aaaaRRSet.ChangeType)
		}
		if len(aaaaRRSet.Records) != 1 || aaaaRRSet.Records[0].Content != "2001:db8::1" {
			t.Errorf("unexpected AAAA records: %+v", aaaaRRSet.Records)
		}
	})

	t.Run("ipv4 only deletes aaaa", func(t *testing.T) {
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

		err := client.SetRelayRecords(context.Background(), "test.com.", "relay.test.com",
			[]string{"1.2.3.4"}, nil, 60)
		if err != nil {
			t.Fatalf("set relay records: %v", err)
		}

		if len(receivedBody.RRSets) != 2 {
			t.Fatalf("expected 2 rrsets, got %d", len(receivedBody.RRSets))
		}
		if receivedBody.RRSets[0].Type != "A" || receivedBody.RRSets[0].ChangeType != "REPLACE" {
			t.Errorf("expected A REPLACE, got %s %s", receivedBody.RRSets[0].Type, receivedBody.RRSets[0].ChangeType)
		}
		if receivedBody.RRSets[1].Type != "AAAA" || receivedBody.RRSets[1].ChangeType != "DELETE" {
			t.Errorf("expected AAAA DELETE, got %s %s", receivedBody.RRSets[1].Type, receivedBody.RRSets[1].ChangeType)
		}
	})

	t.Run("ipv6 only deletes a", func(t *testing.T) {
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

		err := client.SetRelayRecords(context.Background(), "test.com.", "relay.test.com",
			nil, []string{"2001:db8::1"}, 60)
		if err != nil {
			t.Fatalf("set relay records: %v", err)
		}

		if len(receivedBody.RRSets) != 2 {
			t.Fatalf("expected 2 rrsets, got %d", len(receivedBody.RRSets))
		}
		if receivedBody.RRSets[0].Type != "A" || receivedBody.RRSets[0].ChangeType != "DELETE" {
			t.Errorf("expected A DELETE, got %s %s", receivedBody.RRSets[0].Type, receivedBody.RRSets[0].ChangeType)
		}
		if receivedBody.RRSets[1].Type != "AAAA" || receivedBody.RRSets[1].ChangeType != "REPLACE" {
			t.Errorf("expected AAAA REPLACE, got %s %s", receivedBody.RRSets[1].Type, receivedBody.RRSets[1].ChangeType)
		}
	})

	t.Run("no ips deletes both", func(t *testing.T) {
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

		err := client.SetRelayRecords(context.Background(), "test.com.", "relay.test.com",
			nil, nil, 60)
		if err != nil {
			t.Fatalf("set relay records: %v", err)
		}

		if len(receivedBody.RRSets) != 2 {
			t.Fatalf("expected 2 rrsets, got %d", len(receivedBody.RRSets))
		}
		if receivedBody.RRSets[0].ChangeType != "DELETE" {
			t.Errorf("expected A DELETE, got %s", receivedBody.RRSets[0].ChangeType)
		}
		if receivedBody.RRSets[1].ChangeType != "DELETE" {
			t.Errorf("expected AAAA DELETE, got %s", receivedBody.RRSets[1].ChangeType)
		}
	})
}

func TestPowerDNSClient_CreateZone(t *testing.T) {
	t.Run("single nameserver in direct mode", func(t *testing.T) {
		var receivedBody createZoneRequest

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Errorf("expected POST, got %s", r.Method)
			}
			json.NewDecoder(r.Body).Decode(&receivedBody)
			w.WriteHeader(http.StatusCreated)
		}))
		defer server.Close()

		client := NewPowerDNSClient(config.PowerDNSConfig{
			ApiURL:   server.URL,
			ApiKey:   "test-key",
			ServerID: "localhost",
		}, testLogger())

		err := client.CreateZone(context.Background(), "example.com.", "example.com",
			"namek.example.com", []string{"namek.example.com"}, "relay.example.com")
		if err != nil {
			t.Fatalf("create zone: %v", err)
		}

		if len(receivedBody.RRSets) != 3 {
			t.Fatalf("expected 3 rrsets, got %d", len(receivedBody.RRSets))
		}

		// SOA record should use primaryNS as MNAME
		soaRRSet := receivedBody.RRSets[0]
		if soaRRSet.Type != "SOA" {
			t.Fatalf("first rrset type = %q, want SOA", soaRRSet.Type)
		}
		wantSOA := "namek.example.com. admin.example.com. 1 10800 3600 604800 300"
		if soaRRSet.Records[0].Content != wantSOA {
			t.Errorf("SOA content = %q, want %q", soaRRSet.Records[0].Content, wantSOA)
		}

		// NS record should match the single nameserver
		nsRRSet := receivedBody.RRSets[1]
		if nsRRSet.Type != "NS" {
			t.Fatalf("second rrset type = %q, want NS", nsRRSet.Type)
		}
		if len(nsRRSet.Records) != 1 {
			t.Fatalf("NS records len = %d, want 1", len(nsRRSet.Records))
		}
		if nsRRSet.Records[0].Content != "namek.example.com." {
			t.Errorf("NS content = %q, want %q", nsRRSet.Records[0].Content, "namek.example.com.")
		}

		// CNAME record should use relayHostname
		cnameRRSet := receivedBody.RRSets[2]
		if cnameRRSet.Type != "CNAME" {
			t.Fatalf("third rrset type = %q, want CNAME", cnameRRSet.Type)
		}
		if cnameRRSet.Records[0].Content != "relay.example.com." {
			t.Errorf("CNAME content = %q, want %q", cnameRRSet.Records[0].Content, "relay.example.com.")
		}
	})

	t.Run("multiple nameservers produces multiple NS records", func(t *testing.T) {
		var receivedBody createZoneRequest

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewDecoder(r.Body).Decode(&receivedBody)
			w.WriteHeader(http.StatusCreated)
		}))
		defer server.Close()

		client := NewPowerDNSClient(config.PowerDNSConfig{
			ApiURL:   server.URL,
			ApiKey:   "test-key",
			ServerID: "localhost",
		}, testLogger())

		nameservers := []string{"ns1.example.com", "ns2.example.com", "ns3.example.com"}
		err := client.CreateZone(context.Background(), "example.com.", "example.com",
			"namek.example.com", nameservers, "relay.example.com")
		if err != nil {
			t.Fatalf("create zone: %v", err)
		}

		// SOA MNAME should be primaryNS, not any of the nameservers
		soaRRSet := receivedBody.RRSets[0]
		wantSOA := "namek.example.com. admin.example.com. 1 10800 3600 604800 300"
		if soaRRSet.Records[0].Content != wantSOA {
			t.Errorf("SOA content = %q, want %q", soaRRSet.Records[0].Content, wantSOA)
		}

		// NS records should list all three nameservers
		nsRRSet := receivedBody.RRSets[1]
		if len(nsRRSet.Records) != 3 {
			t.Fatalf("NS records len = %d, want 3", len(nsRRSet.Records))
		}
		for i, ns := range nameservers {
			want := ns + "."
			if nsRRSet.Records[i].Content != want {
				t.Errorf("NS record[%d] = %q, want %q", i, nsRRSet.Records[i].Content, want)
			}
		}
	})

	t.Run("hidden primary: SOA MNAME differs from NS records", func(t *testing.T) {
		var receivedBody createZoneRequest

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewDecoder(r.Body).Decode(&receivedBody)
			w.WriteHeader(http.StatusCreated)
		}))
		defer server.Close()

		client := NewPowerDNSClient(config.PowerDNSConfig{
			ApiURL:   server.URL,
			ApiKey:   "test-key",
			ServerID: "localhost",
		}, testLogger())

		err := client.CreateZone(context.Background(), "example.com.", "example.com",
			"hidden.example.com", []string{"ns1.example.com", "ns2.example.com"}, "relay.example.com")
		if err != nil {
			t.Fatalf("create zone: %v", err)
		}

		// SOA MNAME = hidden primary, not the NS servers
		soaContent := receivedBody.RRSets[0].Records[0].Content
		if !strings.HasPrefix(soaContent, "hidden.example.com.") {
			t.Errorf("SOA MNAME should be hidden.example.com., got %q", soaContent)
		}

		// NS records should NOT contain the hidden primary
		nsRRSet := receivedBody.RRSets[1]
		if len(nsRRSet.Records) != 2 {
			t.Fatalf("NS records len = %d, want 2", len(nsRRSet.Records))
		}
		if nsRRSet.Records[0].Content != "ns1.example.com." {
			t.Errorf("NS[0] = %q, want ns1.example.com.", nsRRSet.Records[0].Content)
		}
		if nsRRSet.Records[1].Content != "ns2.example.com." {
			t.Errorf("NS[1] = %q, want ns2.example.com.", nsRRSet.Records[1].Content)
		}
	})

	t.Run("empty nameservers returns error", func(t *testing.T) {
		client := NewPowerDNSClient(config.PowerDNSConfig{
			ApiURL:   "http://unused",
			ApiKey:   "test-key",
			ServerID: "localhost",
		}, testLogger())

		err := client.CreateZone(context.Background(), "example.com.", "example.com",
			"namek.example.com", []string{}, "relay.example.com")
		if err == nil {
			t.Fatal("expected error for empty nameservers")
		}
	})

	t.Run("409 conflict returns nil", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusConflict)
		}))
		defer server.Close()

		client := NewPowerDNSClient(config.PowerDNSConfig{
			ApiURL:   server.URL,
			ApiKey:   "test-key",
			ServerID: "localhost",
		}, testLogger())

		err := client.CreateZone(context.Background(), "example.com.", "example.com",
			"namek.example.com", []string{"namek.example.com"}, "relay.example.com")
		if err != nil {
			t.Fatalf("expected nil on 409, got: %v", err)
		}
	})
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
