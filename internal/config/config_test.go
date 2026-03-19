package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_Valid(t *testing.T) {
	content := `
publicHostname: "namek.test.com"
database:
  url: "postgres://test:test@localhost/test"
dns:
  baseDomain: "test.com"
  zone: "test.com."
  relayHostname: "relay.test.com"
powerDNS:
  apiURL: "http://localhost:8081"
  apiKey: "test-key"
nexus:
  trustedDomainSuffixes:
    - ".nexus.test.com"
`
	path := writeTemp(t, content)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if cfg.PublicHostname != "namek.test.com" {
		t.Errorf("publicHostname = %q", cfg.PublicHostname)
	}
	if cfg.ListenAddress != ":443" {
		t.Errorf("listenAddress default = %q, want :443", cfg.ListenAddress)
	}
	if cfg.Token.TTLSeconds != 30 {
		t.Errorf("token.ttlSeconds default = %d, want 30", cfg.Token.TTLSeconds)
	}
	if cfg.Enrollment.MaxPending != 1000 {
		t.Errorf("enrollment.maxPending default = %d, want 1000", cfg.Enrollment.MaxPending)
	}
	if len(cfg.DNS.Nameservers) != 1 || cfg.DNS.Nameservers[0] != "namek.test.com" {
		t.Errorf("dns.nameservers default = %v, want [namek.test.com]", cfg.DNS.Nameservers)
	}
}

func TestLoad_MissingRequired(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"missing publicHostname", `
database:
  url: "postgres://test:test@localhost/test"
dns:
  baseDomain: "test.com"
  zone: "test.com."
  relayHostname: "relay.test.com"
powerDNS:
  apiURL: "http://localhost:8081"
  apiKey: "test-key"
nexus:
  trustedDomainSuffixes: [".nexus.test.com"]
`},
		{"missing database url", `
publicHostname: "namek.test.com"
dns:
  baseDomain: "test.com"
  zone: "test.com."
  relayHostname: "relay.test.com"
powerDNS:
  apiURL: "http://localhost:8081"
  apiKey: "test-key"
nexus:
  trustedDomainSuffixes: [".nexus.test.com"]
`},
		{"missing powerDNS apiKey", `
publicHostname: "namek.test.com"
database:
  url: "postgres://test:test@localhost/test"
dns:
  baseDomain: "test.com"
  zone: "test.com."
  relayHostname: "relay.test.com"
powerDNS:
  apiURL: "http://localhost:8081"
nexus:
  trustedDomainSuffixes: [".nexus.test.com"]
`},
		{"empty nameserver entry", `
publicHostname: "namek.test.com"
database:
  url: "postgres://test:test@localhost/test"
dns:
  baseDomain: "test.com"
  zone: "test.com."
  relayHostname: "relay.test.com"
  nameservers:
    - ""
powerDNS:
  apiURL: "http://localhost:8081"
  apiKey: "test-key"
nexus:
  trustedDomainSuffixes: [".nexus.test.com"]
`},
		{"duplicate nameserver entry", `
publicHostname: "namek.test.com"
database:
  url: "postgres://test:test@localhost/test"
dns:
  baseDomain: "test.com"
  zone: "test.com."
  relayHostname: "relay.test.com"
  nameservers:
    - "ns1.test.com"
    - "ns1.test.com"
powerDNS:
  apiURL: "http://localhost:8081"
  apiKey: "test-key"
nexus:
  trustedDomainSuffixes: [".nexus.test.com"]
`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTemp(t, tt.content)
			_, err := Load(path)
			if err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestLoad_ExplicitNameservers(t *testing.T) {
	content := `
publicHostname: "namek.test.com"
database:
  url: "postgres://test:test@localhost/test"
dns:
  baseDomain: "test.com"
  zone: "test.com."
  relayHostname: "relay.test.com"
  nameservers:
    - "ns1.test.com"
    - "ns2.test.com"
    - "ns3.test.com"
powerDNS:
  apiURL: "http://localhost:8081"
  apiKey: "test-key"
nexus:
  trustedDomainSuffixes:
    - ".nexus.test.com"
`
	path := writeTemp(t, content)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	want := []string{"ns1.test.com", "ns2.test.com", "ns3.test.com"}
	if len(cfg.DNS.Nameservers) != len(want) {
		t.Fatalf("nameservers len = %d, want %d", len(cfg.DNS.Nameservers), len(want))
	}
	for i, ns := range cfg.DNS.Nameservers {
		if ns != want[i] {
			t.Errorf("nameservers[%d] = %q, want %q", i, ns, want[i])
		}
	}
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	return path
}
