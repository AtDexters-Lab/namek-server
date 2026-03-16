package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	PublicHostname   string `yaml:"publicHostname"`
	AcmeDirectoryURL string `yaml:"acmeDirectoryURL"`
	AcmeCACert       string `yaml:"acmeCACert"`
	ListenAddress    string `yaml:"listenAddress"`
	HTTPAddress      string `yaml:"httpAddress"`

	Database   DatabaseConfig `yaml:"database"`
	DNS        DNSConfig      `yaml:"dns"`
	PowerDNS   PowerDNSConfig `yaml:"powerDNS"`
	TPM        TPMConfig      `yaml:"tpm"`
	Nexus      NexusConfig    `yaml:"nexus"`
	Token      TokenConfig    `yaml:"token"`
	Enrollment EnrollmentConfig `yaml:"enrollment"`
	Hostname     HostnameConfig     `yaml:"hostname"`
	AliasDomain  AliasDomainConfig  `yaml:"aliasDomain"`

	AuditRetentionDays int `yaml:"auditRetentionDays"`
}

type DatabaseConfig struct {
	URL          string `yaml:"url"`
	MaxOpenConns int    `yaml:"maxOpenConns"`
	MaxIdleConns int    `yaml:"maxIdleConns"`
}

type DNSConfig struct {
	BaseDomain    string `yaml:"baseDomain"`
	Zone          string `yaml:"zone"`
	RelayHostname string `yaml:"relayHostname"`
}

type PowerDNSConfig struct {
	ApiURL         string `yaml:"apiURL"`
	ApiKey         string `yaml:"apiKey"`
	ServerID       string `yaml:"serverID"`
	TimeoutSeconds int    `yaml:"timeoutSeconds"`
	DNSAddress     string `yaml:"dnsAddress"`
}

func (c PowerDNSConfig) Timeout() time.Duration {
	if c.TimeoutSeconds <= 0 {
		return 10 * time.Second
	}
	return time.Duration(c.TimeoutSeconds) * time.Second
}

type TPMConfig struct {
	TrustedCACertsDir string `yaml:"trustedCACertsDir"`
	AllowSoftwareTPM  bool   `yaml:"allowSoftwareTPM"`
}

type NexusConfig struct {
	TrustedDomainSuffixes       []string `yaml:"trustedDomainSuffixes"`
	ClientCACertFile            string   `yaml:"clientCACertFile"`
	HeartbeatIntervalSeconds    int      `yaml:"heartbeatIntervalSeconds"`
	InactiveThresholdMultiplier int      `yaml:"inactiveThresholdMultiplier"`
}

type TokenConfig struct {
	TTLSeconds                 int `yaml:"ttlSeconds"`
	DefaultWeight              int `yaml:"defaultWeight"`
	HandshakeMaxAgeSeconds     int `yaml:"handshakeMaxAgeSeconds"`
	ReauthIntervalSeconds      int `yaml:"reauthIntervalSeconds"`
	ReauthGraceSeconds         int `yaml:"reauthGraceSeconds"`
	MaintenanceGraceCapSeconds int `yaml:"maintenanceGraceCapSeconds"`
}

type EnrollmentConfig struct {
	MaxPending              int `yaml:"maxPending"`
	PendingTTLSeconds       int `yaml:"pendingTTLSeconds"`
	RateLimitPerSecond      int `yaml:"rateLimitPerSecond"`
	RateLimitPerIPPerSecond int `yaml:"rateLimitPerIPPerSecond"`
}

type HostnameConfig struct {
	MaxChangesPerYear    int `yaml:"maxChangesPerYear"`
	CooldownDays         int `yaml:"cooldownDays"`
	ReleasedCooldownDays int `yaml:"releasedCooldownDays"`
}

type AliasDomainConfig struct {
	MaxPerAccount              int    `yaml:"maxPerAccount"`
	PendingExpiryDays          int    `yaml:"pendingExpiryDays"`
	VerificationTimeoutSeconds int    `yaml:"verificationTimeoutSeconds"`
	DNSResolver                string `yaml:"dnsResolver"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config file: %w", err)
	}

	cfg.applyDefaults()

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config validation: %w", err)
	}

	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.ListenAddress == "" {
		c.ListenAddress = ":443"
	}
	if c.PowerDNS.DNSAddress == "" {
		c.PowerDNS.DNSAddress = "127.0.0.1:53"
	}
	if c.Database.MaxOpenConns == 0 {
		c.Database.MaxOpenConns = 25
	}
	if c.Database.MaxIdleConns == 0 {
		c.Database.MaxIdleConns = 5
	}
	if c.PowerDNS.ServerID == "" {
		c.PowerDNS.ServerID = "localhost"
	}
	if c.PowerDNS.TimeoutSeconds == 0 {
		c.PowerDNS.TimeoutSeconds = 10
	}
	if c.Nexus.HeartbeatIntervalSeconds == 0 {
		c.Nexus.HeartbeatIntervalSeconds = 30
	}
	if c.Nexus.InactiveThresholdMultiplier == 0 {
		c.Nexus.InactiveThresholdMultiplier = 3
	}
	if c.Token.TTLSeconds == 0 {
		c.Token.TTLSeconds = 30
	}
	if c.Token.DefaultWeight == 0 {
		c.Token.DefaultWeight = 1
	}
	if c.Token.HandshakeMaxAgeSeconds == 0 {
		c.Token.HandshakeMaxAgeSeconds = 60
	}
	if c.Token.ReauthIntervalSeconds == 0 {
		c.Token.ReauthIntervalSeconds = 300
	}
	if c.Token.ReauthGraceSeconds == 0 {
		c.Token.ReauthGraceSeconds = 30
	}
	if c.Token.MaintenanceGraceCapSeconds == 0 {
		c.Token.MaintenanceGraceCapSeconds = 600
	}
	if c.AuditRetentionDays == 0 {
		c.AuditRetentionDays = 90
	}
	if c.Enrollment.MaxPending == 0 {
		c.Enrollment.MaxPending = 1000
	}
	if c.Enrollment.PendingTTLSeconds == 0 {
		c.Enrollment.PendingTTLSeconds = 300
	}
	if c.Enrollment.RateLimitPerSecond == 0 {
		c.Enrollment.RateLimitPerSecond = 10
	}
	if c.Enrollment.RateLimitPerIPPerSecond == 0 {
		c.Enrollment.RateLimitPerIPPerSecond = 2
	}
	if c.Hostname.MaxChangesPerYear == 0 {
		c.Hostname.MaxChangesPerYear = 5
	}
	if c.Hostname.CooldownDays == 0 {
		c.Hostname.CooldownDays = 30
	}
	if c.Hostname.ReleasedCooldownDays == 0 {
		c.Hostname.ReleasedCooldownDays = 365
	}
	if c.AliasDomain.MaxPerAccount == 0 {
		c.AliasDomain.MaxPerAccount = 50
	}
	if c.AliasDomain.PendingExpiryDays == 0 {
		c.AliasDomain.PendingExpiryDays = 7
	}
	if c.AliasDomain.VerificationTimeoutSeconds == 0 {
		c.AliasDomain.VerificationTimeoutSeconds = 10
	}
}

func (c *Config) validate() error {
	if c.PublicHostname == "" {
		return fmt.Errorf("publicHostname must be set")
	}
	if c.Database.URL == "" {
		return fmt.Errorf("database.url must be set")
	}
	if c.DNS.BaseDomain == "" {
		return fmt.Errorf("dns.baseDomain must be set")
	}
	if c.DNS.Zone == "" {
		return fmt.Errorf("dns.zone must be set")
	}
	if c.DNS.RelayHostname == "" {
		return fmt.Errorf("dns.relayHostname must be set")
	}
	if c.PowerDNS.ApiURL == "" {
		return fmt.Errorf("powerDNS.apiURL must be set")
	}
	if c.PowerDNS.ApiKey == "" {
		return fmt.Errorf("powerDNS.apiKey must be set")
	}
	if len(c.Nexus.TrustedDomainSuffixes) == 0 {
		return fmt.Errorf("nexus.trustedDomainSuffixes must have at least one entry")
	}
	if c.Nexus.HeartbeatIntervalSeconds <= 0 {
		return fmt.Errorf("nexus.heartbeatIntervalSeconds must be positive")
	}
	if c.Nexus.InactiveThresholdMultiplier <= 0 {
		return fmt.Errorf("nexus.inactiveThresholdMultiplier must be positive")
	}
	if c.Token.TTLSeconds <= 0 {
		return fmt.Errorf("token.ttlSeconds must be positive")
	}
	if c.Token.HandshakeMaxAgeSeconds <= 0 {
		return fmt.Errorf("token.handshakeMaxAgeSeconds must be positive")
	}
	if c.Token.ReauthIntervalSeconds <= 0 {
		return fmt.Errorf("token.reauthIntervalSeconds must be positive")
	}
	if c.Enrollment.MaxPending <= 0 {
		return fmt.Errorf("enrollment.maxPending must be positive")
	}
	if c.Enrollment.PendingTTLSeconds <= 0 {
		return fmt.Errorf("enrollment.pendingTTLSeconds must be positive")
	}
	if c.Enrollment.RateLimitPerSecond <= 0 {
		return fmt.Errorf("enrollment.rateLimitPerSecond must be positive")
	}
	if c.Enrollment.RateLimitPerIPPerSecond <= 0 {
		return fmt.Errorf("enrollment.rateLimitPerIPPerSecond must be positive")
	}
	if c.AuditRetentionDays <= 0 {
		return fmt.Errorf("auditRetentionDays must be positive")
	}
	if c.Hostname.MaxChangesPerYear <= 0 {
		return fmt.Errorf("hostname.maxChangesPerYear must be positive")
	}
	if c.Hostname.CooldownDays <= 0 {
		return fmt.Errorf("hostname.cooldownDays must be positive")
	}
	if c.Hostname.ReleasedCooldownDays <= 0 {
		return fmt.Errorf("hostname.releasedCooldownDays must be positive")
	}
	if c.AliasDomain.MaxPerAccount <= 0 {
		return fmt.Errorf("aliasDomain.maxPerAccount must be positive")
	}
	if c.AliasDomain.PendingExpiryDays <= 0 {
		return fmt.Errorf("aliasDomain.pendingExpiryDays must be positive")
	}
	if c.AliasDomain.VerificationTimeoutSeconds <= 0 {
		return fmt.Errorf("aliasDomain.verificationTimeoutSeconds must be positive")
	}
	return nil
}

func (c *Config) TokenTTL() time.Duration {
	return time.Duration(c.Token.TTLSeconds) * time.Second
}

func (c *Config) PowerDNSTimeout() time.Duration {
	return time.Duration(c.PowerDNS.TimeoutSeconds) * time.Second
}

func (c *Config) HeartbeatInterval() time.Duration {
	return time.Duration(c.Nexus.HeartbeatIntervalSeconds) * time.Second
}

func (c *Config) InactiveThreshold() time.Duration {
	return c.HeartbeatInterval() * time.Duration(c.Nexus.InactiveThresholdMultiplier)
}

func (c *Config) PendingEnrollmentTTL() time.Duration {
	return time.Duration(c.Enrollment.PendingTTLSeconds) * time.Second
}

func (c *Config) PendingDomainExpiry() time.Duration {
	return time.Duration(c.AliasDomain.PendingExpiryDays) * 24 * time.Hour
}

func (c *Config) VerificationTimeout() time.Duration {
	return time.Duration(c.AliasDomain.VerificationTimeoutSeconds) * time.Second
}
