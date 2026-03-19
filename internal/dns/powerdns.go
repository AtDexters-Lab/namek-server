package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/AtDexters-Lab/namek-server/internal/config"
)

type PowerDNSClient struct {
	apiURL   string
	apiKey   string
	serverID string
	client   *http.Client
	logger   *slog.Logger
}

func NewPowerDNSClient(cfg config.PowerDNSConfig, logger *slog.Logger) *PowerDNSClient {
	return &PowerDNSClient{
		apiURL:   cfg.ApiURL,
		apiKey:   cfg.ApiKey,
		serverID: cfg.ServerID,
		client:   &http.Client{Timeout: cfg.Timeout()},
		logger:   logger,
	}
}

// RRSet represents a PowerDNS resource record set.
type RRSet struct {
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	TTL        int      `json:"ttl"`
	ChangeType string   `json:"changetype"`
	Records    []Record `json:"records"`
}

type Record struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

type patchBody struct {
	RRSets []RRSet `json:"rrsets"`
}

// SetARecords replaces all A records for a name with the given IPs.
func (c *PowerDNSClient) SetARecords(ctx context.Context, zone, name string, ips []string, ttl int) error {
	return c.patchRRSets(ctx, zone, []RRSet{replaceRRSet(ensureDot(name), "A", ips, ttl)})
}

// DeleteARecords removes all A records for a name.
func (c *PowerDNSClient) DeleteARecords(ctx context.Context, zone, name string) error {
	return c.patchRRSets(ctx, zone, []RRSet{deleteRRSet(ensureDot(name), "A")})
}

// SetTXTRecord creates or replaces a TXT record.
func (c *PowerDNSClient) SetTXTRecord(ctx context.Context, zone, name, value string, ttl int) error {
	rrset := RRSet{
		Name:       ensureDot(name),
		Type:       "TXT",
		TTL:        ttl,
		ChangeType: "REPLACE",
		Records:    []Record{{Content: fmt.Sprintf("%q", value), Disabled: false}},
	}
	return c.patchRRSets(ctx, zone, []RRSet{rrset})
}

// DeleteTXTRecord removes a TXT record.
func (c *PowerDNSClient) DeleteTXTRecord(ctx context.Context, zone, name string) error {
	return c.patchRRSets(ctx, zone, []RRSet{deleteRRSet(ensureDot(name), "TXT")})
}

// SetRelayRecords atomically replaces A and AAAA records for the relay hostname.
// Empty slices cause the corresponding record type to be deleted.
func (c *PowerDNSClient) SetRelayRecords(ctx context.Context, zone, name string, ipv4, ipv6 []string, ttl int) error {
	fqdn := ensureDot(name)
	return c.patchRRSets(ctx, zone, []RRSet{
		rrsetForIPs(fqdn, "A", ipv4, ttl),
		rrsetForIPs(fqdn, "AAAA", ipv6, ttl),
	})
}

// rrsetForIPs returns a REPLACE RRSet if ips is non-empty, otherwise a DELETE RRSet.
func rrsetForIPs(fqdn, rrType string, ips []string, ttl int) RRSet {
	if len(ips) > 0 {
		return replaceRRSet(fqdn, rrType, ips, ttl)
	}
	return deleteRRSet(fqdn, rrType)
}

func replaceRRSet(fqdn, rrType string, values []string, ttl int) RRSet {
	records := make([]Record, len(values))
	for i, v := range values {
		records[i] = Record{Content: v, Disabled: false}
	}
	return RRSet{
		Name:       fqdn,
		Type:       rrType,
		TTL:        ttl,
		ChangeType: "REPLACE",
		Records:    records,
	}
}

func deleteRRSet(fqdn, rrType string) RRSet {
	return RRSet{
		Name:       fqdn,
		Type:       rrType,
		ChangeType: "DELETE",
	}
}

// Healthy checks if the PowerDNS API is reachable.
func (c *PowerDNSClient) Healthy(ctx context.Context) error {
	url := fmt.Sprintf("%s/api/v1/servers/%s", c.apiURL, c.serverID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("X-API-Key", c.apiKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("powerdns api request: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("powerdns api returned status %d", resp.StatusCode)
	}
	return nil
}

func (c *PowerDNSClient) patchRRSets(ctx context.Context, zone string, rrsets []RRSet) error {
	body := patchBody{RRSets: rrsets}
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal rrsets: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/servers/%s/zones/%s", c.apiURL, c.serverID, zone)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("X-API-Key", c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("powerdns api request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		c.logger.Error("powerdns api error",
			"status", resp.StatusCode,
			"body", string(respBody),
			"zone", zone,
		)
		return fmt.Errorf("powerdns api returned status %d: %s", resp.StatusCode, string(respBody))
	}

	io.Copy(io.Discard, resp.Body)
	return nil
}

// GetZone checks if a zone exists in PowerDNS. Returns true if it exists.
func (c *PowerDNSClient) GetZone(ctx context.Context, zone string) (bool, error) {
	url := fmt.Sprintf("%s/api/v1/servers/%s/zones/%s", c.apiURL, c.serverID, zone)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("X-API-Key", c.apiKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("powerdns api request: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("powerdns api returned status %d", resp.StatusCode)
	}
	return true, nil
}

type createZoneRequest struct {
	Name        string   `json:"name"`
	Kind        string   `json:"kind"`
	Nameservers []string `json:"nameservers"`
	RRSets      []RRSet  `json:"rrsets"`
}

// CreateZone creates a new zone with SOA, NS, and wildcard CNAME records.
// primaryNS is the SOA MNAME (the zone master / hidden primary).
// nameservers are the NS records that resolvers use (may differ from primaryNS in hidden-primary mode).
// Returns nil if the zone already exists (409 Conflict).
func (c *PowerDNSClient) CreateZone(ctx context.Context, zone, baseDomain, primaryNS string, nameservers []string, relayHostname string) error {
	if len(nameservers) == 0 {
		return fmt.Errorf("nameservers must not be empty")
	}

	// Map nameservers to dot-terminated form for NS records.
	dottedNS := make([]string, len(nameservers))
	for i, ns := range nameservers {
		dottedNS[i] = ensureDot(ns)
	}

	body := createZoneRequest{
		Name: zone,
		Kind: "Native",
		// Nameservers is the PowerDNS API parameter — kept empty so PowerDNS
		// does not auto-create NS records. We supply them explicitly via RRSets.
		Nameservers: []string{},
		RRSets: []RRSet{
			{
				Name: zone,
				Type: "SOA",
				TTL:  86400,
				Records: []Record{{
					Content: fmt.Sprintf("%s %s 1 10800 3600 604800 300", ensureDot(primaryNS), ensureDot("admin."+baseDomain)),
				}},
			},
			replaceRRSet(zone, "NS", dottedNS, 86400),
			{
				Name:    ensureDot(fmt.Sprintf("*.%s", baseDomain)),
				Type:    "CNAME",
				TTL:     300,
				Records: []Record{{Content: ensureDot(relayHostname)}},
			},
		},
	}

	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal zone: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/servers/%s/zones", c.apiURL, c.serverID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("X-API-Key", c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("powerdns api request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		io.Copy(io.Discard, resp.Body)
		return nil
	}
	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return fmt.Errorf("powerdns create zone returned status %d: %s", resp.StatusCode, string(respBody))
	}

	io.Copy(io.Discard, resp.Body)
	return nil
}

func ensureDot(name string) string {
	if len(name) > 0 && name[len(name)-1] != '.' {
		return name + "."
	}
	return name
}
