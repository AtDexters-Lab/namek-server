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
	records := make([]Record, len(ips))
	for i, ip := range ips {
		records[i] = Record{Content: ip, Disabled: false}
	}

	rrset := RRSet{
		Name:       ensureDot(name),
		Type:       "A",
		TTL:        ttl,
		ChangeType: "REPLACE",
		Records:    records,
	}

	return c.patchRRSets(ctx, zone, []RRSet{rrset})
}

// DeleteARecords removes all A records for a name.
func (c *PowerDNSClient) DeleteARecords(ctx context.Context, zone, name string) error {
	rrset := RRSet{
		Name:       ensureDot(name),
		Type:       "A",
		ChangeType: "DELETE",
	}
	return c.patchRRSets(ctx, zone, []RRSet{rrset})
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
	rrset := RRSet{
		Name:       ensureDot(name),
		Type:       "TXT",
		ChangeType: "DELETE",
	}
	return c.patchRRSets(ctx, zone, []RRSet{rrset})
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

func ensureDot(name string) string {
	if len(name) > 0 && name[len(name)-1] != '.' {
		return name + "."
	}
	return name
}
