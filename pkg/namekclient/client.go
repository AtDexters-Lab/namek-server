package namekclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/AtDexters-Lab/namek-server/pkg/tpmdevice"
)

const maxResponseSize = 1 << 20 // 1 MB

// Client is an HTTP client for the namek server API.
type Client struct {
	baseURL    string
	httpClient *http.Client
	tpm        tpmdevice.Device
	deviceID   string
}

// Option configures a Client.
type Option func(*Client)

// WithInsecureSkipVerify disables TLS certificate verification.
// Must be applied after WithHTTPClient if both are used.
func WithInsecureSkipVerify() Option {
	return func(c *Client) {
		t, ok := c.httpClient.Transport.(*http.Transport)
		if !ok || t == nil {
			t = http.DefaultTransport.(*http.Transport).Clone()
		}
		if t.TLSClientConfig == nil {
			t.TLSClientConfig = &tls.Config{}
		}
		t.TLSClientConfig.InsecureSkipVerify = true
		c.httpClient.Transport = t
	}
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		c.httpClient = hc
	}
}

// WithDeviceID restores a previously-enrolled device ID, allowing the client
// to make authenticated requests without re-enrolling.
func WithDeviceID(id string) Option {
	return func(c *Client) {
		c.deviceID = id
	}
}

// New creates a namekclient that uses the given TPM device for attestation.
func New(baseURL string, tpm tpmdevice.Device, opts ...Option) *Client {
	c := &Client{
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		tpm:        tpm,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// DeviceID returns the current device ID, or empty if not yet enrolled.
func (c *Client) DeviceID() string {
	return c.deviceID
}

// Health calls GET /health.
func (c *Client) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/health", nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health: status %d", resp.StatusCode)
	}
	return nil
}

// Ready calls GET /ready.
func (c *Client) Ready(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/ready", nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ready: status %d", resp.StatusCode)
	}
	return nil
}

// enrollStartResponse matches the server's StartEnroll JSON response.
type enrollStartResponse struct {
	Nonce         string `json:"nonce"`
	EncCredential string `json:"enc_credential"`
}

// enrollCompleteResponse matches the server's CompleteEnroll JSON response.
type enrollCompleteResponse struct {
	DeviceID       string   `json:"device_id"`
	Hostname       string   `json:"hostname"`
	IdentityClass  string   `json:"identity_class"`
	NexusEndpoints []string `json:"nexus_endpoints"`
	Reenrolled     bool     `json:"reenrolled"`
}

// Enroll performs the 2-phase enrollment flow.
func (c *Client) Enroll(ctx context.Context) (*EnrollResult, error) {
	// Phase 1: Get EK cert and AK public
	ekCert, err := c.tpm.EKCertDER()
	if err != nil {
		return nil, fmt.Errorf("get ek cert: %w", err)
	}
	akPub, err := c.tpm.AKPublic()
	if err != nil {
		return nil, fmt.Errorf("get ak public: %w", err)
	}

	// POST /api/v1/devices/enroll
	enrollBody := map[string]string{
		"ek_cert":   base64.StdEncoding.EncodeToString(ekCert),
		"ak_params": base64.StdEncoding.EncodeToString(akPub),
	}
	var startResp enrollStartResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/devices/enroll", enrollBody, &startResp); err != nil {
		return nil, fmt.Errorf("start enroll: %w", err)
	}

	// Decrypt credential challenge
	encCredRaw, err := base64.StdEncoding.DecodeString(startResp.EncCredential)
	if err != nil {
		return nil, fmt.Errorf("decode enc_credential: %w", err)
	}
	secret, err := c.tpm.ActivateCredential(encCredRaw)
	if err != nil {
		return nil, fmt.Errorf("activate credential: %w", err)
	}

	// Generate quote over enrollment nonce
	quoteB64, err := c.tpm.Quote(startResp.Nonce)
	if err != nil {
		return nil, fmt.Errorf("generate quote: %w", err)
	}

	// POST /api/v1/devices/enroll/attest
	attestBody := map[string]string{
		"nonce":  startResp.Nonce,
		"secret": base64.StdEncoding.EncodeToString(secret),
		"quote":  quoteB64,
	}
	var completeResp enrollCompleteResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/devices/enroll/attest", attestBody, &completeResp); err != nil {
		return nil, fmt.Errorf("complete enroll: %w", err)
	}

	c.deviceID = completeResp.DeviceID

	return &EnrollResult{
		DeviceID:       completeResp.DeviceID,
		Hostname:       completeResp.Hostname,
		IdentityClass:  completeResp.IdentityClass,
		NexusEndpoints: completeResp.NexusEndpoints,
		Reenrolled:     completeResp.Reenrolled,
	}, nil
}

// GetDeviceInfo calls GET /api/v1/devices/me (authenticated).
func (c *Client) GetDeviceInfo(ctx context.Context) (*DeviceInfo, error) {
	var info DeviceInfo
	resp, err := c.doAuthenticated(ctx, http.MethodGet, "/api/v1/devices/me", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := decodeResponse(resp, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// SetHostname calls PATCH /api/v1/devices/me/hostname (authenticated).
func (c *Client) SetHostname(ctx context.Context, hostname string) error {
	body := map[string]string{"custom_hostname": hostname}
	resp, err := c.doAuthenticated(ctx, http.MethodPatch, "/api/v1/devices/me/hostname", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// RequestNexusToken calls POST /api/v1/tokens/nexus (authenticated).
func (c *Client) RequestNexusToken(ctx context.Context, stage int, sessionNonce string) (string, error) {
	body := map[string]any{
		"stage":         stage,
		"session_nonce": sessionNonce,
	}
	resp, err := c.doAuthenticated(ctx, http.MethodPost, "/api/v1/tokens/nexus", body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var result struct {
		Token string `json:"token"`
	}
	if err := decodeResponse(resp, &result); err != nil {
		return "", err
	}
	return result.Token, nil
}

// CreateACMEChallenge calls POST /api/v1/acme/challenges (authenticated).
func (c *Client) CreateACMEChallenge(ctx context.Context, digest string) (*ChallengeResult, error) {
	body := map[string]string{"digest": digest}
	resp, err := c.doAuthenticated(ctx, http.MethodPost, "/api/v1/acme/challenges", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result ChallengeResult
	if err := decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteACMEChallenge calls DELETE /api/v1/acme/challenges/:id (authenticated).
func (c *Client) DeleteACMEChallenge(ctx context.Context, id string) error {
	resp, err := c.doAuthenticated(ctx, http.MethodDelete, "/api/v1/acme/challenges/"+id, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// RegisterDomain calls POST /api/v1/domains (authenticated).
func (c *Client) RegisterDomain(ctx context.Context, domain string) (*DomainInfo, error) {
	body := map[string]string{"domain": domain}
	resp, err := c.doAuthenticated(ctx, http.MethodPost, "/api/v1/domains", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var info DomainInfo
	if err := decodeResponse(resp, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// VerifyDomain calls POST /api/v1/domains/:id/verify (authenticated).
func (c *Client) VerifyDomain(ctx context.Context, domainID string) (*DomainInfo, error) {
	resp, err := c.doAuthenticated(ctx, http.MethodPost, "/api/v1/domains/"+domainID+"/verify", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var info DomainInfo
	if err := decodeResponse(resp, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// AssignDomain calls POST /api/v1/domains/:id/assignments (authenticated).
func (c *Client) AssignDomain(ctx context.Context, domainID string, deviceIDs []string) ([]DomainAssignment, error) {
	body := map[string]any{"device_ids": deviceIDs}
	resp, err := c.doAuthenticated(ctx, http.MethodPost, "/api/v1/domains/"+domainID+"/assignments", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result struct {
		Assignments []DomainAssignment `json:"assignments"`
	}
	if err := decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return result.Assignments, nil
}

// UnassignDomain calls DELETE /api/v1/domains/:id/assignments/:device_id (authenticated).
func (c *Client) UnassignDomain(ctx context.Context, domainID, deviceID string) error {
	resp, err := c.doAuthenticated(ctx, http.MethodDelete, "/api/v1/domains/"+domainID+"/assignments/"+deviceID, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// DeleteDomain calls DELETE /api/v1/domains/:id (authenticated).
func (c *Client) DeleteDomain(ctx context.Context, domainID string) error {
	resp, err := c.doAuthenticated(ctx, http.MethodDelete, "/api/v1/domains/"+domainID, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// ListAssignments calls GET /api/v1/domains/:id/assignments (authenticated).
func (c *Client) ListAssignments(ctx context.Context, domainID string) ([]DomainAssignment, error) {
	resp, err := c.doAuthenticated(ctx, http.MethodGet, "/api/v1/domains/"+domainID+"/assignments", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result struct {
		Assignments []DomainAssignment `json:"assignments"`
	}
	if err := decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return result.Assignments, nil
}

// ListDomains calls GET /api/v1/domains (authenticated).
func (c *Client) ListDomains(ctx context.Context) ([]DomainInfo, error) {
	resp, err := c.doAuthenticated(ctx, http.MethodGet, "/api/v1/domains", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result struct {
		Domains []DomainInfo `json:"domains"`
	}
	if err := decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return result.Domains, nil
}

// VerifyToken calls POST /api/v1/tokens/verify (no auth).
func (c *Client) VerifyToken(ctx context.Context, token string) (*VerifyResult, error) {
	body := map[string]string{"token": token}
	var result VerifyResult
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/tokens/verify", body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// doAuthenticated performs an authenticated request with nonce + TPM quote.
func (c *Client) doAuthenticated(ctx context.Context, method, path string, body any) (*http.Response, error) {
	if c.deviceID == "" {
		return nil, fmt.Errorf("not enrolled: call Enroll first")
	}

	// 1. Fetch nonce
	var nonceResp struct {
		Nonce string `json:"nonce"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/nonce", nil, &nonceResp); err != nil {
		return nil, fmt.Errorf("get nonce: %w", err)
	}

	// 2. Generate TPM quote over nonce
	quoteB64, err := c.tpm.Quote(nonceResp.Nonce)
	if err != nil {
		return nil, fmt.Errorf("generate quote: %w", err)
	}

	// 3. Build request
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Device-ID", c.deviceID)
	req.Header.Set("X-Nonce", nonceResp.Nonce)
	req.Header.Set("X-TPM-Quote", quoteB64)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		return nil, readError(resp)
	}
	return resp, nil
}

// doJSON performs a simple JSON request/response cycle.
func (c *Client) doJSON(ctx context.Context, method, path string, body any, out any) error {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return readError(resp)
	}

	if out != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize)).Decode(out)
	}
	return nil
}

func decodeResponse(resp *http.Response, out any) error {
	if resp.StatusCode >= 400 {
		return readError(resp)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize)).Decode(out)
}

func readError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Errorf("server error %d: %s", resp.StatusCode, string(body))
}
