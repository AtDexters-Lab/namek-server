package namekclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/AtDexters-Lab/namek-server/pkg/tpmdevice"
)

const maxResponseSize = 1 << 20 // 1 MB

// Client is an HTTP client for the namek server API.
type Client struct {
	baseURL          string
	httpClient       *http.Client
	tpm              tpmdevice.Device
	deviceID         string
	retry            *retryConfig
	limiter          *clientLimiter    // optional; nil means no client-side rate limiting
	reconnectJitter  time.Duration     // max jitter before first request after failure; 0 = disabled
	degraded         atomic.Bool       // true after a request fails; cleared after jitter is applied
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

// WithRetry configures automatic retry with exponential backoff for retryable errors
// (429 Too Many Requests, 503 Service Unavailable). Respects Retry-After headers.
func WithRetry(maxAttempts int, baseDelay, maxDelay time.Duration) Option {
	return func(c *Client) {
		c.retry = &retryConfig{
			maxAttempts: maxAttempts,
			baseDelay:   baseDelay,
			maxDelay:    maxDelay,
			jitterFrac:  0.25,
		}
	}
}

// WithNoRetry disables automatic retry (useful for testing).
func WithNoRetry() Option {
	return func(c *Client) {
		c.retry = nil
	}
}

// WithRateLimit enables client-side rate limiting to prevent overwhelming the server.
// requestsPerSecond is the sustained rate, burst is the maximum concurrent burst.
func WithRateLimit(requestsPerSecond float64, burst int) Option {
	return func(c *Client) {
		c.limiter = newClientLimiter(requestsPerSecond, burst)
	}
}

// WithReconnectJitter sets the maximum random delay applied before the first
// request after a failure. This spreads the thundering herd when many clients
// recover simultaneously (e.g., after a server outage). Default: disabled.
func WithReconnectJitter(maxDelay time.Duration) Option {
	return func(c *Client) {
		if maxDelay > 0 {
			c.reconnectJitter = maxDelay
		}
	}
}

// New creates a namekclient that uses the given TPM device for attestation.
func New(baseURL string, tpm tpmdevice.Device, opts ...Option) *Client {
	rc := defaultRetry
	c := &Client{
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		tpm:        tpm,
		retry:      &rc,
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

// Health calls GET /health. Bypasses jitter and degraded tracking intentionally —
// health probes should not be delayed, and are typically used as readiness gates.
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

// Ready calls GET /ready. Bypasses jitter and degraded tracking (same rationale as Health).
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
	DeviceID       string              `json:"device_id"`
	Hostname       string              `json:"hostname"`
	IdentityClass  string              `json:"identity_class"`
	NexusEndpoints []string            `json:"nexus_endpoints"`
	RelayServices  map[string][]string `json:"relay_services,omitempty"`
	Reenrolled     bool                `json:"reenrolled"`
}

// enrollPhase1Result holds the outputs of the shared enrollment Phase 1 logic.
type enrollPhase1Result struct {
	nonce    string // hex-encoded nonce (echoed back to server)
	secret   []byte
	quoteB64 string
}

// enrollPhase1 performs the shared first phase of enrollment:
// EK/AK retrieval, start enroll POST, credential activation, and quote generation.
func (c *Client) enrollPhase1(ctx context.Context) (*enrollPhase1Result, error) {
	akPub, err := c.tpm.AKPublic()
	if err != nil {
		return nil, fmt.Errorf("get ak public: %w", err)
	}

	// Try EK cert first (richer metadata for trust classification).
	// Fall back to EK public key for TPMs without NVRAM-provisioned certs.
	enrollBody := map[string]string{
		"ak_params": base64.StdEncoding.EncodeToString(akPub),
	}
	ekCert, _ := c.tpm.EKCertDER()
	if ekCert != nil {
		enrollBody["ek_cert"] = base64.StdEncoding.EncodeToString(ekCert)
	} else {
		ekPub, err := c.tpm.EKPublicDER()
		if err != nil {
			return nil, fmt.Errorf("get ek identity: no cert or public key available: %w", err)
		}
		enrollBody["ek_pub"] = base64.StdEncoding.EncodeToString(ekPub)
	}
	var startResp enrollStartResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/devices/enroll", enrollBody, &startResp); err != nil {
		return nil, fmt.Errorf("start enroll: %w", err)
	}

	encCredRaw, err := base64.StdEncoding.DecodeString(startResp.EncCredential)
	if err != nil {
		return nil, fmt.Errorf("decode enc_credential: %w", err)
	}
	secret, err := c.tpm.ActivateCredential(encCredRaw)
	if err != nil {
		return nil, fmt.Errorf("activate credential: %w", err)
	}

	nonceBytes, err := hex.DecodeString(startResp.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode enrollment nonce: %w", err)
	}
	quoteB64, err := c.tpm.Quote(nonceBytes)
	if err != nil {
		return nil, fmt.Errorf("generate quote: %w", err)
	}

	return &enrollPhase1Result{
		nonce:    startResp.Nonce,
		secret:   secret,
		quoteB64: quoteB64,
	}, nil
}

// Enroll performs the 2-phase enrollment flow.
func (c *Client) Enroll(ctx context.Context) (*EnrollResult, error) {
	p1, err := c.enrollPhase1(ctx)
	if err != nil {
		return nil, err
	}

	attestBody := map[string]string{
		"nonce":  p1.nonce,
		"secret": base64.StdEncoding.EncodeToString(p1.secret),
		"quote":  p1.quoteB64,
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
		RelayServices:  completeResp.RelayServices,
		Reenrolled:     completeResp.Reenrolled,
	}, nil
}

// RecoveryBundleInput is the recovery bundle included in the attest request.
type RecoveryBundleInput struct {
	AccountID      string
	Vouchers       []VoucherArtifact
	CustomHostname string
	AliasDomains   []string
}

// EnrollWithRecovery performs the 2-phase enrollment flow with a recovery bundle.
func (c *Client) EnrollWithRecovery(ctx context.Context, bundle *RecoveryBundleInput) (*EnrollResult, error) {
	p1, err := c.enrollPhase1(ctx)
	if err != nil {
		return nil, err
	}

	attestBody := map[string]any{
		"nonce":  p1.nonce,
		"secret": base64.StdEncoding.EncodeToString(p1.secret),
		"quote":  p1.quoteB64,
	}

	if bundle != nil {
		vouchers := make([]map[string]string, 0, len(bundle.Vouchers))
		for _, v := range bundle.Vouchers {
			vp := map[string]string{
				"data":                v.Data,
				"quote":               v.Quote,
				"issuer_ak_public_key": v.IssuerAKPubKey,
			}
			if v.IssuerEKCert != "" {
				vp["issuer_ek_cert"] = v.IssuerEKCert
			}
			vouchers = append(vouchers, vp)
		}
		rb := map[string]any{
			"account_id": bundle.AccountID,
			"vouchers":   vouchers,
		}
		if bundle.CustomHostname != "" {
			rb["custom_hostname"] = bundle.CustomHostname
		}
		if len(bundle.AliasDomains) > 0 {
			rb["alias_domains"] = bundle.AliasDomains
		}
		attestBody["recovery_bundle"] = rb
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
		RelayServices:  completeResp.RelayServices,
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
// hostname is optional: if empty, the challenge targets the device's canonical hostname.
// To target a custom hostname, pass the full FQDN (e.g. "mydevice.example.com").
func (c *Client) CreateACMEChallenge(ctx context.Context, digest, hostname string) (*ChallengeResult, error) {
	body := map[string]string{"digest": digest}
	if hostname != "" {
		body["hostname"] = hostname
	}
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

// CreateInvite calls POST /api/v1/accounts/invite (authenticated).
func (c *Client) CreateInvite(ctx context.Context) (*InviteResult, error) {
	resp, err := c.doAuthenticated(ctx, http.MethodPost, "/api/v1/accounts/invite", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result InviteResult
	if err := decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// JoinAccount calls POST /api/v1/accounts/join (authenticated).
func (c *Client) JoinAccount(ctx context.Context, inviteCode string) error {
	body := map[string]string{"invite_code": inviteCode}
	resp, err := c.doAuthenticated(ctx, http.MethodPost, "/api/v1/accounts/join", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// LeaveAccount calls DELETE /api/v1/accounts/leave (authenticated).
func (c *Client) LeaveAccount(ctx context.Context) error {
	resp, err := c.doAuthenticated(ctx, http.MethodDelete, "/api/v1/accounts/leave", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// SignVoucher calls POST /api/v1/vouchers/sign (authenticated).
func (c *Client) SignVoucher(ctx context.Context, requestID, quoteB64 string) error {
	body := map[string]string{"request_id": requestID, "quote": quoteB64}
	resp, err := c.doAuthenticated(ctx, http.MethodPost, "/api/v1/vouchers/sign", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// GetVouchers calls GET /api/v1/vouchers (authenticated).
func (c *Client) GetVouchers(ctx context.Context) ([]VoucherArtifact, error) {
	resp, err := c.doAuthenticated(ctx, http.MethodGet, "/api/v1/vouchers", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result struct {
		Vouchers []VoucherArtifact `json:"vouchers"`
	}
	if err := decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return result.Vouchers, nil
}

// VerifyToken calls POST /internal/v1/tokens/verify (Nexus mTLS-authenticated).
func (c *Client) VerifyToken(ctx context.Context, token string) (*VerifyResult, error) {
	body := map[string]string{"token": token}
	var result VerifyResult
	if err := c.doJSON(ctx, http.MethodPost, "/internal/v1/tokens/verify", body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// applyReconnectJitter sleeps for a random duration if the client is recovering
// from a degraded state. Returns ctx.Err() if the context is cancelled during the wait.
func (c *Client) applyReconnectJitter(ctx context.Context) error {
	if c.reconnectJitter <= 0 || !c.degraded.CompareAndSwap(true, false) {
		return nil
	}
	jitter := time.Duration(rand.Int64N(int64(c.reconnectJitter)))
	timer := time.NewTimer(jitter)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		// Restore degraded state so the next attempt re-applies jitter
		c.degraded.Store(true)
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// markDegraded sets the client to degraded state after a failed request.
func (c *Client) markDegraded() {
	if c.reconnectJitter > 0 {
		c.degraded.Store(true)
	}
}

// doAuthenticated performs an authenticated request with nonce + TPM quote.
// The entire nonce-fetch + quote + request cycle is retried on retryable errors,
// since the nonce is consumed server-side.
func (c *Client) doAuthenticated(ctx context.Context, method, path string, body any) (*http.Response, error) {
	if c.deviceID == "" {
		return nil, fmt.Errorf("not enrolled: call Enroll first")
	}

	// Marshal body once outside the retry loop
	var bodyData []byte
	if body != nil {
		var err error
		bodyData, err = json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal body: %w", err)
		}
	}

	if err := c.applyReconnectJitter(ctx); err != nil {
		return nil, err
	}

	var resp *http.Response
	err := doWithRetry(ctx, c.retry, method, func() error {
		// Client-side rate limiting (nonce fetch goes through doJSONNoRetry
		// which also checks the limiter, but the authenticated request itself
		// must also be accounted for)
		if c.limiter != nil {
			if err := c.limiter.Wait(ctx); err != nil {
				return err
			}
		}

		// 1. Fetch nonce
		var nonceResp struct {
			Nonce string `json:"nonce"`
		}
		if err := c.doJSONNoRetry(ctx, http.MethodGet, "/api/v1/nonce", nil, &nonceResp); err != nil {
			return fmt.Errorf("get nonce: %w", err)
		}

		// 2. Generate TPM quote over nonce
		authNonceBytes, err := base64.RawURLEncoding.DecodeString(nonceResp.Nonce)
		if err != nil {
			return fmt.Errorf("decode auth nonce: %w", err)
		}
		quoteB64, err := c.tpm.Quote(authNonceBytes)
		if err != nil {
			return fmt.Errorf("generate quote: %w", err)
		}

		// 3. Build request
		var bodyReader io.Reader
		if bodyData != nil {
			bodyReader = bytes.NewReader(bodyData)
		}

		req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
		if err != nil {
			return err
		}
		if bodyData != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("X-Device-ID", c.deviceID)
		req.Header.Set("X-Nonce", nonceResp.Nonce)
		req.Header.Set("X-TPM-Quote", quoteB64)

		r, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}

		if r.StatusCode >= 400 {
			defer r.Body.Close()
			return parseError(r)
		}
		resp = r
		return nil
	})
	if err != nil {
		c.markDegraded()
	}
	return resp, err
}

// doJSON performs a simple JSON request/response cycle with retry.
func (c *Client) doJSON(ctx context.Context, method, path string, body any, out any) error {
	if err := c.applyReconnectJitter(ctx); err != nil {
		return err
	}
	err := doWithRetry(ctx, c.retry, method, func() error {
		return c.doJSONNoRetry(ctx, method, path, body, out)
	})
	if err != nil {
		c.markDegraded()
	}
	return err
}

// doJSONNoRetry performs a single JSON request/response cycle without retry.
// Used internally by doAuthenticated which handles retry at a higher level.
func (c *Client) doJSONNoRetry(ctx context.Context, method, path string, body any, out any) error {
	if c.limiter != nil {
		if err := c.limiter.Wait(ctx); err != nil {
			return err
		}
	}

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
		return parseError(resp)
	}

	if out != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize)).Decode(out)
	}
	return nil
}

func decodeResponse(resp *http.Response, out any) error {
	if resp.StatusCode >= 400 {
		return parseError(resp)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize)).Decode(out)
}
