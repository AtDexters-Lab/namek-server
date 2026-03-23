package namekclient

// EnrollResult is returned after successful enrollment.
type EnrollResult struct {
	DeviceID       string   `json:"device_id"`
	Hostname       string   `json:"hostname"`
	IdentityClass  string   `json:"identity_class"`
	NexusEndpoints []string `json:"nexus_endpoints"`
	Reenrolled     bool     `json:"reenrolled,omitempty"`
}

// DeviceInfo is returned from GET /devices/me.
type DeviceInfo struct {
	DeviceID               string                  `json:"device_id"`
	Hostname               string                  `json:"hostname"`
	CustomHostname         *string                 `json:"custom_hostname"`
	AccountID              string                  `json:"account_id"`
	Status                 string                  `json:"status"`
	IdentityClass          string                  `json:"identity_class"`
	RecoveryStatus         string                  `json:"recovery_status"`
	NexusEndpoints         []string                `json:"nexus_endpoints"`
	AliasDomains           []string                `json:"alias_domains,omitempty"`
	PendingVoucherRequests []PendingVoucherRequest `json:"pending_voucher_requests,omitempty"`
	NewVouchers            []VoucherArtifact       `json:"new_vouchers,omitempty"`
}

// InviteResult is returned from POST /accounts/invite.
type InviteResult struct {
	InviteCode string `json:"invite_code"`
	AccountID  string `json:"account_id"`
	ExpiresAt  string `json:"expires_at"`
}

// PendingVoucherRequest is a voucher that needs signing.
type PendingVoucherRequest struct {
	RequestID   string `json:"request_id"`
	VoucherData string `json:"voucher_data"`
	Nonce       string `json:"nonce"`
}

// VoucherArtifact is a signed voucher received from a peer.
type VoucherArtifact struct {
	Data           string `json:"data"`
	Quote          string `json:"quote"`
	IssuerAKPubKey string `json:"issuer_ak_public_key"`
	IssuerEKCert   string `json:"issuer_ek_cert,omitempty"`
}

// DomainInfo represents an alias domain registered with the namek server.
type DomainInfo struct {
	ID                 string   `json:"id"`
	AccountID          string   `json:"account_id"`
	Domain             string   `json:"domain"`
	Status             string   `json:"status"` // "pending" or "verified"
	CNAMETarget        string   `json:"cname_target"`
	AssignedDevices    []string `json:"assigned_devices,omitempty"`
	CreatedAt          string   `json:"created_at"`
	ExpiresAt          string   `json:"expires_at,omitempty"`
	VerifiedAt         string   `json:"verified_at,omitempty"`
	VerifiedByDeviceID string   `json:"verified_by_device_id,omitempty"`
}

// DomainAssignment represents a device-to-domain assignment.
type DomainAssignment struct {
	DeviceID  string `json:"device_id"`
	Domain    string `json:"domain"`
	CreatedAt string `json:"created_at"`
}

// ChallengeResult is returned from POST /acme/challenges.
type ChallengeResult struct {
	ID   string `json:"id"`
	FQDN string `json:"fqdn"`
}

// VerifyResult is returned from POST /tokens/verify.
type VerifyResult struct {
	Valid bool   `json:"valid"`
	Error string `json:"error,omitempty"`
}
