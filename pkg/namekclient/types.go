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
	DeviceID       string   `json:"device_id"`
	Hostname       string   `json:"hostname"`
	CustomHostname *string  `json:"custom_hostname"`
	Status         string   `json:"status"`
	IdentityClass  string   `json:"identity_class"`
	NexusEndpoints []string `json:"nexus_endpoints"`
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
