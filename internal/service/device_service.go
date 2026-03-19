package service

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/AtDexters-Lab/namek-server/internal/config"
	"github.com/AtDexters-Lab/namek-server/internal/model"
	"github.com/AtDexters-Lab/namek-server/internal/slug"
	"github.com/AtDexters-Lab/namek-server/internal/store"
	"github.com/AtDexters-Lab/namek-server/internal/tpm"
)

// ErrValidation is a typed error for validation failures safe to return to clients.
type ErrValidation struct {
	Message string
}

func (e *ErrValidation) Error() string { return e.Message }

var (
	ErrEnrollmentCapacity  = errors.New("enrollment capacity reached")
	ErrPendingNotFound     = errors.New("pending enrollment not found or expired")
	ErrSecretMismatch      = errors.New("credential secret mismatch")
	ErrDeviceAlreadyExists = errors.New("device with this EK already exists")
	ErrQuoteVerification   = errors.New("quote verification failed")

	// Lowercase alphanumeric only, 3-24 chars. Cross-namespace uniqueness
	// with slugs (16-char Crockford Base32) is enforced by IsLabelTaken.
	hostnameRegex = regexp.MustCompile(`^[a-z0-9]{3,24}$`)
)

type PendingEnrollment struct {
	EKPubKey         crypto.PublicKey
	AKPubKeyDER      []byte
	AKName           []byte
	ChallengeSecret  []byte
	IdentityClass    string
	EKFingerprint    string
	ClientIP         net.IP
	ExpiresAt        time.Time
	ExistingDeviceID *uuid.UUID // non-nil for re-enrollment of active devices
}

type DeviceService struct {
	deviceStore  *store.DeviceStore
	accountStore *store.AccountStore
	auditStore   *store.AuditStore
	pool         *pgxpool.Pool
	cfg          *config.Config
	logger       *slog.Logger

	reservedHostnames map[string]bool

	mu      sync.Mutex
	pending map[string]*PendingEnrollment // keyed by nonce
	ekIndex map[string]string             // ek_fingerprint -> nonce (for dedup)
}

func NewDeviceService(deviceStore *store.DeviceStore, accountStore *store.AccountStore, auditStore *store.AuditStore, pool *pgxpool.Pool, cfg *config.Config, logger *slog.Logger) *DeviceService {
	reserved := map[string]bool{
		"relay": true, "namek": true, "www": true, "mail": true,
		"admin": true, "api": true, "internal": true,
	}
	// Reserve labels derived from configured nameservers and publicHostname
	// that are subdomains of baseDomain (e.g. "ns1.example.com" with baseDomain "example.com" → "ns1").
	suffix := "." + cfg.DNS.BaseDomain
	fqdns := make([]string, len(cfg.DNS.Nameservers)+1)
	copy(fqdns, cfg.DNS.Nameservers)
	fqdns[len(fqdns)-1] = cfg.PublicHostname
	for _, fqdn := range fqdns {
		if strings.HasSuffix(fqdn, suffix) {
			label := strings.TrimSuffix(fqdn, suffix)
			if label != "" && !strings.Contains(label, ".") {
				reserved[strings.ToLower(label)] = true
			}
		}
	}

	svc := &DeviceService{
		deviceStore:       deviceStore,
		accountStore:      accountStore,
		auditStore:        auditStore,
		pool:              pool,
		cfg:               cfg,
		logger:            logger,
		reservedHostnames: reserved,
		pending:           make(map[string]*PendingEnrollment),
		ekIndex:           make(map[string]string),
	}
	return svc
}

type EnrollRequest struct {
	EKCertDER []byte
	AKParams  []byte
	ClientIP  net.IP
}

type EnrollResponse struct {
	Nonce         string `json:"nonce"`
	EncCredential []byte `json:"enc_credential"`
}

func (s *DeviceService) StartEnrollment(ctx context.Context, req EnrollRequest, verifier tpm.Verifier) (*EnrollResponse, error) {
	// Verify EK cert and classify
	identityClass, ekPubKey, err := verifier.VerifyEKCert(req.EKCertDER)
	if err != nil {
		return nil, fmt.Errorf("ek verification failed: %w", err)
	}

	ekFingerprint := verifier.EKFingerprint(req.EKCertDER)

	// Check for existing device with this EK.
	// Active devices can re-enroll (new AK replaces old); suspended/revoked are blocked.
	var existingDeviceID *uuid.UUID
	existing, err := s.deviceStore.GetByEKFingerprint(ctx, ekFingerprint)
	if err != nil && !errors.Is(err, store.ErrDeviceNotFound) {
		return nil, fmt.Errorf("check existing device: %w", err)
	}
	if existing != nil {
		if existing.Status != model.DeviceStatusActive {
			return nil, ErrDeviceAlreadyExists
		}
		existingDeviceID = &existing.ID
	}

	// Parse AK parameters
	akPubKeyDER, akName, err := verifier.ParseAKPublic(req.AKParams)
	if err != nil {
		return nil, fmt.Errorf("parse ak params: %w", err)
	}

	// Generate challenge secret
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generate challenge secret: %w", err)
	}

	// Make credential (encrypt secret for the TPM)
	encCredential, err := verifier.MakeCredential(ekPubKey, akName, secret)
	if err != nil {
		return nil, fmt.Errorf("make credential: %w", err)
	}

	// Generate nonce for this enrollment
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	nonce := fmt.Sprintf("%x", nonceBytes)

	// Store pending enrollment
	s.mu.Lock()
	defer s.mu.Unlock()

	// Evict old pending for same EK before checking capacity,
	// so legitimate re-enrollment retries are not blocked.
	if oldNonce, ok := s.ekIndex[ekFingerprint]; ok {
		delete(s.pending, oldNonce)
		delete(s.ekIndex, ekFingerprint)
	}

	if len(s.pending) >= s.cfg.Enrollment.MaxPending {
		return nil, ErrEnrollmentCapacity
	}

	pe := &PendingEnrollment{
		EKPubKey:         ekPubKey,
		AKPubKeyDER:      akPubKeyDER,
		AKName:           akName,
		ChallengeSecret:  secret,
		IdentityClass:    identityClass,
		EKFingerprint:    ekFingerprint,
		ClientIP:         req.ClientIP,
		ExpiresAt:        time.Now().Add(s.cfg.PendingEnrollmentTTL()),
		ExistingDeviceID: existingDeviceID,
	}

	s.pending[nonce] = pe
	s.ekIndex[ekFingerprint] = nonce

	s.logger.Info("enrollment started",
		"ek_fingerprint", ekFingerprint,
		"identity_class", identityClass,
		"client_ip", req.ClientIP,
	)

	return &EnrollResponse{
		Nonce:         nonce,
		EncCredential: encCredential,
	}, nil
}

type AttestRequest struct {
	Nonce    string
	Secret   []byte
	QuoteB64 string
	ClientIP net.IP
}

type AttestResponse struct {
	DeviceID       uuid.UUID `json:"device_id"`
	Hostname       string    `json:"hostname"`
	IdentityClass  string    `json:"identity_class"`
	NexusEndpoints []string  `json:"nexus_endpoints"`
	Reenrolled     bool      `json:"reenrolled,omitempty"`
}

func (s *DeviceService) CompleteEnrollment(ctx context.Context, req AttestRequest, verifier tpm.Verifier, nexusEndpoints []string) (*AttestResponse, error) {
	s.mu.Lock()
	pe, ok := s.pending[req.Nonce]
	if !ok {
		s.mu.Unlock()
		return nil, ErrPendingNotFound
	}

	if time.Now().After(pe.ExpiresAt) {
		delete(s.pending, req.Nonce)
		delete(s.ekIndex, pe.EKFingerprint)
		s.mu.Unlock()
		return nil, ErrPendingNotFound
	}

	// Remove from pending (consumed)
	delete(s.pending, req.Nonce)
	delete(s.ekIndex, pe.EKFingerprint)
	s.mu.Unlock()

	// Verify secret
	if !equalBytes(req.Secret, pe.ChallengeSecret) {
		return nil, ErrSecretMismatch
	}

	// Verify TPM quote
	if err := verifier.VerifyQuote(pe.AKPubKeyDER, req.Nonce, req.QuoteB64); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrQuoteVerification, err)
	}

	// Re-enrollment path: update AK on existing active device
	if pe.ExistingDeviceID != nil {
		device, err := s.deviceStore.GetByID(ctx, *pe.ExistingDeviceID)
		if err != nil {
			return nil, fmt.Errorf("get re-enrolled device: %w", err)
		}
		if device.Status != model.DeviceStatusActive {
			return nil, ErrDeviceAlreadyExists
		}
		if err := s.deviceStore.UpdateAKPublicKey(ctx, device.ID, pe.AKPubKeyDER); err != nil {
			return nil, fmt.Errorf("update ak: %w", err)
		}

		s.auditStore.LogAction(ctx, model.ActorTypeDevice, device.ID.String(),
			"device.reenrolled", "device", strPtr(device.ID.String()), nil, req.ClientIP)

		s.logger.Info("device re-enrolled",
			"device_id", device.ID,
			"hostname", device.Hostname,
		)

		return &AttestResponse{
			DeviceID:       device.ID,
			Hostname:       device.Hostname,
			IdentityClass:  device.IdentityClass,
			NexusEndpoints: nexusEndpoints,
			Reenrolled:     true,
		}, nil
	}

	// Fresh enrollment: generate slug, create account + device in a transaction
	deviceID := uuid.New()
	accountID := uuid.New()
	const maxSlugAttempts = 3

	account := &model.Account{ID: accountID}
	var device *model.Device
	for attempt := 0; attempt < maxSlugAttempts; attempt++ {
		candidate := slug.Generate()
		taken, err := s.deviceStore.IsLabelTaken(ctx, candidate)
		if err != nil {
			return nil, fmt.Errorf("check slug availability: %w", err)
		}
		if taken {
			continue
		}

		hostname := fmt.Sprintf("%s.%s", candidate, s.cfg.DNS.BaseDomain)
		device = &model.Device{
			ID:            deviceID,
			AccountID:     accountID,
			Slug:          candidate,
			Hostname:      hostname,
			IdentityClass: pe.IdentityClass,
			EKFingerprint: pe.EKFingerprint,
			AKPublicKey:   pe.AKPubKeyDER,
			IPAddress:     req.ClientIP,
			Status:        model.DeviceStatusActive,
		}

		if err := store.CreateDeviceWithAccount(ctx, s.pool, account, device); err != nil {
			if errors.Is(err, store.ErrDuplicateEK) {
				return nil, ErrDeviceAlreadyExists
			}
			if errors.Is(err, store.ErrDuplicateSlug) {
				device = nil // retry with new slug
				continue
			}
			return nil, fmt.Errorf("create device with account: %w", err)
		}
		break // success
	}
	if device == nil {
		return nil, fmt.Errorf("failed to generate unique slug after %d attempts", maxSlugAttempts)
	}

	s.auditStore.LogAction(ctx, model.ActorTypeDevice, deviceID.String(),
		"device.enrolled", "device", strPtr(deviceID.String()),
		map[string]string{"identity_class": pe.IdentityClass}, req.ClientIP)

	s.logger.Info("device enrolled",
		"device_id", deviceID,
		"hostname", device.Hostname,
		"slug", device.Slug,
		"identity_class", pe.IdentityClass,
	)

	return &AttestResponse{
		DeviceID:       deviceID,
		Hostname:       device.Hostname,
		IdentityClass:  pe.IdentityClass,
		NexusEndpoints: nexusEndpoints,
	}, nil
}

func (s *DeviceService) SetCustomHostname(ctx context.Context, deviceID uuid.UUID, hostname string) error {
	hostname = strings.ToLower(strings.TrimSpace(hostname))

	if !hostnameRegex.MatchString(hostname) {
		return &ErrValidation{Message: "invalid hostname: must be 3-24 lowercase alphanumeric characters"}
	}
	if s.reservedHostnames[hostname] {
		return &ErrValidation{Message: "hostname is reserved"}
	}

	device, err := s.deviceStore.GetByID(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("get device: %w", err)
	}

	// Idempotent: no-op if already set to this hostname
	if device.CustomHostname != nil && *device.CustomHostname == hostname {
		return nil
	}

	// Rate limit: reset counter if year rolled over
	currentYear := time.Now().UTC().Year()
	changeCount := device.HostnameChangesThisYear
	if device.HostnameYear != currentYear {
		changeCount = 0
	}

	if changeCount >= s.cfg.Hostname.MaxChangesPerYear {
		return &ErrValidation{Message: "hostname change limit reached for this year"}
	}

	if device.LastHostnameChangeAt != nil {
		cooldown := time.Duration(s.cfg.Hostname.CooldownDays) * 24 * time.Hour
		if time.Since(*device.LastHostnameChangeAt) < cooldown {
			return &ErrValidation{Message: "hostname change cooldown period has not elapsed"}
		}
	}

	// Check released hostname cooldown
	released, err := s.deviceStore.IsHostnameReleased(ctx, hostname, s.cfg.Hostname.ReleasedCooldownDays)
	if err != nil {
		return fmt.Errorf("check released hostname: %w", err)
	}
	if released {
		return &ErrValidation{Message: "hostname is in cooldown after being released"}
	}

	// Cross-namespace check: reject if hostname matches an existing slug
	taken, err := s.deviceStore.IsLabelTaken(ctx, hostname)
	if err != nil {
		return fmt.Errorf("check label taken: %w", err)
	}
	if taken {
		return &ErrValidation{Message: "hostname already taken"}
	}

	// Release previous custom hostname if set
	if device.CustomHostname != nil {
		if err := s.deviceStore.ReleaseHostname(ctx, *device.CustomHostname, deviceID); err != nil {
			return fmt.Errorf("release old hostname: %w", err)
		}
	}

	if err := s.deviceStore.SetCustomHostname(ctx, store.SetCustomHostnameParams{
		DeviceID:       deviceID,
		CustomHostname: hostname,
		ChangeCount:    changeCount + 1,
		HostnameYear:   currentYear,
	}); err != nil {
		if errors.Is(err, store.ErrDuplicateHostname) {
			return &ErrValidation{Message: "hostname already taken"}
		}
		return fmt.Errorf("set custom hostname: %w", err)
	}

	s.auditStore.LogAction(ctx, model.ActorTypeDevice, deviceID.String(),
		"device.hostname_changed", "device", strPtr(deviceID.String()),
		map[string]string{"custom_hostname": hostname}, nil)

	return nil
}

// CleanupPending removes expired pending enrollments.
func (s *DeviceService) CleanupPending() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	removed := 0
	for nonce, pe := range s.pending {
		if now.After(pe.ExpiresAt) {
			delete(s.pending, nonce)
			delete(s.ekIndex, pe.EKFingerprint)
			removed++
		}
	}

	if removed > 0 {
		s.logger.Debug("cleaned up pending enrollments", "removed", removed, "remaining", len(s.pending))
	}
}

func equalBytes(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

func strPtr(s string) *string {
	return &s
}
