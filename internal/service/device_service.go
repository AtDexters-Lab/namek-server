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

	"github.com/AtDexters-Lab/namek-server/internal/config"
	"github.com/AtDexters-Lab/namek-server/internal/model"
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

	// Lowercase alphanumeric only, 3-24 chars. This also structurally prevents
	// collision with canonical hostnames (UUID format: 36 chars with hyphens),
	// since hyphens are disallowed and max length is well below UUID length.
	hostnameRegex    = regexp.MustCompile(`^[a-z0-9]{3,24}$`)
	reservedHostnames = map[string]bool{
		"relay": true, "namek": true, "www": true, "mail": true,
		"ns1": true, "ns2": true, "admin": true, "api": true,
		"internal": true,
	}
)

type PendingEnrollment struct {
	EKPubKey        crypto.PublicKey
	AKPubKeyDER     []byte
	AKName          []byte
	ChallengeSecret []byte
	IdentityClass   string
	EKFingerprint   string
	ClientIP        net.IP
	ExpiresAt       time.Time
}

type DeviceService struct {
	deviceStore *store.DeviceStore
	auditStore  *store.AuditStore
	cfg         *config.Config
	logger      *slog.Logger

	mu       sync.Mutex
	pending  map[string]*PendingEnrollment // keyed by nonce
	ekIndex  map[string]string             // ek_fingerprint -> nonce (for dedup)
}

func NewDeviceService(deviceStore *store.DeviceStore, auditStore *store.AuditStore, cfg *config.Config, logger *slog.Logger) *DeviceService {
	svc := &DeviceService{
		deviceStore: deviceStore,
		auditStore:  auditStore,
		cfg:         cfg,
		logger:      logger,
		pending:     make(map[string]*PendingEnrollment),
		ekIndex:     make(map[string]string),
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

	// Reject if any device (active, suspended, or revoked) already owns this EK.
	// EK fingerprints are globally unique — re-enrollment requires the old device
	// to be explicitly deleted first.
	_, err = s.deviceStore.GetByEKFingerprint(ctx, ekFingerprint)
	if err != nil && !errors.Is(err, store.ErrDeviceNotFound) {
		return nil, fmt.Errorf("check existing device: %w", err)
	}
	if err == nil {
		return nil, ErrDeviceAlreadyExists
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
		EKPubKey:        ekPubKey,
		AKPubKeyDER:     akPubKeyDER,
		AKName:          akName,
		ChallengeSecret: secret,
		IdentityClass:   identityClass,
		EKFingerprint:   ekFingerprint,
		ClientIP:        req.ClientIP,
		ExpiresAt:       time.Now().Add(s.cfg.PendingEnrollmentTTL()),
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

	// Create device
	deviceID := uuid.New()
	hostname := fmt.Sprintf("%s.%s", deviceID.String(), s.cfg.DNS.BaseDomain)

	device := &model.Device{
		ID:            deviceID,
		Hostname:      hostname,
		IdentityClass: pe.IdentityClass,
		EKFingerprint: pe.EKFingerprint,
		AKPublicKey:   pe.AKPubKeyDER,
		IPAddress:     req.ClientIP,
		Status:        model.DeviceStatusActive,
	}

	if err := s.deviceStore.Create(ctx, device); err != nil {
		if errors.Is(err, store.ErrDuplicateEK) {
			return nil, ErrDeviceAlreadyExists
		}
		return nil, fmt.Errorf("create device: %w", err)
	}

	s.auditStore.LogAction(ctx, model.ActorTypeDevice, deviceID.String(),
		"device.enrolled", "device", strPtr(deviceID.String()),
		map[string]string{"identity_class": pe.IdentityClass}, req.ClientIP)

	s.logger.Info("device enrolled",
		"device_id", deviceID,
		"hostname", hostname,
		"identity_class", pe.IdentityClass,
	)

	return &AttestResponse{
		DeviceID:       deviceID,
		Hostname:       hostname,
		IdentityClass:  pe.IdentityClass,
		NexusEndpoints: nexusEndpoints,
	}, nil
}

func (s *DeviceService) SetCustomHostname(ctx context.Context, deviceID uuid.UUID, hostname string) error {
	hostname = strings.ToLower(strings.TrimSpace(hostname))

	if !hostnameRegex.MatchString(hostname) {
		return &ErrValidation{Message: "invalid hostname: must be 3-24 lowercase alphanumeric characters"}
	}
	if reservedHostnames[hostname] {
		return &ErrValidation{Message: "hostname is reserved"}
	}

	if err := s.deviceStore.UpdateHostname(ctx, deviceID, hostname); err != nil {
		if errors.Is(err, store.ErrDuplicateHostname) {
			return &ErrValidation{Message: "hostname already taken"}
		}
		return fmt.Errorf("update hostname: %w", err)
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
