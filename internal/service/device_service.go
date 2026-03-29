package service

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
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
	"github.com/AtDexters-Lab/namek-server/internal/identity"
	"github.com/AtDexters-Lab/namek-server/internal/metrics"
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
	// with slugs (20-char Crockford Base32) is enforced by IsLabelTaken.
	hostnameRegex = regexp.MustCompile(`^[a-z0-9]{3,24}$`)
)

type PendingEnrollment struct {
	EKPubKey         crypto.PublicKey
	EKCertDER        []byte
	AKPubKeyDER      []byte
	AKName           []byte
	ChallengeSecret  []byte
	IdentityClass    string
	EKFingerprint    string
	EKVerifyResult   *tpm.EKVerifyResult
	ClientIP         net.IP
	ExpiresAt        time.Time
	ExistingDeviceID *uuid.UUID // non-nil for re-enrollment of active devices
}

// RecoveryProcessor handles recovery bundle processing and claim attribution.
type RecoveryProcessor interface {
	ValidateRecoveryBundle(bundle *RecoveryBundle) error
	ProcessRecoveryBundle(ctx context.Context, deviceID uuid.UUID, ekFingerprint string, bundle *RecoveryBundle) error
	AttributeClaimsForDevice(ctx context.Context, ekFingerprint string, akPublicKey []byte) error
}

type DeviceService struct {
	deviceStore       *store.DeviceStore
	accountStore      *store.AccountStore
	auditStore        *store.AuditStore
	censusStore       *store.CensusStore
	pool              *pgxpool.Pool
	cfg               *config.Config
	logger            *slog.Logger
	recoveryProcessor RecoveryProcessor

	reservedHostnames map[string]bool

	mu      sync.RWMutex
	pending map[string]*PendingEnrollment // keyed by nonce
	ekIndex map[string]string             // ek_fingerprint -> nonce (for dedup)
}

func NewDeviceService(deviceStore *store.DeviceStore, accountStore *store.AccountStore, auditStore *store.AuditStore, censusStore *store.CensusStore, pool *pgxpool.Pool, cfg *config.Config, logger *slog.Logger) *DeviceService {
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
		censusStore:       censusStore,
		pool:              pool,
		cfg:               cfg,
		logger:            logger,
		reservedHostnames: reserved,
		pending:           make(map[string]*PendingEnrollment),
		ekIndex:           make(map[string]string),
	}
	return svc
}

// PendingCount returns the number of pending enrollments.
func (s *DeviceService) PendingCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.pending)
}

// SetRecoveryProcessor sets the recovery processor for handling recovery bundles.
func (s *DeviceService) SetRecoveryProcessor(rp RecoveryProcessor) {
	s.recoveryProcessor = rp
}

type EnrollRequest struct {
	EKCertDER []byte // optional: DER-encoded EK certificate
	EKPubDER  []byte // optional: PKIX DER-encoded EK public key (fallback when no cert)
	AKParams  []byte
	ClientIP  net.IP
}

type EnrollResponse struct {
	Nonce         string `json:"nonce"`
	EncCredential []byte `json:"enc_credential"`
}

func (s *DeviceService) StartEnrollment(ctx context.Context, req EnrollRequest, verifier tpm.Verifier) (*EnrollResponse, error) {
	// Resolve EK identity: cert path (richer metadata) or pubkey-only path.
	var ekPubKey crypto.PublicKey
	var ekFingerprint string
	var identityClass string
	var ekVerifyResult *tpm.EKVerifyResult

	if len(req.EKCertDER) > 0 {
		// Cert path: verify against trusted CAs, extract pubkey and issuer metadata.
		ekResult, err := verifier.VerifyEKCert(req.EKCertDER)
		if err != nil {
			return nil, fmt.Errorf("ek verification failed: %w", err)
		}
		ekPubKey = ekResult.EKPubKey
		// Compute fingerprint from the already-extracted public key to avoid
		// re-parsing the cert. Uses the same PKIX DER hash as the pubkey-only path.
		pkixDER, err := x509.MarshalPKIXPublicKey(ekResult.EKPubKey)
		if err != nil {
			return nil, fmt.Errorf("marshal ek public key for fingerprint: %w", err)
		}
		ekFingerprint = verifier.EKPubFingerprint(pkixDER)
		identityClass = ekResult.IdentityClass
		ekVerifyResult = ekResult
	} else {
		// Pubkey-only path: no cert to verify, classify as unverified.
		pubKey, err := x509.ParsePKIXPublicKey(req.EKPubDER)
		if err != nil {
			s.logger.Warn("invalid ek public key", "error", err)
			return nil, &ErrValidation{Message: "invalid ek public key"}
		}
		rsaKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return nil, &ErrValidation{Message: "ek public key must be RSA"}
		}
		if rsaKey.N.BitLen() < 2048 {
			return nil, &ErrValidation{Message: "ek public key must be at least 2048 bits"}
		}
		ekPubKey = pubKey
		ekFingerprint = verifier.EKPubFingerprint(req.EKPubDER)
		identityClass = tpm.IdentityClassUnverified
		// ekVerifyResult stays nil — gates out census recording downstream
	}

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

	// Make credential (encrypt secret for the TPM — only needs the EK public key)
	encCredential, err := verifier.MakeCredential(ekPubKey, akName, secret)
	if err != nil {
		return nil, fmt.Errorf("make credential: %w", err)
	}

	// Generate nonce for this enrollment
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	nonce := hex.EncodeToString(nonceBytes)

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
		metrics.Get().Enroll.Phase1CapacityExceeded.Add(1)
		return nil, ErrEnrollmentCapacity
	}

	pe := &PendingEnrollment{
		EKPubKey:         ekPubKey,
		EKCertDER:        req.EKCertDER, // nil for pubkey-only enrollments
		AKPubKeyDER:      akPubKeyDER,
		AKName:           akName,
		ChallengeSecret:  secret,
		IdentityClass:    identityClass,
		EKFingerprint:    ekFingerprint,
		EKVerifyResult:   ekVerifyResult, // nil for pubkey-only enrollments
		ClientIP:         req.ClientIP,
		ExpiresAt:        time.Now().Add(s.cfg.PendingEnrollmentTTL()),
		ExistingDeviceID: existingDeviceID,
	}

	s.pending[nonce] = pe
	s.ekIndex[ekFingerprint] = nonce

	s.logger.Info("enrollment started",
		"ek_fingerprint", ekFingerprint,
		"identity_class", identityClass,
		"has_cert", len(req.EKCertDER) > 0,
		"client_ip", req.ClientIP,
	)

	metrics.Get().Enroll.Phase1Started.Add(1)
	return &EnrollResponse{
		Nonce:         nonce,
		EncCredential: encCredential,
	}, nil
}

type AttestRequest struct {
	Nonce          string
	Secret         []byte
	QuoteB64       string
	OSVersion      string
	PCRValues      map[int][]byte
	ClientIP       net.IP
	RecoveryBundle *RecoveryBundle // optional, for recovery enrollment
}

type AttestResponse struct {
	DeviceID       uuid.UUID `json:"device_id"`
	Hostname       string    `json:"hostname"`
	IdentityClass  string    `json:"identity_class"`
	TrustLevel     string    `json:"trust_level"`
	NexusEndpoints []string  `json:"nexus_endpoints"`
	Reenrolled     bool      `json:"reenrolled,omitempty"`
	// Recovery replay hints — returned when recovery_bundle was processed,
	// so the client knows what state to replay via separate API calls.
	ReplayCustomHostname string   `json:"replay_custom_hostname,omitempty"`
	ReplayAliasDomains   []string `json:"replay_alias_domains,omitempty"`
}

func (s *DeviceService) CompleteEnrollment(ctx context.Context, req AttestRequest, verifier tpm.Verifier, nexusEndpoints []string) (*AttestResponse, error) {
	s.mu.Lock()
	pe, ok := s.pending[req.Nonce]
	if !ok {
		s.mu.Unlock()
		metrics.Get().Enroll.Phase2Failed.Add(1)
		return nil, ErrPendingNotFound
	}

	if time.Now().After(pe.ExpiresAt) {
		delete(s.pending, req.Nonce)
		delete(s.ekIndex, pe.EKFingerprint)
		s.mu.Unlock()
		metrics.Get().Enroll.Phase2Failed.Add(1)
		return nil, ErrPendingNotFound
	}

	// Remove from pending (consumed)
	delete(s.pending, req.Nonce)
	delete(s.ekIndex, pe.EKFingerprint)
	s.mu.Unlock()

	// From here, any error return is a phase 2 failure (pending already consumed).
	// Success paths set phase2OK before incrementing their specific counter.
	var phase2OK bool
	defer func() {
		if !phase2OK {
			metrics.Get().Enroll.Phase2Failed.Add(1)
		}
	}()

	// Verify secret
	if !equalBytes(req.Secret, pe.ChallengeSecret) {
		return nil, ErrSecretMismatch
	}

	// Verify TPM quote (with PCR validation if provided)
	nonceBytes, err := hex.DecodeString(req.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	if _, err := verifier.VerifyQuote(pe.AKPubKeyDER, nonceBytes, req.QuoteB64, req.PCRValues); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrQuoteVerification, err)
	}

	// Resolve identity class (check for census-based promotion)
	identityClass := pe.IdentityClass
	if identityClass == tpm.IdentityClassUnverified && pe.EKVerifyResult != nil {
		issuer, err := s.censusStore.GetIssuerByFingerprint(ctx, pe.EKVerifyResult.IssuerFingerprint)
		if err == nil && issuer.Tier == model.IssuerTierCrowdCorroborated {
			identityClass = tpm.IdentityClassCrowdCorroborated
		}
	}

	// Prepare PCR values for storage
	pcrValuesJSON := EncodePCRValues(req.PCRValues)

	// Prepare issuer fingerprint and OS version pointers
	var issuerFP *string
	if pe.EKVerifyResult != nil && pe.EKVerifyResult.IssuerFingerprint != "" {
		issuerFP = &pe.EKVerifyResult.IssuerFingerprint
	}
	var osVersion *string
	if req.OSVersion != "" {
		osVersion = &req.OSVersion
	}

	// Compute trust level by querying PCR consensus
	pcrConsensus := s.computePCRConsensus(ctx, pcrValuesJSON, issuerFP, osVersion)
	trustLevel := ComputeTrustLevel(identityClass, pcrConsensus)

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
		// Update trust data on re-enrollment
		if err := s.deviceStore.UpdateTrustData(ctx, device.ID, identityClass, trustLevel, issuerFP, osVersion, pcrValuesJSON); err != nil {
			s.logger.Warn("update trust data on re-enrollment failed (non-blocking)", "device_id", device.ID, "error", err)
		}

		// Census observation recording (non-blocking, device already exists)
		s.recordCensusObservation(ctx, pe, req, identityClass)

		s.auditStore.LogAction(ctx, model.ActorTypeDevice, device.ID.String(),
			"device.reenrolled", "device", strPtr(device.ID.String()), nil, req.ClientIP)
		phase2OK = true
		metrics.Get().Enroll.Reenrolled.Add(1)

		s.logger.Info("device re-enrolled",
			"device_id", device.ID,
			"hostname", device.Hostname,
		)

		// Process recovery bundle on re-enrollment (RFC 004: a device that
		// initially enrolled without a bundle into a wrong solo account can
		// later re-enroll with a bundle to be reconciled into the correct account)
		if req.RecoveryBundle != nil && s.cfg.Recovery.IsEnabled() && s.recoveryProcessor != nil {
			if err := s.recoveryProcessor.ValidateRecoveryBundle(req.RecoveryBundle); err != nil {
				s.logger.Warn("invalid recovery bundle on re-enrollment", "device_id", device.ID, "error", err)
			} else {
				if err := s.recoveryProcessor.ProcessRecoveryBundle(ctx, device.ID, pe.EKFingerprint, req.RecoveryBundle); err != nil {
					s.logger.Warn("recovery bundle processing failed on re-enrollment (non-blocking)",
						"device_id", device.ID, "error", err)
				}
			}
		}
		// Attribute claims from this device's EK on re-enrollment
		if s.recoveryProcessor != nil {
			if err := s.recoveryProcessor.AttributeClaimsForDevice(ctx, pe.EKFingerprint, pe.AKPubKeyDER); err != nil {
				s.logger.Warn("claim attribution failed on re-enrollment (non-blocking)",
					"device_id", device.ID, "error", err)
			}
		}

		return &AttestResponse{
			DeviceID:       device.ID,
			Hostname:       device.Hostname,
			IdentityClass:  identityClass,
			TrustLevel:     string(trustLevel),
			NexusEndpoints: nexusEndpoints,
			Reenrolled:     true,
		}, nil
	}

	// Fresh enrollment: deterministic identity from EK fingerprint
	deviceID := identity.DeviceID(pe.EKFingerprint)

	candidate, err := slug.Derive(pe.EKFingerprint)
	if err != nil {
		return nil, fmt.Errorf("derive slug: %w", err)
	}

	// Determine account: recovery bundle overrides deterministic account ID
	var accountID uuid.UUID
	accountStatus := model.AccountStatusActive
	var recoveryDeadline *time.Time

	if req.RecoveryBundle != nil && s.cfg.Recovery.IsEnabled() {
		if s.recoveryProcessor != nil {
			if err := s.recoveryProcessor.ValidateRecoveryBundle(req.RecoveryBundle); err != nil {
				return nil, &ErrValidation{Message: fmt.Sprintf("invalid recovery bundle: %v", err)}
			}
		}
		parsedID, err := uuid.Parse(req.RecoveryBundle.AccountID)
		if err != nil {
			s.logger.Warn("invalid recovery bundle account_id, falling back to fresh enrollment",
				"error", err, "ek_fingerprint", pe.EKFingerprint)
			accountID = identity.AccountID(pe.EKFingerprint)
		} else {
			accountID = parsedID
			accountStatus = model.AccountStatusPendingRecovery
			deadline := time.Now().Add(s.cfg.QuorumTimeout())
			recoveryDeadline = &deadline
		}
	} else {
		accountID = identity.AccountID(pe.EKFingerprint)
	}

	hostname := fmt.Sprintf("%s.%s", candidate, s.cfg.DNS.BaseDomain)
	device := &model.Device{
		ID:                deviceID,
		AccountID:         accountID,
		Slug:              candidate,
		Hostname:          hostname,
		IdentityClass:     identityClass,
		EKFingerprint:     pe.EKFingerprint,
		EKCertDER:         pe.EKCertDER,
		AKPublicKey:       pe.AKPubKeyDER,
		IssuerFingerprint: issuerFP,
		OSVersion:         osVersion,
		PCRValues:         pcrValuesJSON,
		TrustLevel:        trustLevel,
		IPAddress:         req.ClientIP,
		Status:            model.DeviceStatusActive,
	}

	if accountStatus == model.AccountStatusPendingRecovery {
		// Recovery path: transactional account creation + device insertion
		account := &model.Account{
			ID:               accountID,
			Status:           accountStatus,
			MembershipEpoch:  1,
			RecoveryDeadline: recoveryDeadline,
		}
		if err := store.CreateDeviceWithRecoveryAccount(ctx, s.pool, account, device); err != nil {
			if errors.Is(err, store.ErrDuplicateEK) {
				return nil, ErrDeviceAlreadyExists
			}
			return nil, fmt.Errorf("create device with recovery account: %w", err)
		}
	} else {
		// Standard fresh enrollment
		account := &model.Account{
			ID:                    accountID,
			Status:                model.AccountStatusActive,
			MembershipEpoch:       1,
			FoundingEKFingerprint: pe.EKFingerprint,
		}
		if err := store.CreateDeviceWithAccount(ctx, s.pool, account, device); err != nil {
			if errors.Is(err, store.ErrDuplicateEK) {
				return nil, ErrDeviceAlreadyExists
			}
			return nil, fmt.Errorf("create device with account: %w", err)
		}
	}

	s.auditStore.LogAction(ctx, model.ActorTypeDevice, deviceID.String(),
		"device.enrolled", "device", strPtr(deviceID.String()),
		map[string]string{"identity_class": identityClass, "trust_level": string(trustLevel)}, req.ClientIP)
	phase2OK = true
	metrics.Get().Enroll.Phase2Completed.Add(1)

	s.logger.Info("device enrolled",
		"device_id", deviceID,
		"hostname", hostname,
		"slug", candidate,
		"identity_class", identityClass,
		"trust_level", trustLevel,
	)

	// Post-enrollment: census observation recording (non-blocking, device now exists)
	s.recordCensusObservation(ctx, pe, req, identityClass)

	// Post-enrollment: process recovery bundle (non-blocking)
	if req.RecoveryBundle != nil && s.cfg.Recovery.IsEnabled() && s.recoveryProcessor != nil {
		if err := s.recoveryProcessor.ProcessRecoveryBundle(ctx, deviceID, pe.EKFingerprint, req.RecoveryBundle); err != nil {
			s.logger.Warn("recovery bundle processing failed (non-blocking)",
				"device_id", deviceID, "error", err)
		}
	}

	// Post-enrollment: attribute existing claims from this device (non-blocking)
	if s.recoveryProcessor != nil {
		if err := s.recoveryProcessor.AttributeClaimsForDevice(ctx, pe.EKFingerprint, pe.AKPubKeyDER); err != nil {
			s.logger.Warn("claim attribution failed (non-blocking)",
				"device_id", deviceID, "error", err)
		}
	}

	resp := &AttestResponse{
		DeviceID:       deviceID,
		Hostname:       hostname,
		IdentityClass:  identityClass,
		TrustLevel:     string(trustLevel),
		NexusEndpoints: nexusEndpoints,
	}
	if req.RecoveryBundle != nil {
		resp.ReplayCustomHostname = req.RecoveryBundle.CustomHostname
		resp.ReplayAliasDomains = req.RecoveryBundle.AliasDomains
	}
	return resp, nil
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

// recordCensusObservation records census data after device creation.
// Non-blocking: failures are logged but do not affect enrollment.
func (s *DeviceService) recordCensusObservation(ctx context.Context, pe *PendingEnrollment, req AttestRequest, resolvedIdentityClass string) {
	if pe.EKVerifyResult == nil || pe.EKVerifyResult.IssuerFingerprint == "" {
		return
	}

	ekr := pe.EKVerifyResult

	// Upsert issuer census entry
	// Determine issuer tier and CA properties based on EK verification result
	issuerTier := model.IssuerTierUnverified
	if ekr.IdentityClass == tpm.IdentityClassVerified {
		issuerTier = model.IssuerTierSeed
	}

	census := &model.EKIssuerCensus{
		IssuerFingerprint:  ekr.IssuerFingerprint,
		IssuerSubject:      ekr.IssuerSubject,
		IssuerPublicKeyDER: ekr.IssuerPubKeyDER,
		Tier:               issuerTier,
	}
	// Only set CA properties when we actually have issuer cert data (verified path).
	// For unverified devices, leave nil so COALESCE preserves any existing values
	// from a prior verified enrollment of the same issuer.
	if ekr.IssuerPubKeyDER != nil {
		isCA := ekr.IssuerIsCA
		hasCertSign := ekr.IssuerHasCertSign
		census.IssuerIsCA = &isCA
		census.IssuerHasCertSign = &hasCertSign
	}
	if err := s.censusStore.UpsertIssuerCensus(ctx, census); err != nil {
		s.logger.Warn("census: upsert issuer failed (non-blocking)", "error", err)
		return // can't record observation without issuer row
	}

	// Compute and update structural compliance score
	if pe.EKCertDER != nil {
		cert, err := tpm.ParseEKCertForCompliance(pe.EKCertDER)
		if err == nil {
			score := tpm.ComputeStructuralCompliance(cert)
			if err := s.censusStore.UpdateStructuralComplianceScore(ctx, ekr.IssuerFingerprint, score); err != nil {
				s.logger.Warn("census: update compliance score failed", "error", err)
			}
		}
	}

	// Record observation (requires device to exist — called after device INSERT)
	deviceID := identity.DeviceID(pe.EKFingerprint)
	if pe.ExistingDeviceID != nil {
		deviceID = *pe.ExistingDeviceID
	}
	obs := &model.EKIssuerObservation{
		IssuerFingerprint: ekr.IssuerFingerprint,
		DeviceID:          deviceID,
		ClientIPSubnet:    ExtractSubnet(req.ClientIP),
	}
	if err := s.censusStore.UpsertObservation(ctx, obs); err != nil {
		s.logger.Warn("census: upsert observation failed (non-blocking)", "error", err)
	}

	// Upsert PCR census rows for Tier 1-2 devices with PCR values
	if req.PCRValues == nil || (resolvedIdentityClass != tpm.IdentityClassVerified && resolvedIdentityClass != tpm.IdentityClassCrowdCorroborated) {
		return
	}
	pcrJSON := EncodePCRValues(req.PCRValues)
	issuerFP := ekr.IssuerFingerprint
	var osVer *string
	if req.OSVersion != "" {
		osVer = &req.OSVersion
	}
	for _, group := range model.AllPCRGroups {
		groupKey := PCRGroupingKey(group, &issuerFP, osVer)
		if groupKey == "" {
			continue
		}
		hash := ComputePCRCompositeHash(pcrJSON, group)
		if hash == "" {
			continue
		}
		pcr := &model.PCRCensus{
			GroupingKey:      groupKey,
			PCRGroup:         group,
			PCRCompositeHash: hash,
			PCRValues:        pcrJSON,
			DeviceCount:      1,
		}
		if err := s.censusStore.UpsertPCRCensus(ctx, pcr); err != nil {
			s.logger.Warn("census: upsert pcr census failed", "group", group, "error", err)
		}
	}
}

// computePCRConsensus checks the device's PCR values against census majorities.
func (s *DeviceService) computePCRConsensus(ctx context.Context, pcrValues map[string]string, issuerFP *string, osVersion *string) model.PCRConsensusStatus {
	return EvaluatePCRConsensus(pcrValues, issuerFP, osVersion,
		func(gk string, group model.PCRGroup) (string, bool) {
			m, err := s.censusStore.GetPCRMajority(ctx, gk, group)
			if err != nil || m == nil {
				return "", false
			}
			return m.PCRCompositeHash, true
		})
}
