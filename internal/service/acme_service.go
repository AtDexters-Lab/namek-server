package service

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"regexp"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/AtDexters-Lab/namek-server/internal/config"
	"github.com/AtDexters-Lab/namek-server/internal/dns"
	"github.com/AtDexters-Lab/namek-server/internal/metrics"
	"github.com/AtDexters-Lab/namek-server/internal/model"
	"github.com/AtDexters-Lab/namek-server/internal/store"
)

// printable ASCII: space (0x20) through tilde (0x7E)
var printableASCIIRegex = regexp.MustCompile(`^[\x20-\x7E]+$`)

const challengeTTL = 1 * time.Hour
const fqdnLockStripes = 64

type ACMEService struct {
	acmeStore   *store.ACMEStore
	deviceStore *store.DeviceStore
	pdns        *dns.PowerDNSClient
	txtVerifier *dns.TXTVerifier
	cfg         *config.Config
	logger      *slog.Logger
	fqdnLocks   [fqdnLockStripes]sync.Mutex
}

// lockFQDN acquires a striped mutex for the given FQDN and returns an unlock function.
// Serializes DB-mutate + DNS-write sequences to prevent concurrent operations on the
// same FQDN from clobbering each other's TXT RRSets.
func (s *ACMEService) lockFQDN(fqdn string) func() {
	h := fnv.New32a()
	h.Write([]byte(fqdn))
	mu := &s.fqdnLocks[h.Sum32()%fqdnLockStripes]
	mu.Lock()
	return mu.Unlock
}

// syncTXTRecords rebuilds the TXT RRSet for an FQDN from all active challenges.
// Must be called under lockFQDN.
func (s *ACMEService) syncTXTRecords(ctx context.Context, fqdn string) error {
	digests, err := s.acmeStore.GetActiveDigestsByFQDN(ctx, fqdn)
	if err != nil {
		return fmt.Errorf("get active digests: %w", err)
	}
	if len(digests) == 0 {
		return s.pdns.DeleteTXTRecord(ctx, s.cfg.DNS.Zone, fqdn)
	}
	return s.pdns.SetTXTRecords(ctx, s.cfg.DNS.Zone, fqdn, digests, 300)
}

func NewACMEService(acmeStore *store.ACMEStore, deviceStore *store.DeviceStore, pdns *dns.PowerDNSClient, txtVerifier *dns.TXTVerifier, cfg *config.Config, logger *slog.Logger) *ACMEService {
	return &ACMEService{
		acmeStore:   acmeStore,
		deviceStore: deviceStore,
		pdns:        pdns,
		txtVerifier: txtVerifier,
		cfg:         cfg,
		logger:      logger,
	}
}

type CreateChallengeRequest struct {
	DeviceID uuid.UUID
	Digest   string
	Hostname string // optional: defaults to canonical hostname
}

type CreateChallengeResponse struct {
	ID   uuid.UUID `json:"id"`
	FQDN string    `json:"fqdn"`
}

func (s *ACMEService) CreateChallenge(ctx context.Context, req CreateChallengeRequest) (*CreateChallengeResponse, error) {
	if len(req.Digest) == 0 || len(req.Digest) > 512 {
		return nil, &ErrValidation{Message: "digest must be 1-512 characters"}
	}
	if !printableASCIIRegex.MatchString(req.Digest) {
		return nil, &ErrValidation{Message: "digest must contain only printable ASCII"}
	}

	device, err := s.deviceStore.GetByID(ctx, req.DeviceID)
	if err != nil {
		return nil, fmt.Errorf("get device: %w", err)
	}

	// Determine target hostname (default: canonical)
	targetHostname := device.Hostname
	if req.Hostname != "" {
		customFQDN := ""
		if device.CustomHostname != nil {
			customFQDN = fmt.Sprintf("%s.%s", *device.CustomHostname, s.cfg.DNS.BaseDomain)
		}
		if req.Hostname != device.Hostname && req.Hostname != customFQDN {
			return nil, &ErrValidation{Message: "hostname not authorized for this device"}
		}
		targetHostname = req.Hostname
	}
	fqdn := fmt.Sprintf("_acme-challenge.%s", targetHostname)

	originalID := uuid.New()
	challenge := &model.ACMEChallenge{
		ID:               originalID,
		DeviceID:         req.DeviceID,
		FQDN:             fqdn,
		KeyAuthorization: req.Digest,
		ExpiresAt:        time.Now().Add(challengeTTL),
	}

	// Serialize DB + DNS operations for this FQDN to prevent concurrent
	// multi-SAN challenges from clobbering each other's TXT RRSets.
	unlock := s.lockFQDN(fqdn)

	if err := s.acmeStore.Create(ctx, challenge); err != nil {
		unlock()
		return nil, fmt.Errorf("create challenge: %w", err)
	}

	// Rebuild the full TXT RRSet from all active challenges for this FQDN.
	if err := s.syncTXTRecords(ctx, fqdn); err != nil {
		s.logger.Error("failed to sync acme txt records",
			"fqdn", fqdn,
			"error", err,
		)
		// Only delete if this was a fresh insert (IDs match). On upsert of an
		// existing row, deleting would destroy the pre-existing challenge; the
		// cleanup loop will handle expiry instead.
		if challenge.ID == originalID {
			if delErr := s.acmeStore.Delete(ctx, challenge.ID); delErr != nil {
				s.logger.Error("failed to clean up acme challenge after dns failure",
					"challenge_id", challenge.ID,
					"error", delErr,
				)
			}
		}
		unlock()
		metrics.Get().ACME.DNSSetFailed.Add(1)
		return nil, fmt.Errorf("sync dns txt records: %w", err)
	}

	unlock()

	// Write-back verification (outside lock — read-only, no race concern).
	if verifyErr := s.txtVerifier.VerifyTXT(ctx, fqdn, req.Digest); verifyErr != nil {
		if ctx.Err() != nil {
			s.logger.Debug("acme txt verification skipped: context cancelled", "fqdn", fqdn)
		} else {
			var mismatch *dns.ErrTXTMismatch
			if errors.As(verifyErr, &mismatch) {
				s.logger.Error("acme txt write-back mismatch",
					"fqdn", fqdn,
					"expected", req.Digest,
					"actual", mismatch.Actual,
					"quoted_sent", fmt.Sprintf("%q", req.Digest),
				)
			} else {
				s.logger.Warn("acme txt write-back verification failed",
					"fqdn", fqdn,
					"error", verifyErr,
				)
			}
			metrics.Get().ACME.VerifyFailed.Add(1)
		}
	} else {
		metrics.Get().ACME.VerifyOK.Add(1)
	}

	s.logger.Info("acme challenge created",
		"device_id", req.DeviceID,
		"fqdn", fqdn,
	)

	metrics.Get().ACME.ChallengesCreated.Add(1)
	return &CreateChallengeResponse{
		ID:   challenge.ID,
		FQDN: fqdn,
	}, nil
}

func (s *ACMEService) DeleteChallenge(ctx context.Context, challengeID uuid.UUID, deviceID uuid.UUID) error {
	challenge, err := s.acmeStore.GetByID(ctx, challengeID)
	if err != nil {
		return err
	}

	// Verify ownership (return not-found to avoid leaking existence to other devices)
	if challenge.DeviceID != deviceID {
		return store.ErrChallengeNotFound
	}

	unlock := s.lockFQDN(challenge.FQDN)
	defer unlock()

	if err := s.acmeStore.Delete(ctx, challengeID); err != nil {
		return err
	}

	// Rebuild TXT RRSet with remaining digests, or delete if none remain.
	if err := s.syncTXTRecords(ctx, challenge.FQDN); err != nil {
		s.logger.Warn("failed to sync acme txt records after delete",
			"fqdn", challenge.FQDN,
			"error", err,
		)
		// Stale extra digest in DNS is benign — CA only checks expected digest is present.
	}

	metrics.Get().ACME.ChallengesDeleted.Add(1)
	return nil
}

// CleanupLoop removes expired ACME challenges.
func (s *ACMEService) CleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.cleanup(ctx)
		}
	}
}

func (s *ACMEService) cleanup(ctx context.Context) {
	expired, err := s.acmeStore.GetExpired(ctx)
	if err != nil {
		s.logger.Error("failed to get expired acme challenges", "error", err)
		return
	}

	cleaned := 0
	for _, c := range expired {
		if ctx.Err() != nil {
			return
		}
		if s.cleanupOne(ctx, c) {
			cleaned++
		}
	}

	if cleaned > 0 {
		s.logger.Info("cleaned up expired acme challenges", "count", cleaned)
	}
}

func (s *ACMEService) cleanupOne(ctx context.Context, c *model.ACMEChallenge) bool {
	unlock := s.lockFQDN(c.FQDN)
	defer unlock()

	if err := s.acmeStore.Delete(ctx, c.ID); err != nil {
		s.logger.Error("failed to delete expired acme challenge from db",
			"challenge_id", c.ID,
			"error", err,
		)
		return false
	}

	// Rebuild TXT RRSet with remaining non-expired digests, or delete if none.
	if err := s.syncTXTRecords(ctx, c.FQDN); err != nil {
		s.logger.Warn("failed to sync acme txt records during cleanup, will self-heal on next operation",
			"fqdn", c.FQDN,
			"error", err,
		)
	}

	metrics.Get().ACME.ChallengesExpired.Add(1)
	return true
}
