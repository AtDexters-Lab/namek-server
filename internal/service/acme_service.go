package service

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
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

type ACMEService struct {
	acmeStore   *store.ACMEStore
	deviceStore *store.DeviceStore
	pdns        *dns.PowerDNSClient
	cfg         *config.Config
	logger      *slog.Logger
}

func NewACMEService(acmeStore *store.ACMEStore, deviceStore *store.DeviceStore, pdns *dns.PowerDNSClient, cfg *config.Config, logger *slog.Logger) *ACMEService {
	return &ACMEService{
		acmeStore:   acmeStore,
		deviceStore: deviceStore,
		pdns:        pdns,
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

	// Create uses ON CONFLICT upsert — challenge.ID may change to an existing row's ID.
	if err := s.acmeStore.Create(ctx, challenge); err != nil {
		return nil, fmt.Errorf("create challenge: %w", err)
	}

	// Set TXT record in PowerDNS
	if err := s.pdns.SetTXTRecord(ctx, s.cfg.DNS.Zone, fqdn, req.Digest, 300); err != nil {
		s.logger.Error("failed to set acme txt record",
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
		metrics.Get().ACME.DNSSetFailed.Add(1)
		return nil, fmt.Errorf("set dns txt record: %w", err)
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

	// Delete TXT record from PowerDNS
	if err := s.pdns.DeleteTXTRecord(ctx, s.cfg.DNS.Zone, challenge.FQDN); err != nil {
		s.logger.Error("failed to delete acme txt record",
			"fqdn", challenge.FQDN,
			"error", err,
		)
		// Continue to delete from DB even if DNS cleanup fails
	}

	if err := s.acmeStore.Delete(ctx, challengeID); err != nil {
		return err
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
		// Delete DNS first so a transient DNS failure preserves the DB row for retry.
		// If DNS succeeds but DB delete below fails, the next cycle will re-attempt
		// the DNS delete (idempotent in PowerDNS) then retry the DB delete.
		if err := s.pdns.DeleteTXTRecord(ctx, s.cfg.DNS.Zone, c.FQDN); err != nil {
			s.logger.Error("failed to cleanup acme txt record, will retry next cycle",
				"fqdn", c.FQDN,
				"error", err,
			)
			continue
		}

		if err := s.acmeStore.Delete(ctx, c.ID); err != nil {
			s.logger.Error("failed to delete expired acme challenge from db",
				"challenge_id", c.ID,
				"error", err,
			)
			continue
		}
		metrics.Get().ACME.ChallengesExpired.Add(1)
		cleaned++
	}

	if cleaned > 0 {
		s.logger.Info("cleaned up expired acme challenges", "count", cleaned)
	}
}
