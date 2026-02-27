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
	"github.com/AtDexters-Lab/namek-server/internal/model"
	"github.com/AtDexters-Lab/namek-server/internal/store"
)

// base64url-encoded SHA-256 (43 chars without padding)
var acmeDigestRegex = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

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
}

type CreateChallengeResponse struct {
	ID   uuid.UUID `json:"id"`
	FQDN string    `json:"fqdn"`
}

func (s *ACMEService) CreateChallenge(ctx context.Context, req CreateChallengeRequest) (*CreateChallengeResponse, error) {
	if !acmeDigestRegex.MatchString(req.Digest) {
		return nil, &ErrValidation{Message: "invalid digest: must be base64url-encoded SHA-256 (43 characters)"}
	}

	device, err := s.deviceStore.GetByID(ctx, req.DeviceID)
	if err != nil {
		return nil, fmt.Errorf("get device: %w", err)
	}

	// Derive FQDN from device hostname
	// hostname is "uuid.basedomain" -> fqdn is "_acme-challenge.uuid.basedomain"
	fqdn := fmt.Sprintf("_acme-challenge.%s", device.Hostname)

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
		return nil, fmt.Errorf("set dns txt record: %w", err)
	}

	s.logger.Info("acme challenge created",
		"device_id", req.DeviceID,
		"fqdn", fqdn,
	)

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

	return s.acmeStore.Delete(ctx, challengeID)
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
		cleaned++
	}

	if cleaned > 0 {
		s.logger.Info("cleaned up expired acme challenges", "count", cleaned)
	}
}
