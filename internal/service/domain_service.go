package service

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/AtDexters-Lab/namek-server/internal/config"
	"github.com/AtDexters-Lab/namek-server/internal/dns"
	"github.com/AtDexters-Lab/namek-server/internal/model"
	"github.com/AtDexters-Lab/namek-server/internal/store"
)

type DomainService struct {
	domainStore *store.DomainStore
	deviceStore *store.DeviceStore
	auditStore  *store.AuditStore
	resolver    dns.CNAMEResolver
	cfg         *config.Config
	logger      *slog.Logger
}

func NewDomainService(
	domainStore *store.DomainStore,
	deviceStore *store.DeviceStore,
	auditStore *store.AuditStore,
	resolver dns.CNAMEResolver,
	cfg *config.Config,
	logger *slog.Logger,
) *DomainService {
	return &DomainService{
		domainStore: domainStore,
		deviceStore: deviceStore,
		auditStore:  auditStore,
		resolver:    resolver,
		cfg:         cfg,
		logger:      logger,
	}
}

func (s *DomainService) RegisterDomain(ctx context.Context, deviceID uuid.UUID, domain string) (*model.AccountDomain, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))

	if err := validateDomain(domain, s.cfg.DNS.BaseDomain); err != nil {
		return nil, err
	}

	device, err := s.deviceStore.GetByID(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("get device: %w", err)
	}

	count, err := s.domainStore.CountByAccountID(ctx, device.AccountID)
	if err != nil {
		return nil, fmt.Errorf("count domains: %w", err)
	}
	if count >= s.cfg.AliasDomain.MaxPerAccount {
		return nil, &ErrValidation{Message: "domain limit reached for this account"}
	}

	conflict, err := s.domainStore.HasConflictingDomain(ctx, device.AccountID, domain)
	if err != nil {
		return nil, fmt.Errorf("check conflicts: %w", err)
	}
	if conflict {
		return nil, &ErrValidation{Message: "domain conflicts with an existing domain under another account"}
	}

	expiresAt := time.Now().Add(s.cfg.PendingDomainExpiry())
	cnameTarget := fmt.Sprintf("%s.%s", device.Slug, s.cfg.DNS.BaseDomain)

	ad := &model.AccountDomain{
		ID:          uuid.New(),
		AccountID:   device.AccountID,
		Domain:      domain,
		CNAMETarget: cnameTarget,
		Status:      model.DomainStatusPending,
		ExpiresAt:   &expiresAt,
	}

	if err := s.domainStore.Create(ctx, ad); err != nil {
		return nil, err
	}

	s.auditStore.LogAction(ctx, model.ActorTypeDevice, deviceID.String(),
		"domain.register", "domain", strPtr(ad.ID.String()),
		map[string]string{"domain": domain, "account_id": device.AccountID.String()}, nil)

	return ad, nil
}

// getAccountDomain fetches a domain and verifies the requesting device belongs to the same account.
func (s *DomainService) getAccountDomain(ctx context.Context, deviceID uuid.UUID, domainID uuid.UUID) (*model.Device, *model.AccountDomain, error) {
	device, err := s.deviceStore.GetByID(ctx, deviceID)
	if err != nil {
		return nil, nil, fmt.Errorf("get device: %w", err)
	}

	ad, err := s.domainStore.GetByID(ctx, domainID)
	if err != nil {
		return nil, nil, err
	}

	if ad.AccountID != device.AccountID {
		return nil, nil, store.ErrDomainNotFound
	}

	return device, ad, nil
}

func (s *DomainService) VerifyDomain(ctx context.Context, deviceID uuid.UUID, domainID uuid.UUID) (*model.AccountDomain, error) {
	device, ad, err := s.getAccountDomain(ctx, deviceID, domainID)
	if err != nil {
		return nil, err
	}

	// Idempotent: already verified
	if ad.Status == model.DomainStatusVerified {
		return ad, nil
	}

	// Reject expired pending domains (cleanup loop may not have run yet)
	if ad.ExpiresAt != nil && time.Now().After(*ad.ExpiresAt) {
		return nil, &ErrValidation{Message: "domain registration has expired, please re-register"}
	}

	// Resolve CNAME
	verifyCtx, cancel := context.WithTimeout(ctx, s.cfg.VerificationTimeout())
	defer cancel()

	target, err := s.resolver.Resolve(verifyCtx, ad.Domain)
	if err != nil {
		s.auditStore.LogAction(ctx, model.ActorTypeDevice, deviceID.String(),
			"domain.verify_failed", "domain", strPtr(ad.ID.String()),
			map[string]string{"domain": ad.Domain, "error": err.Error()}, nil)
		return nil, &ErrValidation{Message: "CNAME verification failed"}
	}

	// Lowercase CNAME target (DNS is case-insensitive per RFC 1035)
	target = strings.ToLower(target)

	// Check CNAME target ends with .baseDomain
	baseDomain := s.cfg.DNS.BaseDomain
	if !strings.HasSuffix(target, "."+baseDomain) {
		s.auditStore.LogAction(ctx, model.ActorTypeDevice, deviceID.String(),
			"domain.verify_failed", "domain", strPtr(ad.ID.String()),
			map[string]string{"domain": ad.Domain, "error": "CNAME does not point to baseDomain"}, nil)
		return nil, &ErrValidation{Message: "CNAME target must point to a subdomain of " + baseDomain}
	}

	// Extract slug label from CNAME target
	slugLabel := strings.TrimSuffix(target, "."+baseDomain)
	if strings.Contains(slugLabel, ".") {
		return nil, &ErrValidation{Message: "CNAME target has unexpected format"}
	}

	// Verify slug belongs to a device in the same account
	slugDevice, err := s.deviceStore.GetBySlug(ctx, slugLabel)
	if err != nil {
		s.auditStore.LogAction(ctx, model.ActorTypeDevice, deviceID.String(),
			"domain.verify_failed", "domain", strPtr(ad.ID.String()),
			map[string]string{"domain": ad.Domain, "error": "slug not found"}, nil)
		return nil, &ErrValidation{Message: "CNAME target slug not found"}
	}

	if slugDevice.AccountID != device.AccountID {
		s.auditStore.LogAction(ctx, model.ActorTypeDevice, deviceID.String(),
			"domain.verify_failed", "domain", strPtr(ad.ID.String()),
			map[string]string{"domain": ad.Domain, "error": "slug belongs to different account"}, nil)
		return nil, &ErrValidation{Message: "CNAME target slug does not belong to this account"}
	}

	if err := s.domainStore.UpdateVerified(ctx, domainID, deviceID); err != nil {
		return nil, fmt.Errorf("update verified: %w", err)
	}

	s.auditStore.LogAction(ctx, model.ActorTypeDevice, deviceID.String(),
		"domain.verify", "domain", strPtr(ad.ID.String()),
		map[string]string{"domain": ad.Domain, "cname_resolved": target}, nil)

	// Refresh from DB
	return s.domainStore.GetByID(ctx, domainID)
}

func (s *DomainService) DeleteDomain(ctx context.Context, deviceID uuid.UUID, domainID uuid.UUID) error {
	_, ad, err := s.getAccountDomain(ctx, deviceID, domainID)
	if err != nil {
		return err
	}

	if err := s.domainStore.Delete(ctx, domainID); err != nil {
		return err
	}

	s.auditStore.LogAction(ctx, model.ActorTypeDevice, deviceID.String(),
		"domain.delete", "domain", strPtr(ad.ID.String()),
		map[string]string{"domain": ad.Domain}, nil)

	return nil
}

func (s *DomainService) ListDomains(ctx context.Context, deviceID uuid.UUID) ([]*model.AccountDomain, error) {
	device, err := s.deviceStore.GetByID(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("get device: %w", err)
	}

	return s.domainStore.ListByAccountID(ctx, device.AccountID)
}

func (s *DomainService) AssignDomain(ctx context.Context, deviceID uuid.UUID, domainID uuid.UUID, targetDeviceIDs []uuid.UUID) ([]*model.DomainAssignment, error) {
	if len(targetDeviceIDs) == 0 {
		return nil, &ErrValidation{Message: "device_ids must not be empty"}
	}
	if len(targetDeviceIDs) > 100 {
		return nil, &ErrValidation{Message: "cannot assign more than 100 devices at once"}
	}

	device, ad, err := s.getAccountDomain(ctx, deviceID, domainID)
	if err != nil {
		return nil, err
	}

	if ad.Status != model.DomainStatusVerified {
		return nil, &ErrValidation{Message: "domain must be verified before assignment"}
	}

	ok, err := s.domainStore.AreDevicesInAccount(ctx, device.AccountID, targetDeviceIDs)
	if err != nil {
		return nil, fmt.Errorf("check devices in account: %w", err)
	}
	if !ok {
		return nil, &ErrValidation{Message: "one or more devices do not belong to this account"}
	}

	for _, tid := range targetDeviceIDs {
		if err := s.domainStore.AssignDevice(ctx, domainID, tid); err != nil {
			return nil, fmt.Errorf("assign device %s: %w", tid, err)
		}

		s.auditStore.LogAction(ctx, model.ActorTypeDevice, deviceID.String(),
			"domain.assign", "domain", strPtr(ad.ID.String()),
			map[string]string{"domain": ad.Domain, "target_device_id": tid.String()}, nil)
	}

	return s.domainStore.ListAssignments(ctx, domainID)
}

func (s *DomainService) UnassignDomain(ctx context.Context, deviceID uuid.UUID, domainID uuid.UUID, targetDeviceID uuid.UUID) error {
	_, ad, err := s.getAccountDomain(ctx, deviceID, domainID)
	if err != nil {
		return err
	}

	if err := s.domainStore.UnassignDevice(ctx, domainID, targetDeviceID); err != nil {
		return err
	}

	s.auditStore.LogAction(ctx, model.ActorTypeDevice, deviceID.String(),
		"domain.unassign", "domain", strPtr(ad.ID.String()),
		map[string]string{"domain": ad.Domain, "target_device_id": targetDeviceID.String()}, nil)

	return nil
}

func (s *DomainService) ListAssignments(ctx context.Context, deviceID uuid.UUID, domainID uuid.UUID) ([]*model.DomainAssignment, error) {
	_, _, err := s.getAccountDomain(ctx, deviceID, domainID)
	if err != nil {
		return nil, err
	}

	return s.domainStore.ListAssignments(ctx, domainID)
}

// GetDeviceAliasDomains returns verified alias domain strings for a device.
func (s *DomainService) GetDeviceAliasDomains(ctx context.Context, deviceID uuid.UUID) ([]string, error) {
	return s.domainStore.GetDeviceAliasDomains(ctx, deviceID)
}

// CleanupLoop removes expired pending domains.
func (s *DomainService) CleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			deleted, err := s.domainStore.DeleteExpiredPending(ctx)
			if err != nil {
				s.logger.Error("pending domain cleanup failed", "error", err)
			} else if deleted > 0 {
				s.logger.Info("cleaned up expired pending domains", "count", deleted)
			}
		}
	}
}

// validateDomain checks domain format per RFC 002 rules.
func validateDomain(domain, baseDomain string) error {
	if len(domain) == 0 || len(domain) > 253 {
		return &ErrValidation{Message: "domain must be 1-253 characters"}
	}

	// Reject IP addresses
	if net.ParseIP(domain) != nil {
		return &ErrValidation{Message: "IP addresses are not allowed as domains"}
	}

	labels := strings.Split(domain, ".")
	if len(labels) < 3 {
		return &ErrValidation{Message: "domain must have at least 3 labels (e.g., app.example.com)"}
	}

	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return &ErrValidation{Message: "each domain label must be 1-63 characters"}
		}
		for _, c := range label {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return &ErrValidation{Message: "domain labels must contain only lowercase letters, digits, and hyphens"}
			}
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return &ErrValidation{Message: "domain labels must not start or end with a hyphen"}
		}
	}

	// Reject baseDomain subdomains
	if strings.HasSuffix(domain, "."+baseDomain) || domain == baseDomain {
		return &ErrValidation{Message: "cannot register subdomains of " + baseDomain}
	}

	return nil
}
