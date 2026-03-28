package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/AtDexters-Lab/namek-server/internal/config"
	"github.com/AtDexters-Lab/namek-server/internal/dns"
	"github.com/AtDexters-Lab/namek-server/internal/metrics"
	"github.com/AtDexters-Lab/namek-server/internal/model"
	"github.com/AtDexters-Lab/namek-server/internal/store"
)

type NexusService struct {
	nexusStore *store.NexusStore
	auditStore *store.AuditStore
	pdns       *dns.PowerDNSClient
	cfg        *config.Config
	logger     *slog.Logger
}

func NewNexusService(nexusStore *store.NexusStore, auditStore *store.AuditStore, pdns *dns.PowerDNSClient, cfg *config.Config, logger *slog.Logger) *NexusService {
	return &NexusService{
		nexusStore: nexusStore,
		auditStore: auditStore,
		pdns:       pdns,
		cfg:        cfg,
		logger:     logger,
	}
}

type RegisterNexusRequest struct {
	Hostname    string
	Region      *string
	BackendPort int
}

type RegisterNexusResponse struct {
	HeartbeatInterval int `json:"heartbeat_interval"`
}

func (s *NexusService) Register(ctx context.Context, req RegisterNexusRequest) (*RegisterNexusResponse, error) {
	// Resolve the hostname to get public IPs
	ips, err := net.DefaultResolver.LookupHost(ctx, req.Hostname)
	if err != nil {
		// Check if this is an existing Nexus (heartbeat with resolution failure)
		existing, getErr := s.nexusStore.GetByHostname(ctx, req.Hostname)
		if getErr != nil {
			return nil, fmt.Errorf("dns resolution failed for %s: %w", req.Hostname, err)
		}

		// Heartbeat with resolution failure: update last_seen but keep stale IPs
		s.logger.Warn("dns resolution failed for nexus, keeping stale IPs",
			"hostname", req.Hostname,
			"error", err,
		)

		wasInactive := existing.Status != model.NexusStatusActive
		existing.LastSeenAt = time.Now()
		existing.Status = model.NexusStatusActive
		existing.BackendPort = req.BackendPort
		existing.HeartbeatIntervalSeconds = s.cfg.Nexus.HeartbeatIntervalSeconds
		if req.Region != nil {
			existing.Region = req.Region
		}
		if err := s.nexusStore.Upsert(ctx, existing); err != nil {
			return nil, fmt.Errorf("update nexus instance: %w", err)
		}

		// Restore relay DNS and audit if this instance was previously inactive
		if wasInactive {
			if err := s.updateRelayDNS(ctx); err != nil {
				s.logger.Error("failed to update relay dns after nexus reactivation",
					"hostname", req.Hostname,
					"error", err,
				)
			}
			s.auditStore.LogAction(ctx, model.ActorTypeNexus, req.Hostname,
				"nexus.reactivated", "nexus_instance", strPtr(req.Hostname),
				map[string]any{"dns_resolution_failed": true, "backend_port": req.BackendPort}, nil)
			metrics.Get().Nexus.Reactivated.Add(1)
		}

		return &RegisterNexusResponse{
			HeartbeatInterval: s.cfg.Nexus.HeartbeatIntervalSeconds,
		}, nil
	}

	resolvedIPs := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if parsed := net.ParseIP(ip); parsed != nil {
			resolvedIPs = append(resolvedIPs, parsed)
		}
	}

	// Reuse existing ID for heartbeats, generate new only for first registration.
	// Preserve existing region if the request doesn't provide one.
	instanceID := uuid.New()
	region := req.Region
	existing, err := s.nexusStore.GetByHostname(ctx, req.Hostname)
	if err != nil && !errors.Is(err, store.ErrNexusNotFound) {
		return nil, fmt.Errorf("check existing nexus: %w", err)
	}
	if err == nil {
		instanceID = existing.ID
		if region == nil {
			region = existing.Region
		}
	}

	instance := &model.NexusInstance{
		ID:                       instanceID,
		Hostname:                 req.Hostname,
		ResolvedAddresses:        resolvedIPs,
		Region:                   region,
		BackendPort:              req.BackendPort,
		HeartbeatIntervalSeconds: s.cfg.Nexus.HeartbeatIntervalSeconds,
		Status:                   model.NexusStatusActive,
		LastSeenAt:               time.Now(),
	}

	if err := s.nexusStore.Upsert(ctx, instance); err != nil {
		return nil, fmt.Errorf("upsert nexus instance: %w", err)
	}

	// Update relay DNS (best-effort)
	if err := s.updateRelayDNS(ctx); err != nil {
		s.logger.Error("failed to update relay dns after nexus registration",
			"hostname", req.Hostname,
			"error", err,
		)
		// Don't fail the registration
	}

	s.auditStore.LogAction(ctx, model.ActorTypeNexus, req.Hostname,
		"nexus.registered", "nexus_instance", strPtr(req.Hostname),
		map[string]any{"resolved_ips": ips, "region": region, "backend_port": req.BackendPort}, nil)
	metrics.Get().Nexus.Registered.Add(1)

	s.logger.Info("nexus registered",
		"hostname", req.Hostname,
		"resolved_ips", ips,
		"backend_port", req.BackendPort,
	)

	return &RegisterNexusResponse{
		HeartbeatInterval: s.cfg.Nexus.HeartbeatIntervalSeconds,
	}, nil
}

// GetActiveEndpoints returns WebSocket URLs for all active Nexus instances.
func (s *NexusService) GetActiveEndpoints(ctx context.Context) ([]string, error) {
	instances, err := s.nexusStore.ListActive(ctx)
	if err != nil {
		return nil, err
	}

	endpoints := make([]string, 0, len(instances))
	for _, inst := range instances {
		if inst.BackendPort == 443 {
			endpoints = append(endpoints, fmt.Sprintf("wss://%s/connect", inst.Hostname))
		} else {
			endpoints = append(endpoints, fmt.Sprintf("wss://%s:%d/connect", inst.Hostname, inst.BackendPort))
		}
	}
	return endpoints, nil
}

// HealthCheckLoop periodically checks for inactive Nexus instances.
func (s *NexusService) HealthCheckLoop(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.HeartbeatInterval())
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.healthCheck(ctx)
		}
	}
}

func (s *NexusService) healthCheck(ctx context.Context) {
	thresholdSecs := s.cfg.Nexus.HeartbeatIntervalSeconds * s.cfg.Nexus.InactiveThresholdMultiplier

	// Mark stale instances as inactive
	inactiveIDs, err := s.nexusStore.MarkInactive(ctx, thresholdSecs)
	if err != nil {
		s.logger.Error("failed to mark inactive nexus instances", "error", err)
		return
	}

	if len(inactiveIDs) > 0 {
		s.logger.Info("marked nexus instances inactive", "count", len(inactiveIDs))

		for _, id := range inactiveIDs {
			s.auditStore.LogAction(ctx, model.ActorTypeSystem, "health_check",
				"nexus.inactive", "nexus_instance", strPtr(id.String()), nil, nil)
			metrics.Get().Nexus.MarkedInactive.Add(1)
		}

		// Update relay DNS
		if err := s.updateRelayDNS(ctx); err != nil {
			s.logger.Error("failed to update relay dns after marking inactive", "error", err)
		}
	}

	// Re-resolve active instances (refresh IPs)
	s.reResolveActive(ctx)
}

func (s *NexusService) reResolveActive(ctx context.Context) {
	instances, err := s.nexusStore.ListActive(ctx)
	if err != nil {
		s.logger.Error("failed to list active nexus for re-resolution", "error", err)
		return
	}

	changed := false
	for _, inst := range instances {
		ips, err := net.DefaultResolver.LookupHost(ctx, inst.Hostname)
		if err != nil {
			s.logger.Warn("dns re-resolution failed for nexus",
				"hostname", inst.Hostname,
				"error", err,
			)
			continue
		}

		newIPs := make([]net.IP, 0, len(ips))
		for _, ip := range ips {
			if parsed := net.ParseIP(ip); parsed != nil {
				newIPs = append(newIPs, parsed)
			}
		}

		if !ipsEqual(inst.ResolvedAddresses, newIPs) {
			if err := s.nexusStore.UpdateResolvedAddresses(ctx, inst.ID, newIPs); err != nil {
				s.logger.Error("failed to update resolved addresses", "hostname", inst.Hostname, "error", err)
				continue
			}
			changed = true
			s.logger.Info("nexus resolved addresses changed",
				"hostname", inst.Hostname,
				"old_ips", inst.ResolvedAddresses,
				"new_ips", newIPs,
			)
		}
	}

	if changed {
		if err := s.updateRelayDNS(ctx); err != nil {
			s.logger.Error("failed to update relay dns after re-resolution", "error", err)
		}
	}
}

func (s *NexusService) updateRelayDNS(ctx context.Context) error {
	instances, err := s.nexusStore.ListActive(ctx)
	if err != nil {
		return fmt.Errorf("list active instances: %w", err)
	}

	// Collect IPv4 and IPv6 separately, filtering non-routable addresses
	ipv4Set := make(map[string]bool)
	ipv6Set := make(map[string]bool)
	for _, inst := range instances {
		for _, ip := range inst.ResolvedAddresses {
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				ipv4Set[ip4.String()] = true
			} else {
				ipv6Set[ip.String()] = true
			}
		}
	}

	ipv4s := slices.Collect(maps.Keys(ipv4Set))
	ipv6s := slices.Collect(maps.Keys(ipv6Set))

	if len(ipv4s) == 0 && len(ipv6s) == 0 && len(instances) > 0 {
		s.logger.Warn("no IP addresses found for active nexus instances",
			"active_instances", len(instances))
	}

	return s.pdns.SetRelayRecords(ctx, s.cfg.DNS.Zone, s.cfg.DNS.RelayHostname, ipv4s, ipv6s, 60)
}

func ipsEqual(a []net.IP, b []net.IP) bool {
	if len(a) != len(b) {
		return false
	}
	aSet := make(map[string]bool, len(a))
	for _, ip := range a {
		aSet[ip.String()] = true
	}
	for _, ip := range b {
		if !aSet[ip.String()] {
			return false
		}
	}
	return true
}
