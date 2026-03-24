package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/AtDexters-Lab/namek-server/internal/config"
	"github.com/AtDexters-Lab/namek-server/internal/model"
	"github.com/AtDexters-Lab/namek-server/internal/store"
	"github.com/AtDexters-Lab/namek-server/internal/tpm"
)

const censusAdvisoryLockID int64 = 723003

type CensusService struct {
	censusStore *store.CensusStore
	deviceStore *store.DeviceStore
	auditStore  *store.AuditStore
	pool        *pgxpool.Pool
	cfg         *config.Config
	logger      *slog.Logger
}

func NewCensusService(censusStore *store.CensusStore, deviceStore *store.DeviceStore, auditStore *store.AuditStore, pool *pgxpool.Pool, cfg *config.Config, logger *slog.Logger) *CensusService {
	return &CensusService{
		censusStore: censusStore,
		deviceStore: deviceStore,
		auditStore:  auditStore,
		pool:        pool,
		cfg:         cfg,
		logger:      logger,
	}
}

// Run starts the periodic census analysis loop.
func (s *CensusService) Run(ctx context.Context) {
	interval := s.cfg.CensusAnalysisInterval()
	if interval <= 0 {
		s.logger.Info("census analysis disabled (interval is 0)")
		return
	}

	s.logger.Info("census analysis started", "interval", interval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("census analysis stopped")
			return
		case <-ticker.C:
			if err := s.Analyze(ctx); err != nil {
				s.logger.Error("census analysis failed", "error", err)
			}
		}
	}
}

// Analyze runs a single census analysis pass with advisory lock protection.
func (s *CensusService) Analyze(ctx context.Context) error {
	// Try to acquire advisory lock (non-blocking)
	var acquired bool
	err := s.pool.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, censusAdvisoryLockID).Scan(&acquired)
	if err != nil {
		return fmt.Errorf("acquire advisory lock: %w", err)
	}
	if !acquired {
		s.logger.Debug("census analysis skipped: another instance holds the lock")
		return nil
	}
	defer s.pool.Exec(ctx, `SELECT pg_advisory_unlock($1)`, censusAdvisoryLockID)

	s.logger.Info("census analysis started")
	start := time.Now()

	if err := s.recomputeIssuerCounts(ctx); err != nil {
		s.logger.Error("recompute issuer counts failed", "error", err)
	}
	if err := s.reEvaluateIssuerTiers(ctx); err != nil {
		s.logger.Error("issuer tier re-evaluation failed", "error", err)
	}
	if err := s.recalculatePCRMajorities(ctx); err != nil {
		s.logger.Error("PCR majority recalculation failed", "error", err)
	}
	if err := s.recomputeDeviceTrustLevels(ctx); err != nil {
		s.logger.Error("device trust level recomputation failed", "error", err)
	}

	s.logger.Info("census analysis completed", "duration_ms", time.Since(start).Milliseconds())
	return nil
}

func (s *CensusService) recomputeIssuerCounts(ctx context.Context) error {
	return s.censusStore.RecomputeAllIssuerCounts(ctx, s.cfg.FleetTrust.CensusActiveWindowDays)
}

func (s *CensusService) reEvaluateIssuerTiers(ctx context.Context) error {
	issuers, err := s.censusStore.GetUnverifiedIssuers(ctx)
	if err != nil {
		return fmt.Errorf("get unverified issuers: %w", err)
	}

	ftCfg := s.cfg.FleetTrust
	for _, issuer := range issuers {
		if issuer.Flagged {
			continue
		}

		// Pre-filter using already-computed counts to avoid N+1 aggregation queries
		if issuer.DeviceCount < ftCfg.CAPromotionMinDevices || issuer.DistinctSubnetCount < ftCfg.CAPromotionMinSubnets {
			continue
		}

		stats, err := s.censusStore.GetPromotionCandidateStats(ctx, issuer.IssuerFingerprint, ftCfg.CensusActiveWindowDays)
		if err != nil {
			s.logger.Warn("get promotion stats failed", "fingerprint", issuer.IssuerFingerprint, "error", err)
			continue
		}

		// Check all promotion criteria
		if stats.DeviceCount < ftCfg.CAPromotionMinDevices {
			continue
		}
		if stats.SpanDays < ftCfg.CAPromotionMinDays {
			continue
		}
		if stats.DistinctSubnets < ftCfg.CAPromotionMinSubnets {
			continue
		}
		if issuer.StructuralComplianceScore == nil || float64(*issuer.StructuralComplianceScore) < ftCfg.CAPromotionMinCompliance {
			continue
		}
		// Validate issuer CA properties when available (from a prior Tier 1 enrollment
		// of the same issuer). When unavailable (IssuerPublicKeyDER is nil), skip —
		// fleet observation criteria provide sufficient anti-Sybil protection.
		if issuer.IssuerPublicKeyDER != nil {
			if issuer.IssuerIsCA == nil || !*issuer.IssuerIsCA {
				continue
			}
			if issuer.IssuerHasCertSign == nil || !*issuer.IssuerHasCertSign {
				continue
			}
		}

		// Promote
		if err := s.censusStore.UpdateIssuerTier(ctx, issuer.IssuerFingerprint, model.IssuerTierCrowdCorroborated); err != nil {
			s.logger.Error("promote issuer failed", "fingerprint", issuer.IssuerFingerprint, "error", err)
			continue
		}

		s.auditStore.LogAction(ctx, model.ActorTypeSystem, "census",
			"issuer.promoted", "ek_issuer_census", &issuer.IssuerFingerprint,
			map[string]string{"tier": string(model.IssuerTierCrowdCorroborated)}, nil)

		s.logger.Info("issuer promoted to crowd_corroborated",
			"fingerprint", issuer.IssuerFingerprint,
			"device_count", stats.DeviceCount,
			"subnets", stats.DistinctSubnets,
		)

		// Cascade: upgrade identity_class for affected devices.
		// Trust level is recomputed by recomputeDeviceTrustLevels which runs next.
		tag, err := s.pool.Exec(ctx, `
			UPDATE devices SET identity_class = $1
			WHERE issuer_fingerprint = $2 AND identity_class = $3
		`, tpm.IdentityClassCrowdCorroborated,
			issuer.IssuerFingerprint, tpm.IdentityClassUnverifiedHW)
		if err != nil {
			s.logger.Error("cascade identity class failed", "fingerprint", issuer.IssuerFingerprint, "error", err)
		} else if tag.RowsAffected() > 0 {
			s.logger.Info("cascaded identity class upgrade", "fingerprint", issuer.IssuerFingerprint, "devices", tag.RowsAffected())
		}
	}

	return nil
}

func (s *CensusService) recalculatePCRMajorities(ctx context.Context) error {
	// Recompute device_count from authoritative devices table (Go-side hashing)
	devices, err := s.censusStore.GetPCRCensusEligibleDevices(ctx, s.cfg.FleetTrust.CensusActiveWindowDays)
	if err != nil {
		return fmt.Errorf("get pcr eligible devices: %w", err)
	}

	// Count devices per (grouping_key, pcr_group, composite_hash)
	type clusterKey struct {
		groupingKey, pcrGroup, compositeHash string
	}
	counts := make(map[clusterKey]int)
	for _, d := range devices {
		for _, group := range model.AllPCRGroups {
			gk := PCRGroupingKey(group, d.IssuerFingerprint, d.OSVersion)
			if gk == "" {
				continue
			}
			hash := ComputePCRCompositeHash(d.PCRValues, group)
			if hash == "" {
				continue
			}
			counts[clusterKey{gk, string(group), hash}]++
		}
	}

	// Reset all counts, then upsert recomputed values (creates new rows for promoted devices)
	if err := s.censusStore.ResetAllPCRCounts(ctx); err != nil {
		s.logger.Warn("reset pcr counts failed", "error", err)
	}
	for ck, count := range counts {
		pcr := &model.PCRCensus{
			GroupingKey:      ck.groupingKey,
			PCRGroup:         model.PCRGroup(ck.pcrGroup),
			PCRCompositeHash: ck.compositeHash,
			DeviceCount:      count,
		}
		if err := s.censusStore.UpsertPCRCensusWithCount(ctx, pcr); err != nil {
			s.logger.Warn("upsert pcr census count failed", "error", err)
		}
	}

	// Reset and recalculate majorities
	groups, err := s.censusStore.GetDistinctPCRGroups(ctx)
	if err != nil {
		return fmt.Errorf("get distinct pcr groups: %w", err)
	}

	for _, g := range groups {
		groupingKey := g[0]
		pcrGroup := model.PCRGroup(g[1])

		if err := s.censusStore.ResetPCRMajority(ctx, groupingKey, pcrGroup); err != nil {
			s.logger.Warn("reset pcr majority failed", "grouping_key", groupingKey, "pcr_group", pcrGroup, "error", err)
			continue
		}

		top, err := s.censusStore.GetTopPCRCluster(ctx, groupingKey, pcrGroup, s.cfg.FleetTrust.PCRMajorityMinPopulation)
		if err != nil {
			s.logger.Warn("get top pcr cluster failed", "grouping_key", groupingKey, "pcr_group", pcrGroup, "error", err)
			continue
		}
		if top == nil {
			continue
		}

		if err := s.censusStore.SetPCRMajority(ctx, top.ID); err != nil {
			s.logger.Warn("set pcr majority failed", "id", top.ID, "error", err)
		}
	}

	return nil
}

// recomputeDeviceTrustLevels recalculates trust_level for all non-overridden devices
// using the full trust matrix (identity_class × PCR consensus).
func (s *CensusService) recomputeDeviceTrustLevels(ctx context.Context) error {
	// Pre-fetch all PCR majorities to avoid N+1 queries during device iteration
	majorities, err := s.censusStore.GetAllPCRMajorities(ctx)
	if err != nil {
		return fmt.Errorf("pre-fetch pcr majorities: %w", err)
	}

	// Collect all non-overridden active devices (close rows before issuing updates)
	type deviceTrust struct {
		id            string
		identityClass string
		issuerFP      *string
		osVersion     *string
		pcrValuesJSON []byte
		trustLevel    string
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, identity_class, issuer_fingerprint, os_version, pcr_values, trust_level
		FROM devices WHERE status = 'active' AND trust_level_override IS NULL
	`)
	if err != nil {
		return fmt.Errorf("query active devices: %w", err)
	}

	var devices []deviceTrust
	for rows.Next() {
		var d deviceTrust
		if err := rows.Scan(&d.id, &d.identityClass, &d.issuerFP, &d.osVersion, &d.pcrValuesJSON, &d.trustLevel); err != nil {
			s.logger.Warn("scan device for trust recompute failed", "error", err)
			continue
		}
		devices = append(devices, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate devices: %w", err)
	}

	// Recompute trust for each device using pre-fetched majorities
	updated := 0
	for _, d := range devices {
		var pcrValues map[string]string
		if len(d.pcrValuesJSON) > 0 {
			if err := json.Unmarshal(d.pcrValuesJSON, &pcrValues); err != nil {
				s.logger.Warn("corrupt pcr_values JSON", "device_id", d.id, "error", err)
			}
		}

		pcrConsensus := EvaluatePCRConsensus(pcrValues, d.issuerFP, d.osVersion,
			func(gk string, group model.PCRGroup) (string, bool) {
				m, ok := majorities[model.PCRMajorityKey(gk, group)]
				if !ok {
					return "", false
				}
				return m.PCRCompositeHash, true
			})

		newTrust := string(ComputeTrustLevel(d.identityClass, pcrConsensus))
		if newTrust != d.trustLevel {
			if _, err := s.pool.Exec(ctx, `UPDATE devices SET trust_level = $1 WHERE id = $2 AND trust_level_override IS NULL`, newTrust, d.id); err != nil {
				s.logger.Warn("update device trust level failed", "device_id", d.id, "error", err)
			} else {
				updated++
			}
		}
	}

	if updated > 0 {
		s.logger.Info("recomputed device trust levels", "updated", updated)
	}
	return nil
}

// ComputeTrustLevel implements the trust matrix from RFC 003.
func ComputeTrustLevel(identityClass string, pcrConsensus model.PCRConsensusStatus) model.TrustLevel {
	switch identityClass {
	case tpm.IdentityClassVerified, tpm.IdentityClassCrowdCorroborated:
		switch pcrConsensus {
		case model.PCRConsensusMajority:
			return model.TrustLevelStrong
		case model.PCRConsensusOutlier:
			return model.TrustLevelSuspicious
		default:
			return model.TrustLevelStandard
		}
	case tpm.IdentityClassUnverifiedHW:
		switch pcrConsensus {
		case model.PCRConsensusOutlier:
			return model.TrustLevelQuarantine
		default:
			return model.TrustLevelProvisional
		}
	case tpm.IdentityClassSoftware:
		return model.TrustLevelSoftware
	default:
		return model.TrustLevelProvisional
	}
}

// EvaluatePCRConsensus determines PCR consensus for a device by checking its PCR values
// against majority data. The lookupMajority function returns (compositeHash, found) for a given key/group.
func EvaluatePCRConsensus(
	pcrValues map[string]string,
	issuerFP, osVersion *string,
	lookupMajority func(groupKey string, group model.PCRGroup) (string, bool),
) model.PCRConsensusStatus {
	if pcrValues == nil {
		return model.PCRConsensusUnknown
	}

	worst := model.PCRConsensusMajority
	checked := 0
	for _, group := range model.AllPCRGroups {
		gk := PCRGroupingKey(group, issuerFP, osVersion)
		if gk == "" {
			continue
		}
		hash := ComputePCRCompositeHash(pcrValues, group)
		if hash == "" {
			continue
		}
		majorityHash, found := lookupMajority(gk, group)
		if !found {
			if worst == model.PCRConsensusMajority {
				worst = model.PCRConsensusUnknown
			}
			continue
		}
		checked++
		if hash != majorityHash {
			worst = model.PCRConsensusOutlier
		}
	}
	if checked == 0 {
		return model.PCRConsensusUnknown
	}
	return worst
}

// EncodePCRValues converts raw PCR digests to hex-encoded strings for storage.
func EncodePCRValues(raw map[int][]byte) map[string]string {
	if raw == nil {
		return nil
	}
	encoded := make(map[string]string, len(raw))
	for idx, digest := range raw {
		encoded[strconv.Itoa(idx)] = hex.EncodeToString(digest)
	}
	return encoded
}

// PCRGroupingKey returns the census grouping key for a PCR group.
func PCRGroupingKey(group model.PCRGroup, issuerFP *string, osVersion *string) string {
	switch group {
	case model.PCRGroupFirmware:
		if issuerFP != nil {
			return *issuerFP
		}
	case model.PCRGroupBoot, model.PCRGroupOS:
		if osVersion != nil {
			return *osVersion
		}
	}
	return ""
}

// ComputePCRCompositeHash computes a deterministic hash for a set of PCR values within a group.
func ComputePCRCompositeHash(pcrValues map[string]string, group model.PCRGroup) string {
	registers, ok := model.PCRGroupRegisters[group]
	if !ok {
		return ""
	}

	// Collect values for registers in this group
	var parts []string
	for _, idx := range registers {
		key := strconv.Itoa(idx)
		if val, exists := pcrValues[key]; exists {
			parts = append(parts, fmt.Sprintf("%d:%s", idx, val))
		}
	}
	if len(parts) == 0 {
		return ""
	}

	sort.Strings(parts)
	composite := strings.Join(parts, "|")
	h := sha256.Sum256([]byte(composite))
	return hex.EncodeToString(h[:])
}

// ExtractSubnet extracts the /24 subnet string from an IP address.
func ExtractSubnet(ip net.IP) string {
	ip = ip.To4()
	if ip == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2])
}
