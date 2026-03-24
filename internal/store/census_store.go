package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/AtDexters-Lab/namek-server/internal/model"
)

var ErrIssuerNotFound = errors.New("issuer not found")

type CensusStore struct {
	pool *pgxpool.Pool
}

func NewCensusStore(pool *pgxpool.Pool) *CensusStore {
	return &CensusStore{pool: pool}
}

// UpsertIssuerCensus creates or updates an issuer census entry.
// On conflict, only last_seen_at is updated — device_count and distinct_subnet_count
// are recomputed by the background census service to prevent drift.
func (s *CensusStore) UpsertIssuerCensus(ctx context.Context, census *model.EKIssuerCensus) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO ek_issuer_census (issuer_fingerprint, issuer_subject, issuer_public_key_der, issuer_is_ca, issuer_has_certsign, tier)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (issuer_fingerprint) DO UPDATE SET
			last_seen_at = NOW(),
			issuer_public_key_der = COALESCE(EXCLUDED.issuer_public_key_der, ek_issuer_census.issuer_public_key_der),
			issuer_is_ca = COALESCE(EXCLUDED.issuer_is_ca, ek_issuer_census.issuer_is_ca),
			issuer_has_certsign = COALESCE(EXCLUDED.issuer_has_certsign, ek_issuer_census.issuer_has_certsign)
	`, census.IssuerFingerprint, census.IssuerSubject, census.IssuerPublicKeyDER,
		census.IssuerIsCA, census.IssuerHasCertSign, census.Tier)
	if err != nil {
		return fmt.Errorf("upsert issuer census: %w", err)
	}
	return nil
}

const issuerColumns = `id, issuer_fingerprint, issuer_subject, issuer_public_key_der,
	issuer_is_ca, issuer_has_certsign, device_count, distinct_subnet_count,
	structural_compliance_score, tier, first_seen_at, last_seen_at,
	flagged, flagged_reason, created_at`

func scanIssuerCensus(row pgx.Row) (*model.EKIssuerCensus, error) {
	c := &model.EKIssuerCensus{}
	err := row.Scan(&c.ID, &c.IssuerFingerprint, &c.IssuerSubject, &c.IssuerPublicKeyDER,
		&c.IssuerIsCA, &c.IssuerHasCertSign, &c.DeviceCount, &c.DistinctSubnetCount,
		&c.StructuralComplianceScore, &c.Tier, &c.FirstSeenAt, &c.LastSeenAt,
		&c.Flagged, &c.FlaggedReason, &c.CreatedAt)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (s *CensusStore) GetIssuerByFingerprint(ctx context.Context, fp string) (*model.EKIssuerCensus, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+issuerColumns+` FROM ek_issuer_census WHERE issuer_fingerprint = $1`, fp)
	c, err := scanIssuerCensus(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrIssuerNotFound
		}
		return nil, fmt.Errorf("get issuer by fingerprint: %w", err)
	}
	return c, nil
}

func (s *CensusStore) ListIssuers(ctx context.Context, tierFilter *string) ([]model.EKIssuerCensus, error) {
	query := `SELECT ` + issuerColumns + ` FROM ek_issuer_census`
	var args []any
	if tierFilter != nil {
		query += ` WHERE tier = $1`
		args = append(args, *tierFilter)
	}
	query += ` ORDER BY device_count DESC LIMIT 1000`

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list issuers: %w", err)
	}
	defer rows.Close()

	var result []model.EKIssuerCensus
	for rows.Next() {
		c, err := scanIssuerCensus(rows)
		if err != nil {
			return nil, fmt.Errorf("scan issuer: %w", err)
		}
		result = append(result, *c)
	}
	return result, rows.Err()
}

func (s *CensusStore) UpsertObservation(ctx context.Context, obs *model.EKIssuerObservation) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO ek_issuer_observations (issuer_fingerprint, device_id, client_ip_subnet)
		VALUES ($1, $2, $3)
		ON CONFLICT (issuer_fingerprint, device_id) DO UPDATE SET
			client_ip_subnet = EXCLUDED.client_ip_subnet,
			observed_at = NOW()
	`, obs.IssuerFingerprint, obs.DeviceID, obs.ClientIPSubnet)
	if err != nil {
		return fmt.Errorf("upsert observation: %w", err)
	}
	return nil
}

func (s *CensusStore) GetIssuerObservations(ctx context.Context, fp string) ([]model.EKIssuerObservation, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, issuer_fingerprint, device_id, client_ip_subnet, observed_at
		FROM ek_issuer_observations WHERE issuer_fingerprint = $1 ORDER BY observed_at DESC
	`, fp)
	if err != nil {
		return nil, fmt.Errorf("get observations: %w", err)
	}
	defer rows.Close()

	var result []model.EKIssuerObservation
	for rows.Next() {
		o := model.EKIssuerObservation{}
		if err := rows.Scan(&o.ID, &o.IssuerFingerprint, &o.DeviceID, &o.ClientIPSubnet, &o.ObservedAt); err != nil {
			return nil, fmt.Errorf("scan observation: %w", err)
		}
		result = append(result, o)
	}
	return result, rows.Err()
}

// PromotionCandidateStats holds aggregated stats for evaluating CA promotion criteria.
type PromotionCandidateStats struct {
	DeviceCount     int
	DistinctSubnets int
	SpanDays        int
}

func (s *CensusStore) GetPromotionCandidateStats(ctx context.Context, fp string, activeWindowDays int) (*PromotionCandidateStats, error) {
	stats := &PromotionCandidateStats{}
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT device_id),
		       COUNT(DISTINCT client_ip_subnet),
		       COALESCE(EXTRACT(DAY FROM MAX(observed_at) - MIN(observed_at))::INT, 0)
		FROM ek_issuer_observations
		WHERE issuer_fingerprint = $1
		  AND observed_at > NOW() - make_interval(days => $2)
	`, fp, activeWindowDays).Scan(&stats.DeviceCount, &stats.DistinctSubnets, &stats.SpanDays)
	if err != nil {
		return nil, fmt.Errorf("get promotion stats: %w", err)
	}
	return stats, nil
}

func (s *CensusStore) UpdateIssuerTier(ctx context.Context, fp string, tier model.IssuerTier) error {
	tag, err := s.pool.Exec(ctx, `UPDATE ek_issuer_census SET tier = $1 WHERE issuer_fingerprint = $2`, tier, fp)
	if err != nil {
		return fmt.Errorf("update issuer tier: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrIssuerNotFound
	}
	return nil
}

func (s *CensusStore) UpdateStructuralComplianceScore(ctx context.Context, fp string, score float32) error {
	_, err := s.pool.Exec(ctx, `UPDATE ek_issuer_census SET structural_compliance_score = $1 WHERE issuer_fingerprint = $2`, score, fp)
	if err != nil {
		return fmt.Errorf("update compliance score: %w", err)
	}
	return nil
}

func (s *CensusStore) FlagIssuer(ctx context.Context, fp string, reason string) error {
	_, err := s.pool.Exec(ctx, `UPDATE ek_issuer_census SET flagged = TRUE, flagged_reason = $1 WHERE issuer_fingerprint = $2`, reason, fp)
	if err != nil {
		return fmt.Errorf("flag issuer: %w", err)
	}
	return nil
}

func (s *CensusStore) UnflagIssuer(ctx context.Context, fp string) error {
	_, err := s.pool.Exec(ctx, `UPDATE ek_issuer_census SET flagged = FALSE, flagged_reason = NULL WHERE issuer_fingerprint = $1`, fp)
	if err != nil {
		return fmt.Errorf("unflag issuer: %w", err)
	}
	return nil
}

// RecomputeAllIssuerCounts batch-updates device_count and distinct_subnet_count for all issuers.
func (s *CensusStore) RecomputeAllIssuerCounts(ctx context.Context, activeWindowDays int) error {
	_, err := s.pool.Exec(ctx, `
		WITH stats AS (
			SELECT issuer_fingerprint,
			       COUNT(DISTINCT device_id) AS dc,
			       COUNT(DISTINCT client_ip_subnet) AS sc
			FROM ek_issuer_observations
			WHERE observed_at > NOW() - make_interval(days => $1)
			GROUP BY issuer_fingerprint
		)
		UPDATE ek_issuer_census c
		SET device_count = COALESCE(s.dc, 0),
		    distinct_subnet_count = COALESCE(s.sc, 0)
		FROM stats s
		WHERE c.issuer_fingerprint = s.issuer_fingerprint
	`, activeWindowDays)
	if err != nil {
		return fmt.Errorf("recompute all issuer counts: %w", err)
	}

	// Zero out counts for issuers with no recent observations
	_, err = s.pool.Exec(ctx, `
		UPDATE ek_issuer_census
		SET device_count = 0, distinct_subnet_count = 0
		WHERE issuer_fingerprint NOT IN (
			SELECT DISTINCT issuer_fingerprint FROM ek_issuer_observations
			WHERE observed_at > NOW() - make_interval(days => $1)
		) AND (device_count > 0 OR distinct_subnet_count > 0)
	`, activeWindowDays)
	if err != nil {
		return fmt.Errorf("zero stale issuer counts: %w", err)
	}

	return nil
}

func (s *CensusStore) GetUnverifiedIssuers(ctx context.Context) ([]model.EKIssuerCensus, error) {
	tier := string(model.IssuerTierUnverified)
	return s.ListIssuers(ctx, &tier)
}

func (s *CensusStore) GetCrowdCorroboratedIssuers(ctx context.Context) ([]model.EKIssuerCensus, error) {
	tier := string(model.IssuerTierCrowdCorroborated)
	return s.ListIssuers(ctx, &tier)
}

// UpsertPCRCensus creates or updates a PCR census entry.
func (s *CensusStore) UpsertPCRCensus(ctx context.Context, pcr *model.PCRCensus) error {
	pcrJSON, _ := json.Marshal(pcr.PCRValues)
	_, err := s.pool.Exec(ctx, `
		INSERT INTO pcr_census (grouping_key, pcr_group, pcr_composite_hash, pcr_values, device_count)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (grouping_key, pcr_group, pcr_composite_hash) DO UPDATE SET
			last_seen_at = NOW()
	`, pcr.GroupingKey, pcr.PCRGroup, pcr.PCRCompositeHash, pcrJSON, pcr.DeviceCount)
	if err != nil {
		return fmt.Errorf("upsert pcr census: %w", err)
	}
	return nil
}

func (s *CensusStore) GetPCRMajority(ctx context.Context, groupingKey string, pcrGroup model.PCRGroup) (*model.PCRCensus, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, grouping_key, pcr_group, pcr_composite_hash, pcr_values, device_count, is_majority, first_seen_at, last_seen_at
		FROM pcr_census WHERE grouping_key = $1 AND pcr_group = $2 AND is_majority = TRUE
	`, groupingKey, pcrGroup)
	return scanPCRCensus(row)
}

func (s *CensusStore) ResetPCRMajority(ctx context.Context, groupingKey string, pcrGroup model.PCRGroup) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE pcr_census SET is_majority = FALSE
		WHERE grouping_key = $1 AND pcr_group = $2
	`, groupingKey, pcrGroup)
	if err != nil {
		return fmt.Errorf("reset pcr majority: %w", err)
	}
	return nil
}

func (s *CensusStore) SetPCRMajority(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `UPDATE pcr_census SET is_majority = TRUE WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("set pcr majority: %w", err)
	}
	return nil
}

func (s *CensusStore) ListPCRClusters(ctx context.Context, groupingKey *string) ([]model.PCRCensus, error) {
	query := `SELECT id, grouping_key, pcr_group, pcr_composite_hash, pcr_values, device_count, is_majority, first_seen_at, last_seen_at FROM pcr_census`
	var args []any
	if groupingKey != nil {
		query += ` WHERE grouping_key = $1`
		args = append(args, *groupingKey)
	}
	query += ` ORDER BY device_count DESC LIMIT 1000`

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list pcr clusters: %w", err)
	}
	defer rows.Close()

	var result []model.PCRCensus
	for rows.Next() {
		p, err := scanPCRCensus(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, *p)
	}
	return result, rows.Err()
}

// PCRCensusEligibleDevice holds minimal data for PCR census aggregation.
type PCRCensusEligibleDevice struct {
	IssuerFingerprint *string
	OSVersion         *string
	PCRValues         map[string]string
}

// GetPCRCensusEligibleDevices returns Tier 1-2 devices with PCR values within the active window.
func (s *CensusStore) GetPCRCensusEligibleDevices(ctx context.Context, activeWindowDays int) ([]PCRCensusEligibleDevice, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT issuer_fingerprint, os_version, pcr_values
		FROM devices
		WHERE identity_class IN ('verified', 'crowd_corroborated')
		  AND pcr_values IS NOT NULL
		  AND last_seen_at > NOW() - make_interval(days => $1)
	`, activeWindowDays)
	if err != nil {
		return nil, fmt.Errorf("get pcr eligible devices: %w", err)
	}
	defer rows.Close()

	var result []PCRCensusEligibleDevice
	for rows.Next() {
		d := PCRCensusEligibleDevice{}
		var pcrJSON []byte
		if err := rows.Scan(&d.IssuerFingerprint, &d.OSVersion, &pcrJSON); err != nil {
			return nil, fmt.Errorf("scan device: %w", err)
		}
		if len(pcrJSON) > 0 {
			_ = json.Unmarshal(pcrJSON, &d.PCRValues)
		}
		result = append(result, d)
	}
	return result, rows.Err()
}

// ResetAllPCRCounts sets all device_count to 0 before recomputation.
func (s *CensusStore) ResetAllPCRCounts(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `UPDATE pcr_census SET device_count = 0`)
	return err
}

// SetPCRDeviceCount updates the device_count for a specific PCR census entry.
func (s *CensusStore) SetPCRDeviceCount(ctx context.Context, groupingKey string, pcrGroup model.PCRGroup, compositeHash string, count int) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE pcr_census SET device_count = $1
		WHERE grouping_key = $2 AND pcr_group = $3 AND pcr_composite_hash = $4
	`, count, groupingKey, pcrGroup, compositeHash)
	return err
}

// UpsertPCRCensusWithCount creates or updates a PCR census entry with an exact device count.
// Used by the background census service to set authoritative counts from device aggregation.
func (s *CensusStore) UpsertPCRCensusWithCount(ctx context.Context, pcr *model.PCRCensus) error {
	pcrJSON, _ := json.Marshal(pcr.PCRValues)
	_, err := s.pool.Exec(ctx, `
		INSERT INTO pcr_census (grouping_key, pcr_group, pcr_composite_hash, pcr_values, device_count)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (grouping_key, pcr_group, pcr_composite_hash) DO UPDATE SET
			device_count = EXCLUDED.device_count,
			last_seen_at = NOW()
	`, pcr.GroupingKey, pcr.PCRGroup, pcr.PCRCompositeHash, pcrJSON, pcr.DeviceCount)
	if err != nil {
		return fmt.Errorf("upsert pcr census with count: %w", err)
	}
	return nil
}

// GetDistinctPCRGroups returns distinct (grouping_key, pcr_group) pairs for recalculation.
func (s *CensusStore) GetDistinctPCRGroups(ctx context.Context) ([][2]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT grouping_key, pcr_group FROM pcr_census`)
	if err != nil {
		return nil, fmt.Errorf("get distinct pcr groups: %w", err)
	}
	defer rows.Close()

	var result [][2]string
	for rows.Next() {
		var gk, pg string
		if err := rows.Scan(&gk, &pg); err != nil {
			return nil, fmt.Errorf("scan pcr group: %w", err)
		}
		result = append(result, [2]string{gk, pg})
	}
	return result, rows.Err()
}

// GetTopPCRCluster returns the cluster with the highest device_count for the given key/group.
func (s *CensusStore) GetTopPCRCluster(ctx context.Context, groupingKey string, pcrGroup model.PCRGroup, minPopulation int) (*model.PCRCensus, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, grouping_key, pcr_group, pcr_composite_hash, pcr_values, device_count, is_majority, first_seen_at, last_seen_at
		FROM pcr_census
		WHERE grouping_key = $1 AND pcr_group = $2 AND device_count >= $3
		ORDER BY device_count DESC LIMIT 1
	`, groupingKey, pcrGroup, minPopulation)
	p, err := scanPCRCensus(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil // no cluster meets threshold
		}
		return nil, err
	}
	return p, nil
}

func scanPCRCensus(row pgx.Row) (*model.PCRCensus, error) {
	p := &model.PCRCensus{}
	var pcrJSON []byte
	err := row.Scan(&p.ID, &p.GroupingKey, &p.PCRGroup, &p.PCRCompositeHash, &pcrJSON,
		&p.DeviceCount, &p.IsMajority, &p.FirstSeenAt, &p.LastSeenAt)
	if err != nil {
		return nil, err
	}
	if len(pcrJSON) > 0 {
		_ = json.Unmarshal(pcrJSON, &p.PCRValues)
	}
	return p, nil
}
