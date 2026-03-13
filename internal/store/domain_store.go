package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/AtDexters-Lab/namek-server/internal/model"
)

var (
	ErrDomainNotFound     = errors.New("domain not found")
	ErrDuplicateDomain    = errors.New("domain already registered")
	ErrAssignmentNotFound = errors.New("assignment not found")
)

type DomainStore struct {
	pool *pgxpool.Pool
}

func NewDomainStore(pool *pgxpool.Pool) *DomainStore {
	return &DomainStore{pool: pool}
}

func (s *DomainStore) Create(ctx context.Context, d *model.AccountDomain) error {
	err := s.pool.QueryRow(ctx, `
		INSERT INTO account_domains (id, account_id, domain, cname_target, status, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING created_at
	`, d.ID, d.AccountID, d.Domain, d.CNAMETarget, d.Status, d.ExpiresAt).Scan(&d.CreatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrDuplicateDomain
		}
		return fmt.Errorf("insert domain: %w", err)
	}
	return nil
}

func (s *DomainStore) GetByID(ctx context.Context, id uuid.UUID) (*model.AccountDomain, error) {
	d := &model.AccountDomain{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, account_id, domain, cname_target, status, created_at, expires_at, verified_at, verified_by_device_id
		FROM account_domains WHERE id = $1
	`, id).Scan(
		&d.ID, &d.AccountID, &d.Domain, &d.CNAMETarget, &d.Status,
		&d.CreatedAt, &d.ExpiresAt, &d.VerifiedAt, &d.VerifiedByDeviceID,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrDomainNotFound
		}
		return nil, fmt.Errorf("get domain by id: %w", err)
	}
	return d, nil
}

func (s *DomainStore) GetByDomain(ctx context.Context, domain string) (*model.AccountDomain, error) {
	d := &model.AccountDomain{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, account_id, domain, cname_target, status, created_at, expires_at, verified_at, verified_by_device_id
		FROM account_domains WHERE domain = $1
	`, domain).Scan(
		&d.ID, &d.AccountID, &d.Domain, &d.CNAMETarget, &d.Status,
		&d.CreatedAt, &d.ExpiresAt, &d.VerifiedAt, &d.VerifiedByDeviceID,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrDomainNotFound
		}
		return nil, fmt.Errorf("get domain by name: %w", err)
	}
	return d, nil
}

func (s *DomainStore) ListByAccountID(ctx context.Context, accountID uuid.UUID) ([]*model.AccountDomain, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT ad.id, ad.account_id, ad.domain, ad.cname_target, ad.status,
		       ad.created_at, ad.expires_at, ad.verified_at, ad.verified_by_device_id,
		       COALESCE(array_agg(dda.device_id) FILTER (WHERE dda.device_id IS NOT NULL), '{}')
		FROM account_domains ad
		LEFT JOIN device_domain_assignments dda ON dda.domain_id = ad.id
		WHERE ad.account_id = $1
		GROUP BY ad.id
		ORDER BY ad.created_at
	`, accountID)
	if err != nil {
		return nil, fmt.Errorf("list domains by account: %w", err)
	}
	defer rows.Close()

	var domains []*model.AccountDomain
	for rows.Next() {
		d := &model.AccountDomain{}
		if err := rows.Scan(
			&d.ID, &d.AccountID, &d.Domain, &d.CNAMETarget, &d.Status,
			&d.CreatedAt, &d.ExpiresAt, &d.VerifiedAt, &d.VerifiedByDeviceID,
			&d.AssignedDeviceIDs,
		); err != nil {
			return nil, fmt.Errorf("scan domain row: %w", err)
		}
		domains = append(domains, d)
	}
	return domains, rows.Err()
}

func (s *DomainStore) UpdateVerified(ctx context.Context, id uuid.UUID, verifiedByDeviceID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE account_domains
		SET status = 'verified', verified_at = NOW(), verified_by_device_id = $1, expires_at = NULL
		WHERE id = $2
	`, verifiedByDeviceID, id)
	if err != nil {
		return fmt.Errorf("update domain verified: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrDomainNotFound
	}
	return nil
}

func (s *DomainStore) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM account_domains WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete domain: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrDomainNotFound
	}
	return nil
}

func (s *DomainStore) CountByAccountID(ctx context.Context, accountID uuid.UUID) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM account_domains WHERE account_id = $1
	`, accountID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count domains by account: %w", err)
	}
	return count, nil
}

func (s *DomainStore) HasConflictingDomain(ctx context.Context, accountID uuid.UUID, domain string) (bool, error) {
	var exists bool
	// Check for parent domains under other accounts: existing domain is a suffix of requested domain
	// Check for child domains under other accounts: requested domain is a suffix of existing domain
	// LIKE is safe here because domain validation rejects all LIKE metacharacters (%, _)
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM account_domains
			WHERE account_id != $1
			AND (
				$2 LIKE '%.' || domain
				OR domain LIKE '%.' || $2
			)
		)
	`, accountID, domain).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check conflicting domain: %w", err)
	}
	return exists, nil
}

func (s *DomainStore) DeleteExpiredPending(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM account_domains
		WHERE status = 'pending' AND expires_at < NOW()
	`)
	if err != nil {
		return 0, fmt.Errorf("delete expired pending domains: %w", err)
	}
	return tag.RowsAffected(), nil
}

// AssignDevice assigns a domain to a device.
func (s *DomainStore) AssignDevice(ctx context.Context, domainID, deviceID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO device_domain_assignments (device_id, domain_id)
		VALUES ($1, $2)
		ON CONFLICT DO NOTHING
	`, deviceID, domainID)
	if err != nil {
		return fmt.Errorf("assign device to domain: %w", err)
	}
	return nil
}

// UnassignDevice removes a device assignment from a domain.
func (s *DomainStore) UnassignDevice(ctx context.Context, domainID, deviceID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM device_domain_assignments WHERE domain_id = $1 AND device_id = $2
	`, domainID, deviceID)
	if err != nil {
		return fmt.Errorf("unassign device from domain: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrAssignmentNotFound
	}
	return nil
}

// ListAssignments returns all device assignments for a domain.
func (s *DomainStore) ListAssignments(ctx context.Context, domainID uuid.UUID) ([]*model.DomainAssignment, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT dda.device_id, ad.domain, dda.created_at
		FROM device_domain_assignments dda
		JOIN account_domains ad ON ad.id = dda.domain_id
		WHERE dda.domain_id = $1
		ORDER BY dda.created_at
	`, domainID)
	if err != nil {
		return nil, fmt.Errorf("list domain assignments: %w", err)
	}
	defer rows.Close()

	var assignments []*model.DomainAssignment
	for rows.Next() {
		a := &model.DomainAssignment{}
		if err := rows.Scan(&a.DeviceID, &a.Domain, &a.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan assignment row: %w", err)
		}
		assignments = append(assignments, a)
	}
	return assignments, rows.Err()
}

// GetDeviceAliasDomains returns verified domain strings for a device.
func (s *DomainStore) GetDeviceAliasDomains(ctx context.Context, deviceID uuid.UUID) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT ad.domain FROM account_domains ad
		JOIN device_domain_assignments dda ON dda.domain_id = ad.id
		WHERE dda.device_id = $1 AND ad.status = 'verified'
	`, deviceID)
	if err != nil {
		return nil, fmt.Errorf("get device alias domains: %w", err)
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return nil, fmt.Errorf("scan alias domain: %w", err)
		}
		domains = append(domains, domain)
	}
	return domains, rows.Err()
}

// AreDevicesInAccount checks that all given device IDs belong to the specified account.
func (s *DomainStore) AreDevicesInAccount(ctx context.Context, accountID uuid.UUID, deviceIDs []uuid.UUID) (bool, error) {
	if len(deviceIDs) == 0 {
		return true, nil
	}
	var count int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM devices
		WHERE id = ANY($1) AND account_id = $2
	`, deviceIDs, accountID).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("check devices in account: %w", err)
	}
	return count == len(deviceIDs), nil
}

