package store

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/AtDexters-Lab/namek-server/internal/model"
)

var ErrNexusNotFound = errors.New("nexus instance not found")

type NexusStore struct {
	pool *pgxpool.Pool
}

func NewNexusStore(pool *pgxpool.Pool) *NexusStore {
	return &NexusStore{pool: pool}
}

func (s *NexusStore) Upsert(ctx context.Context, n *model.NexusInstance) error {
	addrs := make([]string, len(n.ResolvedAddresses))
	for i, ip := range n.ResolvedAddresses {
		addrs[i] = ip.String()
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO nexus_instances (id, hostname, resolved_addresses, region, backend_port, heartbeat_interval_seconds, status, last_seen_at)
		VALUES ($1, $2, $3::inet[], $4, $5, $6, $7, NOW())
		ON CONFLICT (hostname) DO UPDATE SET
			resolved_addresses = $3::inet[],
			region = $4,
			backend_port = $5,
			heartbeat_interval_seconds = $6,
			status = 'active',
			last_seen_at = NOW()
	`, n.ID, n.Hostname, addrs, n.Region, n.BackendPort, n.HeartbeatIntervalSeconds, n.Status)
	if err != nil {
		return fmt.Errorf("upsert nexus instance: %w", err)
	}
	return nil
}

func (s *NexusStore) GetByHostname(ctx context.Context, hostname string) (*model.NexusInstance, error) {
	n := &model.NexusInstance{}
	var addrs []string
	// host() extracts bare IPs from inet; inet::text includes CIDR notation
	// (e.g. "1.2.3.4/32") which net.ParseIP cannot parse.
	err := s.pool.QueryRow(ctx, `
		SELECT id, hostname,
		       (SELECT coalesce(array_agg(host(a)), '{}') FROM unnest(resolved_addresses) a),
		       region, backend_port, heartbeat_interval_seconds, status, registered_at, last_seen_at
		FROM nexus_instances WHERE hostname = $1
	`, hostname).Scan(
		&n.ID, &n.Hostname, &addrs, &n.Region, &n.BackendPort, &n.HeartbeatIntervalSeconds,
		&n.Status, &n.RegisteredAt, &n.LastSeenAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNexusNotFound
		}
		return nil, fmt.Errorf("get nexus by hostname: %w", err)
	}
	n.ResolvedAddresses = parseIPs(addrs)
	return n, nil
}

func (s *NexusStore) ListActive(ctx context.Context) ([]*model.NexusInstance, error) {
	// host() extracts bare IPs from inet; inet::text includes CIDR notation
	// (e.g. "1.2.3.4/32") which net.ParseIP cannot parse.
	rows, err := s.pool.Query(ctx, `
		SELECT id, hostname,
		       (SELECT coalesce(array_agg(host(a)), '{}') FROM unnest(resolved_addresses) a),
		       region, backend_port, heartbeat_interval_seconds, status, registered_at, last_seen_at
		FROM nexus_instances WHERE status = 'active'
	`)
	if err != nil {
		return nil, fmt.Errorf("list active nexus instances: %w", err)
	}
	defer rows.Close()

	var instances []*model.NexusInstance
	for rows.Next() {
		n := &model.NexusInstance{}
		var addrs []string
		if err := rows.Scan(
			&n.ID, &n.Hostname, &addrs, &n.Region, &n.BackendPort, &n.HeartbeatIntervalSeconds,
			&n.Status, &n.RegisteredAt, &n.LastSeenAt,
		); err != nil {
			return nil, fmt.Errorf("scan nexus instance: %w", err)
		}
		n.ResolvedAddresses = parseIPs(addrs)
		instances = append(instances, n)
	}
	return instances, rows.Err()
}

func (s *NexusStore) MarkInactive(ctx context.Context, thresholdSeconds int) ([]uuid.UUID, error) {
	rows, err := s.pool.Query(ctx, `
		UPDATE nexus_instances
		SET status = 'inactive'
		WHERE last_seen_at < NOW() - make_interval(secs => $1) AND status = 'active'
		RETURNING id
	`, thresholdSeconds)
	if err != nil {
		return nil, fmt.Errorf("mark inactive nexus instances: %w", err)
	}
	defer rows.Close()

	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan inactive nexus id: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *NexusStore) UpdateResolvedAddresses(ctx context.Context, id uuid.UUID, addrs []net.IP) error {
	strs := make([]string, len(addrs))
	for i, ip := range addrs {
		strs[i] = ip.String()
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE nexus_instances SET resolved_addresses = $1::inet[] WHERE id = $2
	`, strs, id)
	if err != nil {
		return fmt.Errorf("update resolved addresses: %w", err)
	}
	return nil
}

// CountByStatus returns nexus instance counts grouped by status.
func (s *NexusStore) CountByStatus(ctx context.Context) (map[string]int, error) {
	return countGroupBy(ctx, s.pool, "nexus_instances", "status")
}

func parseIPs(strs []string) []net.IP {
	ips := make([]net.IP, 0, len(strs))
	for _, s := range strs {
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}
