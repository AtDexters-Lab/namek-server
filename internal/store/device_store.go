package store

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/AtDexters-Lab/namek-server/internal/model"
)

var ErrDeviceNotFound = errors.New("device not found")
var ErrDuplicateEK = errors.New("duplicate ek fingerprint")
var ErrDuplicateHostname = errors.New("hostname already taken")

type DeviceStore struct {
	pool *pgxpool.Pool
}

func NewDeviceStore(pool *pgxpool.Pool) *DeviceStore {
	return &DeviceStore{pool: pool}
}

func (s *DeviceStore) Create(ctx context.Context, d *model.Device) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO devices (id, hostname, custom_hostname, identity_class, ek_fingerprint, ak_public_key, ip_address, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, d.ID, d.Hostname, d.CustomHostname, d.IdentityClass, d.EKFingerprint, d.AKPublicKey, ipToString(d.IPAddress), d.Status)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			switch pgErr.ConstraintName {
			case "devices_hostname_key", "devices_custom_hostname_key":
				return ErrDuplicateHostname
			default:
				return ErrDuplicateEK
			}
		}
		return fmt.Errorf("insert device: %w", err)
	}
	return nil
}

func (s *DeviceStore) GetByID(ctx context.Context, id uuid.UUID) (*model.Device, error) {
	d := &model.Device{}
	var ipAddr *string
	err := s.pool.QueryRow(ctx, `
		SELECT id, hostname, custom_hostname, identity_class, ek_fingerprint, ak_public_key,
		       ip_address::text, timezone, status, created_at, last_seen_at
		FROM devices WHERE id = $1
	`, id).Scan(
		&d.ID, &d.Hostname, &d.CustomHostname, &d.IdentityClass, &d.EKFingerprint, &d.AKPublicKey,
		&ipAddr, &d.Timezone, &d.Status, &d.CreatedAt, &d.LastSeenAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrDeviceNotFound
		}
		return nil, fmt.Errorf("get device by id: %w", err)
	}
	if ipAddr != nil {
		d.IPAddress = net.ParseIP(*ipAddr)
	}
	return d, nil
}

func (s *DeviceStore) GetByEKFingerprint(ctx context.Context, fingerprint string) (*model.Device, error) {
	d := &model.Device{}
	var ipAddr *string
	err := s.pool.QueryRow(ctx, `
		SELECT id, hostname, custom_hostname, identity_class, ek_fingerprint, ak_public_key,
		       ip_address::text, timezone, status, created_at, last_seen_at
		FROM devices WHERE ek_fingerprint = $1
	`, fingerprint).Scan(
		&d.ID, &d.Hostname, &d.CustomHostname, &d.IdentityClass, &d.EKFingerprint, &d.AKPublicKey,
		&ipAddr, &d.Timezone, &d.Status, &d.CreatedAt, &d.LastSeenAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrDeviceNotFound
		}
		return nil, fmt.Errorf("get device by ek fingerprint: %w", err)
	}
	if ipAddr != nil {
		d.IPAddress = net.ParseIP(*ipAddr)
	}
	return d, nil
}

func (s *DeviceStore) UpdateHostname(ctx context.Context, id uuid.UUID, customHostname string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE devices SET custom_hostname = $1 WHERE id = $2
	`, customHostname, id)
	if err != nil {
		if isDuplicateKeyError(err) {
			return ErrDuplicateHostname
		}
		return fmt.Errorf("update hostname: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrDeviceNotFound
	}
	return nil
}

func (s *DeviceStore) UpdateLastSeen(ctx context.Context, id uuid.UUID, ip net.IP) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE devices SET last_seen_at = NOW(), ip_address = $1 WHERE id = $2
	`, ipToString(ip), id)
	if err != nil {
		return fmt.Errorf("update last seen: %w", err)
	}
	return nil
}

func (s *DeviceStore) UpdateStatus(ctx context.Context, id uuid.UUID, status model.DeviceStatus) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE devices SET status = $1 WHERE id = $2
	`, status, id)
	if err != nil {
		return fmt.Errorf("update status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrDeviceNotFound
	}
	return nil
}

func (s *DeviceStore) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM devices WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete device: %w", err)
	}
	return nil
}

func ipToString(ip net.IP) *string {
	if ip == nil {
		return nil
	}
	s := ip.String()
	return &s
}

func isDuplicateKeyError(err error) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505" // unique_violation
	}
	return strings.Contains(err.Error(), "duplicate key")
}
