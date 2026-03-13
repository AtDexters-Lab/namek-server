package store

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/AtDexters-Lab/namek-server/internal/model"
)

var ErrDeviceNotFound = errors.New("device not found")
var ErrDuplicateEK = errors.New("duplicate ek fingerprint")
var ErrDuplicateHostname = errors.New("hostname already taken")
var ErrDuplicateSlug = errors.New("duplicate slug")

type DeviceStore struct {
	pool *pgxpool.Pool
}

func NewDeviceStore(pool *pgxpool.Pool) *DeviceStore {
	return &DeviceStore{pool: pool}
}

const deviceColumns = `id, account_id, slug, hostname, custom_hostname, identity_class, ek_fingerprint, ak_public_key,
		       ip_address::text, timezone, status,
		       hostname_changes_this_year, hostname_year, last_hostname_change_at,
		       created_at, last_seen_at`

func scanDevice(row pgx.Row) (*model.Device, error) {
	d := &model.Device{}
	var ipAddr *string
	err := row.Scan(
		&d.ID, &d.AccountID, &d.Slug, &d.Hostname, &d.CustomHostname, &d.IdentityClass, &d.EKFingerprint, &d.AKPublicKey,
		&ipAddr, &d.Timezone, &d.Status,
		&d.HostnameChangesThisYear, &d.HostnameYear, &d.LastHostnameChangeAt,
		&d.CreatedAt, &d.LastSeenAt,
	)
	if err != nil {
		return nil, err
	}
	if ipAddr != nil {
		d.IPAddress = net.ParseIP(*ipAddr)
	}
	return d, nil
}

func (s *DeviceStore) GetByID(ctx context.Context, id uuid.UUID) (*model.Device, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+deviceColumns+` FROM devices WHERE id = $1`, id)
	d, err := scanDevice(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrDeviceNotFound
		}
		return nil, fmt.Errorf("get device by id: %w", err)
	}
	return d, nil
}

func (s *DeviceStore) GetByEKFingerprint(ctx context.Context, fingerprint string) (*model.Device, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+deviceColumns+` FROM devices WHERE ek_fingerprint = $1`, fingerprint)
	d, err := scanDevice(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrDeviceNotFound
		}
		return nil, fmt.Errorf("get device by ek fingerprint: %w", err)
	}
	return d, nil
}

type SetCustomHostnameParams struct {
	DeviceID        uuid.UUID
	CustomHostname  string
	ChangeCount     int
	HostnameYear    int
}

func (s *DeviceStore) SetCustomHostname(ctx context.Context, p SetCustomHostnameParams) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE devices
		SET custom_hostname = $1,
		    hostname_changes_this_year = $2,
		    hostname_year = $3,
		    last_hostname_change_at = NOW()
		WHERE id = $4
	`, p.CustomHostname, p.ChangeCount, p.HostnameYear, p.DeviceID)
	if err != nil {
		if isDuplicateKeyError(err) {
			return ErrDuplicateHostname
		}
		return fmt.Errorf("set custom hostname: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrDeviceNotFound
	}
	return nil
}

func (s *DeviceStore) IsLabelTaken(ctx context.Context, label string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM devices WHERE slug = $1 OR custom_hostname = $1)
	`, label).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check label taken: %w", err)
	}
	return exists, nil
}

func (s *DeviceStore) UpdateAKPublicKey(ctx context.Context, id uuid.UUID, akPub []byte) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE devices SET ak_public_key = $1 WHERE id = $2 AND status = 'active'
	`, akPub, id)
	if err != nil {
		return fmt.Errorf("update ak public key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrDeviceNotFound
	}
	return nil
}

func (s *DeviceStore) IsHostnameReleased(ctx context.Context, label string, cooldownDays int) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM released_hostnames
			WHERE label = $1 AND released_at > NOW() - make_interval(days => $2)
		)
	`, label, cooldownDays).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check released hostname: %w", err)
	}
	return exists, nil
}

func (s *DeviceStore) ReleaseHostname(ctx context.Context, label string, deviceID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO released_hostnames (label, released_by)
		VALUES ($1, $2)
		ON CONFLICT (label) DO UPDATE SET released_at = NOW(), released_by = $2
	`, label, deviceID)
	if err != nil {
		return fmt.Errorf("release hostname: %w", err)
	}
	return nil
}

func (s *DeviceStore) CleanupReleasedHostnames(ctx context.Context, maxAgeDays int) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM released_hostnames
		WHERE released_at < NOW() - make_interval(days => $1)
	`, maxAgeDays)
	if err != nil {
		return 0, fmt.Errorf("cleanup released hostnames: %w", err)
	}
	return tag.RowsAffected(), nil
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

func (s *DeviceStore) GetBySlug(ctx context.Context, slug string) (*model.Device, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+deviceColumns+` FROM devices WHERE slug = $1`, slug)
	d, err := scanDevice(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrDeviceNotFound
		}
		return nil, fmt.Errorf("get device by slug: %w", err)
	}
	return d, nil
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

// CreateDeviceWithAccount creates an account and a device in a single transaction.
func CreateDeviceWithAccount(ctx context.Context, pool *pgxpool.Pool, account *model.Account, device *model.Device) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `INSERT INTO accounts (id) VALUES ($1)`, account.ID)
	if err != nil {
		return fmt.Errorf("insert account: %w", err)
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO devices (id, account_id, slug, hostname, custom_hostname, identity_class, ek_fingerprint, ak_public_key, ip_address, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, device.ID, device.AccountID, device.Slug, device.Hostname, device.CustomHostname,
		device.IdentityClass, device.EKFingerprint, device.AKPublicKey,
		ipToString(device.IPAddress), device.Status)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			switch pgErr.ConstraintName {
			case "devices_hostname_key", "devices_custom_hostname_key":
				return ErrDuplicateHostname
			case "devices_slug_unique":
				return ErrDuplicateSlug
			default:
				return ErrDuplicateEK
			}
		}
		return fmt.Errorf("insert device: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	account.CreatedAt = time.Now()
	return nil
}
