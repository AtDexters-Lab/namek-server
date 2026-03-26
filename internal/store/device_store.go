package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
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

// host() extracts the bare IP from inet, avoiding CIDR notation (e.g. "1.2.3.4/32")
// that net.ParseIP cannot parse.
const deviceColumns = `id, account_id, slug, hostname, custom_hostname, identity_class, ek_fingerprint, ek_cert_der, ak_public_key,
		       issuer_fingerprint, os_version, pcr_values, trust_level, trust_level_override,
		       host(ip_address), timezone, status,
		       hostname_changes_this_year, hostname_year, last_hostname_change_at,
		       voucher_pending_since,
		       created_at, last_seen_at`

func scanDevice(row pgx.Row) (*model.Device, error) {
	d := &model.Device{}
	var ipAddr *string
	var pcrValuesJSON []byte
	err := row.Scan(
		&d.ID, &d.AccountID, &d.Slug, &d.Hostname, &d.CustomHostname, &d.IdentityClass, &d.EKFingerprint, &d.EKCertDER, &d.AKPublicKey,
		&d.IssuerFingerprint, &d.OSVersion, &pcrValuesJSON, &d.TrustLevel, &d.TrustLevelOverride,
		&ipAddr, &d.Timezone, &d.Status,
		&d.HostnameChangesThisYear, &d.HostnameYear, &d.LastHostnameChangeAt,
		&d.VoucherPendingSince,
		&d.CreatedAt, &d.LastSeenAt,
	)
	if err != nil {
		return nil, err
	}
	if ipAddr != nil {
		d.IPAddress = net.ParseIP(*ipAddr)
	}
	if len(pcrValuesJSON) > 0 {
		_ = json.Unmarshal(pcrValuesJSON, &d.PCRValues)
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

// ListByAccountID returns all active devices in an account.
func (s *DeviceStore) ListByAccountID(ctx context.Context, accountID uuid.UUID) ([]model.Device, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+deviceColumns+` FROM devices WHERE account_id = $1 AND status = 'active'`, accountID)
	if err != nil {
		return nil, fmt.Errorf("list devices by account: %w", err)
	}
	defer rows.Close()

	var devices []model.Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, fmt.Errorf("scan device: %w", err)
		}
		devices = append(devices, *d)
	}
	return devices, rows.Err()
}

// UpdateAccountID moves a device to a different account and cleans up
// alias-domain assignments from the old account.
func (s *DeviceStore) UpdateAccountID(ctx context.Context, deviceID uuid.UUID, accountID uuid.UUID) error {
	// Remove alias-domain assignments so the device doesn't keep access
	// to the old account's verified domains after the transfer.
	_, err := s.pool.Exec(ctx, `
		DELETE FROM device_domain_assignments WHERE device_id = $1
	`, deviceID)
	if err != nil {
		return fmt.Errorf("clean domain assignments: %w", err)
	}
	_, err = s.pool.Exec(ctx, `UPDATE devices SET account_id = $1 WHERE id = $2`, accountID, deviceID)
	if err != nil {
		return fmt.Errorf("update device account_id: %w", err)
	}
	return nil
}

// SetVoucherPendingSince sets or clears the voucher_pending_since timestamp on a device.
func (s *DeviceStore) SetVoucherPendingSince(ctx context.Context, deviceID uuid.UUID, t *time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE devices SET voucher_pending_since = $1 WHERE id = $2`, t, deviceID)
	if err != nil {
		return fmt.Errorf("set voucher pending since: %w", err)
	}
	return nil
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

// LastSeenBatcher coalesces per-request UpdateLastSeen writes into periodic batch UPDATEs.
// This replaces unbounded fire-and-forget goroutines with a single flush goroutine.
type LastSeenBatcher struct {
	mu      sync.Mutex
	pending map[uuid.UUID]lastSeenEntry
	pool    *pgxpool.Pool
	logger  *slog.Logger
}

type lastSeenEntry struct {
	ip        net.IP
	timestamp time.Time
}

type flushEntry struct {
	id uuid.UUID
	e  lastSeenEntry
}

func NewLastSeenBatcher(pool *pgxpool.Pool, logger *slog.Logger) *LastSeenBatcher {
	return &LastSeenBatcher{
		pending: make(map[uuid.UUID]lastSeenEntry),
		pool:    pool,
		logger:  logger,
	}
}

// Record stores a last-seen update to be flushed later. Non-blocking, no DB call.
func (b *LastSeenBatcher) Record(deviceID uuid.UUID, ip net.IP) {
	b.mu.Lock()
	b.pending[deviceID] = lastSeenEntry{ip: ip, timestamp: time.Now()}
	b.mu.Unlock()
}

// FlushLoop periodically flushes pending updates. Sequential: waits for each flush
// to complete before starting the next. Stops when ctx is cancelled.
func (b *LastSeenBatcher) FlushLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.Flush(ctx)
		}
	}
}

// Flush writes all pending updates to the database. Safe to call from shutdown code.
func (b *LastSeenBatcher) Flush(ctx context.Context) {
	b.mu.Lock()
	if len(b.pending) == 0 {
		b.mu.Unlock()
		return
	}
	// Swap out the pending map
	batch := b.pending
	b.pending = make(map[uuid.UUID]lastSeenEntry, len(batch))
	b.mu.Unlock()

	start := time.Now()
	batchSize := len(batch)

	// Chunk into batches of 5000 to avoid oversized queries
	const chunkSize = 5000
	entries := make([]flushEntry, 0, batchSize)
	for id, e := range batch {
		entries = append(entries, flushEntry{id, e})
	}

	for i := 0; i < len(entries); i += chunkSize {
		end := i + chunkSize
		if end > len(entries) {
			end = len(entries)
		}
		chunk := entries[i:end]

		if err := b.flushChunk(ctx, chunk); err != nil {
			b.logger.Warn("last_seen batch flush failed",
				"error", err,
				"batch_size", len(chunk),
				"dropped", true,
			)
			// Discard on failure — last_seen_at is advisory data
			continue
		}
	}

	b.logger.Debug("last_seen batch flush",
		"batch_size", batchSize,
		"duration_ms", time.Since(start).Milliseconds(),
	)
}

func (b *LastSeenBatcher) flushChunk(ctx context.Context, chunk []flushEntry) error {
	if len(chunk) == 0 {
		return nil
	}

	// Build batch UPDATE using VALUES clause
	var sb strings.Builder
	args := make([]any, 0, len(chunk)*3)
	sb.WriteString("UPDATE devices AS d SET last_seen_at = v.ts::timestamptz, ip_address = v.ip FROM (VALUES ")

	for i, entry := range chunk {
		if i > 0 {
			sb.WriteString(", ")
		}
		argBase := i * 3
		fmt.Fprintf(&sb, "($%d::uuid, $%d::timestamptz, $%d::text)", argBase+1, argBase+2, argBase+3)
		args = append(args, entry.id, entry.e.timestamp, ipToString(entry.e.ip))
	}
	sb.WriteString(") AS v(id, ts, ip) WHERE d.id = v.id")

	_, err := b.pool.Exec(ctx, sb.String(), args...)
	return err
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

// UpdateTrustLevel sets both trust_level and trust_level_override (operator override).
// The override prevents system-computed trust from overwriting the operator's decision.
func (s *DeviceStore) UpdateTrustLevel(ctx context.Context, id uuid.UUID, trustLevel model.TrustLevel) error {
	tag, err := s.pool.Exec(ctx, `UPDATE devices SET trust_level = $1, trust_level_override = $1 WHERE id = $2`, trustLevel, id)
	if err != nil {
		return fmt.Errorf("update trust level: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrDeviceNotFound
	}
	return nil
}

// ClearTrustOverride removes the operator override, allowing system-computed trust to take effect.
func (s *DeviceStore) ClearTrustOverride(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `UPDATE devices SET trust_level_override = NULL WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("clear trust override: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrDeviceNotFound
	}
	return nil
}

func (s *DeviceStore) UpdateIdentityClass(ctx context.Context, id uuid.UUID, identityClass string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE devices SET identity_class = $1 WHERE id = $2`, identityClass, id)
	if err != nil {
		return fmt.Errorf("update identity class: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrDeviceNotFound
	}
	return nil
}

func (s *DeviceStore) UpdateTrustData(ctx context.Context, id uuid.UUID, identityClass string, trustLevel model.TrustLevel, issuerFP *string, osVersion *string, pcrValues map[string]string) error {
	// Only update trust_level if not operator-overridden
	_, err := s.pool.Exec(ctx, `
		UPDATE devices SET identity_class = $1,
			trust_level = CASE WHEN trust_level_override IS NULL THEN $2::text ELSE trust_level END,
			issuer_fingerprint = $3, os_version = $4, pcr_values = $5 WHERE id = $6
	`, identityClass, trustLevel, issuerFP, osVersion, pcrValuesToJSON(pcrValues), id)
	if err != nil {
		return fmt.Errorf("update trust data: %w", err)
	}
	return nil
}

func pcrValuesToJSON(pcrValues map[string]string) []byte {
	if pcrValues == nil {
		return nil
	}
	data, _ := json.Marshal(pcrValues)
	return data
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

// CreateDevice inserts a device into an existing account.
func (s *DeviceStore) CreateDevice(ctx context.Context, device *model.Device) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO devices (id, account_id, slug, hostname, custom_hostname, identity_class, ek_fingerprint, ek_cert_der, ak_public_key, issuer_fingerprint, os_version, pcr_values, trust_level, ip_address, status, last_seen_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, NOW())
	`, device.ID, device.AccountID, device.Slug, device.Hostname, device.CustomHostname,
		device.IdentityClass, device.EKFingerprint, device.EKCertDER, device.AKPublicKey,
		device.IssuerFingerprint, device.OSVersion, pcrValuesToJSON(device.PCRValues), device.TrustLevel,
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
	return nil
}

// CreateDeviceWithAccount creates an account and a device in a single transaction.
func CreateDeviceWithAccount(ctx context.Context, pool *pgxpool.Pool, account *model.Account, device *model.Device) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `INSERT INTO accounts (id, status, membership_epoch, founding_ek_fingerprint) VALUES ($1, $2, $3, $4)`,
		account.ID, account.Status, account.MembershipEpoch, account.FoundingEKFingerprint)
	if err != nil {
		return fmt.Errorf("insert account: %w", err)
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO devices (id, account_id, slug, hostname, custom_hostname, identity_class, ek_fingerprint, ek_cert_der, ak_public_key, issuer_fingerprint, os_version, pcr_values, trust_level, ip_address, status, last_seen_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, NOW())
	`, device.ID, device.AccountID, device.Slug, device.Hostname, device.CustomHostname,
		device.IdentityClass, device.EKFingerprint, device.EKCertDER, device.AKPublicKey,
		device.IssuerFingerprint, device.OSVersion, pcrValuesToJSON(device.PCRValues), device.TrustLevel,
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

// CreateDeviceWithRecoveryAccount creates a recovery account (ON CONFLICT DO NOTHING)
// and a device in a single transaction. Used for recovery enrollment where the account
// may already exist from another device's concurrent enrollment.
func CreateDeviceWithRecoveryAccount(ctx context.Context, pool *pgxpool.Pool, account *model.Account, device *model.Device) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `
		INSERT INTO accounts (id, status, membership_epoch, founding_ek_fingerprint, recovery_deadline)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (id) DO NOTHING
	`, account.ID, account.Status, account.MembershipEpoch, account.FoundingEKFingerprint, account.RecoveryDeadline)
	if err != nil {
		return fmt.Errorf("insert recovery account: %w", err)
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO devices (id, account_id, slug, hostname, custom_hostname, identity_class, ek_fingerprint, ek_cert_der, ak_public_key, issuer_fingerprint, os_version, pcr_values, trust_level, ip_address, status, last_seen_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, NOW())
	`, device.ID, device.AccountID, device.Slug, device.Hostname, device.CustomHostname,
		device.IdentityClass, device.EKFingerprint, device.EKCertDER, device.AKPublicKey,
		device.IssuerFingerprint, device.OSVersion, pcrValuesToJSON(device.PCRValues), device.TrustLevel,
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

	return nil
}
