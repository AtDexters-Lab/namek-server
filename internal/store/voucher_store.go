package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/AtDexters-Lab/namek-server/internal/model"
)

var ErrVoucherRequestNotFound = errors.New("voucher request not found")

type VoucherStore struct {
	pool *pgxpool.Pool
}

func NewVoucherStore(pool *pgxpool.Pool) *VoucherStore {
	return &VoucherStore{pool: pool}
}

// CreateRequest upserts a voucher request. If a request for this issuer/subject pair
// already exists, it is replaced (new epoch, new voucher data).
func (s *VoucherStore) CreateRequest(ctx context.Context, req *model.VoucherRequest) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO voucher_requests (id, account_id, issuer_device_id, subject_device_id, voucher_data, epoch, status)
		VALUES ($1, $2, $3, $4, $5, $6, 'pending')
		ON CONFLICT (issuer_device_id, subject_device_id)
		DO UPDATE SET voucher_data = EXCLUDED.voucher_data, epoch = EXCLUDED.epoch,
		              status = 'pending', quote = NULL, signed_at = NULL
	`, req.ID, req.AccountID, req.IssuerDeviceID, req.SubjectDeviceID, req.VoucherData, req.Epoch)
	if err != nil {
		return fmt.Errorf("create voucher request: %w", err)
	}
	return nil
}

// GetPendingForDevice returns pending voucher requests where the device is the issuer.
func (s *VoucherStore) GetPendingForDevice(ctx context.Context, deviceID uuid.UUID) ([]model.VoucherRequest, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, account_id, issuer_device_id, subject_device_id, voucher_data, epoch,
		       status, quote, created_at, signed_at
		FROM voucher_requests
		WHERE issuer_device_id = $1 AND status = 'pending'
	`, deviceID)
	if err != nil {
		return nil, fmt.Errorf("get pending voucher requests: %w", err)
	}
	defer rows.Close()

	var reqs []model.VoucherRequest
	for rows.Next() {
		var r model.VoucherRequest
		if err := rows.Scan(&r.ID, &r.AccountID, &r.IssuerDeviceID, &r.SubjectDeviceID,
			&r.VoucherData, &r.Epoch, &r.Status, &r.Quote, &r.CreatedAt, &r.SignedAt); err != nil {
			return nil, fmt.Errorf("scan voucher request: %w", err)
		}
		reqs = append(reqs, r)
	}
	return reqs, rows.Err()
}

// GetByID returns a voucher request by ID.
func (s *VoucherStore) GetByID(ctx context.Context, id uuid.UUID) (*model.VoucherRequest, error) {
	r := &model.VoucherRequest{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, account_id, issuer_device_id, subject_device_id, voucher_data, epoch,
		       status, quote, created_at, signed_at
		FROM voucher_requests WHERE id = $1
	`, id).Scan(&r.ID, &r.AccountID, &r.IssuerDeviceID, &r.SubjectDeviceID,
		&r.VoucherData, &r.Epoch, &r.Status, &r.Quote, &r.CreatedAt, &r.SignedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrVoucherRequestNotFound
		}
		return nil, fmt.Errorf("get voucher request: %w", err)
	}
	return r, nil
}

// SignRequest marks a voucher request as signed.
func (s *VoucherStore) SignRequest(ctx context.Context, requestID uuid.UUID, quote string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE voucher_requests
		SET status = 'signed', quote = $1, signed_at = NOW()
		WHERE id = $2 AND status = 'pending'
	`, quote, requestID)
	if err != nil {
		return fmt.Errorf("sign voucher request: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrVoucherRequestNotFound
	}
	return nil
}

// GetSignedForSubject returns signed voucher requests where the device is the subject.
func (s *VoucherStore) GetSignedForSubject(ctx context.Context, subjectDeviceID uuid.UUID) ([]model.VoucherRequest, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, account_id, issuer_device_id, subject_device_id, voucher_data, epoch,
		       status, quote, created_at, signed_at
		FROM voucher_requests
		WHERE subject_device_id = $1 AND status = 'signed'
	`, subjectDeviceID)
	if err != nil {
		return nil, fmt.Errorf("get signed vouchers for subject: %w", err)
	}
	defer rows.Close()

	var reqs []model.VoucherRequest
	for rows.Next() {
		var r model.VoucherRequest
		if err := rows.Scan(&r.ID, &r.AccountID, &r.IssuerDeviceID, &r.SubjectDeviceID,
			&r.VoucherData, &r.Epoch, &r.Status, &r.Quote, &r.CreatedAt, &r.SignedAt); err != nil {
			return nil, fmt.Errorf("scan voucher request: %w", err)
		}
		reqs = append(reqs, r)
	}
	return reqs, rows.Err()
}

// ExpireStale marks unfulfilled requests older than maxAge as expired.
func (s *VoucherStore) ExpireStale(ctx context.Context, maxAge time.Duration) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE voucher_requests
		SET status = 'expired'
		WHERE status = 'pending' AND created_at < NOW() - $1::interval
	`, maxAge.String())
	if err != nil {
		return 0, fmt.Errorf("expire stale voucher requests: %w", err)
	}
	return tag.RowsAffected(), nil
}


