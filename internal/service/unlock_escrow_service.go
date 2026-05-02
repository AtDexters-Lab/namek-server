package service

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/AtDexters-Lab/namek-server/internal/config"
	"github.com/AtDexters-Lab/namek-server/internal/metrics"
	"github.com/AtDexters-Lab/namek-server/internal/model"
	"github.com/AtDexters-Lab/namek-server/internal/store"
)

const unlockEscrowSecretLen = 32 // 256-bit F per the auto-unlock design

// TimestampLayout is the millisecond-precision UTC timestamp format used for
// every external string representation of an unlock-escrow timestamp (audit
// details, PUT/GET response bodies). Kept identical across surfaces so
// operators reconciling audit entries against client-observed expires_at
// don't need to normalize formats.
const TimestampLayout = "2006-01-02T15:04:05.000Z"

// UnlockEscrowService implements the per-device singleton escrow that holds the
// per-cycle auto-unlock secret F. piccolod deposits F pre-reboot, retrieves it
// post-reboot, and revokes on success. Failures fall through to manual unlock.
type UnlockEscrowService struct {
	store      *store.UnlockEscrowStore
	auditStore *store.AuditStore
	cfg        *config.Config
	logger     *slog.Logger
}

func NewUnlockEscrowService(s *store.UnlockEscrowStore, auditStore *store.AuditStore, cfg *config.Config, logger *slog.Logger) *UnlockEscrowService {
	return &UnlockEscrowService{
		store:      s,
		auditStore: auditStore,
		cfg:        cfg,
		logger:     logger,
	}
}

// DepositResult is returned to the handler so the PUT response can signal
// whether the device's requested window was clamped to the server ceiling.
type DepositResult struct {
	ExpiresAt              time.Time
	EffectiveWindowSeconds int
	RequestedClamped       bool
}

// Deposit upserts the device's escrow row with a fresh secret and a clamped
// window. Returns ErrValidation for invalid input (zero/negative window, wrong
// secret length).
func (s *UnlockEscrowService) Deposit(ctx context.Context, deviceID uuid.UUID, secret []byte, requestedWindowSec int) (*DepositResult, error) {
	if requestedWindowSec <= 0 {
		return nil, &ErrValidation{Message: "window_seconds must be positive"}
	}
	if len(secret) != unlockEscrowSecretLen {
		return nil, &ErrValidation{Message: "secret must be 32 bytes"}
	}

	ceiling := s.cfg.AutoUnlock.MaxWindowSeconds
	effective := requestedWindowSec
	clamped := false
	if effective > ceiling {
		effective = ceiling
		clamped = true
	}

	expiresAt := time.Now().Add(time.Duration(effective) * time.Second)
	replacedPrior, err := s.store.Upsert(ctx, &model.UnlockEscrow{
		DeviceID:  deviceID,
		Secret:    secret,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return nil, err
	}

	metrics.Get().AutoUnlock.Deposited.Add(1)
	if replacedPrior {
		metrics.Get().AutoUnlock.DepositedReplaced.Add(1)
	}
	if clamped {
		metrics.Get().AutoUnlock.DepositedClamped.Add(1)
	}

	details := map[string]any{
		"window_seconds":           effective,
		"requested_window_seconds": requestedWindowSec,
		"clamped":                  clamped,
		"expires_at":               expiresAt.UTC().Format(TimestampLayout),
		"replaced_prior":           replacedPrior,
	}
	s.auditStore.LogAction(ctx, model.ActorTypeDevice, deviceID.String(),
		"auto_unlock.escrow.deposited", "unlock_escrow", strPtr(deviceID.String()), details, nil)

	return &DepositResult{
		ExpiresAt:              expiresAt,
		EffectiveWindowSeconds: effective,
		RequestedClamped:       clamped,
	}, nil
}

// Pickup atomically claims the first pickup of the current cycle (single-CTE)
// and returns the secret. On first-pickup transitions, emits an audit entry;
// idempotent retries within W return the same secret silently. Maps
// ErrEscrowNotFound through unchanged so the handler can map to 404.
func (s *UnlockEscrowService) Pickup(ctx context.Context, deviceID uuid.UUID) ([]byte, time.Time, error) {
	row, firstPickup, err := s.store.ClaimFirstPickup(ctx, deviceID)
	if err != nil {
		return nil, time.Time{}, err
	}
	if firstPickup {
		metrics.Get().AutoUnlock.PickedUp.Add(1)
		s.auditStore.LogAction(ctx, model.ActorTypeDevice, deviceID.String(),
			"auto_unlock.escrow.picked_up", "unlock_escrow", strPtr(deviceID.String()), nil, nil)
	}
	return row.Secret, row.ExpiresAt, nil
}

// Revoke deletes the device's escrow row. Audit emit is gated on whether a row
// was actually deleted, so idempotent retries don't inflate the audit trail.
// Always returns nil — Delete is idempotent.
func (s *UnlockEscrowService) Revoke(ctx context.Context, deviceID uuid.UUID) error {
	deleted, err := s.store.Delete(ctx, deviceID)
	if err != nil {
		return err
	}
	if deleted {
		metrics.Get().AutoUnlock.Revoked.Add(1)
		s.auditStore.LogAction(ctx, model.ActorTypeDevice, deviceID.String(),
			"auto_unlock.escrow.revoked", "unlock_escrow", strPtr(deviceID.String()), nil, nil)
	}
	return nil
}

// CleanupLoop sweeps expired rows. Drains within a tick: keeps calling
// DeleteExpired while the previous call returned exactly SweepBatchSize rows,
// up to SweepMaxIterations. Mirrors ACMEService.cleanup's error handling — on
// DeleteExpired error the tick aborts and the next tick retries fresh.
func (s *UnlockEscrowService) CleanupLoop(ctx context.Context) {
	interval := s.cfg.AutoUnlock.CleanupInterval()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runSweep(ctx)
		}
	}
}

func (s *UnlockEscrowService) runSweep(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}

	batch := s.cfg.AutoUnlock.SweepBatchSize
	maxIter := s.cfg.AutoUnlock.SweepMaxIterations
	totalCleaned := 0
	hitCap := false

	for i := 0; i < maxIter; i++ {
		if ctx.Err() != nil {
			return
		}
		ids, err := s.store.DeleteExpired(ctx, batch)
		if err != nil {
			s.logger.Error("unlock escrow sweep failed; aborting tick",
				"iteration", i,
				"cleaned_so_far", totalCleaned,
				"error", err,
			)
			return
		}
		for _, id := range ids {
			s.auditStore.LogAction(ctx, model.ActorTypeSystem, "unlock_escrow_sweep",
				"auto_unlock.escrow.expired", "unlock_escrow", strPtr(id.String()), nil, nil)
		}
		metrics.Get().AutoUnlock.Expired.Add(int64(len(ids)))
		totalCleaned += len(ids)
		if len(ids) < batch {
			break
		}
		hitCap = i == maxIter-1
	}

	// Update the backlog gauge. When the drain bottomed out (hitCap=false), the
	// table has no more expired rows for the next sweep — gauge is 0. When the
	// loop hit the iteration cap there is genuine backlog left; query for the
	// current oldest age. This avoids a per-tick DB roundtrip in the common
	// steady-state case where there's nothing to age.
	if hitCap {
		if age, err := s.store.OldestExpiredAge(ctx); err != nil {
			s.logger.Warn("unlock escrow oldest-expired-age query failed; leaving prior gauge value", "error", err)
		} else {
			metrics.Get().AutoUnlockGauges.OldestExpiredAgeSeconds.Store(int64(age / time.Second))
		}
	} else {
		metrics.Get().AutoUnlockGauges.OldestExpiredAgeSeconds.Store(0)
	}

	if totalCleaned > 0 {
		s.logger.Info("cleaned up expired unlock escrows", "count", totalCleaned)
	}
}
