package handler

import (
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/AtDexters-Lab/namek-server/internal/auth"
	"github.com/AtDexters-Lab/namek-server/internal/httputil"
	"github.com/AtDexters-Lab/namek-server/internal/service"
	"github.com/AtDexters-Lab/namek-server/internal/store"
)

// maxDepositBodyBytes caps the deposit request body. Generous over the
// expected ~80 bytes (base64url 32-byte secret + small int) so any well-formed
// client succeeds, but bounds memory pressure from a single authenticated
// client looping malformed/oversized payloads.
const maxDepositBodyBytes = 4096

type UnlockEscrowHandler struct {
	svc    *service.UnlockEscrowService
	logger *slog.Logger
}

func NewUnlockEscrowHandler(svc *service.UnlockEscrowService, logger *slog.Logger) *UnlockEscrowHandler {
	return &UnlockEscrowHandler{svc: svc, logger: logger}
}

// Both fields are validated by the service so the handler emits a uniform
// precise error message instead of gin's generic "invalid request body".
type depositUnlockEscrowRequest struct {
	Secret        string `json:"secret"`
	WindowSeconds int    `json:"window_seconds"`
}

type depositUnlockEscrowResponse struct {
	ExpiresAt              string `json:"expires_at"`
	EffectiveWindowSeconds int    `json:"effective_window_seconds"`
	RequestedClamped       bool   `json:"requested_clamped"`
}

type pickupUnlockEscrowResponse struct {
	Secret    string `json:"secret"`
	ExpiresAt string `json:"expires_at"`
}

// Deposit handles PUT /api/v1/devices/me/unlock-escrow.
func (h *UnlockEscrowHandler) Deposit(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxDepositBodyBytes)

	var req depositUnlockEscrowRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httputil.RespondBadRequest(c, "invalid request body")
		return
	}

	secret, err := base64.RawURLEncoding.DecodeString(req.Secret)
	if err != nil {
		httputil.RespondBadRequest(c, "secret must be base64url-encoded")
		return
	}

	deviceID := c.MustGet(auth.ContextKeyDeviceID).(uuid.UUID)

	result, err := h.svc.Deposit(c.Request.Context(), deviceID, secret, req.WindowSeconds)
	if err != nil {
		var validationErr *service.ErrValidation
		if errors.As(err, &validationErr) {
			httputil.RespondBadRequest(c, validationErr.Message)
			return
		}
		h.logger.Error("unlock escrow deposit failed", "device_id", deviceID, "error", err)
		httputil.RespondInternalError(c)
		return
	}

	httputil.RespondOK(c, depositUnlockEscrowResponse{
		ExpiresAt:              result.ExpiresAt.UTC().Format(service.TimestampLayout),
		EffectiveWindowSeconds: result.EffectiveWindowSeconds,
		RequestedClamped:       result.RequestedClamped,
	})
}

// Pickup handles GET /api/v1/devices/me/unlock-escrow. The actual defense
// for reverse-proxy access logs that mirror response bodies is a deployment
// contract documented in the integration spec; the cache header here is
// defense-in-depth for HTTP intermediaries.
func (h *UnlockEscrowHandler) Pickup(c *gin.Context) {
	deviceID := c.MustGet(auth.ContextKeyDeviceID).(uuid.UUID)

	c.Header("Cache-Control", "no-store")

	secret, expiresAt, err := h.svc.Pickup(c.Request.Context(), deviceID)
	if err != nil {
		if errors.Is(err, store.ErrEscrowNotFound) {
			httputil.RespondNotFound(c, "no outstanding escrow")
			return
		}
		h.logger.Error("unlock escrow pickup failed", "device_id", deviceID, "error", err)
		httputil.RespondInternalError(c)
		return
	}

	httputil.RespondOK(c, pickupUnlockEscrowResponse{
		Secret:    base64.RawURLEncoding.EncodeToString(secret),
		ExpiresAt: expiresAt.UTC().Format(service.TimestampLayout),
	})
}

// Revoke handles DELETE /api/v1/devices/me/unlock-escrow. Always 204 — the
// device may retry after a network drop, so the operation must be idempotent.
// Audit emit is gated server-side on whether a row was actually deleted.
func (h *UnlockEscrowHandler) Revoke(c *gin.Context) {
	deviceID := c.MustGet(auth.ContextKeyDeviceID).(uuid.UUID)

	if err := h.svc.Revoke(c.Request.Context(), deviceID); err != nil {
		h.logger.Error("unlock escrow revoke failed", "device_id", deviceID, "error", err)
		httputil.RespondInternalError(c)
		return
	}

	httputil.RespondNoContent(c)
}
