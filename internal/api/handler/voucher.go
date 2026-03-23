package handler

import (
	"errors"
	"log/slog"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/AtDexters-Lab/namek-server/internal/auth"
	"github.com/AtDexters-Lab/namek-server/internal/httputil"
	"github.com/AtDexters-Lab/namek-server/internal/service"
)

type VoucherHandler struct {
	voucherSvc *service.VoucherService
	logger     *slog.Logger
}

func NewVoucherHandler(voucherSvc *service.VoucherService, logger *slog.Logger) *VoucherHandler {
	return &VoucherHandler{voucherSvc: voucherSvc, logger: logger}
}

type signVoucherRequest struct {
	RequestID string `json:"request_id" binding:"required"`
	Quote     string `json:"quote" binding:"required"`
}

func (h *VoucherHandler) SignVoucher(c *gin.Context) {
	deviceID := c.MustGet(auth.ContextKeyDeviceID).(uuid.UUID)

	var req signVoucherRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httputil.RespondBadRequest(c, "invalid request body")
		return
	}

	requestID, err := uuid.Parse(req.RequestID)
	if err != nil {
		httputil.RespondBadRequest(c, "invalid request_id")
		return
	}

	if err := h.voucherSvc.SignVoucher(c.Request.Context(), deviceID, requestID, req.Quote); err != nil {
		var valErr *service.ErrValidation
		if errors.As(err, &valErr) {
			httputil.RespondBadRequest(c, valErr.Message)
			return
		}
		h.logger.Error("sign voucher failed", "device_id", deviceID, "request_id", requestID, "error", err)
		httputil.RespondInternalError(c)
		return
	}

	httputil.RespondNoContent(c)
}

func (h *VoucherHandler) ListVouchers(c *gin.Context) {
	deviceID := c.MustGet(auth.ContextKeyDeviceID).(uuid.UUID)

	vouchers, err := h.voucherSvc.GetNewVouchers(c.Request.Context(), deviceID)
	if err != nil {
		h.logger.Error("list vouchers failed", "device_id", deviceID, "error", err)
		httputil.RespondInternalError(c)
		return
	}

	httputil.RespondOK(c, gin.H{"vouchers": vouchers})
}
