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

type AccountHandler struct {
	accountSvc *service.AccountService
	logger     *slog.Logger
}

func NewAccountHandler(accountSvc *service.AccountService, logger *slog.Logger) *AccountHandler {
	return &AccountHandler{accountSvc: accountSvc, logger: logger}
}

func (h *AccountHandler) CreateInvite(c *gin.Context) {
	deviceID := c.MustGet(auth.ContextKeyDeviceID).(uuid.UUID)

	resp, err := h.accountSvc.CreateInvite(c.Request.Context(), deviceID)
	if err != nil {
		var valErr *service.ErrValidation
		if errors.As(err, &valErr) {
			httputil.RespondBadRequest(c, valErr.Message)
			return
		}
		h.logger.Error("create invite failed", "device_id", deviceID, "error", err)
		httputil.RespondInternalError(c)
		return
	}

	httputil.RespondCreated(c, resp)
}

type joinRequest struct {
	InviteCode string `json:"invite_code" binding:"required"`
}

func (h *AccountHandler) JoinAccount(c *gin.Context) {
	deviceID := c.MustGet(auth.ContextKeyDeviceID).(uuid.UUID)

	var req joinRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httputil.RespondBadRequest(c, "invalid request body")
		return
	}

	if err := h.accountSvc.JoinAccount(c.Request.Context(), deviceID, req.InviteCode); err != nil {
		var valErr *service.ErrValidation
		if errors.As(err, &valErr) {
			httputil.RespondBadRequest(c, valErr.Message)
			return
		}
		h.logger.Error("join account failed", "device_id", deviceID, "error", err)
		httputil.RespondInternalError(c)
		return
	}

	httputil.RespondNoContent(c)
}

func (h *AccountHandler) LeaveAccount(c *gin.Context) {
	deviceID := c.MustGet(auth.ContextKeyDeviceID).(uuid.UUID)

	if err := h.accountSvc.LeaveAccount(c.Request.Context(), deviceID); err != nil {
		var valErr *service.ErrValidation
		if errors.As(err, &valErr) {
			httputil.RespondBadRequest(c, valErr.Message)
			return
		}
		h.logger.Error("leave account failed", "device_id", deviceID, "error", err)
		httputil.RespondInternalError(c)
		return
	}

	httputil.RespondNoContent(c)
}
