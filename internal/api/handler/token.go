package handler

import (
	"log/slog"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/AtDexters-Lab/namek-server/internal/httputil"
	"github.com/AtDexters-Lab/namek-server/internal/auth"
	"github.com/AtDexters-Lab/namek-server/internal/service"
)

type TokenHandler struct {
	tokenSvc *service.TokenService
	logger   *slog.Logger
}

func NewTokenHandler(tokenSvc *service.TokenService, logger *slog.Logger) *TokenHandler {
	return &TokenHandler{
		tokenSvc: tokenSvc,
		logger:   logger,
	}
}

type issueTokenRequest struct {
	Stage        int    `json:"stage" binding:"min=0,max=2"`
	SessionNonce string `json:"session_nonce"`
}

func (h *TokenHandler) IssueNexusToken(c *gin.Context) {
	var req issueTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httputil.RespondBadRequest(c, "invalid request body")
		return
	}

	// Stage 1 and 2 require session_nonce
	if req.Stage > 0 && req.SessionNonce == "" {
		httputil.RespondBadRequest(c, "session_nonce required for stage 1 and 2")
		return
	}

	deviceID := c.MustGet(auth.ContextKeyDeviceID).(uuid.UUID)

	tokenStr, err := h.tokenSvc.IssueNexusToken(c.Request.Context(), service.IssueTokenRequest{
		DeviceID:     deviceID,
		Stage:        req.Stage,
		SessionNonce: req.SessionNonce,
	})
	if err != nil {
		h.logger.Error("failed to issue nexus token", "device_id", deviceID, "error", err)
		httputil.RespondInternalError(c)
		return
	}

	httputil.RespondOK(c, gin.H{"token": tokenStr})
}
