package handler

import (
	"errors"
	"log/slog"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/AtDexters-Lab/namek-server/internal/auth"
	"github.com/AtDexters-Lab/namek-server/internal/httputil"
	"github.com/AtDexters-Lab/namek-server/internal/service"
	"github.com/AtDexters-Lab/namek-server/internal/store"
)

type ACMEHandler struct {
	acmeSvc *service.ACMEService
	logger  *slog.Logger
}

func NewACMEHandler(acmeSvc *service.ACMEService, logger *slog.Logger) *ACMEHandler {
	return &ACMEHandler{
		acmeSvc: acmeSvc,
		logger:  logger,
	}
}

type createChallengeRequest struct {
	Digest   string `json:"digest" binding:"required"`
	Hostname string `json:"hostname"`
}

func (h *ACMEHandler) CreateChallenge(c *gin.Context) {
	var req createChallengeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httputil.RespondBadRequest(c, "invalid request body")
		return
	}

	deviceID := c.MustGet(auth.ContextKeyDeviceID).(uuid.UUID)

	resp, err := h.acmeSvc.CreateChallenge(c.Request.Context(), service.CreateChallengeRequest{
		DeviceID: deviceID,
		Digest:   req.Digest,
		Hostname: req.Hostname,
	})
	if err != nil {
		var validationErr *service.ErrValidation
		if errors.As(err, &validationErr) {
			httputil.RespondBadRequest(c, validationErr.Message)
			return
		}
		h.logger.Error("failed to create acme challenge", "device_id", deviceID, "error", err)
		httputil.RespondInternalError(c)
		return
	}

	httputil.RespondCreated(c, resp)
}

func (h *ACMEHandler) DeleteChallenge(c *gin.Context) {
	challengeIDStr := c.Param("id")
	challengeID, err := uuid.Parse(challengeIDStr)
	if err != nil {
		httputil.RespondBadRequest(c, "invalid challenge id")
		return
	}

	deviceID := c.MustGet(auth.ContextKeyDeviceID).(uuid.UUID)

	if err := h.acmeSvc.DeleteChallenge(c.Request.Context(), challengeID, deviceID); err != nil {
		if err == store.ErrChallengeNotFound {
			httputil.RespondNotFound(c, "challenge not found")
			return
		}
		h.logger.Error("failed to delete acme challenge", "challenge_id", challengeID, "error", err)
		httputil.RespondInternalError(c)
		return
	}

	httputil.RespondNoContent(c)
}
