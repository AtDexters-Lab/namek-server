package handler

import (
	"errors"
	"log/slog"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/AtDexters-Lab/namek-server/internal/auth"
	"github.com/AtDexters-Lab/namek-server/internal/httputil"
	"github.com/AtDexters-Lab/namek-server/internal/model"
	"github.com/AtDexters-Lab/namek-server/internal/service"
)

type DeviceHandler struct {
	deviceSvc *service.DeviceService
	nexusSvc  *service.NexusService
	logger    *slog.Logger
}

func NewDeviceHandler(deviceSvc *service.DeviceService, nexusSvc *service.NexusService, logger *slog.Logger) *DeviceHandler {
	return &DeviceHandler{
		deviceSvc: deviceSvc,
		nexusSvc:  nexusSvc,
		logger:    logger,
	}
}

func (h *DeviceHandler) GetMe(c *gin.Context) {
	device, exists := c.Get(auth.ContextKeyDevice)
	if !exists {
		httputil.RespondInternalError(c)
		return
	}

	d := device.(*model.Device)

	endpoints, err := h.nexusSvc.GetActiveEndpoints(c.Request.Context())
	if err != nil {
		h.logger.Error("failed to get nexus endpoints", "error", err)
		endpoints = []string{}
	}

	resp := gin.H{
		"device_id":       d.ID,
		"hostname":        d.Hostname,
		"custom_hostname": d.CustomHostname,
		"status":          d.Status,
		"identity_class":  d.IdentityClass,
		"nexus_endpoints": endpoints,
	}

	httputil.RespondOK(c, resp)
}

type hostnameRequest struct {
	CustomHostname string `json:"custom_hostname" binding:"required"`
}

func (h *DeviceHandler) UpdateHostname(c *gin.Context) {
	var req hostnameRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httputil.RespondBadRequest(c, "invalid request body")
		return
	}

	deviceID := c.MustGet(auth.ContextKeyDeviceID).(uuid.UUID)

	if err := h.deviceSvc.SetCustomHostname(c.Request.Context(), deviceID, req.CustomHostname); err != nil {
		var valErr *service.ErrValidation
		if errors.As(err, &valErr) {
			httputil.RespondBadRequest(c, valErr.Message)
		} else {
			h.logger.Error("failed to set custom hostname", "device_id", deviceID, "error", err)
			httputil.RespondInternalError(c)
		}
		return
	}

	httputil.RespondOK(c, gin.H{"custom_hostname": req.CustomHostname})
}
