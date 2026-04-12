package handler

import (
	"errors"
	"log/slog"
	"net"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/AtDexters-Lab/namek-server/internal/auth"
	"github.com/AtDexters-Lab/namek-server/internal/httputil"
	"github.com/AtDexters-Lab/namek-server/internal/service"
)

// DeviceHeartbeatHandler backs POST /api/v1/devices/me/heartbeat. Devices in
// first-time setup mode post their LAN IPs here so that piccolospace.com/setup
// can surface them to a caller on the same public IP. TPM-authenticated via
// the existing deviceAuth group.
type DeviceHeartbeatHandler struct {
	deviceSvc *service.DeviceService
	logger    *slog.Logger
}

func NewDeviceHeartbeatHandler(deviceSvc *service.DeviceService, logger *slog.Logger) *DeviceHeartbeatHandler {
	return &DeviceHeartbeatHandler{deviceSvc: deviceSvc, logger: logger}
}

type heartbeatRequest struct {
	// LANIPs is required for ongoing (setup_complete=false) heartbeats but
	// optional when SetupComplete=true — the terminal heartbeat just needs to
	// clear the row. Service-layer validation enforces the conditional
	// requirement (see DeviceService.UpdateSetupHeartbeat).
	LANIPs        []string `json:"lan_ips" binding:"omitempty,max=10,dive,ip"`
	SetupComplete bool     `json:"setup_complete"`
}

func (h *DeviceHeartbeatHandler) Heartbeat(c *gin.Context) {
	deviceID := c.MustGet(auth.ContextKeyDeviceID).(uuid.UUID)
	clientIP := net.ParseIP(c.ClientIP())

	var req heartbeatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httputil.RespondBadRequest(c, err.Error())
		return
	}

	ctx := c.Request.Context()
	if err := h.deviceSvc.UpdateSetupHeartbeat(ctx, deviceID, clientIP, req.LANIPs, req.SetupComplete); err != nil {
		if errors.Is(err, service.ErrInvalidLANIP) {
			httputil.RespondBadRequest(c, err.Error())
			return
		}
		h.logger.Error("setup heartbeat failed", "device_id", deviceID, "error", err)
		httputil.RespondInternalError(c)
		return
	}
	c.Status(204)
}
