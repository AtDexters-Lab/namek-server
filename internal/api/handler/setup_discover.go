package handler

import (
	"log/slog"
	"net"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/AtDexters-Lab/namek-server/internal/httputil"
	"github.com/AtDexters-Lab/namek-server/internal/metrics"
	"github.com/AtDexters-Lab/namek-server/internal/service"
)

// SetupDiscoverHandler backs GET /api/v1/setup/discover. Unauthenticated but
// CORS-gated and rate-limited. Returns setup-mode devices whose last recorded
// public IP matches the caller's. Empty array on no match — never 404.
type SetupDiscoverHandler struct {
	deviceSvc *service.DeviceService
	ttl       time.Duration
	logger    *slog.Logger
}

func NewSetupDiscoverHandler(deviceSvc *service.DeviceService, ttl time.Duration, logger *slog.Logger) *SetupDiscoverHandler {
	return &SetupDiscoverHandler{deviceSvc: deviceSvc, ttl: ttl, logger: logger}
}

type discoverDeviceOut struct {
	HardwareModel *string  `json:"hardware_model,omitempty"`
	LANIPs        []string `json:"lan_ips"`
}

func (h *SetupDiscoverHandler) Discover(c *gin.Context) {
	// Discover responses vary by caller public IP. Mark them uncacheable so that
	// a future shared cache / CDN / reverse proxy cannot replay one caller's
	// setup-mode device list to another caller. Vary: Origin is already set by
	// SetupDiscoverCORS, but it does not cover IP-based variance.
	c.Header("Cache-Control", "no-store, private")

	callerIP := net.ParseIP(c.ClientIP())
	if callerIP == nil {
		httputil.RespondBadRequest(c, "invalid client ip")
		return
	}

	ctx := c.Request.Context()
	devices, err := h.deviceSvc.DiscoverSetupDevices(ctx, callerIP, h.ttl)
	if err != nil {
		h.logger.Error("setup discover failed", "caller_ip", callerIP.String(), "error", err)
		metrics.Get().SetupDiscover.Errors.Add(1)
		httputil.RespondInternalError(c)
		return
	}

	if len(devices) > 0 {
		metrics.Get().SetupDiscover.Matched.Add(1)
	} else {
		metrics.Get().SetupDiscover.NoMatch.Add(1)
	}

	out := make([]discoverDeviceOut, len(devices))
	for i, d := range devices {
		// Guarantee non-nil slice so the JSON is `[]` not `null`.
		ips := d.LANIPs
		if ips == nil {
			ips = []string{}
		}
		out[i] = discoverDeviceOut{HardwareModel: d.HardwareModel, LANIPs: ips}
	}
	c.JSON(200, gin.H{"devices": out})
}
