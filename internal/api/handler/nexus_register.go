package handler

import (
	"log/slog"

	"github.com/gin-gonic/gin"

	"github.com/AtDexters-Lab/namek-server/internal/httputil"
	"github.com/AtDexters-Lab/namek-server/internal/service"
)

type NexusRegisterHandler struct {
	nexusSvc *service.NexusService
	logger   *slog.Logger
}

func NewNexusRegisterHandler(nexusSvc *service.NexusService, logger *slog.Logger) *NexusRegisterHandler {
	return &NexusRegisterHandler{
		nexusSvc: nexusSvc,
		logger:   logger,
	}
}

type nexusRegisterRequest struct {
	Region      *string `json:"region"`
	BackendPort int     `json:"backendPort" binding:"required"`
}

func (h *NexusRegisterHandler) Register(c *gin.Context) {
	var req nexusRegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httputil.RespondBadRequest(c, "invalid request body")
		return
	}

	if req.BackendPort < 1 || req.BackendPort > 65535 {
		httputil.RespondBadRequest(c, "backendPort must be between 1 and 65535")
		return
	}

	hostname, exists := c.Get("nexus_hostname")
	if !exists {
		httputil.RespondInternalError(c)
		return
	}

	resp, err := h.nexusSvc.Register(c.Request.Context(), service.RegisterNexusRequest{
		Hostname:    hostname.(string),
		Region:      req.Region,
		BackendPort: req.BackendPort,
	})
	if err != nil {
		h.logger.Error("nexus registration failed",
			"hostname", hostname,
			"error", err,
		)
		httputil.RespondInternalError(c)
		return
	}

	httputil.RespondOK(c, resp)
}
