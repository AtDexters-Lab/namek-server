package handler

import (
	"io"
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
	Region *string `json:"region"`
}

func (h *NexusRegisterHandler) Register(c *gin.Context) {
	var req nexusRegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Empty body is OK (region is optional), but malformed JSON is not
		if err != io.EOF {
			httputil.RespondBadRequest(c, "invalid request body")
			return
		}
	}

	hostname, exists := c.Get("nexus_hostname")
	if !exists {
		httputil.RespondInternalError(c)
		return
	}

	resp, err := h.nexusSvc.Register(c.Request.Context(), service.RegisterNexusRequest{
		Hostname: hostname.(string),
		Region:   req.Region,
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
