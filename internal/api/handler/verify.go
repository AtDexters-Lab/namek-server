package handler

import (
	"github.com/gin-gonic/gin"

	"github.com/AtDexters-Lab/namek-server/internal/httputil"
	"github.com/AtDexters-Lab/namek-server/internal/service"
)

type VerifyHandler struct {
	tokenSvc *service.TokenService
}

func NewVerifyHandler(tokenSvc *service.TokenService) *VerifyHandler {
	return &VerifyHandler{tokenSvc: tokenSvc}
}

type verifyRequest struct {
	Token string `json:"token" binding:"required"`
}

func (h *VerifyHandler) VerifyToken(c *gin.Context) {
	var req verifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httputil.RespondBadRequest(c, "invalid request body")
		return
	}

	result := h.tokenSvc.VerifyToken(req.Token)
	httputil.RespondOK(c, result)
}
