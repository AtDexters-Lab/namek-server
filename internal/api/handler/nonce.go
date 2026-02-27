package handler

import (
	"github.com/gin-gonic/gin"

	"github.com/AtDexters-Lab/namek-server/internal/httputil"
	"github.com/AtDexters-Lab/namek-server/internal/auth"
)

type NonceHandler struct {
	nonceStore *auth.NonceStore
}

func NewNonceHandler(nonceStore *auth.NonceStore) *NonceHandler {
	return &NonceHandler{nonceStore: nonceStore}
}

func (h *NonceHandler) GetNonce(c *gin.Context) {
	nonce, expiresAt, err := h.nonceStore.Generate()
	if err != nil {
		if err == auth.ErrNonceCapacity {
			httputil.RespondServiceUnavailable(c, "nonce store at capacity")
			return
		}
		httputil.RespondInternalError(c)
		return
	}

	httputil.RespondOK(c, gin.H{
		"nonce":      nonce,
		"expires_at": expiresAt,
	})
}
