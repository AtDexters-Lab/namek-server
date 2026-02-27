package httputil

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type ErrorResponse struct {
	Error string `json:"error"`
}

func RespondOK(c *gin.Context, data any) {
	c.JSON(http.StatusOK, data)
}

func RespondCreated(c *gin.Context, data any) {
	c.JSON(http.StatusCreated, data)
}

func RespondNoContent(c *gin.Context) {
	c.Status(http.StatusNoContent)
}

func RespondError(c *gin.Context, status int, msg string) {
	c.JSON(status, ErrorResponse{Error: msg})
}

func RespondBadRequest(c *gin.Context, msg string) {
	RespondError(c, http.StatusBadRequest, msg)
}

func RespondUnauthorized(c *gin.Context, msg string) {
	RespondError(c, http.StatusUnauthorized, msg)
}

func RespondForbidden(c *gin.Context, msg string) {
	RespondError(c, http.StatusForbidden, msg)
}

func RespondNotFound(c *gin.Context, msg string) {
	RespondError(c, http.StatusNotFound, msg)
}

func RespondConflict(c *gin.Context, msg string) {
	RespondError(c, http.StatusConflict, msg)
}

func RespondInternalError(c *gin.Context) {
	RespondError(c, http.StatusInternalServerError, "internal server error")
}

func RespondServiceUnavailable(c *gin.Context, msg string) {
	RespondError(c, http.StatusServiceUnavailable, msg)
}
