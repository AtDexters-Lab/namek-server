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
	"github.com/AtDexters-Lab/namek-server/internal/store"
)

type DomainHandler struct {
	domainSvc *service.DomainService
	logger    *slog.Logger
}

func NewDomainHandler(domainSvc *service.DomainService, logger *slog.Logger) *DomainHandler {
	return &DomainHandler{
		domainSvc: domainSvc,
		logger:    logger,
	}
}

type registerDomainRequest struct {
	Domain string `json:"domain" binding:"required"`
}

func (h *DomainHandler) RegisterDomain(c *gin.Context) {
	var req registerDomainRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httputil.RespondBadRequest(c, "invalid request body")
		return
	}

	deviceID := c.MustGet(auth.ContextKeyDeviceID).(uuid.UUID)

	ad, err := h.domainSvc.RegisterDomain(c.Request.Context(), deviceID, req.Domain)
	if err != nil {
		h.handleError(c, deviceID, err)
		return
	}

	httputil.RespondCreated(c, ad)
}

func (h *DomainHandler) ListDomains(c *gin.Context) {
	deviceID := c.MustGet(auth.ContextKeyDeviceID).(uuid.UUID)

	domains, err := h.domainSvc.ListDomains(c.Request.Context(), deviceID)
	if err != nil {
		h.logger.Error("failed to list domains", "device_id", deviceID, "error", err)
		httputil.RespondInternalError(c)
		return
	}

	if domains == nil {
		domains = []*model.AccountDomain{}
	}

	httputil.RespondOK(c, gin.H{"domains": domains})
}

func (h *DomainHandler) VerifyDomain(c *gin.Context) {
	domainID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		httputil.RespondBadRequest(c, "invalid domain id")
		return
	}

	deviceID := c.MustGet(auth.ContextKeyDeviceID).(uuid.UUID)

	ad, err := h.domainSvc.VerifyDomain(c.Request.Context(), deviceID, domainID)
	if err != nil {
		h.handleError(c, deviceID, err)
		return
	}

	httputil.RespondOK(c, ad)
}

func (h *DomainHandler) DeleteDomain(c *gin.Context) {
	domainID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		httputil.RespondBadRequest(c, "invalid domain id")
		return
	}

	deviceID := c.MustGet(auth.ContextKeyDeviceID).(uuid.UUID)

	if err := h.domainSvc.DeleteDomain(c.Request.Context(), deviceID, domainID); err != nil {
		h.handleError(c, deviceID, err)
		return
	}

	httputil.RespondNoContent(c)
}

func (h *DomainHandler) ListAssignments(c *gin.Context) {
	domainID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		httputil.RespondBadRequest(c, "invalid domain id")
		return
	}

	deviceID := c.MustGet(auth.ContextKeyDeviceID).(uuid.UUID)

	assignments, err := h.domainSvc.ListAssignments(c.Request.Context(), deviceID, domainID)
	if err != nil {
		h.handleError(c, deviceID, err)
		return
	}

	if assignments == nil {
		assignments = []*model.DomainAssignment{}
	}

	httputil.RespondOK(c, gin.H{"assignments": assignments})
}

type assignDomainRequest struct {
	DeviceIDs []uuid.UUID `json:"device_ids" binding:"required"`
}

func (h *DomainHandler) AssignDomain(c *gin.Context) {
	domainID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		httputil.RespondBadRequest(c, "invalid domain id")
		return
	}

	var req assignDomainRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httputil.RespondBadRequest(c, "invalid request body")
		return
	}

	deviceID := c.MustGet(auth.ContextKeyDeviceID).(uuid.UUID)

	assignments, err := h.domainSvc.AssignDomain(c.Request.Context(), deviceID, domainID, req.DeviceIDs)
	if err != nil {
		h.handleError(c, deviceID, err)
		return
	}

	httputil.RespondOK(c, gin.H{"assignments": assignments})
}

func (h *DomainHandler) UnassignDomain(c *gin.Context) {
	domainID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		httputil.RespondBadRequest(c, "invalid domain id")
		return
	}

	targetDeviceID, err := uuid.Parse(c.Param("device_id"))
	if err != nil {
		httputil.RespondBadRequest(c, "invalid device id")
		return
	}

	deviceID := c.MustGet(auth.ContextKeyDeviceID).(uuid.UUID)

	if err := h.domainSvc.UnassignDomain(c.Request.Context(), deviceID, domainID, targetDeviceID); err != nil {
		h.handleError(c, deviceID, err)
		return
	}

	httputil.RespondNoContent(c)
}

func (h *DomainHandler) handleError(c *gin.Context, deviceID uuid.UUID, err error) {
	var valErr *service.ErrValidation
	if errors.As(err, &valErr) {
		httputil.RespondBadRequest(c, valErr.Message)
		return
	}
	if errors.Is(err, store.ErrDomainNotFound) {
		httputil.RespondNotFound(c, "domain not found")
		return
	}
	if errors.Is(err, store.ErrAssignmentNotFound) {
		httputil.RespondNotFound(c, "assignment not found")
		return
	}
	if errors.Is(err, store.ErrDuplicateDomain) {
		httputil.RespondConflict(c, "domain already registered")
		return
	}

	h.logger.Error("domain operation failed", "device_id", deviceID, "error", err)
	httputil.RespondInternalError(c)
}
