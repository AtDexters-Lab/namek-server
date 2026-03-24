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

type DeviceHandler struct {
	deviceSvc    *service.DeviceService
	nexusSvc     *service.NexusService
	domainSvc    *service.DomainService
	voucherSvc   *service.VoucherService
	accountStore *store.AccountStore
	logger       *slog.Logger
}

func NewDeviceHandler(
	deviceSvc *service.DeviceService,
	nexusSvc *service.NexusService,
	domainSvc *service.DomainService,
	voucherSvc *service.VoucherService,
	accountStore *store.AccountStore,
	logger *slog.Logger,
) *DeviceHandler {
	return &DeviceHandler{
		deviceSvc:    deviceSvc,
		nexusSvc:     nexusSvc,
		domainSvc:    domainSvc,
		voucherSvc:   voucherSvc,
		accountStore: accountStore,
		logger:       logger,
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

	aliasDomains, err := h.domainSvc.GetDeviceAliasDomains(c.Request.Context(), d.ID)
	if err != nil {
		h.logger.Error("failed to get alias domains", "device_id", d.ID, "error", err)
		aliasDomains = []string{}
	}
	if aliasDomains == nil {
		aliasDomains = []string{}
	}

	// Derive recovery status from account
	recoveryStatus := "active"
	account, err := h.accountStore.GetByID(c.Request.Context(), d.AccountID)
	if err == nil {
		switch {
		case account.Status == model.AccountStatusPendingRecovery:
			recoveryStatus = "pending_recovery"
		case account.DissolvedAt != nil:
			recoveryStatus = "standalone"
		}
	}

	resp := gin.H{
		"device_id":          d.ID,
		"hostname":           d.Hostname,
		"custom_hostname":    d.CustomHostname,
		"alias_domains":      aliasDomains,
		"status":             d.Status,
		"identity_class":     d.IdentityClass,
		"trust_level":        d.TrustLevel,
		"issuer_fingerprint": d.IssuerFingerprint,
		"os_version":         d.OSVersion,
		"account_id":         d.AccountID,
		"recovery_status":    recoveryStatus,
		"nexus_endpoints":    endpoints,
	}

	// Conditionally include voucher data (optimization: only query when device
	// is involved in voucher exchange, indicated by VoucherPendingSince)
	if d.VoucherPendingSince != nil {
		pendingReqs, err := h.voucherSvc.GetPendingRequests(c.Request.Context(), d.ID)
		if err != nil {
			h.logger.Error("failed to get pending voucher requests", "device_id", d.ID, "error", err)
		} else if len(pendingReqs) > 0 {
			resp["pending_voucher_requests"] = pendingReqs
		}

		newVouchers, err := h.voucherSvc.GetNewVouchers(c.Request.Context(), d.ID)
		if err != nil {
			h.logger.Error("failed to get new vouchers", "device_id", d.ID, "error", err)
		} else if len(newVouchers) > 0 {
			resp["new_vouchers"] = newVouchers
		}
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
