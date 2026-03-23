package handler

import (
	"log/slog"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/AtDexters-Lab/namek-server/internal/httputil"
	"github.com/AtDexters-Lab/namek-server/internal/model"
	"github.com/AtDexters-Lab/namek-server/internal/service"
	"github.com/AtDexters-Lab/namek-server/internal/store"
)

type RecoveryHandler struct {
	recoverySvc   *service.RecoveryService
	recoveryStore *store.RecoveryStore
	accountStore  *store.AccountStore
	auditStore    *store.AuditStore
	logger        *slog.Logger
}

func NewRecoveryHandler(
	recoverySvc *service.RecoveryService,
	recoveryStore *store.RecoveryStore,
	accountStore *store.AccountStore,
	auditStore *store.AuditStore,
	logger *slog.Logger,
) *RecoveryHandler {
	return &RecoveryHandler{
		recoverySvc:   recoverySvc,
		recoveryStore: recoveryStore,
		accountStore:  accountStore,
		auditStore:    auditStore,
		logger:        logger,
	}
}

func (h *RecoveryHandler) ListPendingAccounts(c *gin.Context) {
	accountIDs, err := h.recoveryStore.ListPendingRecoveryAccounts(c.Request.Context())
	if err != nil {
		h.logger.Error("list pending recovery accounts failed", "error", err)
		httputil.RespondInternalError(c)
		return
	}

	type accountSummary struct {
		AccountID       uuid.UUID `json:"account_id"`
		DeviceCount     int       `json:"device_count"`
		AttributedCount int       `json:"attributed_count"`
	}

	results := make([]accountSummary, 0, len(accountIDs))
	for _, id := range accountIDs {
		deviceCount, _ := h.accountStore.CountDevices(c.Request.Context(), id)
		attributedCount, _ := h.recoveryStore.CountAttributedByAccount(c.Request.Context(), id)
		results = append(results, accountSummary{
			AccountID:       id,
			DeviceCount:     deviceCount,
			AttributedCount: attributedCount,
		})
	}

	httputil.RespondOK(c, gin.H{"accounts": results})
}

func (h *RecoveryHandler) GetAccountStatus(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		httputil.RespondBadRequest(c, "invalid account id")
		return
	}

	account, err := h.accountStore.GetByID(c.Request.Context(), id)
	if err != nil {
		httputil.RespondNotFound(c, "account not found")
		return
	}

	claims, err := h.recoveryStore.GetByAccount(c.Request.Context(), id)
	if err != nil {
		h.logger.Error("get claims failed", "account_id", id, "error", err)
		httputil.RespondInternalError(c)
		return
	}

	deviceCount, _ := h.accountStore.CountDevices(c.Request.Context(), id)
	attributedCount, _ := h.recoveryStore.CountAttributedByAccount(c.Request.Context(), id)

	httputil.RespondOK(c, gin.H{
		"account_id":        id,
		"status":            account.Status,
		"recovery_deadline": account.RecoveryDeadline,
		"device_count":      deviceCount,
		"attributed_count":  attributedCount,
		"total_claims":      len(claims),
	})
}

func (h *RecoveryHandler) OverrideAccount(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		httputil.RespondBadRequest(c, "invalid account id")
		return
	}

	account, err := h.accountStore.GetByID(c.Request.Context(), id)
	if err != nil {
		httputil.RespondNotFound(c, "account not found")
		return
	}

	if account.Status != model.AccountStatusPendingRecovery {
		httputil.RespondBadRequest(c, "account is not in pending_recovery state")
		return
	}

	if err := h.accountStore.UpdateStatus(c.Request.Context(), id, model.AccountStatusActive); err != nil {
		h.logger.Error("override account failed", "account_id", id, "error", err)
		httputil.RespondInternalError(c)
		return
	}

	h.auditStore.LogAction(c.Request.Context(), model.ActorTypeOperator, "operator",
		"recovery.override", "account", strPtr(id.String()),
		map[string]string{"action": "promote"}, nil)

	httputil.RespondOK(c, gin.H{"status": "active"})
}

func (h *RecoveryHandler) DissolveAccount(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		httputil.RespondBadRequest(c, "invalid account id")
		return
	}

	account, err := h.accountStore.GetByID(c.Request.Context(), id)
	if err != nil {
		httputil.RespondNotFound(c, "account not found")
		return
	}

	if account.Status != model.AccountStatusPendingRecovery {
		httputil.RespondBadRequest(c, "account is not in pending_recovery state")
		return
	}

	// Delegate to service which handles full dissolution (device splitting)
	h.recoverySvc.DissolveAccount(c.Request.Context(), id)

	h.auditStore.LogAction(c.Request.Context(), model.ActorTypeOperator, "operator",
		"recovery.account_dissolved", "account", strPtr(id.String()),
		map[string]string{"action": "operator_dissolve"}, nil)

	httputil.RespondOK(c, gin.H{"status": "dissolved"})
}

func strPtr(s string) *string {
	return &s
}
