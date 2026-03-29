package handler

import (
	"errors"
	"log/slog"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/AtDexters-Lab/namek-server/internal/httputil"
	"github.com/AtDexters-Lab/namek-server/internal/model"
	"github.com/AtDexters-Lab/namek-server/internal/service"
	"github.com/AtDexters-Lab/namek-server/internal/store"
)

type CensusHandler struct {
	censusStore *store.CensusStore
	deviceStore *store.DeviceStore
	auditStore  *store.AuditStore
	censusSvc   *service.CensusService
	logger      *slog.Logger
}

func NewCensusHandler(censusStore *store.CensusStore, deviceStore *store.DeviceStore, auditStore *store.AuditStore, censusSvc *service.CensusService, logger *slog.Logger) *CensusHandler {
	return &CensusHandler{
		censusStore: censusStore,
		deviceStore: deviceStore,
		auditStore:  auditStore,
		censusSvc:   censusSvc,
		logger:      logger,
	}
}

func (h *CensusHandler) ListIssuers(c *gin.Context) {
	var tierFilter *string
	if tier := c.Query("tier"); tier != "" {
		tierFilter = &tier
	}
	issuers, err := h.censusStore.ListIssuers(c.Request.Context(), tierFilter)
	if err != nil {
		h.logger.Error("list issuers failed", "error", err)
		httputil.RespondInternalError(c)
		return
	}
	if issuers == nil {
		issuers = []model.EKIssuerCensus{}
	}
	httputil.RespondOK(c, gin.H{"issuers": issuers})
}

func (h *CensusHandler) GetIssuer(c *gin.Context) {
	fp := c.Param("fingerprint")
	issuer, err := h.censusStore.GetIssuerByFingerprint(c.Request.Context(), fp)
	if err != nil {
		if errors.Is(err, store.ErrIssuerNotFound) {
			httputil.RespondNotFound(c, "issuer not found")
		} else {
			h.logger.Error("get issuer failed", "error", err)
			httputil.RespondInternalError(c)
		}
		return
	}

	observations, err := h.censusStore.GetIssuerObservations(c.Request.Context(), fp)
	if err != nil {
		h.logger.Error("get observations failed", "error", err)
		observations = []model.EKIssuerObservation{}
	}
	if observations == nil {
		observations = []model.EKIssuerObservation{}
	}

	httputil.RespondOK(c, gin.H{
		"issuer":       issuer,
		"observations": observations,
	})
}

type flagRequest struct {
	Flagged bool   `json:"flagged"`
	Reason  string `json:"reason,omitempty"`
}

func (h *CensusHandler) FlagIssuer(c *gin.Context) {
	fp := c.Param("fingerprint")
	var req flagRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httputil.RespondBadRequest(c, "invalid request body")
		return
	}

	var err error
	if req.Flagged {
		err = h.censusStore.FlagIssuer(c.Request.Context(), fp, req.Reason)
	} else {
		err = h.censusStore.UnflagIssuer(c.Request.Context(), fp)
	}
	if err != nil {
		h.logger.Error("flag issuer failed", "error", err)
		httputil.RespondInternalError(c)
		return
	}

	h.auditStore.LogAction(c.Request.Context(), model.ActorTypeOperator, "operator",
		"issuer.flagged", "ek_issuer_census", &fp,
		map[string]string{"flagged": boolStr(req.Flagged), "reason": req.Reason}, nil)

	httputil.RespondOK(c, gin.H{"status": "ok"})
}

type overrideTierRequest struct {
	Tier string `json:"tier" binding:"required"`
}

func (h *CensusHandler) OverrideIssuerTier(c *gin.Context) {
	fp := c.Param("fingerprint")
	var req overrideTierRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httputil.RespondBadRequest(c, "invalid request body")
		return
	}

	tier := model.IssuerTier(req.Tier)
	switch tier {
	case model.IssuerTierSeed, model.IssuerTierCrowdCorroborated, model.IssuerTierUnverified:
	default:
		httputil.RespondBadRequest(c, "invalid tier: must be seed, crowd_corroborated, or unverified")
		return
	}

	if err := h.censusStore.UpdateIssuerTier(c.Request.Context(), fp, tier); err != nil {
		h.logger.Error("override issuer tier failed", "error", err)
		httputil.RespondInternalError(c)
		return
	}

	h.auditStore.LogAction(c.Request.Context(), model.ActorTypeOperator, "operator",
		"issuer.tier_overridden", "ek_issuer_census", &fp,
		map[string]string{"tier": req.Tier}, nil)

	httputil.RespondOK(c, gin.H{"status": "ok"})
}

func (h *CensusHandler) ListPCRClusters(c *gin.Context) {
	var gkFilter *string
	if gk := c.Query("grouping_key"); gk != "" {
		gkFilter = &gk
	}
	clusters, err := h.censusStore.ListPCRClusters(c.Request.Context(), gkFilter)
	if err != nil {
		h.logger.Error("list pcr clusters failed", "error", err)
		httputil.RespondInternalError(c)
		return
	}
	if clusters == nil {
		clusters = []model.PCRCensus{}
	}
	httputil.RespondOK(c, gin.H{"clusters": clusters})
}

func (h *CensusHandler) GetPCRClusters(c *gin.Context) {
	gk := c.Param("grouping_key")
	clusters, err := h.censusStore.ListPCRClusters(c.Request.Context(), &gk)
	if err != nil {
		h.logger.Error("get pcr clusters failed", "error", err)
		httputil.RespondInternalError(c)
		return
	}
	if clusters == nil {
		clusters = []model.PCRCensus{}
	}
	httputil.RespondOK(c, gin.H{"clusters": clusters})
}

type trustOverrideRequest struct {
	TrustLevel string `json:"trust_level" binding:"required"`
}

func (h *CensusHandler) TrustOverride(c *gin.Context) {
	idStr := c.Param("id")
	deviceID, err := uuid.Parse(idStr)
	if err != nil {
		httputil.RespondBadRequest(c, "invalid device id")
		return
	}

	var req trustOverrideRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httputil.RespondBadRequest(c, "invalid request body")
		return
	}

	tl := model.TrustLevel(req.TrustLevel)
	switch tl {
	case model.TrustLevelStrong, model.TrustLevelStandard, model.TrustLevelProvisional,
		model.TrustLevelSuspicious, model.TrustLevelQuarantine:
	default:
		httputil.RespondBadRequest(c, "invalid trust_level")
		return
	}

	if err := h.deviceStore.UpdateTrustLevel(c.Request.Context(), deviceID, tl); err != nil {
		h.logger.Error("trust override failed", "error", err)
		httputil.RespondInternalError(c)
		return
	}

	h.auditStore.LogAction(c.Request.Context(), model.ActorTypeOperator, "operator",
		"device.trust_overridden", "device", &idStr,
		map[string]string{"trust_level": req.TrustLevel}, nil)

	httputil.RespondOK(c, gin.H{"status": "ok"})
}

func (h *CensusHandler) ClearTrustOverride(c *gin.Context) {
	idStr := c.Param("id")
	deviceID, err := uuid.Parse(idStr)
	if err != nil {
		httputil.RespondBadRequest(c, "invalid device id")
		return
	}

	if err := h.deviceStore.ClearTrustOverride(c.Request.Context(), deviceID); err != nil {
		if errors.Is(err, store.ErrDeviceNotFound) {
			httputil.RespondNotFound(c, "device not found")
		} else {
			h.logger.Error("clear trust override failed", "error", err)
			httputil.RespondInternalError(c)
		}
		return
	}

	// Recompute the system trust level immediately so the device doesn't keep
	// the stale manual value until the next census run.
	device, err := h.deviceStore.GetByID(c.Request.Context(), deviceID)
	if err == nil {
		pcrConsensus := service.EvaluatePCRConsensus(device.PCRValues, device.IssuerFingerprint, device.OSVersion,
			func(gk string, group model.PCRGroup) (string, bool) {
				m, lookupErr := h.censusStore.GetPCRMajority(c.Request.Context(), gk, group)
				if lookupErr != nil || m == nil {
					return "", false
				}
				return m.PCRCompositeHash, true
			})
		newTrust := service.ComputeTrustLevel(device.IdentityClass, pcrConsensus)
		_ = h.deviceStore.UpdateTrustData(c.Request.Context(), deviceID, device.IdentityClass, newTrust,
			device.IssuerFingerprint, device.OSVersion, device.PCRValues)
	}

	h.auditStore.LogAction(c.Request.Context(), model.ActorTypeOperator, "operator",
		"device.trust_override_cleared", "device", &idStr, nil, nil)

	httputil.RespondOK(c, gin.H{"status": "ok"})
}

func (h *CensusHandler) TrustExplain(c *gin.Context) {
	idStr := c.Param("id")
	deviceID, err := uuid.Parse(idStr)
	if err != nil {
		httputil.RespondBadRequest(c, "invalid device id")
		return
	}

	device, err := h.deviceStore.GetByID(c.Request.Context(), deviceID)
	if err != nil {
		if errors.Is(err, store.ErrDeviceNotFound) {
			httputil.RespondNotFound(c, "device not found")
		} else {
			h.logger.Error("get device failed", "error", err)
			httputil.RespondInternalError(c)
		}
		return
	}

	ekAssessment := gin.H{
		"identity_class": device.IdentityClass,
	}
	if device.IssuerFingerprint != nil {
		ekAssessment["issuer_fingerprint"] = *device.IssuerFingerprint
		issuer, err := h.censusStore.GetIssuerByFingerprint(c.Request.Context(), *device.IssuerFingerprint)
		if err == nil {
			ekAssessment["issuer_subject"] = issuer.IssuerSubject
			ekAssessment["issuer_tier"] = issuer.Tier
			ekAssessment["structural_compliance_score"] = issuer.StructuralComplianceScore
		}
	}

	// PCR assessment per group
	pcrAssessment := gin.H{}
	for _, group := range model.AllPCRGroups {
		groupKey := service.PCRGroupingKey(group, device.IssuerFingerprint, device.OSVersion)

		entry := gin.H{"status": "unknown", "cluster_size": 0, "group_key": groupKey}
		if groupKey != "" {
			majority, err := h.censusStore.GetPCRMajority(c.Request.Context(), groupKey, group)
			if err == nil && majority != nil {
				if device.PCRValues != nil {
					deviceHash := service.ComputePCRCompositeHash(device.PCRValues, group)
					if deviceHash == majority.PCRCompositeHash {
						entry["status"] = "majority"
					} else {
						entry["status"] = "outlier"
					}
				}
				entry["cluster_size"] = majority.DeviceCount
			}
		}
		pcrAssessment[string(group)] = entry
	}

	httputil.RespondOK(c, gin.H{
		"device_id":      device.ID,
		"trust_level":    device.TrustLevel,
		"overridden":     device.TrustLevelOverride != nil,
		"ek_assessment":  ekAssessment,
		"pcr_assessment": pcrAssessment,
	})
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
