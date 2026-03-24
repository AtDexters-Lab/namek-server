package handler

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/AtDexters-Lab/namek-server/internal/httputil"
	"github.com/AtDexters-Lab/namek-server/internal/service"
	"github.com/AtDexters-Lab/namek-server/internal/tpm"
)

type DeviceEnrollHandler struct {
	deviceSvc   *service.DeviceService
	nexusSvc    *service.NexusService
	tpmVerifier tpm.Verifier
	logger      *slog.Logger
}

func NewDeviceEnrollHandler(deviceSvc *service.DeviceService, nexusSvc *service.NexusService, tpmVerifier tpm.Verifier, logger *slog.Logger) *DeviceEnrollHandler {
	return &DeviceEnrollHandler{
		deviceSvc:   deviceSvc,
		nexusSvc:    nexusSvc,
		tpmVerifier: tpmVerifier,
		logger:      logger,
	}
}

type enrollRequest struct {
	EKCert   string `json:"ek_cert" binding:"required"`
	AKParams string `json:"ak_params" binding:"required"`
}

func (h *DeviceEnrollHandler) StartEnroll(c *gin.Context) {
	var req enrollRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httputil.RespondBadRequest(c, "invalid request body")
		return
	}

	ekCertDER, err := base64.StdEncoding.DecodeString(req.EKCert)
	if err != nil {
		httputil.RespondBadRequest(c, "invalid ek_cert encoding")
		return
	}

	akParams, err := base64.StdEncoding.DecodeString(req.AKParams)
	if err != nil {
		httputil.RespondBadRequest(c, "invalid ak_params encoding")
		return
	}

	resp, err := h.deviceSvc.StartEnrollment(c.Request.Context(), service.EnrollRequest{
		EKCertDER: ekCertDER,
		AKParams:  akParams,
		ClientIP:  net.ParseIP(c.ClientIP()),
	}, h.tpmVerifier)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrEnrollmentCapacity):
			httputil.RespondServiceUnavailable(c, "enrollment capacity reached")
		case errors.Is(err, service.ErrDeviceAlreadyExists):
			httputil.RespondConflict(c, "device already enrolled")
		default:
			h.logger.Error("enrollment start failed", "error", err)
			httputil.RespondInternalError(c)
		}
		return
	}

	httputil.RespondOK(c, gin.H{
		"nonce":          resp.Nonce,
		"enc_credential": base64.StdEncoding.EncodeToString(resp.EncCredential),
	})
}

type attestRequest struct {
	Nonce          string                `json:"nonce" binding:"required"`
	Secret         string                `json:"secret" binding:"required"`
	Quote          string                `json:"quote" binding:"required"`
	OSVersion      string                `json:"os_version,omitempty"`
	PCRValues      map[string]string     `json:"pcr_values,omitempty"`
	RecoveryBundle *attestRecoveryBundle `json:"recovery_bundle,omitempty"`
}

type attestRecoveryBundle struct {
	AccountID      string               `json:"account_id" binding:"required"`
	Vouchers       []attestVoucherProof `json:"vouchers" binding:"required,min=1,max=100"`
	CustomHostname string               `json:"custom_hostname,omitempty"`
	AliasDomains   []string             `json:"alias_domains,omitempty"`
}

type attestVoucherProof struct {
	Data              string `json:"data" binding:"required"`
	Quote             string `json:"quote" binding:"required"`
	IssuerAKPublicKey string `json:"issuer_ak_public_key" binding:"required"`
	IssuerEKCert      string `json:"issuer_ek_cert,omitempty"`
}

func (h *DeviceEnrollHandler) CompleteEnroll(c *gin.Context) {
	var req attestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httputil.RespondBadRequest(c, "invalid request body")
		return
	}

	secret, err := base64.StdEncoding.DecodeString(req.Secret)
	if err != nil {
		httputil.RespondBadRequest(c, "invalid secret encoding")
		return
	}

	// Get Nexus endpoints for the response
	endpoints, err := h.nexusSvc.GetActiveEndpoints(c.Request.Context())
	if err != nil {
		h.logger.Error("failed to get nexus endpoints", "error", err)
		endpoints = []string{}
	}

	// Parse PCR values from hex strings to raw bytes
	var pcrValues map[int][]byte
	if len(req.PCRValues) > 0 {
		pcrValues = make(map[int][]byte, len(req.PCRValues))
		for key, hexVal := range req.PCRValues {
			idx, err := strconv.Atoi(key)
			if err != nil || idx < 0 || idx > 23 {
				httputil.RespondBadRequest(c, "invalid pcr_values key: must be 0-23")
				return
			}
			digest, err := hex.DecodeString(hexVal)
			if err != nil || len(digest) != 32 {
				httputil.RespondBadRequest(c, "invalid pcr_values: each value must be 64 hex chars (32 bytes SHA-256)")
				return
			}
			pcrValues[idx] = digest
		}
	}

	attestReq := service.AttestRequest{
		Nonce:     req.Nonce,
		Secret:    secret,
		QuoteB64:  req.Quote,
		OSVersion: req.OSVersion,
		PCRValues: pcrValues,
		ClientIP:  net.ParseIP(c.ClientIP()),
	}

	// Convert handler-level recovery bundle to service-level
	if req.RecoveryBundle != nil {
		rb := &service.RecoveryBundle{
			AccountID:      req.RecoveryBundle.AccountID,
			CustomHostname: req.RecoveryBundle.CustomHostname,
			AliasDomains:   req.RecoveryBundle.AliasDomains,
		}
		for _, vp := range req.RecoveryBundle.Vouchers {
			rb.Vouchers = append(rb.Vouchers, service.VoucherProof{
				Data:              vp.Data,
				Quote:             vp.Quote,
				IssuerAKPublicKey: vp.IssuerAKPublicKey,
				IssuerEKCert:      vp.IssuerEKCert,
			})
		}
		attestReq.RecoveryBundle = rb
	}

	resp, err := h.deviceSvc.CompleteEnrollment(c.Request.Context(), attestReq, h.tpmVerifier, endpoints)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrPendingNotFound):
			httputil.RespondBadRequest(c, "enrollment expired or not found")
		case errors.Is(err, service.ErrSecretMismatch):
			httputil.RespondUnauthorized(c, "credential verification failed")
		case errors.Is(err, service.ErrQuoteVerification):
			h.logger.Warn("quote verification failed", "error", err)
			httputil.RespondUnauthorized(c, "quote verification failed")
		case errors.Is(err, service.ErrDeviceAlreadyExists):
			httputil.RespondConflict(c, "device already enrolled")
		default:
			h.logger.Error("enrollment completion failed", "error", err)
			httputil.RespondInternalError(c)
		}
		return
	}

	result := gin.H{
		"device_id":       resp.DeviceID,
		"hostname":        resp.Hostname,
		"identity_class":  resp.IdentityClass,
		"trust_level":     resp.TrustLevel,
		"nexus_endpoints": resp.NexusEndpoints,
	}
	if resp.Reenrolled {
		result["reenrolled"] = true
	}
	if len(resp.NexusEndpoints) == 0 {
		result["retry_after_seconds"] = 5
	}

	if resp.Reenrolled {
		httputil.RespondOK(c, result)
	} else {
		httputil.RespondCreated(c, result)
	}
}
