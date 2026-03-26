package api

import (
	"crypto/x509"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/AtDexters-Lab/namek-server/internal/api/handler"
	"github.com/AtDexters-Lab/namek-server/internal/auth"
	"github.com/AtDexters-Lab/namek-server/internal/config"
	"github.com/AtDexters-Lab/namek-server/internal/dns"
	"github.com/AtDexters-Lab/namek-server/internal/service"
	"github.com/AtDexters-Lab/namek-server/internal/store"
	"github.com/AtDexters-Lab/namek-server/internal/token"
	"github.com/AtDexters-Lab/namek-server/internal/tpm"
)

type RouterDeps struct {
	Config      *config.Config
	Logger      *slog.Logger
	NonceStore  *auth.NonceStore
	TPMVerifier tpm.Verifier
	TokenIssuer *token.Issuer
	DeviceSvc   *service.DeviceService
	NexusSvc    *service.NexusService
	TokenSvc    *service.TokenService
	ACMESvc     *service.ACMEService
	DomainSvc   *service.DomainService
	AccountSvc    *service.AccountService
	VoucherSvc    *service.VoucherService
	AuditStore    *store.AuditStore
	DeviceStore      *store.DeviceStore
	AccountStore     *store.AccountStore
	LastSeenBatcher  *store.LastSeenBatcher
	Pool             *pgxpool.Pool
	PowerDNS    *dns.PowerDNSClient
}

func NewRouter(deps RouterDeps) http.Handler {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	// Trust no proxies by default so c.ClientIP() returns the direct peer IP.
	// This prevents X-Forwarded-For spoofing that would bypass per-IP rate limits.
	r.SetTrustedProxies(nil)
	r.Use(gin.Recovery())
	r.Use(auth.RequestIDMiddleware())
	r.Use(loggerMiddleware(deps.Logger))

	// Handlers
	healthH := handler.NewHealthHandler(deps.Pool)
	nonceH := handler.NewNonceHandler(deps.NonceStore)
	enrollH := handler.NewDeviceEnrollHandler(deps.DeviceSvc, deps.NexusSvc, deps.TPMVerifier, deps.Logger)
	deviceH := handler.NewDeviceHandler(deps.DeviceSvc, deps.NexusSvc, deps.DomainSvc, deps.VoucherSvc, deps.AccountStore, deps.Logger)
	domainH := handler.NewDomainHandler(deps.DomainSvc, deps.Logger)
	accountH := handler.NewAccountHandler(deps.AccountSvc, deps.Logger)
	voucherH := handler.NewVoucherHandler(deps.VoucherSvc, deps.Logger)
	tokenH := handler.NewTokenHandler(deps.TokenSvc, deps.Logger)
	verifyH := handler.NewVerifyHandler(deps.TokenSvc)
	nexusH := handler.NewNexusRegisterHandler(deps.NexusSvc, deps.Logger)
	acmeH := handler.NewACMEHandler(deps.ACMESvc, deps.Logger)

	// System endpoints (no auth)
	r.GET("/health", healthH.Health)
	r.GET("/ready", healthH.Ready)

	v1 := r.Group("/api/v1")

	// Enrollment rate limiting (tight: protects TPM credential challenge)
	enrollRL := v1.Group("/")
	enrollRL.Use(auth.RateLimit(
		deps.Config.Enrollment.RateLimitPerSecond,
		deps.Config.Enrollment.BurstPerSecond,
		deps.Config.Enrollment.RateLimitPerIPPerSecond,
		deps.Config.Enrollment.BurstPerIPPerSecond,
	))
	{
		enrollRL.POST("/devices/enroll", enrollH.StartEnroll)
		enrollRL.POST("/devices/enroll/attest", enrollH.CompleteEnroll)
	}

	// Nonce rate limiting (generous: called on every authenticated request)
	nonceRL := v1.Group("/")
	nonceRL.Use(auth.RateLimit(
		deps.Config.Nonce.RateLimitPerSecond,
		deps.Config.Nonce.BurstPerSecond,
		deps.Config.Nonce.RateLimitPerIPPerSecond,
		deps.Config.Nonce.BurstPerIPPerSecond,
	))
	{
		nonceRL.GET("/nonce", nonceH.GetNonce)
	}

	// Device TPM-authenticated endpoints with per-device rate limiting
	deviceAuth := v1.Group("/")
	deviceAuth.Use(auth.DeviceTPMAuth(
		deps.DeviceStore,
		deps.NonceStore,
		deps.TPMVerifier,
		deps.LastSeenBatcher,
		deps.Logger,
	))
	deviceAuth.Use(auth.DeviceRateLimit(
		deps.Config.DeviceRateLimit.MutationPerMin,
		deps.Config.DeviceRateLimit.MutationBurst,
		deps.Config.DeviceRateLimit.ReadPerMin,
		deps.Config.DeviceRateLimit.ReadBurst,
	))
	{
		deviceAuth.GET("/devices/me", deviceH.GetMe)
		deviceAuth.PATCH("/devices/me/hostname", deviceH.UpdateHostname)
		deviceAuth.POST("/tokens/nexus", tokenH.IssueNexusToken)
		deviceAuth.POST("/acme/challenges", acmeH.CreateChallenge)
		deviceAuth.DELETE("/acme/challenges/:id", acmeH.DeleteChallenge)

		// Account management
		deviceAuth.POST("/accounts/invite", accountH.CreateInvite)
		deviceAuth.POST("/accounts/join", accountH.JoinAccount)
		deviceAuth.DELETE("/accounts/leave", accountH.LeaveAccount)

		// Voucher exchange
		deviceAuth.POST("/vouchers/sign", voucherH.SignVoucher)
		deviceAuth.GET("/vouchers", voucherH.ListVouchers)

		// Domain management with tighter per-device rate limiting (stacks with
		// the parent deviceAuth limiter — a request consumes from both buckets)
		domainRoutes := deviceAuth.Group("/domains")
		domainRoutes.Use(auth.DeviceRateLimit(10, 5, 30, 10))
		{
			domainRoutes.POST("", domainH.RegisterDomain)
			domainRoutes.GET("", domainH.ListDomains)
			domainRoutes.POST("/:id/verify", domainH.VerifyDomain)
			domainRoutes.DELETE("/:id", domainH.DeleteDomain)
			domainRoutes.GET("/:id/assignments", domainH.ListAssignments)
			domainRoutes.POST("/:id/assignments", domainH.AssignDomain)
			domainRoutes.DELETE("/:id/assignments/:device_id", domainH.UnassignDomain)
		}
	}

	// Load Nexus client CA: explicit file if configured, otherwise system cert pool.
	// When an explicit file is set but fails to load, clientCAs stays nil (503 on
	// registration) — this surfaces the misconfiguration instead of silently falling
	// back to the system pool.
	var clientCAs *x509.CertPool
	if deps.Config.Nexus.ClientCACertFile != "" {
		data, err := os.ReadFile(deps.Config.Nexus.ClientCACertFile)
		if err != nil {
			deps.Logger.Error("failed to read nexus client ca cert, nexus registration will be rejected", "error", err)
		} else {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(data) {
				clientCAs = pool
			} else {
				deps.Logger.Error("nexus client ca cert contains no valid PEM blocks, nexus registration will be rejected",
					"file", deps.Config.Nexus.ClientCACertFile)
			}
		}
	} else {
		systemPool, err := x509.SystemCertPool()
		if err != nil {
			deps.Logger.Error("failed to load system cert pool, nexus mTLS disabled", "error", err)
		} else {
			clientCAs = systemPool
			deps.Logger.Warn("nexus client CA: using system cert pool (no clientCACertFile configured)")
		}
	}

	// Nexus mTLS-authenticated endpoints
	internal := r.Group("/internal/v1")
	internal.Use(auth.NexusAuth(deps.Config, clientCAs, deps.Logger))
	{
		internal.POST("/nexus/register", nexusH.Register)
		internal.POST("/tokens/verify", verifyH.VerifyToken)
	}

	// Operator endpoints (census, recovery, trust) are on the admin listener,
	// not the public HTTPS listener. See internal/admin/webui.go.

	return r
}

func loggerMiddleware(logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		status := c.Writer.Status()
		attrs := []any{
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"status", status,
			"latency_ms", time.Since(start).Milliseconds(),
			"client_ip", c.ClientIP(),
			"request_id", c.GetString(auth.ContextKeyRequestID),
		}

		switch {
		case status >= 500:
			logger.Error("request completed", attrs...)
		case status >= 400:
			logger.Warn("request completed", attrs...)
		default:
			logger.Debug("request completed", attrs...)
		}
	}
}
