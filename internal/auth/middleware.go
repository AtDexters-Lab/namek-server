package auth

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/AtDexters-Lab/namek-server/internal/metrics"

	"github.com/AtDexters-Lab/namek-server/internal/config"
	"github.com/AtDexters-Lab/namek-server/internal/httputil"
	"github.com/AtDexters-Lab/namek-server/internal/model"
	"github.com/AtDexters-Lab/namek-server/internal/ratelimit"
	"github.com/AtDexters-Lab/namek-server/internal/store"
	"github.com/AtDexters-Lab/namek-server/internal/tpm"
)

// ContextKeys for values stored in Gin context
const (
	ContextKeyDeviceID = "device_id"
	ContextKeyDevice   = "device"
	ContextKeyRequestID = "request_id"
)

// RequestIDMiddleware adds a unique request ID to each request.
func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := uuid.New().String()
		c.Set(ContextKeyRequestID, id)
		c.Header("X-Request-ID", id)
		c.Next()
	}
}

// DeviceTPMAuth validates per-request TPM attestation.
// If lastSeenBatcher is non-nil, last-seen updates are batched instead of fire-and-forget.
func DeviceTPMAuth(deviceStore *store.DeviceStore, nonceStore *NonceStore, verifier tpm.Verifier, lastSeenBatcher *store.LastSeenBatcher, logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		deviceIDStr := c.GetHeader("X-Device-ID")
		nonce := c.GetHeader("X-Nonce")
		quoteB64 := c.GetHeader("X-TPM-Quote")

		if deviceIDStr == "" || nonce == "" || quoteB64 == "" {
			httputil.RespondUnauthorized(c, "missing authentication headers")
			c.Abort()
			return
		}

		deviceID, err := uuid.Parse(deviceIDStr)
		if err != nil {
			httputil.RespondUnauthorized(c, "invalid device id")
			c.Abort()
			return
		}

		// Consume nonce (one-time use)
		if err := nonceStore.Consume(nonce); err != nil {
			httputil.RespondUnauthorized(c, "invalid or expired nonce")
			c.Abort()
			return
		}

		// Look up device
		device, err := deviceStore.GetByID(c.Request.Context(), deviceID)
		if err != nil {
			if errors.Is(err, store.ErrDeviceNotFound) {
				httputil.RespondUnauthorized(c, "device not found")
			} else {
				logger.Error("device lookup failed", "device_id", deviceID, "error", err)
				httputil.RespondInternalError(c)
			}
			c.Abort()
			return
		}

		// Check device status
		if device.Status != model.DeviceStatusActive {
			httputil.RespondForbidden(c, "device is "+string(device.Status))
			c.Abort()
			return
		}

		// Verify TPM quote
		nonceBytes, err := base64.RawURLEncoding.DecodeString(nonce)
		if err != nil {
			logger.Warn("nonce decode failed", "device_id", deviceID, "error", err)
			httputil.RespondUnauthorized(c, "invalid nonce encoding")
			c.Abort()
			return
		}
		if _, err := verifier.VerifyQuote(device.AKPublicKey, nonceBytes, quoteB64, nil); err != nil {
			logger.Warn("tpm quote verification failed",
				"device_id", deviceID,
				"error", err,
			)
			httputil.RespondUnauthorized(c, "tpm quote verification failed")
			c.Abort()
			return
		}

		// Update last seen (batched for efficiency, or fire-and-forget as fallback)
		clientIP := net.ParseIP(c.ClientIP())
		if lastSeenBatcher != nil {
			lastSeenBatcher.Record(deviceID, clientIP)
		} else {
			go deviceStore.UpdateLastSeen(context.WithoutCancel(c.Request.Context()), deviceID, clientIP)
		}

		c.Set(ContextKeyDeviceID, deviceID)
		c.Set(ContextKeyDevice, device)
		c.Next()
	}
}

// NexusAuth validates mTLS client certificates for Nexus registration.
func NexusAuth(cfg *config.Config, clientCAs *x509.CertPool, logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.TLS == nil || len(c.Request.TLS.PeerCertificates) == 0 {
			httputil.RespondUnauthorized(c, "client certificate required")
			c.Abort()
			return
		}

		cert := c.Request.TLS.PeerCertificates[0]

		// Verify cert against CA pool (required)
		if clientCAs == nil {
			logger.Error("nexus client ca not configured, rejecting request")
			httputil.RespondServiceUnavailable(c, "nexus authentication not configured")
			c.Abort()
			return
		}
		// Build intermediates pool from the rest of the peer certificate chain
		intermediates := x509.NewCertPool()
		for _, ic := range c.Request.TLS.PeerCertificates[1:] {
			intermediates.AddCert(ic)
		}
		opts := x509.VerifyOptions{
			Roots:         clientCAs,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		}
		if _, err := cert.Verify(opts); err != nil {
			logger.Warn("nexus client cert verification failed", "error", err)
			httputil.RespondUnauthorized(c, "invalid client certificate")
			c.Abort()
			return
		}

		// Check SAN against trusted domain suffixes (label-safe matching).
		// Skip wildcard SANs (e.g. "*.nexus.example.com") since they are not
		// concrete hostnames and would fail DNS resolution in Register.
		var matchedHostname string
		for _, san := range cert.DNSNames {
			if strings.HasPrefix(san, "*") {
				continue
			}
			for _, suffix := range cfg.Nexus.TrustedDomainSuffixes {
				if suffix == "" {
					continue
				}
				// Ensure suffix starts with a dot to prevent partial matches
				// e.g., ".nexus.example.com" should NOT match "evilnexus.example.com"
				safeSuffix := suffix
				if safeSuffix[0] != '.' {
					safeSuffix = "." + safeSuffix
				}
				if strings.HasSuffix(san, safeSuffix) || san == safeSuffix[1:] {
					matchedHostname = san
					break
				}
			}
			if matchedHostname != "" {
				break
			}
		}

		if matchedHostname == "" {
			logger.Warn("nexus cert SAN doesn't match trusted suffixes",
				"sans", cert.DNSNames,
				"trusted", cfg.Nexus.TrustedDomainSuffixes,
			)
			httputil.RespondUnauthorized(c, "certificate SAN not trusted")
			c.Abort()
			return
		}

		c.Set("nexus_hostname", matchedHostname)
		c.Next()
	}
}

// DeviceRateLimit implements per-device rate limiting with separate limits for
// mutations (POST, DELETE) and reads (GET, PATCH, etc.). PATCH is intentionally
// classified as a read — it is idempotent and infrequent (hostname changes).
func DeviceRateLimit(mutPerMin, mutBurst, readPerMin, readBurst int) gin.HandlerFunc {
	mutBuckets := ratelimit.NewBucketMap[uuid.UUID](10000)
	readBuckets := ratelimit.NewBucketMap[uuid.UUID](10000)

	mutRate := float64(mutPerMin) / 60.0
	readRate := float64(readPerMin) / 60.0

	return func(c *gin.Context) {
		deviceIDVal, exists := c.Get(ContextKeyDeviceID)
		if !exists {
			c.Next()
			return
		}
		deviceID := deviceIDVal.(uuid.UUID)

		isMutation := c.Request.Method == "POST" || c.Request.Method == "DELETE"

		var b *ratelimit.Bucket
		if isMutation {
			b = mutBuckets.GetOrCreate(deviceID, mutRate, float64(mutBurst))
		} else {
			b = readBuckets.GetOrCreate(deviceID, readRate, float64(readBurst))
		}

		if !b.TryConsume() {
			metrics.Get().RateLimit.RejectedPerDevice.Add(1)
			c.Header("Retry-After", fmt.Sprintf("%d", b.RetryAfterSecs()))
			httputil.RespondError(c, http.StatusTooManyRequests, "rate limit exceeded")
			c.Abort()
			return
		}

		c.Next()
	}
}

// RateLimit implements global + per-IP token bucket rate limiting.
func RateLimit(globalRPS, globalBurst, perIPRPS, perIPBurst int) gin.HandlerFunc {
	globalBucket := ratelimit.NewBucket(float64(globalRPS), float64(globalBurst))
	ipBuckets := ratelimit.NewBucketMap[string](10000)

	return func(c *gin.Context) {
		// Per-IP rate limit first (avoids wasting a global token on per-IP rejection)
		ip := c.ClientIP()
		ipb := ipBuckets.GetOrCreate(ip, float64(perIPRPS), float64(perIPBurst))
		if !ipb.TryConsume() {
			metrics.Get().RateLimit.RejectedPerIP.Add(1)
			c.Header("Retry-After", fmt.Sprintf("%d", ipb.RetryAfterSecs()))
			httputil.RespondError(c, http.StatusTooManyRequests, "rate limit exceeded")
			c.Abort()
			return
		}

		// Global rate limit
		if !globalBucket.TryConsume() {
			metrics.Get().RateLimit.RejectedGlobal.Add(1)
			c.Header("Retry-After", fmt.Sprintf("%d", globalBucket.RetryAfterSecs()))
			httputil.RespondError(c, http.StatusTooManyRequests, "rate limit exceeded")
			c.Abort()
			return
		}

		c.Next()
	}
}
