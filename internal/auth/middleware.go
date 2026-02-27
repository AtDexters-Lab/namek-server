package auth

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/AtDexters-Lab/namek-server/internal/config"
	"github.com/AtDexters-Lab/namek-server/internal/httputil"
	"github.com/AtDexters-Lab/namek-server/internal/model"
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
func DeviceTPMAuth(deviceStore *store.DeviceStore, nonceStore *NonceStore, verifier tpm.Verifier, logger *slog.Logger) gin.HandlerFunc {
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
		if err := verifier.VerifyQuote(device.AKPublicKey, nonce, quoteB64); err != nil {
			logger.Warn("tpm quote verification failed",
				"device_id", deviceID,
				"error", err,
			)
			httputil.RespondUnauthorized(c, "tpm quote verification failed")
			c.Abort()
			return
		}

		// Update last seen (best effort, detached context to survive request completion)
		clientIP := net.ParseIP(c.ClientIP())
		go deviceStore.UpdateLastSeen(context.WithoutCancel(c.Request.Context()), deviceID, clientIP)

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
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
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

// RateLimit implements a simple token bucket rate limiter with periodic cleanup.
func RateLimit(globalRPS, perIPRPS int) gin.HandlerFunc {
	const staleAfter = 5 * time.Minute

	type bucket struct {
		tokens    float64
		lastCheck time.Time
	}

	var mu sync.Mutex
	ipBuckets := make(map[string]*bucket)
	globalBucket := &bucket{tokens: float64(globalRPS), lastCheck: time.Now()}
	lastCleanup := time.Now()

	refill := func(b *bucket, rate int) {
		now := time.Now()
		elapsed := now.Sub(b.lastCheck).Seconds()
		b.tokens += elapsed * float64(rate)
		if b.tokens > float64(rate) {
			b.tokens = float64(rate)
		}
		b.lastCheck = now
	}

	return func(c *gin.Context) {
		mu.Lock()

		// Periodic cleanup of stale IP buckets
		if time.Since(lastCleanup) > time.Minute {
			now := time.Now()
			for ip, b := range ipBuckets {
				if now.Sub(b.lastCheck) > staleAfter {
					delete(ipBuckets, ip)
				}
			}
			lastCleanup = now
		}

		// Global rate limit
		refill(globalBucket, globalRPS)
		if globalBucket.tokens < 1 {
			mu.Unlock()
			c.Header("Retry-After", "1")
			httputil.RespondError(c, http.StatusTooManyRequests, "rate limit exceeded")
			c.Abort()
			return
		}

		// Per-IP rate limit
		ip := c.ClientIP()
		ipb, ok := ipBuckets[ip]
		if !ok {
			ipb = &bucket{tokens: float64(perIPRPS), lastCheck: time.Now()}
			ipBuckets[ip] = ipb
		}
		refill(ipb, perIPRPS)

		if ipb.tokens < 1 {
			mu.Unlock()
			c.Header("Retry-After", "1")
			httputil.RespondError(c, http.StatusTooManyRequests, "rate limit exceeded")
			c.Abort()
			return
		}

		globalBucket.tokens--
		ipb.tokens--
		mu.Unlock()

		c.Next()
	}
}
