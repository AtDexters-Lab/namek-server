package admin

import (
	_ "embed"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/AtDexters-Lab/namek-server/internal/api/handler"
	"github.com/AtDexters-Lab/namek-server/internal/auth"
	"github.com/AtDexters-Lab/namek-server/internal/service"
	"github.com/AtDexters-Lab/namek-server/internal/store"
)

// index.html is powerdns-webui by james-stevens (GPL-3.0).
// Source: https://github.com/james-stevens/powerdns-webui
// Served unmodified; see THIRD-PARTY-NOTICES for license.
//
//go:embed index.html
var indexHTML []byte

//go:embed dashboard.html
var dashboardHTML []byte

// OperatorDeps holds dependencies for operator API endpoints on the admin server.
type OperatorDeps struct {
	CensusStore   *store.CensusStore
	DeviceStore   *store.DeviceStore
	AuditStore    *store.AuditStore
	RecoveryStore *store.RecoveryStore
	AccountStore  *store.AccountStore
	CensusSvc     *service.CensusService
	RecoverySvc   *service.RecoveryService

	// Observability dashboard deps
	NexusStore             *store.NexusStore
	Pool                   *pgxpool.Pool
	NonceStore             *auth.NonceStore
	PendingCounter         PendingCounter
	CensusAnalysisInterval time.Duration
	MaxPendingEnrollments  int
}

// NewHandler returns an http.Handler that serves the powerdns-webui at /,
// reverse-proxies /api/ requests to the PowerDNS API, and mounts operator
// endpoints under /operator/ (census, recovery, trust management).
// adminAddr is the configured listen address (e.g., "127.0.0.1:8056") for CSRF origin validation.
func NewHandler(pdnsAPIURL, pdnsAPIKey string, adminAddr string, logger *slog.Logger, operatorDeps *OperatorDeps) (http.Handler, error) {
	target, err := url.Parse(pdnsAPIURL)
	if err != nil {
		return nil, fmt.Errorf("admin: invalid PowerDNS API URL %q: %w", pdnsAPIURL, err)
	}

	mux := http.NewServeMux()

	serveHTML := func(content []byte) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Content-Length", strconv.Itoa(len(content)))
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'")
			w.Write(content)
		}
	}

	mux.HandleFunc("GET /{$}", serveHTML(indexHTML))
	if operatorDeps != nil {
		mux.HandleFunc("GET /dashboard", serveHTML(dashboardHTML))
	}

	// Return 204 for favicon to avoid proxy noise
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	// Health endpoint
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Reverse proxy /api/ requests to PowerDNS
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.Host = target.Host
			r.Out.Header.Set("X-API-Key", pdnsAPIKey)
		},
		Transport: &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConnsPerHost:   10,
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Error("admin proxy error", "error", err, "path", r.URL.Path)
			http.Error(w, "proxy error", http.StatusBadGateway)
		},
	}
	mux.Handle("/api/", proxy)

	// Operator API endpoints (census, recovery, trust management)
	if operatorDeps != nil {
		gin.SetMode(gin.ReleaseMode)
		g := gin.New()
		g.Use(gin.Recovery())
		// CSRF protection: reject cross-origin mutation requests.
		// Allow origins matching the configured admin address (loopback or internal network).
		allowedOrigins := buildAllowedOrigins(adminAddr)
		g.Use(func(c *gin.Context) {
			if c.Request.Method != "GET" && c.Request.Method != "HEAD" {
				origin := c.GetHeader("Origin")
				if origin != "" && !allowedOrigins[origin] {
					c.AbortWithStatusJSON(403, gin.H{"error": "cross-origin requests denied"})
					return
				}
			}
			c.Next()
		})

		censusH := handler.NewCensusHandler(operatorDeps.CensusStore, operatorDeps.DeviceStore, operatorDeps.AuditStore, operatorDeps.CensusSvc, logger)
		recoveryH := handler.NewRecoveryHandler(operatorDeps.RecoverySvc, operatorDeps.RecoveryStore, operatorDeps.AccountStore, operatorDeps.AuditStore, logger)
		obsH := newObservabilityHandler(operatorDeps, logger)

		op := g.Group("/operator/v1")
		{
			// Observability
			op.GET("/system/health", obsH.SystemHealth)
			op.GET("/system/metrics", obsH.Metrics)
			op.GET("/fleet/summary", obsH.FleetSummary)
			op.GET("/audit", obsH.AuditLog)

			// Census
			op.GET("/census/issuers", censusH.ListIssuers)
			op.GET("/census/issuers/:fingerprint", censusH.GetIssuer)
			op.POST("/census/issuers/:fingerprint/flag", censusH.FlagIssuer)
			op.POST("/census/issuers/:fingerprint/override", censusH.OverrideIssuerTier)
			op.GET("/census/pcr", censusH.ListPCRClusters)
			op.GET("/census/pcr/:grouping_key", censusH.GetPCRClusters)

			// Device trust
			op.POST("/devices/:id/trust-override", censusH.TrustOverride)
			op.DELETE("/devices/:id/trust-override", censusH.ClearTrustOverride)
			op.GET("/devices/:id/trust-explain", censusH.TrustExplain)

			// Recovery
			op.GET("/recovery/accounts", recoveryH.ListPendingAccounts)
			op.GET("/recovery/accounts/:id", recoveryH.GetAccountStatus)
			op.POST("/recovery/accounts/:id/override", recoveryH.OverrideAccount)
			op.POST("/recovery/accounts/:id/dissolve", recoveryH.DissolveAccount)
		}

		mux.Handle("/operator/", g)
	}

	return withLogging(mux, logger), nil
}

// buildAllowedOrigins returns a set of permitted Origin values for CSRF checks,
// derived from the configured admin listen address.
func buildAllowedOrigins(adminAddr string) map[string]bool {
	origins := map[string]bool{
		"http://127.0.0.1:8056": true,
		"http://localhost:8056":  true,
	}
	// Parse the configured address to allow its origin
	host, port, err := net.SplitHostPort(adminAddr)
	if err == nil {
		if host == "" || host == "0.0.0.0" || host == "::" {
			// Wildcard bind — allow localhost variants only
			origins["http://127.0.0.1:"+port] = true
			origins["http://localhost:"+port] = true
		} else {
			origins["http://"+host+":"+port] = true
			origins["http://"+net.JoinHostPort(host, port)] = true
		}
	}
	return origins
}

// statusRecorder wraps http.ResponseWriter to capture the status code.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// withLogging wraps an http.Handler with access logging.
// Skips high-frequency, low-value paths (health checks, favicon).
func withLogging(next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(rec, r)
		path := r.URL.Path
		if path == "/health" || path == "/favicon.ico" ||
			path == "/operator/v1/system/health" ||
			path == "/operator/v1/system/metrics" ||
			path == "/operator/v1/fleet/summary" {
			return
		}
		logger.Info("admin request",
			"method", r.Method,
			"path", path,
			"status", rec.status,
			"duration", time.Since(start),
		)
	})
}
