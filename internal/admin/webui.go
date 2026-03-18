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
)

// index.html is powerdns-webui by james-stevens (GPL-3.0).
// Source: https://github.com/james-stevens/powerdns-webui
// Served unmodified; see THIRD-PARTY-NOTICES for license.
//
//go:embed index.html
var indexHTML []byte

// NewHandler returns an http.Handler that serves the powerdns-webui at /
// and reverse-proxies /api/ requests to the PowerDNS API.
func NewHandler(pdnsAPIURL, pdnsAPIKey string, logger *slog.Logger) (http.Handler, error) {
	target, err := url.Parse(pdnsAPIURL)
	if err != nil {
		return nil, fmt.Errorf("admin: invalid PowerDNS API URL %q: %w", pdnsAPIURL, err)
	}

	mux := http.NewServeMux()

	// Serve embedded powerdns-webui at root
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(indexHTML)))
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Write(indexHTML)
	})

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

	return withLogging(mux, logger), nil
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
		if path == "/health" || path == "/favicon.ico" {
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
