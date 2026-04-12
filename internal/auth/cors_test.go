package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func setupCORSRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	allowed := []string{"https://piccolospace.com", "https://www.piccolospace.com"}
	rl := r.Group("/api/v1/setup")
	rl.Use(SetupDiscoverCORS(allowed))
	// A downstream handler that bumps a counter so we can detect whether
	// preflight short-circuited before reaching it.
	var hits int
	rl.Use(func(c *gin.Context) {
		hits++
		c.Next()
	})
	rl.GET("/discover", func(c *gin.Context) { c.JSON(200, gin.H{"devices": []any{}}) })
	rl.OPTIONS("/discover", func(c *gin.Context) {})
	return r
}

func TestSetupDiscoverCORS_AllowedOrigin(t *testing.T) {
	r := setupCORSRouter()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/setup/discover", nil)
	req.Header.Set("Origin", "https://piccolospace.com")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d body=%q", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://piccolospace.com" {
		t.Errorf("ACAO = %q, want https://piccolospace.com", got)
	}
	if got := w.Header().Get("Vary"); got != "Origin" {
		t.Errorf("Vary = %q, want Origin", got)
	}
}

func TestSetupDiscoverCORS_DisallowedOrigin(t *testing.T) {
	r := setupCORSRouter()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/setup/discover", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("ACAO should be absent for disallowed origin, got %q", got)
	}
}

func TestSetupDiscoverCORS_Preflight(t *testing.T) {
	r := setupCORSRouter()
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/setup/discover", nil)
	req.Header.Set("Origin", "https://piccolospace.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 204 {
		t.Fatalf("preflight expected 204, got %d", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://piccolospace.com" {
		t.Errorf("preflight ACAO = %q, want https://piccolospace.com", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Methods"); got != "GET, OPTIONS" {
		t.Errorf("preflight ACAM = %q", got)
	}
	if got := w.Header().Get("Access-Control-Max-Age"); got != "3600" {
		t.Errorf("preflight Max-Age = %q", got)
	}
}

// Regression test for the load-bearing middleware ordering. The CORS layer must
// short-circuit preflight with AbortWithStatus so downstream middleware (notably
// the rate limiter in production) never runs.
func TestSetupDiscoverCORS_PreflightShortCircuits(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	downstreamRan := false
	rl := r.Group("/api/v1/setup")
	rl.Use(SetupDiscoverCORS([]string{"https://piccolospace.com"}))
	rl.Use(func(c *gin.Context) {
		downstreamRan = true
		c.Next()
	})
	rl.OPTIONS("/discover", func(c *gin.Context) {})

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/setup/discover", nil)
	req.Header.Set("Origin", "https://piccolospace.com")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 204 {
		t.Fatalf("expected 204, got %d", w.Code)
	}
	if downstreamRan {
		t.Error("downstream middleware ran during preflight — CORS layer did not short-circuit")
	}
}
