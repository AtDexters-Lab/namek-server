package admin

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestRootServesHTML(t *testing.T) {
	handler, err := NewHandler("http://localhost:8081", "test-key", testLogger())
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("expected text/html content-type, got %q", ct)
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("expected X-Frame-Options: DENY")
	}
	body := rec.Body.String()
	if len(body) == 0 {
		t.Fatal("expected non-empty body")
	}
	if !strings.Contains(body, "PowerDNS") && !strings.Contains(body, "powerdns") {
		t.Fatal("expected body to contain powerdns-webui content")
	}
}

func TestAPIProxy(t *testing.T) {
	var gotAPIKey string
	var gotPath string

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAPIKey = r.Header.Get("X-API-Key")
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"zones":[]}`))
	}))
	defer backend.Close()

	handler, err := NewHandler(backend.URL, "secret-key", testLogger())
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/servers/localhost/zones", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if gotAPIKey != "secret-key" {
		t.Fatalf("expected API key %q, got %q", "secret-key", gotAPIKey)
	}
	if gotPath != "/api/v1/servers/localhost/zones" {
		t.Fatalf("expected path /api/v1/servers/localhost/zones, got %q", gotPath)
	}
}

func TestAPIKeyOverwrite(t *testing.T) {
	var gotAPIKey string

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAPIKey = r.Header.Get("X-API-Key")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	handler, err := NewHandler(backend.URL, "real-key", testLogger())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/servers", nil)
	req.Header.Set("X-API-Key", "fake-key")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if gotAPIKey != "real-key" {
		t.Fatalf("expected proxy to overwrite API key to %q, got %q", "real-key", gotAPIKey)
	}
}

func TestProxyError(t *testing.T) {
	handler, err := NewHandler("http://127.0.0.1:1", "key", testLogger())
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/servers", nil))

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", rec.Code)
	}
}

func TestHealth(t *testing.T) {
	handler, err := NewHandler("http://localhost:8081", "key", testLogger())
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestFavicon(t *testing.T) {
	handler, err := NewHandler("http://localhost:8081", "key", testLogger())
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/favicon.ico", nil))

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if len(body) != 0 {
		t.Fatalf("expected empty body, got %d bytes", len(body))
	}
}

func TestNonAPIPathReturns404(t *testing.T) {
	handler, err := NewHandler("http://localhost:8081", "key", testLogger())
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for non-API path, got %d", rec.Code)
	}
}
