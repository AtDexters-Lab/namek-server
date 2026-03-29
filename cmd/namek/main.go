package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/AtDexters-Lab/namek-server/internal/admin"
	"github.com/AtDexters-Lab/namek-server/internal/api"
	"github.com/AtDexters-Lab/namek-server/internal/auth"
	"github.com/AtDexters-Lab/namek-server/internal/config"
	"github.com/AtDexters-Lab/namek-server/internal/db"
	"github.com/AtDexters-Lab/namek-server/internal/dns"
	"github.com/AtDexters-Lab/namek-server/internal/service"
	"github.com/AtDexters-Lab/namek-server/internal/store"
	"github.com/AtDexters-Lab/namek-server/internal/token"
	"github.com/AtDexters-Lab/namek-server/internal/tpm"
)

var version = "dev"

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	logger.Info("starting namek server", "version", version)

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Database (retry with backoff — Postgres may not be ready in container environments)
	var pool *pgxpool.Pool
	{
		backoff := time.Second
		deadline := time.Now().Add(30 * time.Second)
		for {
			pool, err = db.NewPool(ctx, cfg.Database, logger)
			if err == nil {
				break
			}
			if time.Now().After(deadline) {
				logger.Error("failed to connect to database", "error", err)
				os.Exit(1)
			}
			logger.Info("database not ready, retrying", "error", err, "backoff", backoff)
			select {
			case <-ctx.Done():
				logger.Error("context cancelled while waiting for database")
				os.Exit(1)
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > 5*time.Second {
				backoff = 5 * time.Second
			}
		}
	}
	defer pool.Close()

	if err := db.Migrate(ctx, pool, logger); err != nil {
		logger.Error("failed to run migrations", "error", err)
		os.Exit(1)
	}

	// Stores
	stores := store.New(pool)

	// PowerDNS client
	pdns := dns.NewPowerDNSClient(cfg.PowerDNS, logger)

	// Bootstrap DNS zone (retries until PowerDNS is ready)
	if err := dns.BootstrapZone(ctx, pdns, cfg.DNS, cfg.PublicHostname, logger); err != nil {
		logger.Error("failed to bootstrap dns zone", "error", err)
		os.Exit(1)
	}

	// Nonce store
	nonceStore := auth.NewNonceStore(logger, cfg.Nonce.MaxNonces, cfg.NonceTTL())
	go nonceStore.CleanupLoop(ctx)

	// Last-seen batcher (replaces per-request fire-and-forget goroutines)
	lastSeenBatcher := store.NewLastSeenBatcher(pool, logger)
	go lastSeenBatcher.FlushLoop(ctx, 5*time.Second)

	// TPM verifier
	tpmVerifier, err := tpm.NewVerifier(cfg.TPM, logger)
	if err != nil {
		logger.Error("failed to create TPM verifier", "error", err)
		os.Exit(1)
	}

	// Token issuer (ephemeral secret)
	tokenIssuer, err := token.NewIssuer(cfg.Token, cfg.PublicHostname, logger)
	if err != nil {
		logger.Error("failed to create token issuer", "error", err)
		os.Exit(1)
	}

	// CNAME resolver
	cnameResolver := dns.NewDNSCNAMEResolver(cfg.AliasDomain.DNSResolver, cfg.VerificationTimeout())

	// Services
	deviceSvc := service.NewDeviceService(stores.Device, stores.Account, stores.Audit, stores.Census, pool, cfg, logger)
	nexusSvc := service.NewNexusService(stores.Nexus, stores.Audit, pdns, cfg, logger)
	tokenSvc := service.NewTokenService(stores.Device, stores.Domain, tokenIssuer, cfg, logger)
	txtVerifier := dns.NewTXTVerifier(cfg.PowerDNS.DNSAddress, 1*time.Second)
	acmeSvc := service.NewACMEService(stores.ACME, stores.Device, pdns, txtVerifier, cfg, logger)
	domainSvc := service.NewDomainService(stores.Domain, stores.Device, stores.Audit, cnameResolver, cfg, logger)
	accountSvc := service.NewAccountService(stores.Account, stores.Device, stores.Invite, stores.Audit, cfg, logger)
	voucherSvc := service.NewVoucherService(stores.Voucher, stores.Device, stores.Account, stores.Audit, tpmVerifier, cfg, logger)
	recoverySvc := service.NewRecoveryService(stores.Recovery, stores.Account, stores.Device, stores.Audit, tpmVerifier, cfg, logger)
	censusSvc := service.NewCensusService(stores.Census, stores.Device, stores.Audit, pool, cfg, logger)
	accountSvc.SetVoucherCreator(voucherSvc)
	deviceSvc.SetRecoveryProcessor(recoverySvc)

	// Start background goroutines
	go censusSvc.Run(ctx)
	go nexusSvc.HealthCheckLoop(ctx)
	go acmeSvc.CleanupLoop(ctx)
	go domainSvc.CleanupLoop(ctx)

	// Pending enrollment cleanup (every 60s)
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				deviceSvc.CleanupPending()
			}
		}
	}()

	// Released hostname cleanup (daily)
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				deleted, err := stores.Device.CleanupReleasedHostnames(ctx, cfg.Hostname.ReleasedCooldownDays)
				if err != nil {
					logger.Error("released hostname cleanup failed", "error", err)
				} else if deleted > 0 {
					logger.Info("released hostname cleanup", "deleted", deleted)
				}
			}
		}
	}()

	// Audit log retention cleanup (daily)
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				for {
					if ctx.Err() != nil {
						return
					}
					deleted, err := stores.Audit.DeleteOlderThan(ctx, cfg.AuditRetentionDays)
					if err != nil {
						logger.Error("audit log cleanup failed", "error", err)
						break
					}
					if deleted == 0 {
						break
					}
					logger.Info("audit log cleanup", "deleted", deleted)
				}
			}
		}
	}()

	// Recovery quorum re-evaluation (every 5 min) and claims cleanup (daily)
	go recoverySvc.QuorumReEvaluationLoop(ctx)
	go recoverySvc.CleanupLoop(ctx)

	// Expired voucher request cleanup (daily)
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				voucherSvc.CleanupExpiredRequests(ctx)
			}
		}
	}()

	// Expired invite cleanup (daily)
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				accountSvc.CleanupExpiredInvites(ctx)
			}
		}
	}()

	// Router
	router := api.NewRouter(api.RouterDeps{
		Config:      cfg,
		Logger:      logger,
		NonceStore:  nonceStore,
		TPMVerifier: tpmVerifier,
		TokenIssuer: tokenIssuer,
		DeviceSvc:   deviceSvc,
		NexusSvc:    nexusSvc,
		TokenSvc:    tokenSvc,
		ACMESvc:     acmeSvc,
		DomainSvc:    domainSvc,
		AccountSvc:   accountSvc,
		VoucherSvc:   voucherSvc,
		DeviceStore:     stores.Device,
		AccountStore:    stores.Account,
		LastSeenBatcher: lastSeenBatcher,
		AuditStore:      stores.Audit,
		Pool:            pool,
		PowerDNS:        pdns,
	})

	// Autocert setup
	certManager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(cfg.PublicHostname),
		Cache:      db.NewPGCertStore(pool),
	}

	if cfg.AcmeDirectoryURL != "" {
		acmeClient := &acme.Client{DirectoryURL: cfg.AcmeDirectoryURL}
		if cfg.AcmeCACert != "" {
			caCert, err := os.ReadFile(cfg.AcmeCACert)
			if err != nil {
				logger.Error("failed to read acme ca cert", "error", err, "path", cfg.AcmeCACert)
				os.Exit(1)
			}
			acmeCertPool := x509.NewCertPool()
			if !acmeCertPool.AppendCertsFromPEM(caCert) {
				logger.Error("acme ca cert contains no valid PEM blocks", "path", cfg.AcmeCACert)
				os.Exit(1)
			}
			acmeClient.HTTPClient = &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{RootCAs: acmeCertPool},
				},
			}
		}
		certManager.Client = acmeClient
		logger.Info("using custom ACME directory", "url", cfg.AcmeDirectoryURL)
	}

	tlsConfig := certManager.TLSConfig()
	tlsConfig.ClientAuth = tls.RequestClientCert // Optional client cert for mTLS (Nexus)

	// Fall back to a cached self-signed cert for single-label hostnames
	// (e.g. "localhost") where autocert cannot issue a real certificate.
	// For multi-label hostnames, autocert errors propagate — no silent fallback.
	var selfSignedOnce sync.Once
	var selfSignedCache *tls.Certificate
	origGetCert := tlsConfig.GetCertificate
	tlsConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := origGetCert(hello)
		if err == nil {
			return cert, nil
		}
		if strings.Contains(hello.ServerName, ".") {
			return nil, err
		}
		selfSignedOnce.Do(func() {
			selfSignedCache, _ = selfSignedCert(hello.ServerName)
		})
		if selfSignedCache == nil {
			return nil, err
		}
		return selfSignedCache, nil
	}

	// Prewarm certificate
	go func() {
		logger.Info("prewarming autocert", "hostname", cfg.PublicHostname)
		_, err := certManager.GetCertificate(&tls.ClientHelloInfo{
			ServerName:     cfg.PublicHostname,
			SupportedProtos: []string{acme.ALPNProto, "http/1.1"},
		})
		if err != nil {
			logger.Warn("autocert prewarm failed", "error", err)
		} else {
			logger.Info("autocert prewarm complete", "hostname", cfg.PublicHostname)
		}
	}()

	// DNS proxy (when PowerDNS listens on a different port than :53)
	var dnsProxy *dns.Proxy
	if cfg.PowerDNS.DNSAddress != "127.0.0.1:53" && cfg.PowerDNS.DNSAddress != ":53" {
		dnsProxy = dns.NewProxy(":53", cfg.PowerDNS.DNSAddress, logger)
		if err := dnsProxy.Start(ctx); err != nil {
			logger.Error("failed to start dns proxy", "error", err)
			os.Exit(1)
		}
	}

	// HTTP server (HTTP-01 challenges — only when httpAddress is configured)
	var httpServer *http.Server
	if cfg.HTTPAddress != "" {
		httpServer = &http.Server{
			Addr:              cfg.HTTPAddress,
			Handler:           certManager.HTTPHandler(nil),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
		}
	}

	// Admin server (PowerDNS web UI + API proxy)
	var adminServer *http.Server
	if cfg.AdminAddress != "" {
		adminHandler, err := admin.NewHandler(cfg.PowerDNS.ApiURL, cfg.PowerDNS.ApiKey, cfg.AdminAddress, logger, &admin.OperatorDeps{
			CensusStore:   stores.Census,
			DeviceStore:   stores.Device,
			AuditStore:    stores.Audit,
			RecoveryStore: stores.Recovery,
			AccountStore:  stores.Account,
			CensusSvc:     censusSvc,
			RecoverySvc:   recoverySvc,

			NexusStore:             stores.Nexus,
			Pool:                   pool,
			NonceStore:             nonceStore,
			PendingCounter:         deviceSvc,
			CensusAnalysisInterval: cfg.CensusAnalysisInterval(),
			MaxPendingEnrollments:  cfg.Enrollment.MaxPending,
		})
		if err != nil {
			logger.Error("failed to create admin handler", "error", err)
			os.Exit(1)
		}
		adminServer = &http.Server{
			Addr:              cfg.AdminAddress,
			Handler:           adminHandler,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
	}

	// HTTPS server
	httpsServer := &http.Server{
		Addr:              cfg.ListenAddress,
		Handler:           router,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Start servers
	errCh := make(chan error, 3) // httpServer + httpsServer + adminServer
	if httpServer != nil {
		go func() {
			logger.Info("starting HTTP server", "addr", cfg.HTTPAddress)
			errCh <- httpServer.ListenAndServe()
		}()
	}
	if adminServer != nil {
		go func() {
			logger.Info("starting admin server", "addr", cfg.AdminAddress)
			errCh <- adminServer.ListenAndServe()
		}()
	}
	go func() {
		logger.Info("starting HTTPS server", "addr", cfg.ListenAddress)
		errCh <- httpsServer.ListenAndServeTLS("", "")
	}()

	// Wait for signal or error
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	select {
	case sig := <-sigCh:
		logger.Info("received signal, shutting down", "signal", sig)
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			logger.Error("server error", "error", err)
		}
	}

	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if dnsProxy != nil {
		dnsProxy.Close()
	}
	if err := httpsServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("https server shutdown error", "error", err)
	}
	if httpServer != nil {
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			logger.Error("http server shutdown error", "error", err)
		}
	}
	if adminServer != nil {
		if err := adminServer.Shutdown(shutdownCtx); err != nil {
			logger.Error("admin server shutdown error", "error", err)
		}
	}

	// Final flush of last-seen batcher before pool closes
	flushCtx, flushCancel := context.WithTimeout(context.Background(), 10*time.Second)
	lastSeenBatcher.Flush(flushCtx)
	flushCancel()

	logger.Info("shutdown complete")
}

func selfSignedCert(serverName string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: serverName},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{serverName},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}

func init() {
	// Ensure we see the version in usage
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "namek-server %s\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage: namek [options]\n\n")
		flag.PrintDefaults()
	}
}
