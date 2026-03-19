package dns

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/AtDexters-Lab/namek-server/internal/config"
)

// BootstrapZone ensures the DNS zone exists in PowerDNS, creating it if necessary.
// Retries with exponential backoff since PowerDNS may not be ready yet.
func BootstrapZone(ctx context.Context, client *PowerDNSClient, dnsCfg config.DNSConfig, publicHostname string, logger *slog.Logger) error {
	backoff := time.Second
	deadline := time.Now().Add(60 * time.Second)

	for {
		err := tryBootstrap(ctx, client, dnsCfg, publicHostname, logger)
		if err == nil {
			return nil
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("zone bootstrap timed out after 60s: %w", err)
		}

		logger.Info("zone bootstrap attempt failed, retrying", "error", err, "backoff", backoff)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}

		backoff *= 2
		if backoff > 5*time.Second {
			backoff = 5 * time.Second
		}
	}
}

func tryBootstrap(ctx context.Context, client *PowerDNSClient, dnsCfg config.DNSConfig, publicHostname string, logger *slog.Logger) error {
	exists, err := client.GetZone(ctx, dnsCfg.Zone)
	if err != nil {
		return fmt.Errorf("check zone: %w", err)
	}

	if exists {
		logger.Info("dns zone already exists, skipping bootstrap", "zone", dnsCfg.Zone)
		return nil
	}

	logger.Info("creating dns zone", "zone", dnsCfg.Zone, "primaryNS", publicHostname, "nameservers", dnsCfg.Nameservers)
	return client.CreateZone(ctx, dnsCfg.Zone, dnsCfg.BaseDomain, publicHostname, dnsCfg.Nameservers, dnsCfg.RelayHostname)
}
