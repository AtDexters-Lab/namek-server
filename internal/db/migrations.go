package db

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
)

const currentVersion = 3

var migrations = []string{
	// Version 1: Initial schema
	`CREATE TABLE IF NOT EXISTS accounts (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS devices (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		account_id UUID NOT NULL REFERENCES accounts(id),
		slug TEXT NOT NULL,
		hostname TEXT NOT NULL UNIQUE,
		custom_hostname TEXT UNIQUE,
		identity_class TEXT NOT NULL CHECK (identity_class IN ('hardware_tpm', 'software_tpm')),
		ek_fingerprint TEXT NOT NULL UNIQUE,
		ak_public_key BYTEA NOT NULL,
		ip_address INET,
		timezone TEXT,
		status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'revoked')),
		hostname_changes_this_year INT NOT NULL DEFAULT 0,
		hostname_year INT NOT NULL DEFAULT EXTRACT(YEAR FROM NOW()),
		last_hostname_change_at TIMESTAMPTZ,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		last_seen_at TIMESTAMPTZ,
		CONSTRAINT devices_slug_unique UNIQUE (slug)
	);

	CREATE INDEX IF NOT EXISTS idx_devices_account_id ON devices(account_id);

	CREATE TABLE IF NOT EXISTS nexus_instances (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		hostname TEXT NOT NULL UNIQUE,
		resolved_addresses INET[],
		region TEXT,
		heartbeat_interval_seconds INT NOT NULL DEFAULT 30,
		status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
		registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS acme_challenges (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
		fqdn TEXT NOT NULL,
		key_authorization TEXT NOT NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		expires_at TIMESTAMPTZ NOT NULL,
		UNIQUE(device_id, fqdn)
	);

	CREATE TABLE IF NOT EXISTS released_hostnames (
		label TEXT PRIMARY KEY,
		released_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		released_by UUID REFERENCES devices(id) ON DELETE SET NULL
	);

	CREATE TABLE IF NOT EXISTS audit_log (
		id BIGSERIAL PRIMARY KEY,
		timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		actor_type TEXT NOT NULL CHECK (actor_type IN ('device', 'nexus', 'system')),
		actor_id TEXT NOT NULL,
		action TEXT NOT NULL,
		resource_type TEXT NOT NULL,
		resource_id TEXT,
		details JSONB,
		ip_address INET
	);

	CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);

	CREATE TABLE IF NOT EXISTS account_domains (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
		domain TEXT NOT NULL UNIQUE CHECK (domain = lower(domain)),
		cname_target TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'verified')),
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		expires_at TIMESTAMPTZ,
		verified_at TIMESTAMPTZ,
		verified_by_device_id UUID REFERENCES devices(id) ON DELETE SET NULL
	);

	CREATE INDEX IF NOT EXISTS idx_account_domains_account_id ON account_domains(account_id);

	CREATE TABLE IF NOT EXISTS device_domain_assignments (
		device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
		domain_id UUID NOT NULL REFERENCES account_domains(id) ON DELETE CASCADE,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		PRIMARY KEY (device_id, domain_id)
	);

	CREATE INDEX IF NOT EXISTS idx_device_domain_assignments_domain_id ON device_domain_assignments(domain_id);`,

	// Version 2: ACME certificate cache
	`CREATE TABLE IF NOT EXISTS acme_certs (
		key        TEXT PRIMARY KEY,
		data       BYTEA NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);`,

	// Version 3: Backend port for nexus relay registration
	`ALTER TABLE nexus_instances ADD COLUMN backend_port INT NOT NULL DEFAULT 443;`,
}

func Migrate(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_version (
			version INT NOT NULL,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`)
	if err != nil {
		return fmt.Errorf("create schema_version table: %w", err)
	}

	var version int
	err = pool.QueryRow(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&version)
	if err != nil {
		return fmt.Errorf("get current schema version: %w", err)
	}

	if version >= currentVersion {
		logger.Info("database schema up to date", "version", version)
		return nil
	}

	for i := version; i < currentVersion; i++ {
		logger.Info("applying migration", "version", i+1)

		tx, err := pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin migration tx (v%d): %w", i+1, err)
		}

		if _, err := tx.Exec(ctx, migrations[i]); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("execute migration v%d: %w", i+1, err)
		}

		if _, err := tx.Exec(ctx, "INSERT INTO schema_version (version) VALUES ($1)", i+1); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("record migration v%d: %w", i+1, err)
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration v%d: %w", i+1, err)
		}

		logger.Info("migration applied", "version", i+1)
	}

	return nil
}
