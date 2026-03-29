package db

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
)

const currentVersion = 3

var migrations = []string{
	// Version 1: Consolidated schema (original + ACME certs + backend port + RFC 004 stateless resilience)
	`CREATE TABLE IF NOT EXISTS accounts (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'pending_recovery')),
		membership_epoch INT NOT NULL DEFAULT 1,
		founding_ek_fingerprint TEXT,
		recovery_deadline TIMESTAMPTZ,
		dissolved_at TIMESTAMPTZ,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS devices (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		account_id UUID NOT NULL REFERENCES accounts(id),
		slug TEXT NOT NULL,
		hostname TEXT NOT NULL UNIQUE,
		custom_hostname TEXT UNIQUE,
		identity_class TEXT NOT NULL CHECK (identity_class IN ('verified', 'crowd_corroborated', 'unverified_hw', 'software')),
		ek_fingerprint TEXT NOT NULL UNIQUE,
		ek_cert_der BYTEA,
		ak_public_key BYTEA NOT NULL,
		issuer_fingerprint TEXT,
		os_version TEXT,
		pcr_values JSONB,
		trust_level TEXT NOT NULL DEFAULT 'provisional'
			CHECK (trust_level IN ('strong','standard','provisional','suspicious','quarantine','software')),
		trust_level_override TEXT
			CHECK (trust_level_override IS NULL OR trust_level_override IN ('strong','standard','provisional','suspicious','quarantine','software')),
		ip_address INET,
		timezone TEXT,
		status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'revoked')),
		hostname_changes_this_year INT NOT NULL DEFAULT 0,
		hostname_year INT NOT NULL DEFAULT EXTRACT(YEAR FROM NOW()),
		last_hostname_change_at TIMESTAMPTZ,
		voucher_pending_since TIMESTAMPTZ,
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
		backend_port INT NOT NULL DEFAULT 443,
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
		actor_type TEXT NOT NULL CHECK (actor_type IN ('device', 'nexus', 'system', 'operator')),
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

	CREATE INDEX IF NOT EXISTS idx_device_domain_assignments_domain_id ON device_domain_assignments(domain_id);

	CREATE TABLE IF NOT EXISTS acme_certs (
		key        TEXT PRIMARY KEY,
		data       BYTEA NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS account_invites (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
		invite_code_hash TEXT NOT NULL UNIQUE,
		created_by_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
		expires_at TIMESTAMPTZ NOT NULL,
		consumed_at TIMESTAMPTZ,
		consumed_by_device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE INDEX IF NOT EXISTS idx_account_invites_account_id ON account_invites(account_id);

	CREATE TABLE IF NOT EXISTS voucher_requests (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
		issuer_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
		subject_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
		voucher_data TEXT NOT NULL,
		epoch INT NOT NULL,
		status TEXT NOT NULL DEFAULT 'pending'
			CHECK (status IN ('pending', 'signed', 'expired')),
		quote TEXT,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		signed_at TIMESTAMPTZ,
		UNIQUE(issuer_device_id, subject_device_id)
	);

	CREATE INDEX IF NOT EXISTS idx_voucher_requests_issuer ON voucher_requests(issuer_device_id)
		WHERE status = 'pending';

	CREATE TABLE IF NOT EXISTS recovery_claims (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
		claimed_account_id UUID NOT NULL,
		voucher_data TEXT NOT NULL,
		voucher_quote TEXT NOT NULL,
		voucher_epoch INT NOT NULL,
		issuer_ak_public_key BYTEA NOT NULL,
		issuer_ek_fingerprint TEXT NOT NULL,
		issuer_ek_cert BYTEA,
		attributed BOOLEAN NOT NULL DEFAULT FALSE,
		rejected BOOLEAN NOT NULL DEFAULT FALSE,
		rejection_reason TEXT,
		attributed_at TIMESTAMPTZ,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		UNIQUE(device_id, claimed_account_id, issuer_ek_fingerprint)
	);

	CREATE INDEX IF NOT EXISTS idx_recovery_claims_account ON recovery_claims(claimed_account_id);
	CREATE INDEX IF NOT EXISTS idx_recovery_claims_account_attributed ON recovery_claims(claimed_account_id, attributed);
	CREATE INDEX IF NOT EXISTS idx_recovery_claims_device ON recovery_claims(device_id);
	CREATE INDEX IF NOT EXISTS idx_recovery_claims_issuer ON recovery_claims(issuer_ek_fingerprint)
		WHERE attributed = FALSE;

	CREATE TABLE IF NOT EXISTS ek_issuer_census (
		id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		issuer_fingerprint          TEXT NOT NULL UNIQUE,
		issuer_subject              TEXT NOT NULL,
		issuer_public_key_der       BYTEA,
		issuer_is_ca                BOOLEAN,
		issuer_has_certsign         BOOLEAN,
		device_count                INT NOT NULL DEFAULT 0,
		distinct_subnet_count       INT NOT NULL DEFAULT 0,
		structural_compliance_score REAL,
		tier                        TEXT NOT NULL DEFAULT 'unverified'
			CHECK (tier IN ('seed', 'crowd_corroborated', 'unverified')),
		first_seen_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		last_seen_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		flagged                     BOOLEAN NOT NULL DEFAULT FALSE,
		flagged_reason              TEXT,
		created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE INDEX IF NOT EXISTS idx_ek_issuer_census_tier ON ek_issuer_census(tier);

	CREATE TABLE IF NOT EXISTS ek_issuer_observations (
		id                  BIGSERIAL PRIMARY KEY,
		issuer_fingerprint  TEXT NOT NULL REFERENCES ek_issuer_census(issuer_fingerprint),
		device_id           UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
		client_ip_subnet    TEXT NOT NULL,
		observed_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		UNIQUE(issuer_fingerprint, device_id)
	);

	CREATE INDEX IF NOT EXISTS idx_ek_issuer_observations_fingerprint
		ON ek_issuer_observations(issuer_fingerprint);

	CREATE TABLE IF NOT EXISTS pcr_census (
		id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		grouping_key        TEXT NOT NULL,
		pcr_group           TEXT NOT NULL CHECK (pcr_group IN ('firmware', 'boot', 'os')),
		pcr_composite_hash  TEXT NOT NULL,
		pcr_values          JSONB NOT NULL,
		device_count        INT NOT NULL DEFAULT 0,
		is_majority         BOOLEAN NOT NULL DEFAULT FALSE,
		first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		UNIQUE(grouping_key, pcr_group, pcr_composite_hash)
	);

	CREATE INDEX IF NOT EXISTS idx_pcr_census_majority
		ON pcr_census(grouping_key, pcr_group) WHERE is_majority = TRUE;`,

	// Version 2: Audit log index for dashboard query performance
	`CREATE INDEX IF NOT EXISTS idx_audit_log_action_id ON audit_log(action text_pattern_ops, id DESC);`,

	// Version 3: Consolidate identity classes — rename "unverified_hw" to "unverified",
	// remove "software" (was incorrectly assigned to real hardware TPMs with unverifiable EK certs).
	// Also remove "software" trust level (no longer produced by any code path).
	`ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_identity_class_check;
	 ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_trust_level_check;
	 ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_trust_level_override_check;
	 UPDATE devices SET identity_class = 'unverified' WHERE identity_class IN ('software', 'unverified_hw');
	 UPDATE devices SET trust_level = 'provisional' WHERE trust_level = 'software';
	 UPDATE devices SET trust_level_override = 'provisional' WHERE trust_level_override = 'software';
	 ALTER TABLE devices ADD CONSTRAINT devices_identity_class_check CHECK (identity_class IN ('verified', 'crowd_corroborated', 'unverified'));
	 ALTER TABLE devices ADD CONSTRAINT devices_trust_level_check CHECK (trust_level IN ('strong','standard','provisional','suspicious','quarantine'));
	 ALTER TABLE devices ADD CONSTRAINT devices_trust_level_override_check CHECK (trust_level_override IS NULL OR trust_level_override IN ('strong','standard','provisional','suspicious','quarantine'));`,
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
