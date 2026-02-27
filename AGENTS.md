# Namek Server

Namek Server is the orchestrator/control plane in the Piccolo ecosystem. It bridges piccolod (on-device daemon) and Nexus Proxy (edge relay).

## Architecture

- **Go 1.24+** with Gin HTTP framework
- **PostgreSQL 16** shared with PowerDNS (separate databases)
- **PowerDNS** for authoritative DNS (gpgsql backend)
- Deployed as a batteries-included pod (Docker Compose)

## Project Layout

- `cmd/namek/` — Entrypoint, DI assembly, autocert, graceful shutdown
- `internal/config/` — YAML config loading + validation
- `internal/db/` — PostgreSQL connection pool (pgx) + migrations
- `internal/model/` — Pure data structs
- `internal/store/` — Database interfaces + PostgreSQL implementations
- `internal/auth/` — Nonce store, TPM auth middleware, mTLS middleware
- `internal/tpm/` — TPM EK verification, quote verification
- `internal/dns/` — PowerDNS REST API client
- `internal/token/` — JWT signing (ephemeral secret)
- `internal/service/` — Business logic layer
- `internal/api/` — Gin router, response helpers, HTTP handlers
- `deploy/` — Docker Compose, init scripts, PowerDNS config

## Key Patterns

- Per-request TPM attestation (no bearer tokens for devices)
- Ephemeral JWT signing secret (regenerated on restart)
- Wildcard CNAME DNS — no per-device DNS operations
- PowerDNS is sole DNS source of truth (no tracking table in Namek)
- Nexus self-registration via mTLS with heartbeat-based health
