# RFC 001: Namek Server Foundation

**Status:** Implemented
**Author:** Piccolo Team
**Created:** 2026-02-26

## Summary

Namek Server is the orchestrator/control plane in the Piccolo ecosystem, bridging piccolod (on-device daemon) and Nexus Proxy (edge relay). This RFC defines the MVP foundation: device authentication via TPM attestation, DNS-01 ACME orchestration, Nexus relay management, and token issuance.

## Deployment Model

Batteries-included pod (Docker Compose / Podman) containing:
- **Namek** — Go binary, auto-TLS via Let's Encrypt HTTP-01
- **PostgreSQL 16** — Shared DB (`namek` + `powerdns` databases)
- **PowerDNS** — Authoritative DNS with gpgsql backend

## Key Decisions

1. **Wildcard CNAME DNS** — `*.<baseDomain> CNAME relay.<baseDomain>`. Zero per-device DNS ops.
2. **Per-request TPM attestation** — No persistent bearer tokens. Every authenticated device request includes a TPM quote.
3. **Ephemeral JWT signing secret** — Generated on startup, never persisted. 30s TTL. Restart = devices re-request.
4. **PowerDNS as sole DNS source of truth** — No tracking table in Namek's DB.
5. **Nexus self-registration via mTLS** — Heartbeat-based health, hostname DNS resolution for IPs.
6. **Device accounts only** — No human user accounts at MVP.

## API Surface

See `api/openapi.yaml` for full specification.

### Public (rate-limited)
- `POST /api/v1/devices/enroll` — Start enrollment
- `POST /api/v1/devices/enroll/attest` — Complete enrollment
- `GET /api/v1/nonce` — Fresh nonce for TPM attestation

### Device TPM-authenticated
- `GET /api/v1/devices/me` — Device info + Nexus endpoints
- `PATCH /api/v1/devices/me/hostname` — Custom hostname
- `POST /api/v1/tokens/nexus` — Nexus JWT (stages 0/1/2)
- `POST /api/v1/acme/challenges` — ACME DNS-01 TXT record
- `DELETE /api/v1/acme/challenges/:id` — Remove TXT record

### Nexus (mTLS)
- `POST /internal/v1/nexus/register` — Registration + heartbeat
- `POST /internal/v1/tokens/verify` — Remote token verification

### Public (no auth)
- `GET /health`, `GET /ready` — System health

## Database Schema

Four tables: `devices`, `nexus_instances`, `acme_challenges`, `audit_log`. See `internal/db/migrations.go` for DDL.

## Known Limitations

1. No geo-routing (all devices share one relay)
2. No admin API (direct DB access for management)
3. Single custom hostname per device
4. Single instance only (in-memory pending enrollments)
5. Ephemeral signing secret (restart invalidates tokens)
