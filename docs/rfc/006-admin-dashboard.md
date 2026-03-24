# RFC 006: Admin Dashboard

**Status:** Draft
**Author:** Piccolo Team
**Created:** 2026-03-24

## Summary

Consolidate all operator functions into a web-based admin dashboard served on the internal admin listener (`:8056`). This replaces the previous approach of exposing operator API endpoints on the public HTTPS listener or behind NexusAuth (which was semantically incorrect — operators are not Nexus relays).

## Motivation

Operator endpoints (census management, recovery oversight, trust overrides) were originally scattered across the public HTTPS router with inconsistent authentication:
- Recovery endpoints used NexusAuth (mTLS designed for relay registration)
- Census endpoints had no authentication at all

This created a security surface on the public listener and confused the auth model. Moving all operator functions to the admin listener (`:8056`, typically bound to loopback) provides network-level isolation without requiring application-level auth for MVP.

The admin listener already serves the PowerDNS web UI. Extending it with a Namek operator dashboard creates a single pane of glass for fleet management.

## Architecture

```
Admin Server (:8056, loopback-only)
├── /                    → Admin dashboard (HTML)
├── /operator/v1/        → Operator API (JSON)
│   ├── census/          → Fleet trust census
│   ├── devices/         → Device trust management
│   └── recovery/        → Account recovery oversight
├── /api/                → PowerDNS API proxy (existing)
└── /health              → Health check (existing)
```

The admin server uses a Gin engine for `/operator/v1/` routes (reusing existing handler code) and `http.ServeMux` for everything else. No authentication middleware — access is controlled by binding to `127.0.0.1:8056` or the internal network.

## Dashboard Views

### Fleet Overview
- Total devices by identity class (verified / crowd_corroborated / unverified_hw / software)
- Total devices by trust level (strong / standard / provisional / suspicious / quarantine / software)
- Census service health: last analysis time, next scheduled, lock status
- Active alerts: flagged issuers, quarantined devices

### Issuer Census
- Table of all known EK issuers with tier, device count, subnet diversity, compliance score
- Promotion progress indicators for unverified issuers (% of criteria met)
- Flag/unflag and tier override actions
- Drill-down: observations per issuer (device list, subnet distribution, temporal spread)

### PCR Census
- Clusters by grouping key and PCR group
- Majority status indicators
- Device count per cluster
- Outlier detection highlights

### Device Trust
- Search/filter devices by trust level, identity class, issuer
- Trust explain view (per-device breakdown of EK assessment + PCR assessment)
- Trust override action with audit trail
- Override indicator (distinguishes system-computed vs operator-overridden trust)

### Recovery Status
- Pending recovery accounts with quorum progress
- Override and dissolve actions
- Historical recovery timeline

### Audit Log
- Filterable stream of operator actions and system events
- Actor type, action, resource, timestamp

## API Surface

All existing operator endpoints move from `/internal/v1/` on the HTTPS listener to `/operator/v1/` on the admin listener:

| Method | Path | Description |
|--------|------|-------------|
| GET | /operator/v1/census/issuers | List EK issuers |
| GET | /operator/v1/census/issuers/:fingerprint | Issuer details + observations |
| POST | /operator/v1/census/issuers/:fingerprint/flag | Flag/unflag issuer |
| POST | /operator/v1/census/issuers/:fingerprint/override | Override issuer tier |
| GET | /operator/v1/census/pcr | PCR cluster summary |
| GET | /operator/v1/census/pcr/:grouping_key | PCR clusters by key |
| POST | /operator/v1/devices/:id/trust-override | Override device trust |
| GET | /operator/v1/devices/:id/trust-explain | Explain trust computation |
| GET | /operator/v1/recovery/accounts | List pending recoveries |
| GET | /operator/v1/recovery/accounts/:id | Recovery account status |
| POST | /operator/v1/recovery/accounts/:id/override | Override quorum |
| POST | /operator/v1/recovery/accounts/:id/dissolve | Dissolve account |

## Implementation Strategy

### Phase 1: Route migration (done)
- Operator API endpoints moved to admin listener under `/operator/v1/`
- Removed from public HTTPS router
- Network-level access control via loopback binding

### Phase 2: Dashboard UI
- Single-page HTML dashboard (embedded via `//go:embed`)
- Vanilla JS + fetch against `/operator/v1/` API
- Minimal dependencies — no build step, no framework
- Follows the PowerDNS web UI pattern (single embedded `index.html`)

### Phase 3: Enhanced features
- Real-time updates via SSE (Server-Sent Events) from census service
- Audit log viewer with filtering
- Batch operations (e.g., override trust for all devices from a specific issuer)
- Export capabilities (CSV/JSON for census data)

## Future Considerations

1. Operator authentication (API key or basic auth) for environments where loopback isn't sufficient
2. Role-based access (read-only dashboard vs. write operations)
3. Webhook notifications for census events (issuer promotion, device quarantine)
4. Grafana-compatible metrics endpoint for external monitoring integration
