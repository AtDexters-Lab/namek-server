# namek-server

Orchestrator for Piccolo OS — handles device authentication, DNS orchestration, and certificate issuance.

![Stage: Alpha](https://img.shields.io/badge/Stage-Alpha-orange)

## Install

### Piccolo OS (Recommended)

If you're running [Piccolo OS](https://github.com/AtDexters-Lab/piccolo-os), Namek is available as a **one-click install** from the [Piccolo Store](https://github.com/AtDexters-Lab/piccolo-store). Open the portal, find Namek, and click install — no configuration required.

### Self-Hosted

For running Namek independently. Requires Go 1.24+, PostgreSQL 16+, and PowerDNS.

```bash
git clone https://github.com/AtDexters-Lab/namek-server.git
cd namek-server
make build                          # outputs bin/namek
cp config.example.yaml config.yaml  # edit for your environment
./bin/namek -config config.yaml
```

All config fields are annotated in [`config.example.yaml`](./config.example.yaml). For a production Docker Compose setup, see [`deploy/`](./deploy/).

Verify it's running:

```bash
curl -k https://localhost/health    # 200 OK — server is up
curl -k https://localhost/ready     # 200 OK — database connected
```

## What It Does

Namek is the control plane for Piccolo OS deployments. It handles the responsibilities that neither the on-device daemon nor the edge proxy should own:

- **Device authentication & attestation** — Verifies device identity via TPM 2.0 and issues tokens for Nexus relay registration.
- **DNS-01 ACME orchestration** — Manages TXT records so piccolod can obtain wildcard TLS certificates without exposing port 80.
- **Account management** — Links user accounts to their registered devices.
- **Custom domain support** — Users can bring their own domains with DNS-based ownership verification.

## Where It Fits

```
┌──────────────┐       ┌──────────────┐       ┌──────────────────┐
│   piccolod   │◄─────►│ Namek Server │◄─────►│  Nexus Proxy     │
│  (on device) │       │ (orchestrator)│       │  (edge relay)    │
└──────────────┘       └──────────────┘       └──────────────────┘
       │                      │
       │  Device attestation  │  DNS-01 challenges
       │  Token issuance      │  Account & domain management
```

- **piccolod** runs on the user's hardware, serves the local portal, and connects to Nexus for remote access.
- **Nexus Proxy** is a privacy-first TLS passthrough relay — it never sees plaintext traffic.
- **Namek Server** coordinates between them: authenticating devices, managing DNS for certificate issuance, and brokering account and domain operations.

All three components are open source and self-hostable. Users who run their own Nexus and orchestrator need no account and pay nothing. For the full architecture, see the [piccolo-os](https://github.com/AtDexters-Lab/piccolo-os) README.

## API

Namek exposes a REST API over HTTPS with health probes at `/health` and `/ready`, device enrollment and operations under `/api/v1/`, and Nexus-internal endpoints under `/internal/v1/` (mTLS).

Operator endpoints (census, fleet health, recovery) are available on the admin listener — see `adminAddress` in [`config.example.yaml`](./config.example.yaml).

Full specification: [`api/openapi.yaml`](./api/openapi.yaml) (OpenAPI 3.1)

## Development

```bash
make dev-deps   # starts Postgres, PowerDNS, Pebble via Docker Compose
make dev        # builds and runs with config.dev.yaml
make test       # runs tests with race detector
make dev-down   # tears down Docker services
```

## Docs

- [piccolod integration spec](./docs/piccolod-integration-spec.md) — how the on-device daemon talks to Namek
- [Nexus integration spec](./docs/nexus-integration-spec.md) — relay registration and token verification
- [RFCs](./docs/rfc/) — design documents covering [architecture](./docs/rfc/001-foundation.md), [custom domains](./docs/rfc/002-alias-domains.md), [fleet trust](./docs/rfc/003-fleet-consensus-trust.md), [resilience](./docs/rfc/004-stateless-resilience.md), and more

## Planned: PSFN Broker

In a future phase, Namek will also broker the **Piccolo Storage Federation Network (PSFN)** — where Piccolo devices replicate data across a peer mesh for durability:

- Peer discovery and negotiation
- Health scoring and network topology
- Per-tenant encryption enforcement with TPM attestation

## The Piccolo Ecosystem

| Component | Role |
|-----------|------|
| [piccolo-os](https://github.com/AtDexters-Lab/piccolo-os) | OS images, install guides, and project hub |
| [piccolod](https://github.com/AtDexters-Lab/piccolod) | On-device daemon — portal, app management, encryption |
| [namek-server](https://github.com/AtDexters-Lab/namek-server) | Orchestrator — device auth, DNS, certificates |
| [nexus-proxy-server](https://github.com/AtDexters-Lab/nexus-proxy-server) | Edge relay — remote access with device-terminated TLS |
| [piccolo-store](https://github.com/AtDexters-Lab/piccolo-store) | App catalog — manifests for installable apps |

## License

AGPL-3.0 — see [LICENSE](./LICENSE).
