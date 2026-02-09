# Namek Server

The Piccolo Orchestrator — a coordination service that bridges [piccolod](https://github.com/AtDexters-Lab/piccolod) devices with [Nexus Proxy](https://github.com/AtDexters-Lab/nexus-proxy-server) for secure remote access.

## What It Does

Namek Server is the managed control plane for Piccolo OS deployments. It handles the responsibilities that neither the on-device daemon nor the edge proxy should own:

- **Device authentication & attestation** — Verifies device identity and issues tokens for Nexus backend registration.
- **DNS-01 ACME orchestration** — Manages TXT records so piccolod can obtain wildcard TLS certificates without exposing port 80.
- **Account management** — Links user accounts to their registered devices.

### Future: PSFN Broker

In the next phase, Namek Server will also broker the **Piccolo Storage Federation Network (PSFN)** — where Piccolo devices replicate data across a peer mesh for durability:

- Peer discovery and negotiation
- Health scoring and network topology
- Per-tenant encryption enforcement with TPM attestation

## Where It Fits

```
┌──────────────┐       ┌──────────────┐       ┌──────────────────┐
│   piccolod   │◄─────►│ Namek Server │◄─────►│  Nexus Proxy     │
│  (on device) │       │ (orchestrator)│       │  (edge relay)    │
└──────────────┘       └──────────────┘       └──────────────────┘
       │                      │
       │  Device attestation  │  DNS-01 challenges
       │  Token issuance      │  Account management
       │  PSFN brokering      │
```

- **piccolod** runs on the user's hardware, serves the local portal, and connects to Nexus for remote access.
- **Nexus Proxy** is a privacy-first TLS passthrough relay — it never sees plaintext traffic.
- **Namek Server** coordinates between them: authenticating devices, managing DNS for certificate issuance, and (soon) brokering storage federation.

All three components are open source and self-hostable. Users who run their own Nexus and orchestrator need no account and pay nothing.

## License

[AGPL-3.0](LICENSE)
