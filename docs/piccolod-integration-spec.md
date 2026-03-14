# Piccolod Integration Spec

Spec for integrating piccolod with namek-server for TPM-attested remote device access.

## 1. Overview

Namek is a device attestation and authorization server. It verifies that a device has a genuine TPM, issues short-lived JWTs for relay (Nexus) authentication, and manages DNS records for device routing.

**Design principle: no bearer tokens.** Every authenticated request to namek requires a fresh TPM quote over a single-use nonce. There is no session cookie or long-lived token. The TPM is the credential.

### Go packages

| Package | Import path | Purpose |
|---------|-------------|---------|
| `tpmdevice` | `github.com/AtDexters-Lab/namek-server/pkg/tpmdevice` | TPM operations: open, quote, activate credential |
| `swtpm` | `github.com/AtDexters-Lab/namek-server/pkg/swtpm` | Software TPM for development/testing |
| `namekclient` | `github.com/AtDexters-Lab/namek-server/pkg/namekclient` | HTTP client for all namek API endpoints |

**Module:** `github.com/AtDexters-Lab/namek-server`
**Key deps:** `go-tpm v0.9.8`, `go-attestation v0.6.0`, Go 1.24+

## 2. Architecture

```
                           +-----------+
                           |  PowerDNS |
                           +-----^-----+
                                 |
                                 | DNS record mgmt
                                 |
+----------+     HTTPS/TPM      +-----------+
| piccolod |-------------------->|   namek   |
+----------+                     +-----------+
     |                                ^
     |  WebSocket                     | mTLS
     |  (JWT auth)                    | /internal/v1/nexus/register
     v                                |
+----------+                     +-----------+
|  Nexus   |-------------------->|   namek   |
|  relay   |   token verify      +-----------+
+----------+
```

### DNS strategy

Namek uses a wildcard CNAME to route all device traffic through the relay:

```
*.baseDomain.  CNAME  relay.baseDomain.
```

This means **zero per-device DNS operations** for routing. When a device enrolls, its hostname (`<slug>.baseDomain`) automatically resolves to the relay via the wildcard. Namek only touches DNS for:

- Relay A records: pointing `relay.baseDomain` at active Nexus IPs
- ACME TXT records: `_acme-challenge.<hostname>.baseDomain` for TLS cert issuance

### Token flow

1. Device gets a JWT from namek via `POST /api/v1/tokens/nexus` (TPM-authenticated)
2. Device presents JWT to Nexus relay during WebSocket connection
3. Nexus verifies JWT via `POST /api/v1/tokens/verify` (no auth required)

## 3. Integration Prerequisites

Two gaps in `pkg/` must be addressed before piccolod can persist identity across restarts.

### Gap 1: AK Persistence

**Status: IMPLEMENTED**

`tpmdevice.Open()` now accepts a `WithStateDir(dir)` option. When set:
- On first open: creates a new AK under the SRK, saves `ak_pub` and `ak_priv` blobs to `dir/`
- On subsequent opens: loads existing blobs from disk, loads the AK into the TPM via the SRK

```go
dev, err := tpmdevice.Open(ctx, "/dev/tpmrm0",
    tpmdevice.WithStateDir("/var/lib/piccolod/tpm"),
)
```

Files written (mode `0600`, directory mode `0700`):
- `ak_pub` — TPMT_PUBLIC bytes (raw, no TPM2B size prefix)
- `ak_priv` — TPM2B_PRIVATE bytes

**Important:** The AK is bound to the SRK, which is a deterministic primary derived from the TPM's seed. As long as the TPM ownership hasn't been cleared, the same SRK is recreated on every boot, and saved AK blobs remain loadable.

### Gap 2: Device ID Restore

**Status: IMPLEMENTED**

`namekclient.New()` now accepts `WithDeviceID(id)`:

```go
client := namekclient.New(serverURL, dev,
    namekclient.WithDeviceID(savedDeviceID),
)
```

This sets the device ID so authenticated requests work without re-enrolling.

### What piccolod must persist

| Field | Source | Purpose |
|-------|--------|---------|
| `device_id` | `EnrollResult.DeviceID` | Identifies device to namek |
| `ak_private` | `ak_priv` file from state dir | Reloads AK into TPM |
| `ak_public` | `ak_pub` file from state dir | Reloads AK into TPM |
| `hostname` | `EnrollResult.Hostname` | Canonical device hostname |
| `identity_class` | `EnrollResult.IdentityClass` | `"hardware_tpm"` or `"software_tpm"` |

**Suggested format:** JSON file at `/var/lib/piccolod/identity.json`, mode `0600`.

```json
{
  "device_id": "550e8400-e29b-41d4-a716-446655440000",
  "hostname": "a1b2c3d4e5f6g7h8.example.com",
  "identity_class": "hardware_tpm"
}
```

AK blobs are stored separately by `tpmdevice` in the state dir (e.g. `/var/lib/piccolod/tpm/`).

## 4. Quick Start

### First boot (no identity file)

```go
ctx := context.Background()

// 1. Open TPM with persistence
dev, err := tpmdevice.Open(ctx, "/dev/tpmrm0",
    tpmdevice.WithStateDir("/var/lib/piccolod/tpm"),
)
if err != nil {
    log.Fatal(err)
}
defer dev.Close()

// 2. Create client and enroll
client := namekclient.New("https://namek.example.com", dev)
result, err := client.Enroll(ctx)
if err != nil {
    log.Fatal(err)
}

// 3. Save identity to disk
saveIdentity(result) // piccolod's responsibility

// 4. Get Nexus token for relay connection
token, err := client.RequestNexusToken(ctx, 0, "") // stage 0 = handshake
if err != nil {
    log.Fatal(err)
}
// Use token to connect to Nexus relay
```

### Restart (identity file exists)

```go
ctx := context.Background()

identity := loadIdentity() // read from /var/lib/piccolod/identity.json

// 1. Open TPM with saved AK
dev, err := tpmdevice.Open(ctx, "/dev/tpmrm0",
    tpmdevice.WithStateDir("/var/lib/piccolod/tpm"),
)
if err != nil {
    log.Fatal(err)
}
defer dev.Close()

// 2. Create client with saved device ID
client := namekclient.New("https://namek.example.com", dev,
    namekclient.WithDeviceID(identity.DeviceID),
)

// 3. Resume — no enrollment needed
token, err := client.RequestNexusToken(ctx, 0, "")
if err != nil {
    // If 401: AK or device ID invalid, re-enroll
    log.Fatal(err)
}
```

## 5. Lifecycle Management

### TPM detection

Piccolod should probe in order:

1. `/dev/tpmrm0` — kernel resource manager (preferred)
2. `/dev/tpm0` — direct access (single-user)
3. Software TPM via `swtpm.Start()` — development only

### Enrollment flow

Two-phase challenge-response:

**Phase 1 — Start enrollment:**
- Device sends EK certificate + AK public parameters
- Server verifies EK cert against trusted CA roots
- Server creates credential challenge encrypted to the EK
- Returns: enrollment nonce + encrypted credential

**Phase 2 — Complete enrollment:**
- Device decrypts credential via `ActivateCredential` (proves EK/AK binding)
- Device generates TPM quote over enrollment nonce (proves AK possession)
- Device sends decrypted secret + quote
- Server verifies both, creates device record with a 16-character base32-crockford slug as hostname label
- Returns: device ID, hostname (`<slug>.baseDomain`), identity class, Nexus endpoints

The `namekclient.Enroll()` method handles both phases in a single call.

**Re-enrollment:** If an active device re-enrolls (same EK, new AK), the server updates the AK on the existing device record. Hostname, slug, and device ID are preserved. Suspended or revoked devices cannot re-enroll (409).

### Identity persistence

After successful enrollment, piccolod must persist:
1. The `EnrollResult` fields to its identity file
2. AK blobs are automatically persisted by `WithStateDir`

File permissions:
- Identity JSON: `0600`
- AK blob directory: `0700`
- AK blob files: `0600`

### Restart recovery decision tree

```
Identity file exists?
├── YES
│   └── TPM accessible + AK loads?
│       ├── YES → Create client with WithDeviceID, resume
│       │   └── Auth succeeds?
│       │       ├── YES → Normal operation
│       │       └── NO (401) → Re-enroll (AK may have been replaced)
│       └── NO → Log error, retry with backoff
└── NO → Fresh enrollment (or re-enrollment if device was previously enrolled)
```

**Re-enrollment:** If identity files are lost but the TPM still has the same EK, calling `Enroll()` again will re-enroll the device — updating the AK on the existing record and returning the same device ID and hostname. No admin intervention needed.

### Error recovery

| Error | Meaning | Action |
|-------|---------|--------|
| TPM open fails | Device/permissions issue | Retry with backoff, check `/dev/tpmrm0` permissions |
| Enroll returns 409 | EK enrolled on suspended/revoked device | Contact admin; active devices re-enroll automatically |
| Enroll returns 503 | Pending enrollment capacity | Retry with backoff (server limit: `enrollment.maxPending`) |
| Auth returns 401 | Nonce expired/invalid, or device not found | Re-fetch nonce and retry; if persistent, re-enroll |
| Auth returns 403 | Device suspended/revoked | Stop retrying, alert operator |
| Token request fails | Server error | Retry with backoff |

## 6. Nexus Token Protocol

Nexus tokens are JWTs issued by namek and presented by devices to the Nexus relay for WebSocket authentication.

### Token stages

```
                    ┌──────────────────┐
                    │  Device connects │
                    │   to Nexus WS    │
                    └────────┬─────────┘
                             │
                    ┌────────▼─────────┐
                    │  Stage 0:        │
                    │  HANDSHAKE       │
                    │  session_nonce="" │
                    │  (initial auth)  │
                    └────────┬─────────┘
                             │
                    ┌────────▼─────────┐
                    │  Nexus sends     │
                    │  session_nonce   │
                    └────────┬─────────┘
                             │
                    ┌────────▼─────────┐
                    │  Stage 1:        │
                    │  ATTEST          │
                    │  session_nonce=X │
                    │  (binds session) │
                    └────────┬─────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
              ▼                             ▼
     ┌─────────────────┐          ┌─────────────────┐
     │  Normal traffic  │          │  After reauth   │
     │                  │          │  interval (300s) │
     └─────────────────┘          └────────┬────────┘
                                           │
                                  ┌────────▼────────┐
                                  │  Stage 2:       │
                                  │  REAUTH         │
                                  │  session_nonce=X│
                                  │  (periodic)     │
                                  └────────┬────────┘
                                           │
                                           ▼
                                     (repeat)
```

**Stage 0 (Handshake):** Device requests token with `stage=0, session_nonce=""`. Token includes `handshake_max_age_seconds` telling Nexus how long to wait for Stage 1. The `session_nonce` claim is empty.

**Stage 1 (Attest):** After WebSocket connection, Nexus provides a `session_nonce`. Device requests token with `stage=1, session_nonce=<from_nexus>`. This binds the token to the specific WebSocket session.

**Stage 2 (Reauth):** Periodic re-authentication. Device requests token with `stage=2, session_nonce=<same>` every `reauth_interval_seconds` (default 300s). Grace period of `reauth_grace_seconds` (default 30s) before Nexus drops the connection.

### JWT claims reference

```json
{
  "iss": "authorizer",
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "aud": ["nexus"],
  "iat": 1709000000,
  "exp": 1709000030,
  "hostnames": [
    "a1b2c3d4e5f6g7h8.example.com",
    "*.a1b2c3d4e5f6g7h8.example.com",
    "mydevice.example.com",
    "*.mydevice.example.com"
  ],
  "tcp_ports": [],
  "udp_routes": [],
  "weight": 1,
  "session_nonce": "abc123",
  "handshake_max_age_seconds": 60,
  "reauth_interval_seconds": 300,
  "reauth_grace_seconds": 30,
  "maintenance_grace_cap_seconds": 600,
  "authorizer_status_uri": "https://namek.example.com/health",
  "policy_version": "",
  "issued_at_quote": ""
}
```

| Claim | Type | Description |
|-------|------|-------------|
| `iss` | string | Always `"authorizer"` |
| `sub` | string | Device UUID |
| `aud` | string[] | Always `["nexus"]` |
| `iat` | int | Unix timestamp of issuance |
| `exp` | int | Unix timestamp of expiry (default: `iat + 30s`) |
| `hostnames` | string[] | Canonical + custom hostnames, each with a `*.` wildcard variant for subdomain routing |
| `tcp_ports` | int[] | Allowed TCP ports (currently empty) |
| `udp_routes` | object[] | UDP routing config (currently empty) |
| `weight` | int | Load balancing weight (default: 1) |
| `session_nonce` | string | Nexus-provided session identifier; empty for stage 0 |
| `handshake_max_age_seconds` | int\|null | Max time for stage 1 after stage 0 (stage 0 only, default: 60) |
| `reauth_interval_seconds` | int\|null | How often to reauth (default: 300) |
| `reauth_grace_seconds` | int\|null | Grace period after missed reauth (default: 30) |
| `maintenance_grace_cap_seconds` | int\|null | Max grace during maintenance (default: 600) |
| `authorizer_status_uri` | string | Health endpoint for the authorizer |
| `policy_version` | string | Reserved for future use |
| `issued_at_quote` | string | Reserved for future use |

**Important:** The JWT signing secret is generated randomly at namek startup. Restarting namek invalidates all previously-issued tokens. Devices must request new tokens after a namek restart.

## 7. ACME TLS Certificates

Optional. Only needed if the device runs an HTTPS server that needs a valid TLS certificate.

### DNS-01 challenge flow

```
1. Device computes ACME challenge digest:
   digest = base64url(SHA-256(key_authorization))
   // Printable ASCII, max 512 characters

2. Device calls: POST /api/v1/acme/challenges { "digest": "<digest>", "hostname": "<optional>" }
   → namek creates TXT record: _acme-challenge.<target-hostname> = <digest>
   ← Returns: { "id": "<uuid>", "fqdn": "_acme-challenge.<hostname>" }

3. Device tells ACME CA to validate the DNS-01 challenge
   → CA queries DNS, finds the TXT record, validates

4. Device calls: DELETE /api/v1/acme/challenges/<id>
   → namek removes the TXT record
```

**Notes:**
- Challenge TTL: 1 hour
- Auto-cleanup: every 5 minutes, expired challenges and their DNS records are removed
- ACME challenges can target **any hostname the device owns** (canonical or custom FQDN). If `hostname` is omitted, defaults to the canonical hostname.
- Digest validation: printable ASCII (0x20-0x7E), 1-512 characters
- TXT record TTL in DNS: 300 seconds

## 8. Custom Hostname

Devices get a canonical hostname at enrollment: `<slug>.baseDomain` (16-char base32-crockford slug, 80 bits entropy). They can optionally set a custom hostname for human-friendly access.

### Validation rules

- Pattern: `^[a-z0-9]{3,24}$` (lowercase alphanumeric, 3-24 chars)
- No hyphens, underscores, or dots
- Reserved words: `relay`, `namek`, `www`, `mail`, `ns1`, `ns2`, `admin`, `api`, `internal`
- Must be unique across all devices and not match any device's slug (cross-namespace uniqueness)
- Must not be in the released hostname cooldown period (default: 365 days)

### Effect on tokens

When a custom hostname is set, the `hostnames` JWT claim includes both with wildcard variants:
```json
[
  "a1b2c3d4e5f6g7h8.example.com",
  "*.a1b2c3d4e5f6g7h8.example.com",
  "mydevice.example.com",
  "*.mydevice.example.com"
]
```

The custom hostname resolves via the same wildcard CNAME as the canonical hostname.

### Rate limiting

Hostname changes are rate-limited:
- **Max changes per year:** 5 (default)
- **Cooldown between changes:** 30 days (default)
- **Released hostname cooldown:** 365 days (default) — after a device releases a hostname, no one can claim it for this duration

### Changing hostname

A device can change its custom hostname via `PATCH /api/v1/devices/me/hostname`, subject to rate limits. The old hostname is released and enters the cooldown period before it can be claimed by any device.

## 9. API Reference

All endpoints are under `https://<namek-host>`. Request/response bodies are JSON.

### Error format

All errors return:
```json
{ "error": "<message>" }
```

### System endpoints (no auth)

#### GET /health

Returns server liveness.

**Response:** `200 OK`
```json
{ "status": "ok" }
```

#### GET /ready

Returns server readiness (checks database connectivity).

**Response:** `200 OK`
```json
{ "status": "ready" }
```

**Response:** `503 Service Unavailable`
```json
{ "status": "not ready", "error": "database unavailable" }
```

---

### Enrollment endpoints (rate-limited, no auth)

#### POST /api/v1/devices/enroll

Start enrollment. Rate-limited per-IP.

**Request:**
```json
{
  "ek_cert": "<base64 DER-encoded EK certificate>",
  "ak_params": "<base64 TPMT_PUBLIC bytes>"
}
```

**Response:** `200 OK`
```json
{
  "nonce": "<hex enrollment nonce>",
  "enc_credential": "<base64 encrypted credential>"
}
```

**Errors:**
| Status | Meaning |
|--------|---------|
| 400 | Invalid request body or encoding |
| 409 | Device with this EK is suspended or revoked (active devices proceed to re-enrollment) |
| 429 | Rate limit exceeded (check `Retry-After` header) |
| 500 | Internal error |
| 503 | Enrollment capacity reached |

#### POST /api/v1/devices/enroll/attest

Complete enrollment with credential proof and TPM quote.

**Request:**
```json
{
  "nonce": "<enrollment nonce from phase 1>",
  "secret": "<base64 decrypted 32-byte secret>",
  "quote": "<base64 TPM quote wire format>"
}
```

**Response:** `201 Created` (fresh enrollment) or `200 OK` (re-enrollment)
```json
{
  "device_id": "550e8400-e29b-41d4-a716-446655440000",
  "hostname": "a1b2c3d4e5f6g7h8.example.com",
  "identity_class": "hardware_tpm",
  "nexus_endpoints": ["wss://relay.example.com/connect"],
  "retry_after_seconds": 5,
  "reenrolled": true
}
```

- `retry_after_seconds` is included only when `nexus_endpoints` is empty (no relay registered yet).
- `reenrolled` is `true` when an active device re-enrolls with a new AK. The device ID and hostname are preserved.

**Errors:**
| Status | Meaning |
|--------|---------|
| 400 | Invalid body, expired/unknown nonce |
| 401 | Credential verification or quote verification failed |
| 409 | Device already enrolled (race with another enrollment) |
| 429 | Rate limit exceeded |
| 500 | Internal error |

---

### Auth endpoint (rate-limited, no auth)

#### GET /api/v1/nonce

Get a single-use nonce for TPM quote authentication.

**Response:** `200 OK`
```json
{
  "nonce": "<base64url-encoded 32-byte nonce>",
  "expires_at": "2024-03-01T12:00:60Z"
}
```

**Errors:**
| Status | Meaning |
|--------|---------|
| 429 | Rate limit exceeded |
| 503 | Nonce store at capacity (10,000 active nonces) |

---

### Device endpoints (TPM-authenticated)

All device endpoints require three headers:
```
X-Device-ID: <device UUID>
X-Nonce: <nonce from GET /nonce>
X-TPM-Quote: <base64 TPM quote over nonce>
```

The nonce is consumed on use (single-use). A new nonce must be fetched for each request.

#### GET /api/v1/devices/me

Get device info.

**Response:** `200 OK`
```json
{
  "device_id": "550e8400-e29b-41d4-a716-446655440000",
  "hostname": "a1b2c3d4e5f6g7h8.example.com",
  "custom_hostname": "mydevice",
  "alias_domains": ["app.example.com"],
  "status": "active",
  "identity_class": "hardware_tpm",
  "nexus_endpoints": ["wss://relay.example.com/connect"]
}
```

#### PATCH /api/v1/devices/me/hostname

Set or update custom hostname.

**Request:**
```json
{ "custom_hostname": "mydevice" }
```

**Response:** `200 OK`
```json
{ "custom_hostname": "mydevice" }
```

**Errors:**
| Status | Meaning |
|--------|---------|
| 400 | Invalid hostname, rate limit exceeded, cooldown not elapsed, or hostname in released cooldown (see section 8) |

---

### Token endpoints

#### POST /api/v1/tokens/nexus (TPM-authenticated)

Issue a Nexus JWT.

**Request:**
```json
{
  "stage": 0,
  "session_nonce": ""
}
```

`stage` must be 0, 1, or 2. `session_nonce` is required for stages 1 and 2.

**Response:** `200 OK`
```json
{ "token": "<signed JWT>" }
```

**Errors:**
| Status | Meaning |
|--------|---------|
| 400 | Invalid stage or missing session_nonce |
| 401 | TPM auth failed |
| 500 | Token signing failed |

#### POST /api/v1/tokens/verify (no auth)

Verify a Nexus JWT. Called by Nexus relays.

**Request:**
```json
{ "token": "<JWT string>" }
```

**Response:** `200 OK`
```json
{
  "valid": true,
  "claims": { ... },
  "error": ""
}
```

On invalid token:
```json
{
  "valid": false,
  "claims": null,
  "error": "jwt validation failed: token is expired"
}
```

---

### ACME endpoints (TPM-authenticated)

#### POST /api/v1/acme/challenges

Create an ACME DNS-01 challenge TXT record.

**Request:**
```json
{
  "digest": "<printable ASCII, 1-512 chars>",
  "hostname": "<optional: canonical or custom FQDN>"
}
```

If `hostname` is omitted, the challenge targets the device's canonical hostname. If provided, the device must own the hostname (canonical or custom FQDN).

**Response:** `201 Created`
```json
{
  "id": "challenge-uuid",
  "fqdn": "_acme-challenge.a1b2c3d4e5f6g7h8.example.com"
}
```

**Errors:**
| Status | Meaning |
|--------|---------|
| 400 | Invalid digest format, or hostname not authorized |
| 500 | DNS record creation failed |

---

### Alias domain endpoints (TPM-authenticated)

All alias domain endpoints require TPM authentication headers and are rate-limited: 10 mutations/min and 30 reads/min per device.

#### POST /api/v1/domains

Register a new alias domain for the device's account.

**Request:**
```json
{ "domain": "app.example.com" }
```

**Response:** `201 Created`
```json
{
  "id": "<uuid>",
  "account_id": "<uuid>",
  "domain": "app.example.com",
  "status": "pending",
  "cname_target": "a1b2c3d4e5f6g7h8.example.com",
  "created_at": "2026-03-12T00:00:00Z",
  "expires_at": "2026-03-19T00:00:00Z"
}
```

**Errors:**
| Status | Meaning |
|--------|---------|
| 400 | Invalid domain format, baseDomain subdomain, or conflicts with domain under another account |
| 409 | Domain already registered |
| 429 | Rate limit exceeded |

#### GET /api/v1/domains

List all alias domains for the device's account.

**Response:** `200 OK`
```json
{
  "domains": [
    {
      "id": "<uuid>",
      "account_id": "<uuid>",
      "domain": "app.example.com",
      "status": "verified",
      "cname_target": "a1b2c3d4e5f6g7h8.example.com",
      "created_at": "2026-03-12T00:00:00Z",
      "verified_at": "2026-03-12T00:05:00Z",
      "assigned_devices": ["<uuid>"]
    }
  ]
}
```

#### POST /api/v1/domains/:id/verify

Trigger CNAME verification. The domain's CNAME must point to a `<slug>.baseDomain` where the slug belongs to a device under the same account.

**Response:** `200 OK`
```json
{
  "id": "<uuid>",
  "domain": "app.example.com",
  "status": "verified",
  "verified_at": "2026-03-12T00:05:00Z"
}
```

**Errors:**
| Status | Meaning |
|--------|---------|
| 400 | CNAME not found, does not point to baseDomain, or slug not in this account |
| 404 | Domain not found |

#### DELETE /api/v1/domains/:id

Delete an alias domain and all its device assignments.

**Response:** `204 No Content`

#### GET /api/v1/domains/:id/assignments

List device assignments for a domain.

**Response:** `200 OK`
```json
{
  "assignments": [
    { "device_id": "<uuid>", "domain": "app.example.com", "created_at": "2026-03-12T00:10:00Z" }
  ]
}
```

#### POST /api/v1/domains/:id/assignments

Assign a verified domain to one or more devices. Additive — existing assignments are preserved.

**Request:**
```json
{ "device_ids": ["<uuid>"] }
```

**Response:** `200 OK`
```json
{
  "assignments": [
    { "device_id": "<uuid>", "domain": "app.example.com", "created_at": "2026-03-12T00:10:00Z" }
  ]
}
```

**Errors:**
| Status | Meaning |
|--------|---------|
| 400 | Domain not verified, or device not in same account |
| 404 | Domain not found |

#### DELETE /api/v1/domains/:id/assignments/:device_id

Remove a device's assignment to a domain.

**Response:** `204 No Content`

---

#### DELETE /api/v1/acme/challenges/:id

Delete an ACME challenge and its DNS record.

**Response:** `204 No Content`

**Errors:**
| Status | Meaning |
|--------|---------|
| 400 | Invalid challenge UUID |
| 404 | Challenge not found (or not owned by this device) |
| 500 | Internal error |

## 10. Error Handling

### HTTP error codes

| Code | Meaning | Retry? |
|------|---------|--------|
| 400 | Bad request (malformed input) | No — fix request |
| 401 | Auth failed (bad nonce, quote, or device) | Yes — re-fetch nonce, retry |
| 403 | Forbidden (device suspended/revoked) | No — contact admin |
| 404 | Resource not found | No |
| 409 | Conflict (duplicate enrollment) | No — already enrolled |
| 429 | Rate limited | Yes — wait `Retry-After` seconds |
| 500 | Server error | Yes — retry with backoff |
| 503 | Service unavailable (capacity) | Yes — retry with backoff |

### Nonce lifecycle

- Nonces are single-use: consumed immediately on verification
- TTL: 60 seconds — fetch nonce immediately before the request that uses it
- Max capacity: 10,000 concurrent nonces
- Cleanup: every 30 seconds
- If a request fails and the nonce was consumed, fetch a new one

### Enrollment error scenarios

| Scenario | What happens |
|----------|-------------|
| EK cert not trusted | `StartEnroll` returns 500 (logged as EK verification failure) |
| EK enrolled (suspended/revoked) | `StartEnroll` returns 409 (active devices re-enroll) |
| Enrollment timeout (>300s between phases) | `CompleteEnroll` returns 400 (pending expired) |
| Wrong secret | `CompleteEnroll` returns 401 |
| Bad quote | `CompleteEnroll` returns 401 |
| Max pending reached | `StartEnroll` returns 503 |

### Recommended retry strategy

```
base_delay = 1s
max_delay = 60s
jitter = random(0, 0.5 * delay)

for attempt in 1..max_attempts:
    result = make_request()
    if result.success or result.status in [400, 403, 404, 409]:
        return result  // don't retry client errors (except 401, 429)
    delay = min(base_delay * 2^attempt, max_delay) + jitter
    sleep(delay)
```

## 11. Development Setup

### Prerequisites

- Docker and Docker Compose
- `swtpm` and `swtpm-tools` (software TPM)
- Go 1.24+

### Setup and run

```bash
# 1. Start infrastructure (PostgreSQL, PowerDNS, Pebble ACME) + init swtpm
make dev-deps

# 2. Build and run namek server
make dev

# 3. Run integration tests (in another terminal)
make test-integration
```

### Key paths

| Path | Purpose |
|------|---------|
| `.local/swtpm/` | Software TPM state directory |
| `.local/swtpm/localca/` | swtpm CA certificates (EK signing) |
| `deploy/pebble/pebble.minica.pem` | Pebble ACME CA cert |
| `config.dev.yaml` | Dev server configuration |

### Dev config defaults

```yaml
listenAddress: ":8443"         # HTTPS
httpAddress: ":8080"           # HTTP redirect

dns:
  baseDomain: "test.local"
  zone: "test.local."
  relayHostname: "relay.test.local"

token:
  ttlSeconds: 30               # JWT lifetime (implicit default)
  handshakeMaxAgeSeconds: 60
  reauthIntervalSeconds: 300
  reauthGraceSeconds: 30
  maintenanceGraceCapSeconds: 600
  defaultWeight: 1

enrollment:
  maxPending: 100
  pendingTTLSeconds: 300
  rateLimitPerSecond: 100
  rateLimitPerIPPerSecond: 50
```

## 12. Known Limitations

1. **Ephemeral JWT signing secret.** Generated randomly at namek startup. All tokens are invalidated when namek restarts. Devices must request new tokens.

2. **Single namek instance.** Pending enrollments are stored in memory. Multi-instance deployment would require shared state for the pending enrollment map.

3. **No PCR validation.** TPM quotes verify proof-of-possession of the AK only. PCR values in the quote are not checked against any reference measurements.

4. **No admin API.** Device management (suspension, revocation, deletion) must be done directly in the database.

## 13. Appendix: Wire Formats

### TPM Quote

```
base64(uint32_BE(attestLen) || TPMS_ATTEST || TPMT_SIGNATURE)
```

- `attestLen`: 4 bytes, big-endian length of the TPMS_ATTEST structure
- `TPMS_ATTEST`: variable-length attestation data from `tpm2.QuoteRaw`
- `TPMT_SIGNATURE`: variable-length signature (RSASSA-SHA256, 2048-bit)

### EncCredential (credential challenge)

```
uint16_BE(credBlobLen) || credBlob || encSecret
```

- `credBlobLen`: 2 bytes, big-endian length of credBlob
- `credBlob`: includes TPM2B size prefix (2 bytes + HMAC + encrypted credential)
- `encSecret`: includes TPM2B size prefix (2 bytes + RSA-OAEP encrypted seed)

The `ActivateCredential` implementation strips the TPM2B prefixes before calling the TPM command, since `ActivateCredentialUsingAuth` adds its own framing.

### AK Parameters

Raw `TPMT_PUBLIC` bytes as returned by `tpm2.CreateKey`. No `TPM2B_PUBLIC` size prefix. Server-side `tpm2legacy.DecodePublic()` expects this format.

Key properties:
- Algorithm: RSA 2048-bit
- Scheme: RSASSA with SHA-256
- Attributes: FixedTPM, FixedParent, SensitiveDataOrigin, Restricted, Sign, NoDA, UserWithAuth
