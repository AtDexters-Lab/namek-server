# Nexus Integration Spec

Spec for integrating a Nexus relay with namek-server for token-verified device traffic relay.

## 1. Overview

**Namek** is the device attestation authority, DNS orchestrator, and token issuer. It verifies that devices have genuine TPMs, issues short-lived JWTs, and manages DNS records that route traffic through relay infrastructure.

**Nexus** is the traffic relay. It accepts WebSocket connections from devices, verifies their JWTs via Namek's remote verifier, manages session nonces for the 3-stage handshake protocol, and routes traffic to device hostnames.

### How they interact

1. **Registration:** Nexus registers with Namek via mTLS (`POST /internal/v1/nexus/register`), sending periodic heartbeats at the server-specified interval.
2. **DNS orchestration:** Namek resolves the Nexus hostname to IPs and populates `relay.baseDomain` with A (IPv4) and AAAA (IPv6) records. A wildcard CNAME (`*.baseDomain → relay.baseDomain`) routes all device traffic through active relays.
3. **Token issuance:** Devices request JWTs from Namek (TPM-authenticated) and present them to Nexus on WebSocket connect.
4. **Token verification:** Nexus verifies device JWTs by calling Namek's remote verify endpoint (`POST /api/v1/tokens/verify`).

### Architecture

```
                           +-----------+
                           |  PowerDNS |
                           +-----^-----+
                                 |
                                 | A/AAAA record mgmt
                                 | (relay.baseDomain)
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
+----------+  /api/v1/tokens/verify
```

## 2. Registration & Heartbeat Protocol

### Endpoint

`POST /internal/v1/nexus/register`

### Authentication

mTLS with client certificate. The certificate must satisfy:

- **CA chain verification:** Certificate must chain to the CA loaded from `nexus.clientCACertFile`. Intermediate certificates are accepted from the TLS handshake. The verify options require `ExtKeyUsageClientAuth`.
- **SAN suffix matching:** At least one DNS SAN must match a suffix in `nexus.trustedDomainSuffixes`. Matching rules:
  - A leading dot is prepended to the suffix if not already present (prevents partial label matches — e.g., suffix `.proxy.example.com` will NOT match `evilproxy.example.com`)
  - A SAN matches if it ends with the dot-prefixed suffix, OR if it exactly equals the suffix without the leading dot (e.g., suffix `.proxy.example.com` accepts SAN `proxy.example.com`)
  - Wildcard SANs (e.g., `*.nexus.example.com`) are skipped — they are not concrete hostnames and would fail DNS resolution
- **Hostname extraction:** The first matching SAN becomes the Nexus identity. Namek resolves this hostname to determine relay IPs.

### Request body

```json
{"region": "us-west-2"}
```

The `region` field is optional. An empty body or `{}` is valid.

### Response

**HTTP 200:**
```json
{"heartbeat_interval": 30}
```

`heartbeat_interval` is an integer in seconds.

### Heartbeat cadence

Nexus must re-POST to the registration endpoint at the interval specified in `heartbeat_interval` (default: 30 seconds). Each heartbeat renews the instance's active status.

### Missed heartbeats

If Namek does not receive a heartbeat within `heartbeat_interval × inactive_threshold_multiplier` (defaults: 30s × 3 = 90s), the Nexus instance is marked inactive and its IPs are removed from relay DNS records.

### DNS effect

Active Nexus instance addresses populate `relay.baseDomain`:
- **A records** for IPv4 addresses (60s TTL)
- **AAAA records** for IPv6 addresses (60s TTL)
- Both record types are managed independently — a Nexus with only IPv6 addresses will have AAAA records but no A records, and vice versa
- A wildcard CNAME `*.baseDomain → relay.baseDomain` routes all device traffic through active relays

### IP resolution

Namek resolves the Nexus hostname to IPs on each heartbeat. On transient DNS resolution failures, stale IPs are preserved — the instance remains active with its last-known addresses. IPs are also periodically re-resolved between heartbeats to detect changes.

### Action item

Nexus must implement a registration client that:
1. Sends `POST /internal/v1/nexus/register` with mTLS on startup
2. Re-sends at the `heartbeat_interval` from the response
3. Retries with backoff on connection failure

## 3. Token Verification

### Endpoint

`POST /api/v1/tokens/verify` (no authentication required)

### Request

```json
{"token": "<JWT string>"}
```

### Response (valid token)

```json
{
  "valid": true,
  "claims": { /* full NexusClaims object */ },
  "error": ""
}
```

### Response (invalid token)

```json
{
  "valid": false,
  "claims": null,
  "error": "jwt validation failed: token is expired"
}
```

### Key behaviors

- **Always HTTP 200.** Invalid tokens are not HTTP errors. Always check the `valid` field.
- **Signing:** HMAC-SHA256 with an ephemeral secret generated at Namek startup. The secret is regenerated on every restart, invalidating all previously-issued tokens.
- **Why remote verification:** Nexus cannot know the signing secret (it's ephemeral and never shared). All token verification must go through Namek's remote endpoint.

### Nexus configuration

```yaml
remoteVerifierURL: "https://namek.example.com/api/v1/tokens/verify"
remoteVerifierTimeoutSeconds: 5
```

**`backendsJWTSecret` must be UNSET.** Nexus's validator falls back to local HMAC verification if the remote verifier returns a 5xx or network error. With Namek's ephemeral secret, local HMAC will always fail (different secret), silently masking remote verifier issues. Leave `backendsJWTSecret` empty so remote failures surface immediately.

### Namek restart impact

When Namek restarts:
1. Ephemeral signing secret is regenerated
2. All previously-issued tokens become invalid
3. Remote verify returns `valid: false` for all existing tokens
4. Any pending token verification fails — whether it's a new connection (stage 0), an in-progress handshake (stage 1), or a periodic reauth (stage 2)
5. Devices re-request tokens from Namek, which now signs with the new secret (automatic — devices re-attest)

The cascade is self-healing but causes a brief disruption.

### What the remote verifier checks

- HMAC-SHA256 signature validity
- Token expiry (`exp`)
- Issuer: `iss = "authorizer"`
- Audience: `aud = "nexus"`

### What Nexus checks locally after verify

- `handshake_max_age_seconds` — stage 0 token age limit
- `session_nonce` — must match Nexus-issued nonce (stages 1/2)
- Hostname/port consistency between handshake stages
- Weight consistency between stages

## 4. JWT Claims Reference

### Complete claims object

```json
{
  "iss": "authorizer",
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "aud": ["nexus"],
  "iat": 1709000000,
  "exp": 1709000030,
  "hostnames": [
    "a1b2c3d4e5f6g7h8.test.local",
    "*.a1b2c3d4e5f6g7h8.test.local",
    "mydevice.test.local",
    "*.mydevice.test.local"
  ],
  "tcp_ports": [],
  "udp_routes": [],
  "weight": 1,
  "session_nonce": "",
  "handshake_max_age_seconds": 60,
  "reauth_interval_seconds": 300,
  "reauth_grace_seconds": 30,
  "maintenance_grace_cap_seconds": 600,
  "authorizer_status_uri": "https://namek.example.com/health",
  "policy_version": "",
  "issued_at_quote": ""
}
```

### Claims table

| Claim | Type | Default | Description |
|-------|------|---------|-------------|
| `iss` | string | `"authorizer"` | Validated by remote verifier |
| `sub` | string | — | Device UUID, used for logging/metrics |
| `aud` | string[] | `["nexus"]` | Validated by remote verifier |
| `exp` / `iat` | int | 30s TTL | Short-lived; validated by remote verifier |
| `hostnames` | string[] | — | Canonical + custom hostnames, each with a `*.` wildcard variant |
| `tcp_ports` | int[] | `[]` | Currently empty (reserved) |
| `udp_routes` | object[] | `[]` | Currently empty (reserved) |
| `weight` | int | 1 | WRR load balancing weight |
| `session_nonce` | string | `""` | Empty for stage 0; Nexus-issued nonce for stages 1+ |
| `handshake_max_age_seconds` | int\|null | 60 | Stage 0 only; null for stages 1/2 |
| `reauth_interval_seconds` | int\|null | 300 | Present for all stages |
| `reauth_grace_seconds` | int\|null | 30 | Present for all stages |
| `maintenance_grace_cap_seconds` | int\|null | 600 | Present for all stages |
| `authorizer_status_uri` | string | — | `https://<namek>/health` |
| `policy_version` | string | `""` | Reserved, currently empty |
| `issued_at_quote` | string | `""` | Reserved, currently empty |

### Per-stage claim presence matrix

| Claim | Stage 0 | Stage 1 | Stage 2 |
|-------|---------|---------|---------|
| `session_nonce` | `""` (forced empty) | Nexus-issued nonce | Nexus-issued nonce |
| `handshake_max_age_seconds` | 60 (present) | `null` | `null` |
| `reauth_interval_seconds` | present | present | present |
| `reauth_grace_seconds` | present | present | present |
| `maintenance_grace_cap_seconds` | present | present | present |
| `hostnames`, `weight`, etc. | present | present | present |

## 5. Hostname Routing

### Hostname formats

- **Canonical:** `<slug>.baseDomain` — 16-character lowercase Crockford Base32 slug (alphabet: `0-9a-hjkmnp-tv-z`, excludes `i`, `l`, `o`, `u`). Example: `a1b2c3d4e5f6g7h8.test.local`
- **Custom:** `<label>.baseDomain` — human-friendly label (3-24 chars, lowercase alphanumeric). Example: `mydevice.test.local`
- **Wildcard:** Every hostname also has a `*.<hostname>` variant for subdomain routing

### How Nexus routes

SNI (L4) or Host header (L7) → exact match → wildcard suffix match against the `hostnames` claim.

### Wildcard compatibility

Nexus's `IsValidWildcard` requires ≥2 labels after `*.`. All Namek-issued wildcards satisfy this:
- `*.a1b2c3d4e5f6g7h8.test.local` → 3 labels after `*.` ✓

**Deployment constraint:** `baseDomain` must have ≥2 labels (e.g., `test.local`, not `local`). Wildcards like `*.slug.local` would have only 1 label after `*.` and fail `IsValidWildcard`.

### DNS wildcard CNAME

```
*.baseDomain.  CNAME  relay.baseDomain.
```

Zero per-device DNS operations for routing. Device hostnames resolve to the relay via the wildcard CNAME automatically.

## 6. Connection Lifecycle (3-Stage Protocol)

### Stage 0 — Handshake

1. Device requests token from Namek: `POST /api/v1/tokens/nexus { "stage": 0, "session_nonce": "" }`
2. Token includes hostnames, weight, timing parameters; `session_nonce` forced to `""`; `handshake_max_age_seconds` present
3. Device presents token to Nexus on WebSocket connect at `/connect`
4. Nexus verifies via remote verifier, issues challenge: `{"type": "handshake_challenge", "nonce": "<base64url-32-bytes>"}`

### Stage 1 — Attest

1. Device requests token from Namek: `POST /api/v1/tokens/nexus { "stage": 1, "session_nonce": "<from-nexus>" }`
2. Token includes same claims + `session_nonce` matching Nexus's challenge; `handshake_max_age_seconds` omitted
3. Nexus verifies nonce match, enables traffic

### Stage 2 — Reauth

1. Nexus sends challenge: `{"type": "reauth_challenge", "nonce": "<base64url-32-bytes>"}`
2. Device requests token from Namek: `POST /api/v1/tokens/nexus { "stage": 2, "session_nonce": "<from-nexus>" }`
3. Same as stage 1 but periodic (every `reauth_interval_seconds`)

### Challenge nonce format

32 bytes from `crypto/rand`, encoded as base64-raw-URL (no padding).

### Timing defaults

| Parameter | Default | Description |
|-----------|---------|-------------|
| `token.ttlSeconds` | 30 | JWT lifetime |
| `token.handshakeMaxAgeSeconds` | 60 | Max age for stage 0 tokens |
| `token.reauthIntervalSeconds` | 300 | Reauth every 5 minutes |
| `token.reauthGraceSeconds` | 30 | Grace period after challenge |
| `token.maintenanceGraceCapSeconds` | 600 | Max cumulative deferral |

## 7. Device Re-enrollment

When a device re-enrolls (same TPM, new AK), Namek updates the AK but preserves device ID, hostname, and slug.

**What Nexus observes:** The old WebSocket connection closes (device-initiated). A new connection opens with a fresh token. Same `sub` (device UUID), same `hostnames`. From Nexus's perspective, this is indistinguishable from a normal reconnect.

**No Nexus code changes needed.**

## 8. Health & Status

- **Namek health:** `GET /health` returns `{"status": "ok"}` — used by Nexus for `authorizer_status_uri` maintenance checks
- **Namek readiness:** `GET /ready` checks DB connectivity — returns `{"status": "ready"}` or `503`
- **Nexus health monitoring by Namek:** Namek marks Nexus inactive if heartbeat is missed; re-resolves IPs periodically to detect address changes

## 9. Configuration Guide

### Required Nexus configuration

```yaml
# Token verification — MUST use remote verifier (Namek's signing secret is ephemeral)
remoteVerifierURL: "https://namek.example.com/api/v1/tokens/verify"
remoteVerifierTimeoutSeconds: 5
# Do NOT set backendsJWTSecret — incompatible with Namek's ephemeral secret

# Hub TLS — cert SAN must match Namek's nexus.trustedDomainSuffixes
hubTlsCertFile: "/path/to/nexus-cert.pem"   # SAN: e.g., nexus-us.proxy.example.com
hubTlsKeyFile: "/path/to/nexus-key.pem"
```

### Registration client configuration (to be implemented)

```yaml
# Namek registration
namekRegistrationURL: "https://namek.example.com/internal/v1/nexus/register"
namekTlsCertFile: "/path/to/nexus-client-cert.pem"  # mTLS client cert
namekTlsKeyFile: "/path/to/nexus-client-key.pem"
namekCACertFile: "/path/to/namek-ca.pem"             # Namek server CA
region: "us-west-2"  # optional, sent in registration
```

## 10. Action Items for Nexus Team

1. **Registration client** — Periodic `POST /internal/v1/nexus/register` with mTLS, using `heartbeat_interval` from response
2. **Graceful re-registration** — On startup, register immediately; on connection failure, retry with backoff
3. **Config additions** — Namek URL, mTLS cert paths, region

## 11. Error Handling

### Token verify endpoint

Always HTTP 200 with `{valid, claims, error}` — never HTTP errors for invalid tokens.

### Registration endpoint

| Status | Meaning |
|--------|---------|
| 200 | Success |
| 400 | Malformed request body |
| 401 | Client certificate required / CA chain verification failed / SAN not trusted |
| 500 | Internal server error |
| 503 | Nexus authentication not configured on Namek (Namek misconfiguration; Nexus cannot fix) |

### Health endpoint

| Status | Meaning |
|--------|---------|
| 200 | OK |
| 503 | Not ready |

**Note:** The Nexus hostname is extracted from the mTLS client cert SAN by Namek's middleware, not from the request body. The cert SAN determines Nexus identity.

## 12. What Nexus Does NOT Need to Implement

- **TPM quote validation** — Namek handles all attestation
- **Device enrollment or state management** — Namek owns device lifecycle
- **JWT signing or key management** — Tokens are opaque to Nexus; verified remotely
- **DNS record management** — Namek orchestrates all DNS based on heartbeats

## 13. Known Limitations

1. **Ephemeral JWT signing secret.** Namek restart invalidates all tokens. Devices must re-authenticate. The cascade is self-healing (see Section 3).
2. **Single Namek instance.** Pending enrollments held in memory. No HA yet.
3. **No PCR validation.** TPM quotes verify proof-of-possession only; PCR values are not checked against reference measurements.
