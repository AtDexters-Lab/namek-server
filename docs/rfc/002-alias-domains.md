# RFC 002: Alias Domains

**Status:** Draft
**Author:** Piccolo Team
**Created:** 2026-03-12

## Summary

Allow users to bring their own domains (e.g., `app.example.com`) and point them at their Piccolo devices. Alias domains are verified via CNAME, routed through the existing Nexus relay infrastructure, and secured with per-subdomain HTTP-01 TLS certificates issued on demand by the device.

This RFC also introduces a minimal **account** concept. Currently Namek only has devices (no user accounts). Alias domains — and eventually custom hostnames — are account-level resources that can be shared across multiple devices, enabling future clustering and load balancing.

## Key Decisions

1. **Account-scoped domains** — Alias domains belong to an account, not a device. Multiple devices under the same account can be assigned the same domain. This keeps the architecture sound for future clustering where Nexus load-balances across backends. Initially, each device gets its own account (1:1); multi-device accounts require a separate grouping mechanism (see Known Limitations).
2. **CNAME-as-verification-and-routing** — The user points their domain via CNAME to `<slug>.baseDomain`. This single DNS record proves ownership and sets up traffic routing through the relay.
3. **Always paired: `alias` + `*.alias`** — Every verified alias domain includes both the bare domain and its wildcard variant in JWT hostnames. No option to disable the wildcard. This is compatible with Nexus's `IsValidWildcard` constraint (requires ≥2 labels after `*.`) because alias domains must have ≥2 labels (e.g., `*.app.example.com` has 3 labels after `*.`; the minimum `*.ab.cd` has 2).
4. **HTTP-01 for TLS** — Devices obtain per-subdomain certificates via HTTP-01 (Nexus supports ACME challenge passthrough over plain HTTP on port 80). No wildcard certs for alias domains (HTTP-01 limitation).
5. **Same lifecycle as other hostnames** — Alias domains ride the same JWT, same suspension/revocation behavior. No special treatment.
6. **Apex domains out of scope** — Only CNAME-able domains are supported. Apex/bare domains (e.g., `example.com`) cannot have CNAME records per the DNS specification and are explicitly unsupported. Native apex support via Namek nameservers is a future consideration.
7. **No hard limit on aliases per device** — Soft configurable limit per account (default: 50) for abuse protection. Not an architectural constraint.

## Ownership Model

### Current state

```
device ──owns──> slug (1:1, immutable)
device ──owns──> custom_hostname (1:1, device-scoped)
```

### Target state

```
account ──owns──> alias domains (1:many)
account ──has───> devices (1:many)
device  ──owns──> slug (1:1, immutable)
device  ──assigned──> alias domains (many:many, via account)
device  ──assigned──> custom hostnames (future: also account-scoped)
```

Slugs remain device-level identity — they are the immutable, TPM-bound identifier. Custom hostnames and alias domains are account-level resources assignable to one or more devices under the account.

### Accounts (minimal)

This RFC introduces the smallest viable account model:

- An account is created implicitly on first device enrollment (no separate registration flow).
- A device belongs to exactly one account.
- Account-level operations (domain management) use device TPM authentication — the device's account is inferred from its identity.
- Initially 1:1 device-to-account. The API is designed for multi-device accounts but this only becomes functional once an account grouping mechanism exists (future work).
- No multi-user, no RBAC, no account merging. These are future concerns.

## Verification Flow

### Step 1: Register domain

Device calls `POST /api/v1/domains` with the desired domain.

Namek validates the domain format and returns instructions:
- The CNAME target: `<slug>.baseDomain` (using the requesting device's slug as the suggested target)

### Step 2: User configures DNS

The user adds a CNAME record at their DNS provider:

```
app.example.com.  CNAME  a1b2c3d4e5f6g7h8.piccolospace.com.
```

The CNAME chain resolves as:
```
app.example.com → a1b2c3d4e5f6g7h8.piccolospace.com → (wildcard CNAME) → relay.piccolospace.com
```

Traffic now flows through the Nexus relay.

### Step 3: Verify ownership

Device calls `POST /api/v1/domains/<id>/verify`.

Namek performs a **single CNAME record lookup** (not a recursive resolution that follows chains) for the registered domain and checks:
1. The CNAME target ends with `.baseDomain`
2. The label before `.baseDomain` is a valid slug belonging to a device under the same account

If both checks pass, the domain is marked **verified**.

### CNAME resolution implementation

Verification must query the CNAME record directly (e.g., via `miekg/dns` or equivalent DNS library), not use the OS resolver's `LookupCNAME` which may follow CNAME chains. Following chains would resolve `app.example.com → slug.baseDomain → relay.baseDomain`, and the verification would incorrectly check `relay` as the slug label.

The DNS query should:
- Use a configurable resolver (default: system resolver, overridable for testing)
- Have a timeout of 10 seconds
- Return the immediate CNAME target only

### Verification notes

- CNAME must point to a slug under the same account — not just any slug. This prevents claiming domains by pointing to someone else's device.
- The `cname_target` stored in `account_domains` is the **suggested** target returned to the user at registration time. Verification does not enforce this exact value — any slug under the same account is accepted.
- Verification is a point-in-time check. Namek does not continuously re-verify. If the user removes the CNAME, traffic stops routing but the domain remains verified.
- The CNAME can point to *any* device slug under the account, not necessarily the device that registered the domain. This supports the case where the "admin" device registers the domain but traffic routes through a different device.
- Pending domains expire after **7 days**. A cleanup loop removes expired pending domains, freeing the global uniqueness constraint. This prevents denial-of-registration attacks where an attacker registers domains they never intend to verify.
- If the target device is deleted after domain registration but before verification, the verification will fail (slug no longer exists). The pending domain eventually expires and can be re-registered.

## Device Assignment

After verification, the alias domain can be assigned to one or more devices under the same account.

`POST /api/v1/domains/<id>/assignments` **additively** assigns the domain to the specified devices. Existing assignments for other devices are preserved. To remove a device, use the DELETE endpoint.

Each assigned device's JWT will include the alias domain (and its wildcard) in the `hostnames` claim. Nexus sees multiple backends for the same SNI and load-balances across them using the existing weighted round-robin mechanism.

**Note:** With the initial 1:1 device-to-account model, the typical flow is registering a domain and assigning it to the requesting device. The multi-device assignment becomes practical once account grouping is implemented.

## TLS Certificates

### How it works

Alias domains use **HTTP-01** ACME challenges. Nexus supports ACME challenge passthrough — HTTP requests to `/.well-known/acme-challenge/<token>` on port 80 are forwarded to the backend device based on Host header matching against the JWT hostnames list.

The flow:
1. Device decides it needs a cert for `app.example.com` (or `sub.app.example.com`)
2. Device initiates HTTP-01 challenge with its ACME client (e.g., certbot, lego)
3. ACME CA sends HTTP validation request to `http://app.example.com/.well-known/acme-challenge/<token>` (port 80)
4. DNS resolves through CNAME chain to relay IP
5. Nexus matches Host header against JWT hostnames, forwards to the device
6. Device responds with the challenge token
7. ACME CA issues the certificate

### Prerequisites

- The alias domain must be verified and assigned to the device (so the JWT includes it in hostnames).
- Nexus must be configured to listen on port 80 for HTTP-01 passthrough.

### What this means

- No Namek involvement in alias domain TLS — the device handles ACME directly.
- The existing DNS-01 ACME infrastructure (PowerDNS TXT records) is **not used** for alias domains. It remains exclusively for `baseDomain` hostnames where Namek controls DNS.
- Each subdomain requires its own certificate (HTTP-01 cannot issue wildcards).
- The device is responsible for cert renewal.

### Future: wildcard certs via DNS-01 delegation

If a user wants `*.app.example.com` as a single wildcard cert (instead of per-subdomain certs), they could additionally set up:

```
_acme-challenge.app.example.com.  CNAME  _acme-challenge.<slug>.baseDomain.
```

This would allow the device to use the existing DNS-01 flow via PowerDNS. This is out of scope for this RFC.

## JWT Integration

When a device is assigned an alias domain, the `hostnames` claim in its Nexus JWT includes both the bare domain and the wildcard:

```json
{
  "hostnames": [
    "a1b2c3d4e5f6g7h8.piccolospace.com",
    "*.a1b2c3d4e5f6g7h8.piccolospace.com",
    "mydevice.piccolospace.com",
    "*.mydevice.piccolospace.com",
    "app.example.com",
    "*.app.example.com"
  ]
}
```

Nexus matches incoming connections by SNI against the hostnames claim. Nexus performs hostname matching purely against the JWT hostnames list with no domain suffix filtering — alias domains are treated identically to baseDomain hostnames. No Nexus changes needed.

### Nexus wildcard compatibility

Nexus's `IsValidWildcard` requires ≥2 labels after `*.`. Since alias domains must have ≥2 labels (see Domain Validation Rules), all alias domain wildcards satisfy this constraint:
- `*.app.example.com` → 3 labels after `*.` ✓
- `*.ab.cd` → 2 labels after `*.` ✓ (minimum)

### Load balancing

When multiple devices are assigned the same alias domain, each device's JWT includes that domain. Nexus already supports multiple backends for a hostname and uses weighted round-robin. The `weight` claim controls distribution.

### Hostname list growth

The JWT hostnames list grows with alias domain assignments. With the default soft limit of 50 domains per account and always-paired wildcards, a device could have up to ~104 hostnames in its JWT (2 for slug + 2 for custom + 100 for aliases). This is within acceptable bounds for JWT size and Nexus SNI matching performance. The soft limit is configurable if this proves problematic.

## API Surface

### Domain management (TPM-authenticated)

All domain management endpoints are rate-limited: 10 requests per minute per device for mutation endpoints (`POST`, `DELETE`), 30 requests per minute per device for read endpoints (`GET`).

#### POST /api/v1/domains

Register a new alias domain.

**Request:**
```json
{
  "domain": "app.example.com"
}
```

**Response:** `201 Created`
```json
{
  "id": "<uuid>",
  "domain": "app.example.com",
  "status": "pending",
  "cname_target": "a1b2c3d4e5f6g7h8.piccolospace.com",
  "created_at": "2026-03-12T00:00:00Z"
}
```

**Errors:**

| Status | Meaning |
|--------|---------|
| 400 | Invalid domain format, or domain conflicts with existing parent/child under another account |
| 409 | Domain already registered (by this or another account) |
| 429 | Rate limit exceeded |

#### GET /api/v1/domains

List all alias domains for the device's account.

**Response:** `200 OK`
```json
{
  "domains": [
    {
      "id": "<uuid>",
      "domain": "app.example.com",
      "status": "verified",
      "cname_target": "a1b2c3d4e5f6g7h8.piccolospace.com",
      "created_at": "2026-03-12T00:00:00Z",
      "verified_at": "2026-03-12T00:05:00Z",
      "assigned_devices": ["<uuid>"]
    }
  ]
}
```

#### POST /api/v1/domains/:id/verify

Trigger CNAME verification for a pending domain.

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
| 400 | CNAME not found, does not point to `.baseDomain`, or slug not under this account |
| 404 | Domain not found |
| 429 | Rate limit exceeded |

#### DELETE /api/v1/domains/:id

Remove an alias domain and all its device assignments.

**Response:** `204 No Content`

#### GET /api/v1/domains/:id/assignments

List device assignments for a domain.

**Response:** `200 OK`
```json
{
  "assignments": [
    {"device_id": "<uuid>", "domain": "app.example.com", "created_at": "2026-03-12T00:10:00Z"}
  ]
}
```

#### POST /api/v1/domains/:id/assignments

Additively assign a verified domain to devices. Existing assignments are preserved.

**Request:**
```json
{
  "device_ids": ["<uuid>"]
}
```

**Response:** `200 OK`
```json
{
  "assignments": [
    {"device_id": "<uuid>", "domain": "app.example.com"}
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

## Database Schema

Since there are no active deployments, the new tables and columns are folded directly into the v1 migration rather than added as a separate migration.

### Changes to v1 migration

The `accounts` table is created **before** `devices`, and `devices` gains an `account_id NOT NULL` FK from the start. Three new tables are appended: `account_domains`, `device_domain_assignments`, and the existing tables are unchanged.

```sql
-- Added before devices table
CREATE TABLE IF NOT EXISTS accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Added to devices table definition
account_id UUID NOT NULL REFERENCES accounts(id),

-- Added after existing tables
CREATE INDEX IF NOT EXISTS idx_devices_account_id ON devices(account_id);

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
```

### Key constraints

- `account_domains.domain` is globally unique — no two accounts can claim the same domain.
- `device_domain_assignments` uses a composite PK — a device can only be assigned to a domain once.
- Cascading deletes: removing an account removes its domains and assignments. Removing a device removes its assignments. Removing a domain removes its assignments.
- `verified_by_device_id` tracks which device triggered verification (audit trail). SET NULL on device deletion preserves the verified status.

## Domain Conflict Detection

When registering a new domain, Namek checks for **parent/child domain conflicts across accounts**:

- Registering `sub.app.example.com` when `app.example.com` is registered under a **different** account is rejected (the parent's `*.app.example.com` wildcard would conflict with routing).
- Registering `app.example.com` when `sub.app.example.com` is registered under a **different** account is rejected (the new domain's wildcard would conflict with the existing subdomain).
- Parent/child registrations within the **same account** are allowed (the operator controls both and can manage routing).

Implementation: on registration, query `account_domains` for any domain that is a parent or child of the requested domain and belongs to a different account.

```sql
-- Check for parent domains under other accounts
SELECT 1 FROM account_domains
WHERE account_id != $1
  AND $2 LIKE '%.' || domain;

-- Check for child domains under other accounts
SELECT 1 FROM account_domains
WHERE account_id != $1
  AND domain LIKE '%.' || $2;
```

## Changes to Existing Systems

### Token service

`IssueNexusToken` must include alias domains in the hostnames list. This should be a **single joined query** to avoid N+1:

```sql
SELECT ad.domain FROM account_domains ad
JOIN device_domain_assignments dda ON dda.domain_id = ad.id
WHERE dda.device_id = $1 AND ad.status = 'verified';
```

This query runs on every token issuance (every ~30s per device). The composite PK index on `device_domain_assignments` makes this efficient.

### ACME service

No changes needed. Alias domains use HTTP-01 handled by the device directly via Nexus passthrough. Namek's ACME service is for DNS-01 via PowerDNS, which only applies to baseDomain hostnames. The existing hostname authorization check (canonical + custom only) is correct as-is.

### Enrollment

`CompleteEnroll` must create an account for new devices. On re-enrollment (same EK, existing device), the device's existing account is preserved.

### GET /api/v1/devices/me

Response includes the alias domain names assigned to the device as a string array:

```json
{
  "device_id": "...",
  "hostname": "a1b2c3d4e5f6g7h8.piccolospace.com",
  "custom_hostname": "mydevice",
  "alias_domains": ["app.example.com"],
  "status": "active",
  "identity_class": "hardware_tpm",
  "nexus_endpoints": ["wss://relay.piccolospace.com/connect"]
}
```

### Audit logging

The following actions are logged to `audit_log` (consistent with existing patterns):

| Action | Actor Type | Details |
|--------|-----------|---------|
| `domain.register` | device | `{domain, account_id}` |
| `domain.verify` | device | `{domain, cname_resolved}` |
| `domain.verify_failed` | device | `{domain, error}` |
| `domain.delete` | device | `{domain}` |
| `domain.assign` | device | `{domain, target_device_id}` |
| `domain.unassign` | device | `{domain, target_device_id}` |

## Lifecycle

Alias domains follow the same lifecycle as other device hostnames:

- **Device suspended/revoked:** JWT is not issued, so alias domains (along with all other hostnames) stop routing. Assignments are **preserved** so that unsuspending restores them.
- **Domain deleted:** Assignments are cascade-deleted. Next JWT issuance excludes the domain. Existing tokens remain valid until expiry (max 30s TTL).
- **Device removed from assignment:** Same as above — next JWT excludes the domain.
- **Account deleted:** All domains and assignments cascade-delete.
- **Pending domain expiry:** Unverified domains are deleted after 7 days by a cleanup loop (runs every hour).

## Domain Validation Rules

- Must be a valid DNS hostname (RFC 1123)
- Must have at least 2 labels (e.g., `app.example.com`, not `com`)
- Must not be an apex/bare domain — must have ≥3 labels (e.g., `app.example.com` is valid; `example.com` is rejected). This ensures the domain is CNAME-able per the DNS specification.
- Must not be a subdomain of `baseDomain` (those are managed via slugs/custom hostnames)
- Must not conflict with a parent or child domain under a different account (see Domain Conflict Detection)
- Must not be an IP address
- Case-insensitive, stored lowercase
- Max length: 253 characters (DNS limit)

## Known Limitations

1. **No continuous re-verification.** CNAME is checked once at verification time. If the user removes the CNAME, traffic stops but the domain stays verified in Namek. If the CNAME is changed to point to a slug in a different account, the domain remains verified under the original account.
2. **No wildcard TLS for alias domains.** HTTP-01 cannot issue wildcard certificates. Each subdomain needs its own cert.
3. **No apex domain support.** Apex/bare domains cannot have CNAME records per the DNS spec and are rejected by validation. Users who need apex support should wait for the future Namek nameserver approach.
4. **Single-device account model.** The minimal account introduced here creates one account per device. The multi-device assignment API is forward-compatible but only becomes practical once account grouping is implemented.
5. **No domain transfer between accounts.** To move a domain, it must be deleted from one account and re-registered on another (subject to uniqueness).

## Future Considerations

1. **Apex domain support via Namek nameservers** — If users delegate their domain's DNS to Namek, we control the zone and can create A/AAAA records directly.
2. **Wildcard certs via DNS-01 delegation** — User adds `_acme-challenge.app.example.com CNAME _acme-challenge.<slug>.baseDomain` to enable wildcard cert issuance through the existing PowerDNS flow.
3. **Periodic re-verification** — Background sweep to check CNAMEs still resolve correctly, with grace period before un-verifying.
4. **Account grouping** — Mechanism to group multiple devices under a single account (e.g., via account invite codes or shared secret during enrollment).
5. **Custom hostnames as account-level resources** — Migrate custom hostnames to the same account-scoped model as alias domains.
