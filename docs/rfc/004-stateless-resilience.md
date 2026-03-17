# RFC 004: Stateless Resilience

**Status:** Draft
**Author:** Piccolo Team
**Created:** 2026-03-17

## Summary

Make the Namek server resilient to catastrophic data loss (full PostgreSQL wipe) by rooting device identity in the TPM rather than server-side state, enabling automatic recovery without human intervention.

Four reinforcing mechanisms:

1. **Deterministic slugs** derived from EK fingerprint — same physical device always gets the same hostname, surviving both DB wipes and AK rotation.
2. **Auto re-enrollment** — devices detect identity loss and re-enroll autonomously.
3. **Device-side state cache** — devices cache their own configuration (custom hostname, alias domains, account membership) and replay it after re-enrollment.
4. **Peer voucher system** — devices in the same account hold TPM-signed cross-attestations of membership, enabling account relationship reconstruction from device-provided proofs alone, with no server-side signing key.

## Key Decisions

1. **All deterministic identity is rooted in the EK.** Slug, device ID, and account ID are all derived from the EK fingerprint (hardware-bound, immutable). This means hostname, UUID, and account survive DB wipes, AK rotation, and state directory loss. No active deployments to migrate.
2. **Slug uses 100-bit entropy (20 chars).** `slug = crockford_base32(ek_fingerprint_bytes[:13])` — 20 Crockford Base32 characters. 100 bits provides strong collision margin for deterministic (non-retryable) slugs. Birthday bound at ~10^15.
3. **Peer vouchers use TPM quotes over deterministic nonces.** AKs are restricted keys (can only sign TPM-generated structures), so vouchers are signed via `TPM2_Quote(nonce = sha256(voucher_data))`. This reuses existing attestation primitives.
4. **Two-phase voucher verification.** Quote validity is checked immediately; issuer identity is attributed only after the issuer re-enrolls and its AK matches the voucher. Only attributed vouchers count toward quorum.
5. **Trust is fully TPM-rooted.** No server-side long-term signing key. Account recovery relies on cross-attestation between peer devices' TPMs. Namek verifies voucher authenticity but doesn't issue membership certificates.
6. **Recovery is device-driven.** After a DB wipe, Namek is passive — it creates empty tables and waits. Devices detect the loss (auth failures), re-enroll, and replay cached state. Namek reconstructs from what devices provide.
7. **Single-device accounts recover without vouchers.** A lone device re-enrolls, gets its deterministic slug, and a new account is created. Vouchers are only needed for multi-device account reconstruction.
8. **Graceful degradation over hard failure.** A device that can't fully recover (e.g., missing vouchers, peers offline) still operates in a degraded state with its deterministic slug — basic connectivity is restored even if account relationships aren't.
9. **Account IDs are deterministic from the founding device's EK.** `account_id = uuid5(namek_namespace, founding_ek_fingerprint)`. Peer vouchers carry this ID and the founding device's EK fingerprint, enabling any device to verify account ID consistency.

## Deterministic Device Identity

All device identity — slug, device ID, and account ID — is derived from the **EK fingerprint** (`sha256(ekCertDER)`). The EK is hardware-bound and immutable, making all derived identifiers stable across DB wipes, AK rotation, and state directory loss.

### Deterministic slugs

`slug.Derive(ekFingerprint)` replaces `slug.Generate()` and computes the slug deterministically from the EK fingerprint:

```go
func Derive(ekFingerprint string) string {
    raw, _ := hex.DecodeString(ekFingerprint) // 32 bytes (sha256 of EK cert)
    return encodeN(raw[:13], 20)              // 100 bits → 20 Crockford Base32 chars
}
```

The EK fingerprint is already `hex(sha256(ekCertDER))` — a 64-char hex string representing 32 bytes. We decode it and take the first 13 bytes (104 bits), encoding to 20 Crockford Base32 characters (100 bits of entropy, 4 bits unused from the 13th byte).

**Properties:**
- Same EK always produces the same slug — survives DB wipes AND AK rotation
- Different EKs produce different slugs (SHA-256 collision resistance)
- 20-character Crockford Base32 format
- `IsValid()` regex: `^[0-9a-hjkmnp-tv-z]{20}$`
- AK loss (state dir wiped) → same slug. The hostname is stable because it's tied to hardware, not key material.

**Collision analysis:** Birthday bound at 100 bits is ~2^50 ≈ 10^15 devices. Deterministic slugs are permanent (non-retryable), so 100 bits provides meaningful margin.

`slug.Generate()` is removed. No active deployments exist, so there is no legacy format to support.

**Hostname construction:** `hostname = slug + "." + baseDomain`. With EK-based slugs, the hostname is a stable function of the device's hardware identity. Example: `a1b2c3d4e5f6g7h8k9mn.baseDomain`.

**Nexus compatibility:** Nexus treats slugs opaquely — it matches SNI against the JWT `hostnames` list without parsing or validating slug format or length. The 20-character change requires no Nexus modifications. DNS labels allow up to 63 characters, so 20 characters is well within bounds.

### Deterministic device IDs

`device_id = uuid5(device_namespace, ek_fingerprint)`. Same EK always produces the same device UUID. Cached `device_ids` in state files and domain assignments survive DB wipes.

### Deterministic account IDs

For new accounts (single-device enrollment):

```go
const namekDeviceNamespaceUUID  = "a3e4b8c1-7f2d-4e6a-9b5c-d8f1e2a3b4c5"
const namekAccountNamespaceUUID = "b4f5c9d2-8a3e-5f7b-0c6d-e9f2a3b4c5d6"

accountID = uuid.NewSHA1(uuid.MustParse(namekAccountNamespaceUUID), []byte(ekFingerprint))
```

This is deterministic from the founding device's EK. On recovery, the same device re-enrolling produces the same account ID. Peer vouchers reference this ID, so cross-device recovery is consistent.

Two separate namespace UUIDs are used — one for devices, one for accounts — ensuring `device_id ≠ account_id` even when derived from the same EK fingerprint. Both are fixed constants defined in `internal/identity/namespace.go`. They must never change — changing either invalidates all deterministic IDs.

### Identity derivation summary

All three identifiers derive from a single root — the EK fingerprint:

```
EK cert (hardware-bound)
  → sha256(ekCertDER) = ek_fingerprint (32 bytes, hex-encoded to 64 chars)
    → slug:       encodeN(raw[:13], 20)                        = 20-char Crockford Base32
    → device_id:  uuid5(device_namespace, ek_fingerprint)      = UUID
    → account_id: uuid5(account_namespace, ek_fingerprint)     = UUID (founding device only)
```

Separate namespace UUIDs for device and account derivation guarantee `device_id ≠ account_id`, avoiding ambiguity in logs, audit trails, and any code that handles UUIDs from both tables. No double-hashing, no separate derivation paths — a single EK fingerprint determines the entire device identity.

## Auto Re-enrollment

### Client-side detection

Piccolod detects identity loss when an authenticated request returns HTTP 401 with a specific error indicating the device is unknown (as opposed to a nonce/quote error):

```json
{"error": "device not found"}
```

### Recovery flow

```
authenticated request → 401 "device not found"
  → log warning: "identity loss detected, initiating re-enrollment"
  → exponential backoff with jitter (prevent thundering herd)
  → Enroll() using existing AK (same as always)
  → deterministic slug → same hostname
  → deterministic device_id → same UUID
  → re-enrollment succeeds → update local identity.json
  → replay cached state (custom hostname, alias domains, vouchers)
  → resume normal operation
```

### Backoff strategy

After DB wipe, all devices discover identity loss near-simultaneously. To prevent overwhelming Namek:

```
base_delay    = 2s
max_delay     = 120s
jitter_factor = 0.5  (random [0, 0.5 * delay])

delay = min(base_delay * 2^attempt, max_delay) + random(0, jitter_factor * delay)
```

Max attempts: unlimited (keep retrying until success). The device is non-functional without enrollment, so persistent retry is correct.

Namek-side: `MaxPending` should be tuned for fleet size. For fleets >100 devices, set `MaxPending` to at least `fleet_size / 2` to avoid cascading rejections during recovery. A future adaptive mechanism could detect mass re-enrollment and temporarily raise limits.

### Distinguishing error types

Piccolod must distinguish between:

| Error | Meaning | Action |
|-------|---------|--------|
| 401 "device not found" | DB wipe or device deleted | Auto re-enroll |
| 401 "nonce expired/invalid" | Normal transient error | Retry with fresh nonce |
| 401 "quote verification failed" | AK mismatch (AK rotated server-side?) | Auto re-enroll |
| 403 "device suspended" | Administrative action | Do NOT re-enroll. Alert operator. |
| 403 "device revoked" | Administrative action | Do NOT re-enroll. Alert operator. |

Critical: auto re-enrollment must **never** trigger for 403 (suspended/revoked). These are intentional administrative states, not data loss.

## Device-Side State Cache

Devices cache their server-side configuration locally, enabling replay after re-enrollment.

### Cache location

```
/var/lib/piccolod/
├── tpm/
│   ├── ak_pub           # AK public key (existing)
│   └── ak_priv          # AK private key, TPM-wrapped (existing)
├── identity.json         # Core identity (existing, extended)
├── state_cache.json      # Recoverable state (new)
└── vouchers/             # Peer vouchers (new)
    ├── <ek_fingerprint_1>.voucher
    └── <ek_fingerprint_2>.voucher
```

### identity.json (extended)

```json
{
  "device_id": "550e8400-e29b-41d4-a716-446655440000",
  "account_id": "660e8400-e29b-41d4-a716-446655440000",
  "hostname": "a1b2c3d4e5f6g7h8k9mn.example.com",
  "identity_class": "verified"
}
```

New field: `account_id` — persisted after enrollment. Used during recovery to present consistent account identity. Note: `device_id` and `account_id` are convenience caches — both are deterministically derivable from the EK fingerprint (via separate namespace UUIDs), but caching avoids recomputation and makes the file self-describing. `identity_class` is a pre-existing field (see piccolod integration spec) retained for informational purposes only — it is NOT authoritative during recovery. As stated in the RFC 003 interaction section, trust data must be re-derived server-side and is never restored from client-cached values.

### state_cache.json (new)

```json
{
  "custom_hostname": "mydevice",
  "alias_domains": [
    {
      "domain": "app.example.com",
      "assigned_device_ids": ["550e8400-..."]
    }
  ],
  "last_synced_at": "2026-03-17T10:00:00Z"
}
```

**Sync strategy:** Updated when the `GET /api/v1/devices/me` response differs from the cached version (content-hash comparison). This avoids unnecessary filesystem writes on every request — important for embedded devices with flash storage where write endurance matters. In practice, state changes infrequently (hostname changes are rate-limited, domain additions are rare), so writes are sporadic.

**Atomic writes:** All state file updates (identity.json, state_cache.json, voucher files) use the write-to-temp-then-rename pattern: write to `<filename>.tmp`, then `os.Rename` to the final path. This prevents partial-write corruption from power loss or crashes. The existing `writeFileAtomic` in `pkg/tpmdevice/open.go` implements this pattern but is unexported and package-scoped. It should be extracted to a shared utility (e.g., `pkg/fsutil/atomic.go`) so both `tpmdevice` and piccolod's state cache can reuse it.

### State replay after re-enrollment

After successful re-enrollment, device replays cached state in order:

1. **Custom hostname** — `PATCH /api/v1/devices/me/hostname` with cached value. May fail if another device claimed it during the outage; device logs warning and continues with slug-only hostname. Since rate-limit counters are lost in the wipe, the first hostname set will always succeed rate-limit-wise.
2. **Alias domains** — For each cached domain: `POST /api/v1/domains` to re-register, then `POST /api/v1/domains/:id/verify` to re-verify. With deterministic slugs, CNAME still points to the correct slug, so verification succeeds automatically. Alias domain replay is permitted even in `pending_recovery` account state since CNAME verification is self-proving (see Quorum rules).
3. **Domain assignments** — `POST /api/v1/domains/:id/assignments` to re-establish device-domain links. With deterministic device IDs, cached `device_ids` are still valid.
4. **Peer vouchers** — Presented during enrollment (see Peer Voucher System below).

Replay is best-effort. Partial failures don't block device operation — the device works in degraded mode with its deterministic slug and can retry state replay later.

### Voucher file management

Voucher files are stored as `vouchers/<issuer_ek_fingerprint>.voucher`. If an issuer's AK is rotated (new voucher from same EK), the new voucher overwrites the old one — this is intentional since the old AK is no longer valid. Vouchers from devices that have left the account should be cleaned up by piccolod when it observes (via `GET /api/v1/devices/me`) that the issuer is no longer in the account's peer list.

## Peer Voucher System

### Purpose

Enable reconstruction of multi-device account relationships after a DB wipe, without requiring any server-side signing key. Trust is rooted entirely in devices' TPMs.

### Voucher structure

A voucher is a TPM-signed attestation that one device recognizes another as a member of the same account.

**Voucher data (the payload being attested):**

```json
{
  "version": 1,
  "type": "peer_membership",
  "account_id": "660e8400-e29b-41d4-a716-446655440000",
  "founding_ek_fingerprint": "e3b0c44298fc1c149afb...",
  "subject_ek_fingerprint": "abc123...",
  "issuer_ek_fingerprint": "def456...",
  "epoch": 3,
  "issued_at": "2026-03-17T10:00:00Z"
}
```

| Field | Purpose |
|-------|---------|
| `version` | Schema version for forward compatibility |
| `type` | Always `peer_membership` (extensible for future voucher types) |
| `account_id` | The account both devices belong to |
| `founding_ek_fingerprint` | EK fingerprint of the device that created the account — enables any device to verify `account_id = uuid5(namespace, founding_ek_fingerprint)` |
| `subject_ek_fingerprint` | EK fingerprint of the device being vouched for |
| `issuer_ek_fingerprint` | EK fingerprint of the device creating the voucher |
| `epoch` | Account membership epoch — incremented on every join/leave event. Stale-epoch vouchers are deprioritized during recovery. |
| `issued_at` | Timestamp for freshness tracking |

**Canonical serialization:** Voucher data is serialized as JSON with keys in alphabetical order, no whitespace, no trailing newline, UTF-8 encoding. This ensures deterministic byte representation for nonce derivation. Example:

```
{"account_id":"660e8400-...","epoch":3,"founding_ek_fingerprint":"e3b0c44...","issued_at":"2026-03-17T10:00:00Z","issuer_ek_fingerprint":"def456...","subject_ek_fingerprint":"abc123...","type":"peer_membership","version":1}
```

Both client and server must use the same canonicalization. The server generates the canonical form when creating voucher requests; the client signs whatever the server provides (does not re-serialize). **Implementation note:** Go's `json.Marshal` on `map[string]any` does not guarantee alphabetical key order. Use a Go struct with fields declared in alphabetical order, or a dedicated canonicalization function. Since the server is the sole producer and the client passes bytes through without re-serializing, only the server needs this logic.

**Complete voucher artifact (stored on device):**

```json
{
  "data": "<base64 of canonical JSON voucher data>",
  "quote": "<base64 TPM quote wire format>",
  "issuer_ak_public_key": "<base64 AK DER>",
  "issuer_ek_cert": "<base64 EK cert DER>"
}
```

The `issuer_ek_cert` field is included for defense-in-depth: during recovery, Namek can immediately verify the issuer's EK certificate against trusted CAs and confirm the EK fingerprint matches, even before the issuer re-enrolls. This provides early rejection of forged vouchers from non-TPM sources. It does not prove AK-EK binding — that is verified in phase 2 (see Two-Phase Verification).

### TPM-based signing

AKs have the TPM `Restricted` attribute, meaning they can only sign TPM-generated structures (TPMS_ATTEST). They cannot sign arbitrary data directly.

**Solution:** Use the existing `TPM2_Quote` mechanism with a deterministic nonce derived from the voucher data:

```
voucher_nonce = hex(sha256(canonical_json_bytes))
quote = TPM2_Quote(AK, voucher_nonce, pcr_selection=empty)
```

**PCR selection for voucher quotes:** Voucher quotes use an **empty PCR selection** — the quote signs only the nonce (extraData), no PCR values. `TPM2_Quote` requires a PCR selection parameter, but it can be empty (no PCR banks selected). The go-attestation library's `akPub.Verify(quote, nil, nonce)` already handles nil PCRs by skipping PCR digest validation — this is the same code path used by the current enrollment flow when `pcrValues` is nil (RFC 003 backward compatibility). On the client side, `tpm2.QuoteRaw` must be called with an empty `tpm2.PCRSelection{}`.

**VerifyQuote return type:** RFC 003 changes `VerifyQuote` to return `(*QuoteResult, error)` and adds a `pcrValues` parameter. For voucher verification, the `QuoteResult` is discarded — only the error matters. The call site is: `_, err := VerifyQuote(issuerAK, nonce, quote, nil)`.

**Implementation dependency:** This RFC depends on RFC 003's `VerifyQuote` signature change (`(akPubKeyDER, nonce, quoteB64, pcrValues) → (*QuoteResult, error)`). If RFC 004 is implemented first, it must carry forward this interface change itself. Both RFCs modify `CompleteEnrollment` — they should be implemented as a single combined change or in strict RFC 003 → RFC 004 order.

### Nonce encoding — worked example

The exact byte-level data flow for voucher signing and verification:

**Signing (client-side):**

```
1. Server provides voucher_data as base64-encoded canonical JSON bytes
2. Client base64-decodes to get raw bytes: [0x7b, 0x22, 0x61, ...]  (the JSON string)
3. Client computes: sha256_hash = sha256(raw_bytes)
   → 32 bytes, e.g.: [0xa3, 0x1f, 0xb2, ...]
4. Client hex-encodes: nonce_string = "a31fb2..."  (64 hex chars, lowercase)
5. Client calls: Device.Quote(nonce_string)
   → TPM internally receives: []byte("a31fb2...")  (64 ASCII bytes)
   → TPM signs TPMS_ATTEST containing these bytes as extraData
6. Client returns the quote wire format (base64-encoded)
```

**Verification (server-side):**

```
1. Server base64-decodes the voucher data field to get raw bytes
2. Server computes: sha256_hash = sha256(raw_bytes)  → same 32 bytes
3. Server hex-encodes: expected_nonce = "a31fb2..."  → same 64 hex chars
4. Server calls: _, err := VerifyQuote(issuer_ak_pub, expected_nonce, quote_b64, nil)
   → VerifyQuote internally: []byte("a31fb2...")  → matches TPM's extraData
   → nil PCRs → skip PCR digest check
   → Signature valid, QuoteResult discarded ✓
```

**Key invariant:** Both sides produce identical byte sequences because:
- The voucher data bytes are passed through, never re-serialized
- SHA-256 is deterministic
- Hex encoding uses lowercase (`hex.EncodeToString` in Go produces lowercase)
- The nonce string's UTF-8 bytes are what the TPM signs and what `VerifyQuote` checks

### Two-phase voucher verification

After a DB wipe, Namek cannot immediately verify that a voucher's `issuer_ak_public_key` belongs to the device identified by `issuer_ek_fingerprint` — that mapping was in the wiped database. An attacker with any TPM could forge a voucher with arbitrary claims and sign it with their own AK.

**Solution: two-phase verification.**

**Phase 1 — Quote verification (immediate, at enrollment):**
1. Verify the TPM quote signature using the provided `issuer_ak_public_key`
2. Optionally verify `issuer_ek_cert` against trusted CAs and confirm EK fingerprint matches
3. Verify `founding_ek_fingerprint` is consistent: `uuid5(namespace, founding_ek_fingerprint) == claimed_account_id`
4. Verify all vouchers in the recovery bundle claim the same `account_id`
5. Store the claim as **unattributed** — quote is valid but issuer identity is unconfirmed

**Phase 2 — Issuer attribution (deferred, when issuer re-enrolls):**
1. When a device re-enrolls, Namek records its `(ek_fingerprint, ak_public_key)` mapping
2. Namek scans unattributed recovery claims where `issuer_ek_fingerprint` matches this device
3. For each claim: check if `issuer_ak_public_key` in the voucher matches the re-enrolled device's actual AK
4. If match → claim is **attributed** (verified). The issuer's TPM provably signed this voucher.
5. If mismatch → claim is **rejected**. Either the voucher is stale (issuer rotated AK) or forged.

**Only attributed vouchers count toward quorum.** This means an attacker with a random TPM cannot forge vouchers for other devices — their AK won't match the legitimate device's AK when the legitimate device re-enrolls.

**Why this is secure:**
- An attacker signs a voucher claiming `issuer_ek_fingerprint = B`, but uses their own AK
- Quote verification passes (valid signature by attacker's AK)
- When real device B re-enrolls, B's AK ≠ attacker's AK
- Attribution fails → forged voucher rejected
- Quorum cannot be reached from forged vouchers alone

### Voucher exchange protocol

Voucher exchange is orchestrated by Namek when devices are in the same account. It's asynchronous — devices sign vouchers as they check in.

**When a new device joins an account:**

1. Namek increments the account's `membership_epoch` counter.

2. Namek creates **pending voucher requests** for all pairs:
   - Existing members need to vouch for the new device
   - New device needs to vouch for all existing members

3. Namek sets `voucher_pending_since` timestamp on the `devices` record for affected devices (this avoids adding voucher queries to every `/devices/me` call — the handler checks this lightweight column, already loaded by auth middleware, and only runs voucher queries when non-null). On each affected device's next authenticated request, Namek includes pending voucher requests in the response to `GET /api/v1/devices/me`:

```json
{
  "device_id": "...",
  "pending_voucher_requests": [
    {
      "request_id": "<uuid>",
      "voucher_data": "<base64 canonical JSON>",
      "nonce": "<hex sha256 of voucher_data>"
    }
  ]
}
```

4. Device generates a TPM quote over the provided nonce and submits:

```
POST /api/v1/vouchers/sign
{
  "request_id": "<uuid>",
  "quote": "<base64 TPM quote>"
}
```

5. Namek verifies the quote, assembles the complete voucher (including the issuer's EK cert from the device record), and distributes it:
   - The subject device receives the voucher via `GET /api/v1/devices/me` (new field: `new_vouchers`)
   - Device stores it in `vouchers/<issuer_ek_fingerprint>.voucher`

6. Once all pairs have exchanged vouchers, the account's voucher graph is complete.

**When a device leaves an account:**

1. Namek increments `membership_epoch`.
2. Namek creates new voucher requests for all remaining pairs (new epoch, excluding the departed device).
3. Old vouchers (lower epoch) are superseded by new ones as devices sign them.
4. Devices clean up vouchers from the departed device on next sync.

**Staleness:** Voucher requests that go unfulfilled for 30 days are expired. If a device never comes online to sign vouchers, its peers won't have vouchers from it. The device itself has vouchers from peers (signed when it joined). This is sufficient — the offline device can still present peer vouchers during recovery, even if peers don't have vouchers from it.

### Recovery protocol

After DB wipe, devices present cached vouchers during re-enrollment.

**Enrollment request extended:**

```json
{
  "nonce": "<enrollment nonce>",
  "secret": "<base64 decrypted secret>",
  "quote": "<base64 TPM quote>",
  "recovery_bundle": {
    "account_id": "660e8400-...",
    "vouchers": [
      {
        "data": "<base64>",
        "quote": "<base64>",
        "issuer_ak_public_key": "<base64>",
        "issuer_ek_cert": "<base64>"
      }
    ],
    "custom_hostname": "mydevice",
    "alias_domains": ["app.example.com"]
  }
}
```

`recovery_bundle` is optional. If absent, standard fresh enrollment applies. If present, Namek processes recovery claims. The `custom_hostname` and `alias_domains` fields are **not** acted upon during enrollment itself — they are stored and queued for post-enrollment state replay via separate API calls (see State Replay After Re-enrollment). Including them in the bundle ensures they survive even if `state_cache.json` is lost but the recovery bundle was constructed from it.

**Server-side recovery logic:**

1. **Consistency check** — All vouchers in the bundle must claim the same `account_id` as the bundle's top-level `account_id`. Reject the entire bundle if inconsistent.
2. **Account ID verification** — Extract `founding_ek_fingerprint` from any voucher and verify: `uuid5(namespace, founding_ek_fingerprint) == claimed_account_id`. Reject if mismatch.
3. **Phase 1 verification** for each voucher — Check quote validity, optionally verify EK cert. Discard invalid vouchers.
4. **Store unattributed claims** — Upsert each valid voucher into `recovery_claims` table (`ON CONFLICT (device_id, claimed_account_id, issuer_ek_fingerprint) DO UPDATE`). This handles retry scenarios where a device re-enrolls multiple times without inflating quorum counts.
5. **Check for immediate attribution** — If the issuer identified by `issuer_ek_fingerprint` has already re-enrolled, cross-reference AK. Attribute if match; mark as rejected with reason if mismatch.
6. **Attribute existing claims** — Scan all unattributed claims where `issuer_ek_fingerprint` matches the enrolling device's EK. Attribute those where AK matches the enrolling device's AK.
7. **Evaluate quorum** — Count attributed vouchers for this account. Quorum is re-evaluated whenever any new attribution occurs (both from the enrolling device's bundle and from previously-unattributed claims now attributable because a new issuer re-enrolled). If quorum is met, promote account to active.
8. **Fast path for single-device accounts** — If no `recovery_bundle` is present, the device creates a new single-device account with its deterministic account ID. This is the common case (fresh enrollment or single-device recovery). If a `recovery_bundle` IS present (indicating the device was part of a multi-device account), the founding device is NOT fast-pathed — it enters `pending_recovery` and participates in quorum like all other devices. This prevents a removed founding device from unilaterally reconstituting an account it no longer belongs to.

**Concurrent enrollment handling:** Multiple devices may re-enroll for the same account simultaneously. Account creation uses `INSERT INTO accounts (id, status) VALUES ($1, 'pending_recovery') ON CONFLICT (id) DO NOTHING`. The second enrollment finds the account already exists and joins it. Device enrollment into the account uses `UPDATE devices SET account_id = $1 WHERE id = $2`. These operations are safe under concurrent execution.

**Non-founding device enrolling first:** If a non-founding device re-enrolls before the founding device, its deterministic account ID (from its own EK) differs from the recovery bundle's `account_id`. When a `recovery_bundle` is present, the enrollment goes directly to the claimed account's `INSERT ... ON CONFLICT DO NOTHING` path, skipping the default single-device account creation.

**Device enrolled in wrong account during recovery:** If a device re-enrolls without a recovery bundle (e.g., voucher files were lost), it creates a single-device account with its own deterministic ID. Later, if the device's peers re-enroll with vouchers referencing this device, or if the device rediscovers its voucher cache and re-enrolls again with a recovery bundle, the device must be moved to the correct account. The reconciliation protocol: when recovery bundle processing determines a device should belong to a different account than it's currently enrolled in, the device's `account_id` is updated to the claimed account, and any alias domains or custom hostnames replayed into the old (wrong) account are re-associated with the new account. The old empty account is deleted. This is safe because the recovery bundle contains vouchers proving the claimed membership, and the old account has only one device (the device being moved).

**Account reconstruction sequence:**

```
Device A (founding) re-enrolls with recovery_bundle:
  → recovery_bundle present → multi-device recovery path (no fast-path)
  → Account X created as pending_recovery
  → A is enrolled in account X (pending)
  → Vouchers from B stored as unattributed claims

Device B re-enrolls with recovery_bundle:
  → B claims account X, has voucher from A
  → A already re-enrolled → cross-reference AK → voucher attributed ✓
  → B's voucher from A is valid → B joins account X
  → Namek checks B's AK against unattributed claims from A's bundle
  → A's voucher from B is now attributed → bidirectional attestation complete
  → Quorum reached (2/2) → account X promoted to active
```

### Epoch-based staleness detection

The `epoch` field in voucher data tracks account membership changes. During recovery:

1. Each device presents vouchers with various epochs
2. Namek identifies the **highest epoch** seen across all recovery bundles for an account
3. Vouchers with `epoch < max_epoch - 1` are considered stale and deprioritized (not rejected outright, but weighted lower in quorum decisions)
4. This detects the case where a removed device presents pre-removal vouchers: the removed device's vouchers will have a lower epoch than current members' vouchers

This is not a hard security guarantee (a sophisticated attacker could forge the epoch), but it provides defense-in-depth against the common case of a legitimately removed device attempting to rejoin after a DB wipe.

### Quorum rules

| Account size | Recovery quorum | Rationale |
|-------------|----------------|-----------|
| 1 device | No vouchers needed | Single-device account, deterministic slug sufficient |
| 2 devices | Both must present (2/2) | No tolerance for forgery with only 2 members |
| 3+ devices | Majority: floor(n/2) + 1 | Tolerates minority of devices being offline or having lost voucher cache |

Quorum examples: n=3 → 2 needed, n=4 → 3 needed, n=5 → 3 needed, n=10 → 6 needed.

**Quorum counts only attributed vouchers.** A device's recovery claim is "attributed" when the voucher issuer has re-enrolled and AK matches. This means in practice, quorum requires the participating devices to have actually re-enrolled (not just be claimed in bundles).

**Pending recovery state:** Until quorum is reached, the account exists in `pending_recovery` status. Devices in pending accounts can still:
- Use their deterministic slug (DNS works)
- Request Nexus tokens (for basic connectivity)
- Replay alias domains and custom hostnames (CNAME verification is self-proving; alias domain replay does not require active account status)
- Cannot perform account management operations (invite, join, leave)

Once quorum is reached, the account is promoted to active and full functionality is restored.

**Recovery claims cleanup:** Once an account is promoted to `active` (quorum reached) or dissolved (timeout), its `recovery_claims` rows are deleted after a 24-hour retention period (for forensic review). Claims whose `claimed_account_id` has no corresponding row in `accounts` after 7 days are also cleaned up (handles cases where the account was never created). A background cleanup loop runs daily, similar to existing cleanup loops for ACME challenges and released hostnames.

**Periodic quorum re-evaluation:** A background loop (every 5 minutes) re-evaluates quorum for all `pending_recovery` accounts. This handles the case where a Namek crash interrupts quorum evaluation during enrollment — claims are persisted but quorum was never checked. The loop also enforces quorum timeouts, dissolving expired `pending_recovery` accounts.

**Recovery kill switch:** A config flag `recovery.enabled` (default `true`) controls whether recovery bundles are processed during enrollment. When disabled, recovery bundles are silently ignored — enrollment succeeds normally but recovery claims are not stored. This allows operators to disable recovery processing if a bug is causing issues, without disabling enrollment itself.

**Quorum timeout:** Configurable, default 7 days (`recovery.quorum_timeout_days`). If quorum isn't reached within this period, pending recovery accounts are dissolved — each device becomes a standalone single-device account. Operators with devices that may be offline for extended periods (seasonal devices, devices in transit) should increase this value. This prevents permanently limbo states when some devices are truly gone.

## Account Grouping

The peer voucher system requires a mechanism for devices to join the same account. This section defines the minimal grouping mechanism needed.

### Invite-based grouping

1. **Device A generates invite:** `POST /api/v1/accounts/invite`

```json
Response:
{
  "invite_code": "<32-byte hex>",
  "account_id": "660e8400-...",
  "expires_at": "2026-03-18T10:00:00Z"
}
```

Invite code is a random secret, stored hashed in DB. Default TTL: 24 hours. Max active invites per account: 5.

2. **Device B accepts invite:** `POST /api/v1/accounts/join`

```json
Request:
{
  "invite_code": "<32-byte hex>"
}
```

Namek verifies the invite code, moves Device B's `account_id` to the inviting account, triggers voucher exchange between all account members.

3. **Voucher exchange begins** automatically (see Voucher Exchange Protocol above).

### Account membership limit

Soft configurable limit: 10 devices per account (default). Prevents voucher graph explosion and limits thundering herd during recovery. Lost devices do not count toward this limit — they are detected by the absence of `last_seen_at` within the active window (90 days per RFC 003).

## Interaction with RFC 003 Fleet-Consensus Trust

### Trust tier degradation after DB wipe

RFC 003 introduces a 4-tier identity class system (`verified`, `crowd_corroborated`, `unverified_hw`, `software`). After a full DB wipe:

- **Census data is lost** — `ek_issuer_census`, `ek_issuer_observations`, and `pcr_census` tables are empty.
- **`crowd_corroborated` devices fall back to `unverified_hw`** — their issuer CA was promoted via fleet observation, but that observation data is gone. The CA must re-earn promotion through new observations.
- **PCR consensus is empty** — all devices get `unknown` PCR status until census rebuilds.
- **Trust levels degrade** — most devices will start at `standard` or `provisional` trust until census analysis catches up.

### Trust tier recovery timeline

| Time | Trust state |
|------|-------------|
| T+0 | All census data lost |
| T+~2m | Devices re-enroll → EK certs re-verified against seed bundle → Tier 1 (verified) devices are immediately classified correctly |
| T+~2m | Tier 2 (crowd_corroborated) devices classified as Tier 3 (unverified_hw) — census observations restart |
| T+7 days | Earliest possible CA re-promotion (7-day temporal spread requirement) |
| T+~1 hour | Census background service runs, begins rebuilding PCR clusters |
| T+hours-days | PCR consensus re-established as clusters reach minimum population (5 devices) |

**Impact:** Devices that were `crowd_corroborated` temporarily lose trust tier and any associated federation privileges. This is acceptable — the trust tier system is designed to be eventually consistent (hourly census analysis), and the degradation is to a safe default, not an unsafe one.

### Software TPM vouchers during recovery

Vouchers from software TPM (Tier 4) devices **are accepted** during recovery. Rationale:
- Software TPM devices are development/testing only (RFC 003)
- Rejecting their vouchers adds protocol complexity for zero production benefit
- In dev/test environments where software TPMs are used, recovery should work seamlessly
- The trust tier is a property of the device, not the voucher; a voucher's value comes from cross-attestation, not the issuer's trust tier

### Device-side trust level caching

The `state_cache.json` does **not** cache `trust_level` or `identity_class`. These are server-authoritative and must be re-derived from EK verification and census data during recovery. Caching them would create a trust-escalation vector where a device claims a higher trust tier than it deserves.

## Changes to Existing Systems

### `internal/slug/slug.go`

New function and updated validation:

```go
// Derive computes a deterministic 20-char slug from an EK fingerprint.
// ekFingerprint is hex(sha256(ekCertDER)) — a 64-char hex string.
func Derive(ekFingerprint string) (string, error) {
    raw, err := hex.DecodeString(ekFingerprint)
    if err != nil || len(raw) < 13 {
        return "", fmt.Errorf("slug: invalid EK fingerprint")
    }
    return encodeN(raw[:13], 20), nil // 100 bits → 20 Crockford Base32 chars
}

// encodeN generalizes the existing encode() bit-packing logic to produce
// nChars output characters. The existing encode() becomes:
//   func encode(src []byte) string { return encodeN(src, 16) }
func encodeN(src []byte, nChars int) string { ... }
```

`IsValid()` regex updated to `^[0-9a-hjkmnp-tv-z]{20}$`. `Generate()` is removed.

**Documentation and code updates required** for the slug format change:
- `docs/nexus-integration-spec.md`
- `docs/piccolod-integration-spec.md` (two references)
- `internal/service/device_service.go` (comment)
- `tests/integration/e2e_test.go` (assertion comment)

### New package: `internal/identity/namespace.go`

```go
package identity

import "github.com/google/uuid"

// Separate namespace UUIDs guarantee device_id ≠ account_id even for the
// same EK fingerprint. WARNING: Changing either value invalidates all
// deterministic IDs and cached identity references. Never change them.
const DeviceNamespaceUUID  = "a3e4b8c1-7f2d-4e6a-9b5c-d8f1e2a3b4c5"
const AccountNamespaceUUID = "b4f5c9d2-8a3e-5f7b-0c6d-e9f2a3b4c5d6"

var (
    deviceNS  = uuid.MustParse(DeviceNamespaceUUID)
    accountNS = uuid.MustParse(AccountNamespaceUUID)
)

// DeviceID derives a deterministic device UUID from an EK fingerprint.
func DeviceID(ekFingerprint string) uuid.UUID {
    return uuid.NewSHA1(deviceNS, []byte(ekFingerprint))
}

// AccountID derives a deterministic account UUID from the founding device's EK.
func AccountID(ekFingerprint string) uuid.UUID {
    return uuid.NewSHA1(accountNS, []byte(ekFingerprint))
}
```

Separate namespaces ensure `DeviceID(ek) ≠ AccountID(ek)` for the same input, avoiding UUID collisions across tables and ambiguity in logs and audit trails.

### Enrollment flow (`internal/service/device_service.go`)

**`CompleteEnrollment` changes:**

- Device ID: `identity.DeviceID(ekFingerprint)` instead of `uuid.New()`
- Slug generation: `slug.Derive(ekFingerprint)` (returns `(string, error)`)
- Account ID: `identity.AccountID(ekFingerprint)` for fresh enrollments
- Process `recovery_bundle` if present:
  - Consistency check: all vouchers must claim same account_id
  - Account ID verification: founding_ek_fingerprint must produce the claimed account_id
  - Phase 1 voucher verification (quote check)
  - Store unattributed claims
  - Attempt immediate attribution against already-enrolled devices
  - Evaluate quorum
  - Queue state replay (custom hostname, alias domains) for post-enrollment processing
- Collision check: the `devices` table's unique constraint on `slug` handles the astronomically rare case of a deterministic slug collision. No explicit pre-check (`IsLabelTaken`) is needed — let the INSERT fail and surface the error.

**Performance notes for recovery bundle processing:**
- **Phase 1 voucher verification** (quote checks) should be parallelized — each voucher is independent. For a 9-voucher bundle, sequential verification adds ~9x CPU to enrollment; parallel verification keeps it near 1x on multi-core hardware.
- **Attribution scan** (step 6): guarded behind `EXISTS(SELECT 1 FROM recovery_claims WHERE attributed = FALSE AND issuer_ek_fingerprint = $1 LIMIT 1)` using the enrolling device's EK fingerprint. This scopes the guard to the specific device, so enrollments for unrelated accounts skip the scan entirely — even if other accounts are in recovery.

**Re-enrollment behavior change:** On re-enrollment (same EK, existing device), the slug is now recomputed deterministically. Since there are no active deployments, this is a non-issue.

### Enrollment API (`internal/api/handler/device_enroll.go`)

Extend `CompleteEnrollRequest` to accept optional `recovery_bundle`:

```go
type CompleteEnrollRequest struct {
    Nonce          string          `json:"nonce"`
    Secret         string          `json:"secret"`
    Quote          string          `json:"quote"`
    RecoveryBundle *RecoveryBundle `json:"recovery_bundle,omitempty"`
}

type RecoveryBundle struct {
    AccountID      string          `json:"account_id"`
    Vouchers       []VoucherProof  `json:"vouchers"`
    CustomHostname string          `json:"custom_hostname,omitempty"`
    AliasDomains   []string        `json:"alias_domains,omitempty"`
}

type VoucherProof struct {
    Data              string `json:"data"`
    Quote             string `json:"quote"`
    IssuerAKPublicKey string `json:"issuer_ak_public_key"`
    IssuerEKCert      string `json:"issuer_ek_cert,omitempty"`
}
```

### Auth middleware response

`GET /api/v1/devices/me` response extended with voucher management and recovery status fields:

```json
{
  "device_id": "...",
  "hostname": "...",
  "account_id": "...",
  "recovery_status": "active",
  "pending_voucher_requests": [...],
  "new_vouchers": [...]
}
```

`recovery_status` is one of: `"active"` (normal operation), `"pending_recovery"` (awaiting quorum), `"standalone"` (account fragmented after quorum timeout — device was moved to a new single-device active account). `standalone` is a derived API value, not a DB state — it is inferred when the device's account is `active` but was created after a quorum timeout dissolution (the account has exactly one device and was created within the dissolution flow). This lets piccolod surface degraded mode to the user.

### New API endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | /api/v1/accounts/invite | TPM | Generate account invite code |
| POST | /api/v1/accounts/join | TPM | Join account via invite code |
| POST | /api/v1/vouchers/sign | TPM | Submit signed voucher quote |
| GET | /api/v1/vouchers | TPM | List device's cached vouchers |
| DELETE | /api/v1/accounts/leave | TPM | Leave current account (reverts to single-device account) |

### Recovery observability (operator, internal API)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /internal/v1/recovery/accounts | List accounts in `pending_recovery` state with quorum progress |
| GET | /internal/v1/recovery/accounts/:id | Detailed recovery status: claimed devices, attributed vs unattributed vouchers, time remaining |
| POST | /internal/v1/recovery/accounts/:id/override | Manually promote a pending_recovery account (operator override) |
| POST | /internal/v1/recovery/accounts/:id/dissolve | Manually dissolve a pending_recovery account |

These endpoints follow the same authentication pattern as RFC 003's census endpoints (internal HTTP listener, not exposed externally).

### Audit logging for voucher operations

The following actions are logged to `audit_log` (consistent with existing patterns). The `audit_log.actor_type` CHECK constraint must be extended from `('device', 'nexus', 'system')` to include `'operator'` for recovery override actions:

| Action | Actor Type | Details |
|--------|-----------|---------|
| `voucher.sign` | device | `{request_id, subject_ek_fingerprint, epoch}` |
| `voucher.attributed` | system | `{issuer_ek_fingerprint, subject_ek_fingerprint, account_id}` |
| `voucher.rejected` | system | `{issuer_ek_fingerprint, subject_ek_fingerprint, reason}` |
| `recovery.claim_submitted` | device | `{account_id, voucher_count}` |
| `recovery.quorum_reached` | system | `{account_id, device_count, quorum_threshold}` |
| `recovery.account_promoted` | system | `{account_id}` |
| `recovery.account_dissolved` | system | `{account_id, reason: "quorum_timeout"}` |
| `recovery.override` | operator | `{account_id, action}` |
| `account.invite_created` | device | `{account_id}` |
| `account.device_joined` | device | `{account_id, invited_by}` |
| `account.device_left` | device | `{account_id}` |

### Client library (`pkg/namekclient`)

New methods:

```go
// SignVoucher generates a TPM quote over voucher data for peer attestation
func (c *Client) SignVoucher(ctx context.Context, requestID, nonce string) error

// GetVouchers retrieves pending vouchers for local caching
func (c *Client) GetVouchers(ctx context.Context) ([]Voucher, error)
```

### Client library (`pkg/tpmdevice`)

New method:

```go
// QuoteOverData generates a TPM quote using sha256(data) as the nonce.
// Used for voucher signing where the "nonce" is a deterministic hash of the voucher payload.
// The nonce passed to the TPM is hex.EncodeToString(sha256.Sum256(data)) — a 64-char
// lowercase hex string whose UTF-8 bytes become the extraData in TPMS_ATTEST.
func (d *Device) QuoteOverData(data []byte) ([]byte, error) {
    h := sha256.Sum256(data)
    return d.Quote(hex.EncodeToString(h[:]))
}
```

### Piccolod integration changes

Updated restart recovery decision tree:

```
Identity file exists?
├── YES
│   └── TPM accessible + AK loads?
│       ├── YES → Create client with WithDeviceID, resume
│       │   └── Auth succeeds?
│       │       ├── YES → Normal operation
│       │       │   └── Sync state cache (on change detection)
│       │       │   └── Process pending voucher requests
│       │       │   └── Cache new vouchers to disk
│       │       └── NO (401 "device not found") → Auto re-enroll
│       │           └── Include recovery_bundle (vouchers + cached state)
│       │           └── Backoff with jitter
│       │       └── NO (403) → Alert operator, do NOT re-enroll
│       └── NO → Log error, retry with backoff
└── NO → Fresh enrollment
    └── Deterministic slug + device_id assigned
    └── Save identity + account_id to disk
```

## Database Schema

All changes modify the existing v1 migration DDL in-place (no active deployments). The current schema is at version 2 (v1: initial schema, v2: ACME cert cache). Since there are no production deployments, both v1 and v2 migrations are rewritten and any dev/staging databases must be dropped and recreated. This follows the same approach as RFC 003.

### `devices` table changes

New column:
- `voucher_pending_since TIMESTAMPTZ` — Set when new voucher requests are created for this device. The `GetMe` handler checks this column (already loaded by auth middleware's `GetByID`) and only queries `voucher_requests`/`new_vouchers` when non-null. Cleared after all pending requests are fulfilled. This avoids adding 2 extra DB queries to the hot path of every `/devices/me` call.

### `accounts` table changes

New columns:
- `status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'pending_recovery'))` — Tracks whether account is fully recovered or awaiting quorum.
- `membership_epoch INT NOT NULL DEFAULT 1` — Incremented on every join/leave event. Used for voucher staleness detection.
- `recovery_deadline TIMESTAMPTZ` — Set when account enters `pending_recovery`. NULL for active accounts.

**Not stored:** `founding_device` flag is not needed — the founding device is identified by `uuid5(namespace, device_ek_fingerprint) == account_id`. The `founding_ek_fingerprint` is carried in voucher data and verified during recovery. Avoiding redundant columns eliminates consistency invariants.

### New tables

**`account_invites`:**

```sql
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

CREATE INDEX idx_account_invites_account_id ON account_invites(account_id);
```

**`voucher_requests`:**

```sql
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

-- When membership_epoch increments (device join/leave), new voucher requests
-- replace old ones via upsert:
-- INSERT INTO voucher_requests (...) VALUES (...)
-- ON CONFLICT (issuer_device_id, subject_device_id)
-- DO UPDATE SET voucher_data = EXCLUDED.voucher_data,
--   epoch = EXCLUDED.epoch, status = 'pending', quote = NULL, signed_at = NULL;

CREATE INDEX idx_voucher_requests_issuer ON voucher_requests(issuer_device_id)
    WHERE status = 'pending';
```

**`recovery_claims`:**

```sql
CREATE TABLE IF NOT EXISTS recovery_claims (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    claimed_account_id UUID NOT NULL,  -- intentionally no FK: account may not exist yet when claim is submitted
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

CREATE INDEX idx_recovery_claims_account ON recovery_claims(claimed_account_id);
CREATE INDEX idx_recovery_claims_account_attributed ON recovery_claims(claimed_account_id, attributed);
CREATE INDEX idx_recovery_claims_device ON recovery_claims(device_id);
CREATE INDEX idx_recovery_claims_issuer ON recovery_claims(issuer_ek_fingerprint)
    WHERE attributed = FALSE;
```

## Recovery Timeline

Assuming full PostgreSQL wipe, with all mechanisms in this RFC deployed:

| Time | Event |
|------|-------|
| T+0 | DB wiped |
| T+0 | Namek restarts, migrations create empty tables |
| T+1s | `BootstrapZone()` recreates DNS zone + wildcard CNAME + NS/SOA |
| T+~30s | Nexus relays auto-register via heartbeat |
| T+~1-2m | Devices detect auth failure, begin auto re-enrollment with backoff+jitter |
| T+~1-2m | Deterministic slug + device_id → same hostname + same UUID → DNS resolution restored |
| T+~1-2m | ACME certs still valid locally → TLS works |
| T+~2m | Single-device accounts: no recovery bundle → immediately active |
| T+~2-5m | Multi-device accounts: devices present vouchers, attribution builds as peers re-enroll |
| T+~5m | Multi-device accounts reach quorum → promoted to active |
| T+~5-10m | Devices replay cached state: custom hostnames, alias domains |
| T+~1 hour | Census service runs → PCR/CA census begins rebuilding |
| T+7 days | Earliest CA re-promotion for crowd_corroborated devices |
| **T+~10m** | **Functional recovery complete, zero human intervention** |
| **T+days-weeks** | **Trust tier recovery complete (census rebuilds)** |

### What remains irrecoverable

| Data | Impact | Mitigation |
|------|--------|------------|
| Audit logs | Compliance gap | Ship to external system (future work) |
| Hostname change rate-limit counters | Rate limits reset | Acceptable in disaster scenario |
| Pending (unverified) alias domains | Must re-register | Low impact — they were unverified |
| Voucher request state | Must re-exchange | Vouchers already on devices survive; only in-flight requests lost |
| Census observations | Trust tiers degrade temporarily | Rebuilds organically as devices re-enroll |

## Known Limitations

1. **EK loss = new identity.** Since all identity is EK-rooted, the device identity (slug, device ID, account ID) is stable across AK rotation and state directory wipes. Only physical TPM replacement or TPM ownership clearing changes the EK, which produces a genuinely new identity. AK loss (state dir wiped) triggers re-enrollment with a new AK but the same slug and device ID — peer vouchers referencing the old AK become invalid and must be re-exchanged, but hostname and device UUID are preserved.
2. **Device filesystem loss degrades recovery, not identity.** Since all identity is EK-rooted, a device whose filesystem is wiped retains its slug, device ID, and (for founding devices) account ID — the TPM's EK survives filesystem loss. What IS lost: AK blobs (device creates a new AK and re-enrolls with the same identity), cached vouchers (multi-device account recovery depends on peers having their copies), and state cache (custom hostname and alias domains must be re-configured manually). A correlated event wiping both server DB and all device filesystems simultaneously results in full automatic identity recovery but no account relationship or configuration recovery.
3. **Voucher exchange requires device liveness.** Devices must come online and make authenticated requests to sign vouchers. A device that joins an account and immediately goes offline won't have vouchers from peers. Its peers will have vouchers from it (signed during the join flow).
4. **Quorum timeout creates account fragmentation.** If a multi-device account can't reach quorum within the timeout (default 7 days, configurable), it fragments into single-device accounts. Account relationships are lost. Operators with seasonally-offline devices should increase the timeout.
5. **Stale vouchers from removed members.** A device removed from an account retains vouchers from before its removal. After a DB wipe, it could present these to attempt rejoining. The epoch-based staleness detection provides defense-in-depth (current members have higher-epoch vouchers), but this is not a hard cryptographic guarantee. This risk requires both a DB wipe AND the removed device still possessing its voucher files.
6. **Thundering herd.** All devices re-enrolling simultaneously after a wipe could overwhelm Namek. Client-side backoff with jitter mitigates this, and `MaxPending` should be tuned for fleet size. See Auto Re-enrollment section for guidance.
7. **Account grouping mechanism is minimal.** Invite-code-based grouping is the simplest viable approach. More sophisticated mechanisms (QR-based pairing, proximity verification, admin-managed groups) are future work.
8. **Voucher graph grows quadratically.** An account with n devices produces n*(n-1) vouchers. With the 10-device account limit, maximum is 90 vouchers — manageable. Larger accounts would need a gossip-based voucher protocol (future work).
9. **Trust tier degradation.** After DB wipe, `crowd_corroborated` devices fall back to `unverified_hw` and must wait for census re-promotion (minimum 7 days). This temporarily reduces federation privileges for affected devices.
10. **Two-phase voucher attribution requires issuer re-enrollment.** A voucher is only fully trusted when its issuer has also re-enrolled. If a voucher issuer is permanently offline, its vouchers never become attributed and don't count toward quorum. This is correct behavior (can't trust a voucher from a device that may no longer exist) but can delay quorum for accounts where some devices are slow to come online.

## Future Considerations

1. **External audit log shipping** — Stream audit events to an external system (Loki, S3, syslog) so they survive DB wipes.
2. **Voucher refresh protocol** — Periodic re-signing of vouchers to keep timestamps and epochs fresh, reflecting account changes (device additions/removals).
3. **Gossip-based voucher exchange** — For large accounts, a gossip protocol where devices exchange vouchers directly (via Nexus relay) rather than through Namek.
4. **Cross-account vouchers** — Vouchers attesting trust relationships between accounts (federation building block).
5. **Hardware-bound state cache** — Store device state cache in TPM NV storage or a TPM-sealed blob, so it's protected against filesystem compromise.
6. **Recovery health dashboard** — Operator-facing view of account recovery progress (how many devices have re-enrolled, quorum status, pending voucher exchanges). The internal recovery API provides the data; a dashboard is the presentation layer.
7. **Backup-less PostgreSQL recovery** — With full stateless resilience, traditional DB backups become optional (defense-in-depth, not primary recovery mechanism).
8. **Deterministic JWT signing key** — Derive from a stable secret in config, so tokens survive Namek restarts. Low priority given 30s TTL.
9. **Operator manual quorum override** — Allow operators to manually accept account recovery with fewer devices than quorum requires, for cases where devices are known to be permanently lost.
10. **Adaptive enrollment rate limiting** — Detect mass re-enrollment (thundering herd) and temporarily raise `MaxPending` and rate limits.
