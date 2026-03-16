# RFC 003: Fleet-Consensus Trust

**Status:** Draft
**Author:** Piccolo Team
**Created:** 2026-03-16

## Summary

Fleet-Consensus Trust replaces the binary hardware/software TPM classification with a 4-tier trust model that uses fleet population observation to verify EK certificate chains and PCR integrity. The `tpm-ca-certificates` project ([loicsikidi/tpm-ca-certificates](https://github.com/loicsikidi/tpm-ca-certificates), BSD-3-Clause) provides a seed trust store; crowd-sourced CA and PCR census data strengthens trust as devices enroll and attest. The seed bundle is vendored into the Namek repository at build time and can be refreshed via dependency update.

## Key Decisions

1. **4-tier EK trust** replaces binary hardware_tpm/software_tpm — Verified, Crowd-Corroborated, Unverified Hardware, Software.
2. **CA census via fleet observation** — unknown issuer CAs are tracked and promoted based on population diversity, not manual intervention.
3. **PCR census via population consensus** — expected PCR values derived from majority clusters, not pre-computed golden images. Only Tier 1-2 (Verified/Crowd-Corroborated) devices contribute to PCR census to prevent bootstrap poisoning.
4. **PCR values as separate JSON fields** — transmitted alongside the quote in the attestation request body (not embedded in the binary wire format), preserving backward compatibility.
5. **Combined trust score governs federation privileges** — EK tier × PCR consensus determines PSFN participation level.
6. **No breaking migration** — no active deployments; schema changes modify the v1 migration DDL in-place. Any existing dev/staging databases must be dropped and recreated.
7. **Census analysis as background service** — periodic re-evaluation with PostgreSQL advisory lock for single-writer guarantee; non-blocking during enrollment.
8. **SHA-256 is the assumed PCR bank** — all PCR digests are 32 bytes. Validated server-side; mismatched digest lengths are rejected.

## EK Trust Tiers

**Tier 1 — Verified:**
EK cert chains to a known manufacturer CA from the `tpm-ca-certificates` seed bundle. The seed bundle is loaded into `trustedCACertsDir` alongside any operator-supplied CAs. Full federation privileges immediately.

**Tier 2 — Crowd-Corroborated:**
EK cert signed by a CA not in the seed bundle, but observed across sufficient independent devices. Promotion criteria from Tier 3:
- Minimum 10 distinct devices enrolled under this issuer fingerprint
- First-to-latest observation spans ≥ 7 days
- Devices from ≥ 5 distinct /24 subnets (acknowledged as a rough proxy; ASN-level diversity is future work)
- Structural compliance score ≥ 0.8
- Issuer certificate passes CA validation (see below)

**Tier 3 — Unverified Hardware:**
TPM credential activation succeeded (proves real TPM), but EK cert chain unverifiable and CA lacks fleet population. Default tier for newly-encountered CAs. Limited federation privileges.

**Tier 4 — Software:**
EK cert chains to software CA pool (swtpm). Development/testing only, no PSFN storage participation.

**Identity class constants:**
```go
const (
    IdentityClassVerified          = "verified"
    IdentityClassCrowdCorroborated = "crowd_corroborated"
    IdentityClassUnverifiedHW      = "unverified_hw"
    IdentityClassSoftware          = "software"
)
```

**Existing config migration:** `SeedBundleDir` supplements the existing `TrustedCACertsDir`. Both are loaded into the same hardware CA pool. `TrustedCACertsDir` allows operators to add their own trusted CAs (e.g., for enterprise-provisioned TPMs). `AllowSoftwareTPM` (boolean) controls whether unverified EK certs are accepted as Tier 4 software devices.

## Structural Analysis of Unknown CAs

When a CA is first encountered, Namek scores **both** the EK certificate and the issuer certificate:

**EK certificate checks:**

| Check | What it validates | Weight |
|-------|-------------------|--------|
| EK Extended Key Usage | No ServerAuth/ClientAuth; may have TPM-specific OID `2.23.133.8.1` or no EKU | 0.2 |
| SAN contains TPM manufacturer info | DirectoryName with OIDs under `2.23.133.2.*` (manufacturer, model, firmware version) | 0.2 |
| Key type and size | RSA-2048 or ECC P-256 per TCG profile | 0.2 |
| Certificate validity period | Long-lived (≥ 10 years); short-lived certs are suspicious | 0.2 |
| Basic Constraints | `IsCA: false` — EK certs must not be CA certs | 0.2 |

**Issuer certificate validation (required for Tier 2 promotion):**
- `BasicConstraints.IsCA` must be `true`
- `KeyUsage` must include `CertSign`
- These properties are verified when the issuer public key is first recorded in `ek_issuer_census`

Score ≥ 0.8 (4 of 5 EK checks) + valid issuer CA properties required for Tier 2 promotion.

## CA Census

**Issuer fingerprint:** SHA-256 of the issuer certificate's SubjectPublicKeyInfo DER encoding. Stable across certificate renewals. If only the issuer DN is available (no intermediate cert in the chain), fall back to SHA-256 of the issuer DN DER encoding.

**Anti-ballot-stuffing:**
- Max 5 new devices per issuer per hour (configurable). Exceeding flags the issuer, doesn't block enrollment.
- /24 subnet extracted from client IP for diversity tracking. Acknowledged as a rough proxy — a determined attacker with VPN access can present diverse /24s. The 7-day temporal spread and enrollment rate limiting provide additional friction. ASN-level diversity is future work.
- 7-day minimum temporal span prevents burst-enrollment.

**Observation recording failure during enrollment is non-blocking.** If the census INSERT/UPSERT fails, enrollment proceeds normally. The observation is lost; future re-enrollment can re-record it.

On re-enrollment, observations are upserted: `ON CONFLICT (issuer_fingerprint, device_id) DO UPDATE SET client_ip_subnet = EXCLUDED.client_ip_subnet, observed_at = NOW()`. This keeps subnet and timestamp current when devices re-enroll from new locations.

## PCR Census

**PCR data is collected at enrollment only, not during per-request attestation.** Per-request quotes continue to verify the signature and nonce (proving device liveness) without PCR data, avoiding write amplification on every authenticated request.

**PCR transmission — separate JSON fields, not binary wire format.**

The binary quote wire format (`uint32(quoteLen) || TPMS_ATTEST || TPMT_SIGNATURE`) is unchanged. PCR values are transmitted as separate fields in the enrollment attestation JSON body:

```json
{
    "nonce": "...",
    "secret": "...",
    "quote": "...",
    "os_version": "piccolo-os-1.2.3",
    "pcr_values": {
        "0": "<hex-encoded 32-byte SHA-256 digest>",
        "1": "<hex-encoded 32-byte SHA-256 digest>",
        "4": "<hex-encoded 32-byte SHA-256 digest>"
    }
}
```

Both `os_version` and `pcr_values` are optional for backward compatibility with older clients.

**PCR register selection rationale:**
- **PCR 0-1:** Core UEFI firmware measurement. Essential for hardware identity clustering.
- **PCR 2-3:** Excluded. UEFI driver and option ROM measurements — these are noisy (vary by peripheral configuration, USB devices present at boot) and would fragment clusters without adding trust signal.
- **PCR 4-7:** Boot manager (4), GPT partition table (5), platform-specific events (6), Secure Boot state (7). The core Piccolo OS boot chain.
- **PCR 8-9:** OS kernel and application-specific measurements.

**Server-side PCR verification:**

When `pcrValues` is provided (non-nil):
1. Validate each digest is exactly 32 bytes (SHA-256). Reject if any mismatch.
2. Construct `[]attest.PCR` structs with `DigestAlg: crypto.SHA256` for each entry.
3. Call `akPub.Verify(quote, pcrs, nonce)` — the go-attestation library computes the composite hash of the provided PCR values and verifies it matches `PCRDigest` in TPMS_ATTEST. This cryptographically binds the JSON-provided values to the TPM-signed quote.
4. Return verified values.

When `pcrValues` is nil (legacy client): call `akPub.Verify(quote, nil, nonce)` as before.

**PCR register groups and grouping keys:**

| Group | Registers | Grouping key | Rationale |
|-------|-----------|--------------|-----------|
| firmware | PCR 0-1 | `issuer_fingerprint` | Firmware varies by hardware vendor, not OS version. Issuer fingerprint serves as a proxy for hardware model since devices from the same manufacturer tend to cluster. |
| boot | PCR 4-7 | `os_version` | Boot manager, kernel, and config are controlled by Piccolo OS. Strong fleet consensus expected per OS release. |
| os | PCR 8-9 | `os_version` | OS-specific measurements correlate with OS version. |

**Census eligibility: Only Tier 1 (Verified) and Tier 2 (Crowd-Corroborated) devices contribute PCR observations to the census.** This prevents bootstrap poisoning where an attacker enrolls a few swtpm instances with fabricated PCR values to establish a false majority before legitimate devices arrive. Tier 3-4 devices' PCR values are still verified against the quote (cryptographic binding) and stored on the device record, but they do not influence majority calculations.

**PCR device_count is recomputed by aggregation, not maintained incrementally.** The census background service queries the `devices` table (joining on identity_class for Tier 1-2 eligibility, filtering by `last_seen_at` within the active window) and groups by PCR composite hash to compute cluster populations.

**Majority rule:** Cluster with highest device count per (grouping_key, pcr_group) where `device_count >= pcrMajorityMinPopulation` (default: 5) is marked majority. Below this threshold, PCR consensus is "unknown" rather than "outlier" for all devices in that group.

**Time-bounded census window:** Only devices with `last_seen_at` within the last 90 days contribute to census calculations. This prevents stale clusters from lingering after firmware updates or device decommissioning.

**PCR majority instability during rollouts:** When a firmware or OS update rolls out across the fleet, the old PCR cluster shrinks and the new one grows. During the transition, neither cluster may meet the minimum threshold, making PCR consensus "unknown" for all devices. This is the safe behavior — devices temporarily get "standard" or "provisional" trust rather than being falsely flagged as outliers. Once the rollout completes and the new cluster crosses the threshold, consensus resumes.

## Combined Trust Assessment

| EK Tier | PCR Consensus | Trust Level | Federation Privileges |
|---------|--------------|-------------|----------------------|
| Verified / Crowd-Corroborated | Matches majority | **Strong** | Full PSFN participation |
| Verified / Crowd-Corroborated | Unknown (no data / insufficient population) | **Standard** | Full PSFN, elevated monitoring |
| Verified / Crowd-Corroborated | Outlier | **Suspicious** | Investigation flag, operator alert |
| Unverified HW | Matches majority | **Provisional** | Limited federation, higher Sybil scrutiny |
| Unverified HW | Unknown | **Provisional** | Same as above |
| Unverified HW | Outlier | **Quarantine** | Minimal privileges, manual review |
| Software | Any | **Development** | No PSFN storage participation |

Trust level stored on device record, recalculated at enrollment, during census analysis, and on operator override.

**Trust level does NOT block enrollment.** All devices complete enrollment regardless of tier. Trust level governs downstream privileges (PSFN capacity allocation, federation participation). Trust level is not currently encoded in Nexus JWTs — it is consumed by the future PSFN service which queries the device record. JWT integration is future work if needed.

**Operator device-level override:** Operators can manually set any device's trust level via `POST /internal/v1/devices/:id/trust-override`. This is essential for incident response (quarantining a specific device) and for manually promoting edge-case devices.

## Sybil Resistance for PSFN

This model addresses the PSFN PRD's "Sybil safeguards (workflow pending)":

1. **Tier 1-2 Sybil cost:** Requires compromising a manufacturer CA private key or acquiring many physical devices from diverse locations — prohibitively expensive.
2. **Tier 3 Sybil cost:** Attacker can create many swtpm instances with a self-signed CA, but anti-ballot-stuffing controls (IP diversity, temporal spread, enrollment rate) prevent CA promotion. Tier 3 gets reduced privileges.
3. **PCR Sybil cost:** Attacker must report matching PCR values. With emulated TPMs, boot measurements reflect the emulator, not Piccolo OS — clustering as outliers. Additionally, only Tier 1-2 devices contribute to PCR census, so Tier 3-4 devices cannot influence the majority.
4. **Capacity pledge cost:** Even if trust checks pass, PSFN requires ongoing storage/bandwidth — scaling linearly with Sybil identities.
5. **Defense depth:** EK trust + PCR consensus + capacity pledge = three independent cost barriers.

**Foundational assumption:** The fleet consensus model assumes legitimate devices outnumber compromised ones. During bootstrap (first ~50 Tier 1-2 devices), the consensus signal is weak. The minimum population thresholds (5 for PCR majority, 10 for CA promotion) provide some protection, but operators should monitor census health during early fleet growth.

**Threat model boundary:** This model targets casual-to-moderate Sybil attacks on a consumer self-hosting network. It is not designed for nation-state adversaries who could compromise TPM manufacturer CAs or fund large-scale physical device acquisition.

## Enrollment Flow Integration

The two-phase enrollment design requires careful data flow for census integration.

**Phase 1 — `StartEnrollment`:**
1. Call `verifier.VerifyEKCert(ekCertDER)` → returns `*EKVerifyResult` with `IdentityClass` (`verified`/`unverified_hw`/`software`), issuer metadata.
2. Store the full `*EKVerifyResult` in `PendingEnrollment` (new field: `EKVerifyResult *tpm.EKVerifyResult`). This carries issuer info to phase 2 without re-parsing.
3. The rest of phase 1 (credential generation, nonce, dedup) proceeds as before.

**Phase 2 — `CompleteEnrollment`:**
1. Verify secret + quote as before. `VerifyQuote` now accepts `pcrValues` from the request body.
2. **Census observation recording** (non-blocking, wrapped in a try-catch so failures don't block enrollment):
   a. `INSERT INTO ek_issuer_census ... ON CONFLICT (issuer_fingerprint) DO UPDATE SET device_count = device_count + 1, last_seen_at = NOW()` — creates the issuer row if new, or updates it.
   b. `INSERT INTO ek_issuer_observations ... ON CONFLICT (issuer_fingerprint, device_id) DO UPDATE SET client_ip_subnet = EXCLUDED.client_ip_subnet, observed_at = NOW()` — records or updates the observation.
   c. If PCR values provided and device will be Tier 1-2: upsert `pcr_census` rows for each PCR group.
3. **Identity class resolution:** If `EKVerifyResult.IdentityClass == "unverified_hw"`, look up `ek_issuer_census` for this issuer fingerprint. If `tier == 'crowd_corroborated'`, upgrade to `crowd_corroborated`. This keeps `VerifyEKCert` as pure crypto while the service layer handles census lookup.
4. **Trust level computation:** Combine identity class + PCR consensus (query `pcr_census` for majority status).
5. Create device record with final `identity_class`, `trust_level`, `issuer_fingerprint`, `os_version`, `pcr_values`.

**Service dependency:** `DeviceService` gains a dependency on `CensusStore` (new `internal/store/census_store.go`) for the census observation recording and issuer tier lookup. This is injected at construction.

## Changes to Existing Interfaces

**Verifier interface** (`internal/tpm/verifier.go`):

`VerifyEKCert` remains a **pure cryptographic operation** — no database access. It returns only `verified`, `unverified_hw`, or `software` based on CA pool membership. It never returns `crowd_corroborated`; that classification is determined by the enrollment service consulting `ek_issuer_census` after `VerifyEKCert` completes.

```go
type EKVerifyResult struct {
    IdentityClass     string          // "verified" | "unverified_hw" | "software"
    EKPubKey          crypto.PublicKey
    IssuerFingerprint string
    IssuerSubject     string
    IssuerPubKeyDER   []byte
    IssuerIsCA        bool
    IssuerHasCertSign bool
}

type QuoteResult struct {
    PCRValues map[int][]byte // nil if no PCR data provided
}

// Changed signatures:
VerifyEKCert(ekCertDER []byte) (*EKVerifyResult, error)
VerifyQuote(akPubKeyDER []byte, nonce string, quoteB64 string, pcrValues map[int][]byte) (*QuoteResult, error)
```

**Call-site migration for `VerifyQuote`:** The `DeviceTPMAuth` middleware (`internal/auth/middleware.go`) must update its call from `verifier.VerifyQuote(ak, nonce, quote)` to `verifier.VerifyQuote(ak, nonce, quote, nil)` and discard the `*QuoteResult` (middleware only needs the error for liveness verification). All tests setting `VerifyQuoteFn` in `TestVerifier` must update their function signatures accordingly.

**Device model** (`internal/model/device.go`) — new fields:

```go
IssuerFingerprint string
OSVersion         string
PCRValues         map[string]string  // JSON-serialized, e.g. {"0":"abc...","4":"def..."}
TrustLevel        TrustLevel         // strong|standard|provisional|suspicious|quarantine|development
```

**Config** (`internal/config/config.go`) — new section:

```go
type FleetTrustConfig struct {
    SeedBundleDir                 string  `yaml:"seedBundleDir"`
    CensusAnalysisIntervalMinutes int     `yaml:"censusAnalysisIntervalMinutes"`  // default: 60
    CAPromotionMinDevices         int     `yaml:"caPromotionMinDevices"`          // default: 10
    CAPromotionMinDays            int     `yaml:"caPromotionMinDays"`             // default: 7
    CAPromotionMinSubnets         int     `yaml:"caPromotionMinSubnets"`          // default: 5
    CAPromotionMinCompliance      float64 `yaml:"caPromotionMinCompliance"`       // default: 0.8
    CAEnrollmentRatePerHour       int     `yaml:"caEnrollmentRatePerHour"`        // default: 5
    PCRMajorityMinPopulation      int     `yaml:"pcrMajorityMinPopulation"`       // default: 5
    CensusActiveWindowDays        int     `yaml:"censusActiveWindowDays"`         // default: 90
}
```

**Existing config migration:** `SeedBundleDir` supplements `TrustedCACertsDir`. Both load into the same hardware CA pool. `TrustedCACertsDir` remains for operator-supplied CAs. `AllowSoftwareTPM` (boolean) controls Tier 4 acceptance.

## Census API Authentication

Census dashboard endpoints serve operator functions and must NOT be under `NexusAuth` (which requires mTLS from Nexus proxy). They are placed in a **separate route group** under `/internal/v1/census/` and `/internal/v1/devices/:id/trust-*` with a distinct authentication middleware.

For MVP: these endpoints are bound to the internal HTTP listener (`HTTPAddress` config, typically `127.0.0.1:8081`) which is not exposed externally. This follows the pattern of health/readiness endpoints. Future work: API key or operator token authentication.

## API Surface

**Enrollment attestation** — `POST /api/v1/devices/enroll/attest`:

Request gains optional fields: `os_version`, `pcr_values`. Response gains `trust_level` field.

**Device info** — `GET /api/v1/devices/me`:

Response gains `trust_level`, `issuer_fingerprint`, `os_version`.

**Census dashboard** (operator, under `/internal/v1/`):

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /internal/v1/census/issuers | List known EK issuers with tier, device count, compliance score |
| GET | /internal/v1/census/issuers/:fingerprint | Detailed issuer info + observations |
| GET | /internal/v1/census/pcr | PCR cluster summary by grouping key and group |
| GET | /internal/v1/census/pcr/:grouping_key | Detailed PCR clusters for a specific key |
| POST | /internal/v1/census/issuers/:fingerprint/flag | Manually flag/unflag an issuer |
| POST | /internal/v1/census/issuers/:fingerprint/override | Override issuer tier (operator action) |
| POST | /internal/v1/devices/:id/trust-override | Override device trust level (operator action) |
| GET | /internal/v1/devices/:id/trust-explain | Explain trust level computation for a device |

**`trust-explain` response schema:**

```json
{
    "device_id": "...",
    "trust_level": "strong",
    "overridden": false,
    "ek_assessment": {
        "identity_class": "verified",
        "issuer_fingerprint": "abc123...",
        "issuer_subject": "CN=Infineon OPTIGA(TM) RSA Manufacturing CA 047",
        "issuer_tier": "seed",
        "structural_compliance_score": null
    },
    "pcr_assessment": {
        "firmware": {"status": "majority", "cluster_size": 42, "group_key": "abc123..."},
        "boot": {"status": "majority", "cluster_size": 380, "group_key": "piccolo-os-1.2.3"},
        "os": {"status": "unknown", "cluster_size": 0, "group_key": "piccolo-os-1.2.3"}
    }
}
```

`pcr_assessment.*.status` is one of: `majority` (matches), `outlier` (doesn't match an existing majority), `unknown` (no majority established or no PCR data).

## Database Schema

All tables fold into the v1 migration (no active deployments).

**`devices` table changes:**

- `identity_class` CHECK constraint: `CHECK (identity_class IN ('verified', 'crowd_corroborated', 'unverified_hw', 'software'))`
- New columns:
  - `issuer_fingerprint TEXT`
  - `os_version TEXT`
  - `pcr_values JSONB` — device's latest PCR snapshot
  - `trust_level TEXT NOT NULL DEFAULT 'provisional' CHECK (trust_level IN ('strong','standard','provisional','suspicious','quarantine','development'))`

**`ek_issuer_census`:**

```sql
CREATE TABLE ek_issuer_census (
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

CREATE INDEX idx_ek_issuer_census_tier ON ek_issuer_census(tier);
```

**`ek_issuer_observations`:**

```sql
CREATE TABLE ek_issuer_observations (
    id                  BIGSERIAL PRIMARY KEY,
    issuer_fingerprint  TEXT NOT NULL REFERENCES ek_issuer_census(issuer_fingerprint),
    device_id           UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    client_ip_subnet    TEXT NOT NULL,
    observed_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(issuer_fingerprint, device_id)
);

CREATE INDEX idx_ek_issuer_observations_fingerprint
    ON ek_issuer_observations(issuer_fingerprint);
```

**`pcr_census`:**

```sql
CREATE TABLE pcr_census (
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

CREATE INDEX idx_pcr_census_majority
    ON pcr_census(grouping_key, pcr_group) WHERE is_majority = TRUE;
```

## Census Background Service

New `internal/service/census_service.go`. Runs on configurable interval (default: hourly). Uses **PostgreSQL advisory lock** (`pg_advisory_lock(census_lock_id)`) at the start of each run to ensure single-writer semantics across instances. Lock is released when the run completes.

**Lifecycle:** Started as a goroutine from `main.go`, following the same pattern as `NonceStore.CleanupLoop`. Accepts a `context.Context` for graceful shutdown.

**CA tier re-evaluation:**
- For each `tier = 'unverified'` issuer: check promotion criteria against observations (filtering to `last_seen_at` within the active window). Promote if all criteria met AND issuer_is_ca AND issuer_has_certsign.
- For each `tier = 'crowd_corroborated'` issuer: check for anomalous patterns (enrollment rate spike, IP concentration). Flag if anomalous. No automated demotion — operator must resolve.
- Update device identity_class and trust_level for affected devices.

**PCR majority recalculation:**
- For each (grouping_key, pcr_group): reset all `is_majority = FALSE`. Find highest-count cluster where `device_count >= pcrMajorityMinPopulation` and at least one contributing device has `last_seen_at` within the active window. Mark as majority.
- Update trust levels for devices whose PCR consensus status changed.

All promotions, demotions, flags, and trust level changes logged to `audit_log` with `actor_type = 'system'`. Each enrollment logs structural compliance score, matched tier, and issuer fingerprint at INFO level.

## Known Limitations

1. **PCR requires client update.** Until piccolod sends PCR values, PCR census has no data. System degrades gracefully — PCR consensus is "unknown."
2. **No automated CA demotion.** Flagged CAs need operator resolution to prevent cascading disruption.
3. **Eventually consistent.** Trust levels recalculated hourly, not real-time.
4. **Single-instance census.** PostgreSQL advisory lock prevents concurrent runs; true multi-instance needs leader election (future).
5. **No PCR event log parsing.** Raw values only; no root-cause analysis of outliers.
6. **OS version self-reported.** Not cryptographically bound to PCR values. A misconfigured client grouping into the wrong OS version population would cause incorrect PCR consensus comparison. Signed OS attestation is future work (high priority).
7. **IP subnet as diversity proxy.** /24 is a rough proxy; VPN-equipped attackers can present diverse /24s. ASN-level diversity is future work.
8. **No census kill switch.** If census analysis has a bug, the only control is disabling the service by setting the interval to 0 or restarting Namek. A proper circuit breaker is future work.
9. **Bootstrap vulnerability.** With few Tier 1-2 devices, consensus signals are weak. Operators should monitor census health during early fleet growth.
10. **PCR majority instability during rollouts.** During firmware/OS rollouts, neither old nor new cluster may meet the majority threshold temporarily. Trust degrades to "standard"/"provisional" (safe behavior) until the rollout completes.

## Future Considerations

1. Event log parsing for PCR outlier root-cause analysis.
2. Signed OS version attestation bound to PCR chain (high priority).
3. Multi-instance census with leader election.
4. fTPM URL-based cert retrieval (Intel EKOP, AMD ftpm.amd.com).
5. Operator notifications (webhook/email) for flagged CAs.
6. Historical trust score tracking for compliance auditing.
7. Dynamic PSFN privilege scaling based on trust level.
8. ASN-level diversity for CA promotion criteria.
9. Census circuit breaker / kill switch.
10. Trust level freshness TTL — stale trust levels degrade to a safe default.
