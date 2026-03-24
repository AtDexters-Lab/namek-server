# RFC 005: Behavioral Trust & PSFN Access Policy

**Status:** Draft
**Author:** Piccolo Team
**Created:** 2026-03-23

## Summary

This RFC introduces a two-layer trust model that complements the cryptographic trust levels from RFC 003. A **behavioral trust** system tracks device lifetime, attestation consistency, and operational behavior to build a reputation score that applies universally to all devices regardless of their cryptographic tier. A **PSFN access policy engine** combines cryptographic trust (RFC 003) and behavioral trust to make access decisions for federation participation and storage allocation.

## Motivation

RFC 003 classifies devices by their cryptographic attestation strength (EK tier + PCR consensus). This is a snapshot-based signal — it doesn't account for how a device behaves over time. Two problems arise:

1. **Software-tier devices have zero cryptographic trust but may be legitimate production devices.** Piccolo OS uses swtpm as a fallback on hardware that lacks a TPM. These devices cannot earn trust through cryptographic attestation alone, yet they need a path to meaningful PSFN participation.

2. **Cryptographic trust is necessary but not sufficient.** A freshly enrolled Tier 1 device with verified hardware has never demonstrated reliable behavior. A Tier 3 device that has been operating reliably for 6 months may deserve more PSFN allocation than a Tier 1 device enrolled yesterday.

The behavioral trust axis provides the missing signal: what has the device *demonstrated* through its operational lifetime?

## Architecture

Two orthogonal trust axes, combined by a policy engine:

```
+----------------------------+     +----------------------------+
|   Cryptographic Trust      |     |   Behavioral Trust         |
|   (RFC 003)                |     |   (this RFC)               |
|                            |     |                            |
|   EK tier + PCR consensus  |     |   Tenure + consistency +   |
|   → trust_level            |     |   liveness + clean record  |
|   (snapshot)               |     |   → reputation_score       |
|                            |     |   (continuous, decays)     |
+-------------+--------------+     +-------------+--------------+
              |                                    |
              +------------------+-----------------+
                                 |
                    +------------v-----------+
                    |   PSFN Policy Engine   |
                    |                        |
                    |   trust_level ×        |
                    |   reputation_score     |
                    |   → access decisions   |
                    +------------------------+
```

## Behavioral Trust Signals

Behavioral trust is computed from signals that accumulate during a device's operational lifetime. Unlike cryptographic trust, behavioral trust:
- **Accrues over time** — longer tenure increases trust
- **Decays on absence** — devices that stop attesting lose reputation
- **Is revocable** — operator flags or anomalous behavior can zero-out reputation instantly

### Signal Categories

**Tenure:**
- Days since initial enrollment
- Continuous active period (longest streak without gaps > threshold)

**Attestation consistency:**
- Ratio of successful attestations to expected (based on heartbeat interval)
- Stability of AK public key (frequent re-enrollments are suspicious)

**Network stability:**
- IP address change frequency (high churn may indicate Sybil rotation)
- Subnet consistency

**Clean record:**
- No operator flags or quarantine history
- No failed attestation attempts (which could indicate replay attacks)
- No anomalous enrollment patterns (e.g., enrollment rate spikes from same EK)

### Reputation Score

`reputation_score` is a normalized value (0.0 - 1.0) computed from weighted signal categories. Stored on the device record, recalculated by the census background service alongside cryptographic trust analysis.

The exact weighting and thresholds are configurable and will be determined during implementation based on fleet telemetry.

## Graduated PSFN Access

The policy engine maps (trust_level, reputation_score) to concrete PSFN privileges:

### Storage Allocation Tiers

| Trust Level | Reputation | PSFN Access |
|-------------|------------|-------------|
| strong | any | Full allocation, scales with reputation |
| standard | >= 0.5 | Full allocation, scales with reputation |
| standard | < 0.5 | Reduced allocation |
| provisional | >= 0.7 | Limited allocation |
| provisional | < 0.7 | Minimal allocation |
| suspicious | any | Frozen — no new allocation, existing honored |
| quarantine | any | Suspended — no PSFN participation |
| software | >= 0.8 | Limited allocation (earned through behavior) |
| software | 0.3 - 0.8 | Minimal allocation |
| software | < 0.3 | No allocation (probation) |

**Key insight:** Software-tier devices can earn meaningful PSFN participation through sustained good behavior, even without cryptographic hardware attestation. A software device with 6 months of perfect attestation history and a reputation score of 0.9 may contribute more to the network than a freshly enrolled hardware-verified device.

### Allocation Scaling

Within each access tier, actual storage allocation scales linearly with `reputation_score`. This creates a smooth gradient rather than hard thresholds — every day of good behavior incrementally increases a device's contribution capacity.

### Decay Mechanics

Reputation decays when a device becomes inactive:
- Grace period (configurable, default: 7 days) — no decay
- Linear decay after grace period — reputation drops toward 0 over configurable window (default: 90 days)
- Instant zero on operator quarantine or security flag

## Sybil Resistance

The behavioral trust layer adds a fourth cost barrier to Sybil attacks (complementing RFC 003's three cryptographic barriers):

1. **Time cost:** Sybil identities must maintain liveness for extended periods to earn reputation. This scales linearly with the number of fake devices — an attacker running 100 swtpm instances must keep all 100 attesting consistently for months.
2. **Capacity pledge cost:** Even with reputation, PSFN requires ongoing storage/bandwidth that scales linearly with Sybil identities.
3. **Behavioral consistency cost:** Sybil devices must exhibit "normal" behavior patterns — stable IPs, consistent attestation cadence, no anomalous enrollment patterns.
4. **Detection surface:** Behavioral analysis can identify coordinated Sybil fleets through correlated activity patterns (same IP ranges, synchronized enrollment, identical behavior profiles).

**Defense depth:** Cryptographic trust (RFC 003) + behavioral trust (this RFC) + capacity pledge = independent cost barriers that must be overcome simultaneously.

## Database Schema

**`device_behavior` table:**

```sql
CREATE TABLE device_behavior (
    device_id               UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    reputation_score        REAL NOT NULL DEFAULT 0.0,
    tenure_days             INT NOT NULL DEFAULT 0,
    longest_active_streak   INT NOT NULL DEFAULT 0,
    attestation_success     BIGINT NOT NULL DEFAULT 0,
    attestation_expected    BIGINT NOT NULL DEFAULT 0,
    last_attestation_at     TIMESTAMPTZ,
    ip_change_count         INT NOT NULL DEFAULT 0,
    reenrollment_count      INT NOT NULL DEFAULT 0,
    reputation_frozen       BOOLEAN NOT NULL DEFAULT FALSE,
    reputation_frozen_reason TEXT,
    last_computed_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

**`device_behavior_log` table (for decay and audit):**

```sql
CREATE TABLE device_behavior_log (
    id          BIGSERIAL PRIMARY KEY,
    device_id   UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    event_type  TEXT NOT NULL,
    delta       REAL,
    details     JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_device_behavior_log_device
    ON device_behavior_log(device_id, created_at DESC);
```

## API Surface

**Device info** — `GET /api/v1/devices/me`:
Response gains `reputation_score` field.

**Operator endpoints** (under `/internal/v1/`):

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /internal/v1/devices/:id/reputation | Detailed reputation breakdown |
| POST | /internal/v1/devices/:id/reputation/freeze | Freeze reputation (security incident) |
| POST | /internal/v1/devices/:id/reputation/unfreeze | Unfreeze reputation |
| GET | /internal/v1/psfn/policy | Current policy configuration |
| GET | /internal/v1/psfn/allocation/:device_id | Explain PSFN allocation for a device |

## Integration with Census Service

The behavioral trust computation runs alongside the census analysis from RFC 003 in the same background service. On each analysis cycle:

1. RFC 003 analysis: CA tier re-evaluation, PCR majority recalculation, cryptographic trust level update
2. RFC 005 analysis: behavioral signal aggregation, reputation score computation, decay application
3. PSFN policy evaluation: combine trust_level + reputation_score → allocation decisions

## Known Limitations

1. **No real-time reputation updates.** Reputation is recomputed on the census service interval (default: hourly). Reputation changes are eventually consistent.
2. **Self-reported attestation cadence.** Attestation frequency depends on client behavior. A device could artificially inflate its success ratio by attesting more frequently.
3. **IP stability as trust signal is fragile.** Mobile devices, VPNs, and CGNAT can cause legitimate IP changes.
4. **No coordinated Sybil detection at MVP.** Correlated activity pattern detection is future work.
5. **Policy thresholds are initial estimates.** The exact reputation thresholds for each PSFN tier will need tuning based on real fleet data.

## Future Considerations

1. Coordinated Sybil fleet detection via behavioral clustering.
2. Machine learning-based anomaly detection for behavioral signals.
3. Cross-device reputation (devices in the same account share reputation signals).
4. Reputation portability across Namek instances (for fleet migration).
5. Dynamic policy adjustment based on fleet health metrics.
6. Reputation staking — devices can "stake" PSFN capacity to vouch for new devices.
