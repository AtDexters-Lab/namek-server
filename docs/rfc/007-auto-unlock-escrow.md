# RFC 007: Auto-unlock Escrow

**Status:** Draft
**Author:** Piccolo Team
**Created:** 2026-05-01

## Summary

Add a per-device, time-bounded escrow service to namek-server: piccolod
deposits a fresh 256-bit secret `F` before a planned reboot, retrieves it
post-reboot, and revokes on success. `F` lets piccolod decrypt the on-disk
unlock blob and bring AionFS back online without an admin typing a password
at the console.

Three TPM-AK-authenticated endpoints under `/api/v1/devices/me/unlock-escrow`:
`PUT` (deposit), `GET` (pickup), `DELETE` (revoke). Single row per device,
TTL-bounded, swept by a background loop. Posture B (TPM-sealed AK) and
Posture C (sw-sealed AK) are byte-for-byte identical at this surface — the
security difference lives entirely on the device side.

## Motivation

Piccolo OS today gates every reboot on user presence to type the disk-unlock
password. This is the deliberate "no surprise downtime" stance, but it costs:
deferred OS updates, security debt, and cognitive load on non-technical
owners. The opt-in auto-unlock framework (see
`org-context/02_product/auto_unlock.md` and `02_product/auto_unlock.md`)
defers manual unlock for postures B and C; namek as the v1 provider holds the
per-cycle secret needed to bring the device back without user presence.

For Namek, that resolves to "TTL-bounded, per-device, single-row escrow
service" — exactly the shape this RFC implements.

## Non-goals (v1)

- **Kill-switch / "stolen device" state.** Deferred to a future RFC. v1 has no
  primitive that lets a user remotely refuse pickups for a device they no
  longer control.
- **PCR-bound policy.** A future cross-cutting endpoint guarantee will require
  a fresh PCR quote on every authenticated request; v1 inherits the existing
  `DeviceTPMAuth` semantics unchanged.
- **Encryption-at-rest of `F` beyond OS FDE.** Namek runs on Piccolo OS with
  full-disk encryption; that is the protection boundary for plaintext `F` in
  Postgres.
- **Test-mode endpoint.** Device-side simulation is purely a piccolod concern.
- **Distinguishing posture B from C.** Identical at the protocol surface.

## Design

### Schema (migration v6)

```
CREATE TABLE unlock_escrows (
    device_id     UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    secret        BYTEA NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    picked_up_at  TIMESTAMPTZ
);
CREATE INDEX idx_unlock_escrows_expires_at ON unlock_escrows(expires_at);
```

`device_id` as primary key enforces the singleton-per-device invariant at the
schema level. `picked_up_at` is nullable and gates the first-pickup audit
emit; it is reset to NULL on every Upsert so each new deposit cycle re-arms
the audit signal.

### Endpoint contract

`PUT /api/v1/devices/me/unlock-escrow` — Deposit. Body:
`{ secret: <base64url 32-byte>, window_seconds: <int> }`. The server clamps
`window_seconds` to `autoUnlock.maxWindowSeconds` (default 600s) and signals
the clamp in the response: `{ expires_at, effective_window_seconds, requested_clamped }`.

`GET /api/v1/devices/me/unlock-escrow` — Pickup. Returns the secret and
`expires_at`. Idempotent within the window. The server emits an audit entry
only on the first successful pickup; retries within W are silent.

`DELETE /api/v1/devices/me/unlock-escrow` — Revoke. Always 204. Audit emit
gated on whether a row was actually deleted.

All three inherit the existing `DeviceTPMAuth` middleware (nonce + AK-signed
TPM quote). `deviceID` comes from `auth.ContextKeyDeviceID`, never from the
URL — cross-device pickup is structurally impossible.

### Atomic first-pickup via single CTE

`ClaimFirstPickup` runs a single SQL statement that combines the
mark-and-return for the first-pickup case with a fall-through SELECT for the
idempotent-retry case:

```sql
WITH claimed AS (
    UPDATE unlock_escrows
    SET picked_up_at = NOW()
    WHERE device_id = $1 AND expires_at > NOW() AND picked_up_at IS NULL
    RETURNING ...
)
SELECT ..., true AS first_pickup FROM claimed
UNION ALL
SELECT ..., false AS first_pickup FROM unlock_escrows
WHERE device_id = $1 AND expires_at > NOW() AND NOT EXISTS (SELECT 1 FROM claimed)
```

Both arms run under one Postgres MVCC snapshot. The `NOT EXISTS (SELECT 1
FROM claimed)` predicate ensures the second arm contributes a row only when
the UPDATE arm did not. The earlier two-statement design had a race where a
concurrent Deposit between the UPDATE and the SELECT could swap rows; the CTE
form closes that window.

**READ COMMITTED note.** Under Postgres's default isolation, the UPDATE arm
uses EvalPlanQual to re-read the latest committed row at lock-acquire time;
the SELECT arm uses the statement snapshot. This is correct for the
audit-emit-once-per-cycle invariant — a Deposit that commits between snapshot
and lock causes the UPDATE to claim the new cycle's row, which is the desired
behavior. Callers must NOT assume snapshot-coherence between this read and
any other read in the same transaction.

### Cleanup loop

Drain-with-cap. Each tick:

1. Sample `OldestExpiredAge` and update the gauge metric. Query error: log
   warn, leave prior gauge value, proceed with drain.
2. Loop while last `DeleteExpired` returned exactly `SweepBatchSize` rows.
3. Hard cap of `SweepMaxIterations` per tick (default 10 iterations × 1000
   rows = 10K rows max).
4. `ctx.Done()` checked between iterations.
5. Per-device `auto_unlock.escrow.expired` audit emit for each cleared row.
   Audit emit is best-effort (`AuditStore.LogAction` swallows DB errors —
   codebase convention shared with every other audit emit). The row is
   already deleted; there is nothing to roll back. A future improvement —
   if and when audit gaps become visible operationally — would be a
   `dropped_audit` counter so silent gaps surface as a metric.
6. `DeleteExpired` error: log error with iteration count, abort the current
   tick, retry next tick. Mirrors `ACMEService.cleanup`.

### Audit emit policy

- `auto_unlock.escrow.deposited` on every Deposit.
- `auto_unlock.escrow.picked_up` only on first-pickup (gated by
  `picked_up_at IS NULL` in the CTE UPDATE arm).
- `auto_unlock.escrow.revoked` only when Delete actually removed a row.
- `auto_unlock.escrow.expired` once per device-row removed by sweep.

All emits go through `AuditStore.LogAction` and inherit its best-effort
semantics (DB errors are swallowed). Per-row counters in
`AutoUnlockMetrics` increment regardless of whether the audit row landed,
so under shutdown mid-iteration the `Expired` counter may briefly exceed
the count of audit rows actually written. The drift is bounded by
`SweepBatchSize` (default 1000) per shutdown event.

`details` field is free-form, same convention as the rest of the codebase
(`device.enrolled`, `domain.register`, etc.). **Developer guidance:** do not
include `secret` or any function of `secret` (hash, prefix, fingerprint) in
`details`. Same caliber as the codebase-wide expectation that recovery keys,
passwords, and TPM private material are never logged. No structural
enforcement specific to this feature.

### Audit cycle key

`auto_unlock.escrow.picked_up` is per-cycle, not per-device-per-day. A fresh
deposit creates a fresh cycle and re-arms audit emit. Auditors reconstructing
incidents must use `(device_id, escrow.deposited.created_at)` as the cycle
key, not `(device_id, day)`.

### Idempotent DELETE

The handler always returns 204, regardless of whether a row was present.
This is a deliberate divergence from `acme_store.Delete`'s 404-on-missing
pattern: post-pickup cleanup is the dominant call path for unlock-escrow, and
a network-drop retry must succeed.

### Clock-skew bound

`expires_at` is computed on the namek-server host (`time.Now()`); read
predicates (`expires_at > NOW()`) use Postgres's wall clock. NTP drift
between the two hosts shifts the effective confidentiality window by up to
the drift magnitude — a 30 s skew with the namek-server ahead of Postgres
extends a 600 s window to ~630 s as Postgres sees it. Bounded by realistic
NTP drift (typically < 1 s in healthy fleets); operators concerned about
the asymmetry can move `expires_at` computation server-side via
`NOW() + make_interval(secs => $N)` in the Upsert SQL — out of scope for v1.

### Re-enrollment invariant

An in-flight escrow survives device re-enrollment with a new AK. The FK is
on `device.id`, which is stable across re-enrollment (`device_service`
updates `ak_public_key` on the existing row). The new AK authenticates the
same device row; pickup works against the existing escrow.

### Suspended/revoked devices and CASCADE

`ON DELETE CASCADE` fires only on a DELETE of the device row.
`UpdateStatus(suspended|revoked)` is an UPDATE and does NOT fire CASCADE.

This is acceptable because `DeviceTPMAuth` (`internal/auth/middleware.go:86`)
already returns 403 for any non-active device, so a suspended device cannot
pickup its own escrow regardless of whether the row is still in DB. Worst
case: an inert row sits in DB for at most W until the sweep removes it.

Operators relying on suspension as a kill-switch must understand this. The
upcoming kill-switch RFC will provide stronger semantics (immediate
invalidation of pending issuances + refusal of future ones).

### Secret-on-the-wire defense

The PUT request body and the GET response body both carry the secret. The
GET handler sets `Cache-Control: no-store` as defense-in-depth against HTTP
caches; that header does NOT bind reverse-proxy access logs (which can
mirror request bodies as well as response bodies for debugging).

The actual defense for the secret-on-the-wire is a deployment contract:
operators deploying a TLS-terminating reverse proxy MUST disable both
request-body and response-body access logging on every method of this path,
OR terminate TLS at namek-server itself. See the integration spec deployment
constraint.

The handler also caps the PUT request body via `http.MaxBytesReader` (4 KB)
so an authenticated client cannot exhaust the API server's memory by
streaming oversized JSON; the cap is generous over the expected ~80 bytes
of payload.

### Metrics

`AutoUnlockMetrics` (counters) and `AutoUnlockGauges` (gauges). They live in
sibling structs so the existing `Collector` "monotonic counters" contract
stays intact.

| Metric | Type | Notes |
|---|---|---|
| `Deposited` | counter | every Deposit |
| `DepositedReplaced` | counter | subset of Deposited (Upsert replaced a prior row) |
| `DepositedClamped` | counter | subset of Deposited (requested window > ceiling) |
| `PickedUp` | counter | first-pickup only — matches audit emit cadence |
| `Revoked` | counter | Revoke that actually deleted a row |
| `Expired` | counter | rows removed by sweep |
| `OldestExpiredAgeSeconds` | gauge | overwritten at each sweep tick |

Dashboard authors must not sum subset counters as peers of `Deposited` —
they double-count. The struct + JSON tag comments call this out explicitly.

### Operator guidance

**Worst-case sweep audit volume.** Bounded by `SweepBatchSize ×
SweepMaxIterations × tickRate`. With defaults, that is 10 000 rows per 5 min
≈ 2 000 audit INSERTs/min sustained when draining a backlog. At fleet scales
beyond ~100 K devices, operators should size `SweepBatchSize` and tick
interval to bound audit-table growth under correlated failure (e.g., a
regional cellular flap where many devices fail their post-pickup DELETE).

**`SweepMaxIterations` tuning.** Default `10` supports 10 K rows/tick =
33 rows/sec sustained drain. Reducing to `1` drops drain throughput 10×;
only do so if backed by a known fleet-size bound.

### Inheritance from existing RFCs

TPM-AK uniqueness comes from the existing enrollment flow (RFC 003 /
`device_service`). This RFC does not re-validate AK uniqueness — it inherits
the upstream invariant.

## Open questions

- **Kill-switch shape.** Deferred to its own RFC. Likely involves a new
  device state or a `kill_switch_at` flag that `DeviceTPMAuth` reads
  independently of `Status`, plus an authenticated revocation endpoint.
- **PCR-bound policy.** Will be cross-cutting when it lands; this endpoint
  inherits whatever the platform decides.
- **Audit-table growth at extreme fleet scales.** Worst-case bound is named
  above; if cellular-flap correlated failures become a real operational
  problem, a roll-up alternative for `escrow.expired` (one entry per sweep
  with count) can replace the per-device emit without changing any wire
  contract.

## Out-of-repo follow-ups (not part of this work)

- `../piccolo-store` Namek app manifest: surface
  `autoUnlock.maxWindowSeconds` as a configurable env/setting.
- `../org-context` `02_product/auto_unlock.md`: drop `issue_id` references,
  correct the ceiling from 30 min to 10 min, soften "Namek deletes F on
  first successful retrieval / single-use F" language to reflect the
  lazy-expiry semantic.
